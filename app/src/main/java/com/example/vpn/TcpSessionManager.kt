package com.example.vpn

import com.example.model.LogLevel
import com.example.protocol.ParsedCleanIp
import com.example.protocol.ParsedWorkerUrl
import com.example.protocol.WorkerProtocol
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import okio.ByteString
import okio.ByteString.Companion.toByteString
import java.io.ByteArrayOutputStream
import java.util.TreeMap
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import kotlin.random.Random

class TcpSessionManager(
  private val scope: CoroutineScope,
  private val parsedWorkerUrl: ParsedWorkerUrl,
  private val uuid: String,
  private val cleanIp: ParsedCleanIp?,
  private val sharedWorkerClient: OkHttpClient,
  private val hostMapper: VirtualHostMapper,
  private val vpnStateRepository: VpnStateRepository,
  workerThreads: Int = 8,
  tunMtu: Int = 1440,
  private val writeToTun: (ByteArray) -> Unit,
  private val webSocketConnector: (Request, WebSocketListener) -> WebSocket = { req, listener ->
    sharedWorkerClient.newWebSocket(req, listener)
  },
) {
  companion object {
    private const val SERVER_WINDOW_SCALE = 2 // 4x multiplier -> max scaled window 262,140 B matching buffer budget
    private const val WINDOW_SHIFT_FACTOR = 1 shl SERVER_WINDOW_SCALE
    private const val SESSION_IDLE_MS = 120_000L
    private const val HALF_CLOSED_IDLE_MS = 20_000L
    private const val CLOSING_LINGER_MS = 3_000L
    private const val MAX_PRE_OPEN_BUFFER_BYTES = 256 * 1024
    private const val MAX_PRE_OPEN_HARD_CAP_BYTES = 384 * 1024
    private const val WS_BACKPRESSURE_HIGH_WATER_BYTES = 1024 * 1024L
    private const val WS_BACKPRESSURE_LOW_WATER_BYTES = 256 * 1024L
    private const val MAX_OOO_SEGMENTS = 32
    private const val MAX_OOO_GAP_BYTES = 131_072L
    private val EMPTY_BYTES = ByteArray(0)

    internal fun isSeqBefore(a: Long, b: Long): Boolean {
      val diff = ((a - b) and 0xFFFFFFFFL).toInt()
      return diff < 0
    }

    internal fun isSeqAfter(a: Long, b: Long): Boolean {
      val diff = ((a - b) and 0xFFFFFFFFL).toInt()
      return diff > 0
    }
  }

  private val mss = (tunMtu.coerceIn(1280, 1460) - 40).coerceIn(1200, 1400)

  private val threadCount = workerThreads.coerceIn(2, 32)
  private val laneIdCounter = AtomicInteger(0)
  private val workerLanes: Array<ExecutorService> =
    Array(threadCount) {
      Executors.newSingleThreadExecutor { runnable ->
        Thread(runnable, "CloudNG-Lane-${laneIdCounter.incrementAndGet()}").apply {
          isDaemon = true
          priority = Thread.NORM_PRIORITY
        }
      }
    }

  @Volatile private var isShutdown = false
  @Volatile private var lastBackpressureLogMs = 0L

  data class TcpKey(
    val srcIp: Int,
    val srcPort: Int,
    val dstIp: Int,
    val dstPort: Int,
  )

  private enum class State {
    CONNECTING,
    ESTABLISHED,
    CLOSING,
    CLOSED,
  }

  private inner class TcpSession(
    val key: TcpKey,
    val targetHost: String,
    val initialClientSeq: Long,
    private val negotiateWindowScale: Boolean,
  ) {
    val createdAtMs = System.currentTimeMillis()
    @Volatile var lastActivityMs = createdAtMs
    @Volatile var closingAtMs = 0L
    @Volatile var state = State.CONNECTING
    @Volatile var clientNextSeq = (initialClientSeq + 1L) and 0xFFFFFFFFL
    @Volatile var serverSeq = Random.nextLong(10_000L, 0x7FFF_FFFFL)
    @Volatile var ws: WebSocket? = null
    @Volatile var cryptoKey: ByteArray = ByteArray(0)
    @Volatile var initSent = false
    @Volatile var ackVerified = false
    @Volatile var clientFinReceived = false
    @Volatile var serverFinSent = false
    @Volatile var zeroWindowAdvertised = false
    private var unackedClientBytes = 0
    private val pendingPreOpen = ByteArrayOutputStream()
    private val oooBuffer = TreeMap<Long, ByteArray>()

    // Separate upload and downlink-TUN locks so full-duplex transfers never block each other
    private val uploadLock = Any()
    private val tunTxLock = Any()

    fun touch() {
      lastActivityMs = System.currentTimeMillis()
    }

    private fun currentAdvertisedWindow(activeWs: WebSocket?): Int {
      val budgetBytes =
        if (!initSent) {
          (MAX_PRE_OPEN_BUFFER_BYTES - pendingPreOpen.size()).coerceAtLeast(0).toLong()
        } else {
          val queued = activeWs?.queueSize() ?: 0L
          (WS_BACKPRESSURE_HIGH_WATER_BYTES - queued).coerceAtLeast(0L)
        }
      if (budgetBytes <= 0L) {
        zeroWindowAdvertised = true
        return 0
      }
      return if (negotiateWindowScale) {
        ((budgetBytes / WINDOW_SHIFT_FACTOR).coerceIn(1L, 65535L)).toInt()
      } else {
        budgetBytes.coerceIn(1L, 65535L).toInt()
      }
    }

    private fun maybeScheduleWindowResume(activeWs: WebSocket) {
      if (!zeroWindowAdvertised) return
      val queueNow = activeWs.queueSize()
      if (queueNow <= WS_BACKPRESSURE_LOW_WATER_BYTES && state == State.ESTABLISHED) {
        zeroWindowAdvertised = false
        sendAck(currentAdvertisedWindow(activeWs))
      }
    }

    fun startTunnelOptimistic() {
      sendSynAck()

      val request = WorkerProtocol.buildWebSocketRequest(parsedWorkerUrl, cleanIp)
      ws =
        webSocketConnector(
          request,
          object : WebSocketListener() {
            override fun onOpen(webSocket: WebSocket, response: Response) {
              val negProto = response.header("Sec-WebSocket-Protocol")
              if (negProto != null && !negProto.equals(WorkerProtocol.SUBPROTOCOL, ignoreCase = true)) {
                vpnStateRepository.log(
                  LogLevel.ERROR,
                  "TCP",
                  "Subprotocol mismatch for $targetHost:${key.dstPort}: '$negProto'",
                )
                webSocket.close(1002, "Unexpected subprotocol: $negProto")
                sendRstAck()
                closeInternal()
                return
              }

              var needWindowResumeAck = false
              var sendFailed = false
              synchronized(uploadLock) {
                if (state == State.CLOSED || state == State.CLOSING) {
                  webSocket.cancel()
                  return
                }
                val (initFrame, encKey) =
                  WorkerProtocol.buildInitPacket(
                    uuid = uuid,
                    targetHost = targetHost,
                    targetPort = key.dstPort,
                  )
                cryptoKey = encKey
                initSent = true
                if (!webSocket.send(initFrame.toByteString())) {
                  sendFailed = true
                  return@synchronized
                }

                if (pendingPreOpen.size() > 0) {
                  val buffered = pendingPreOpen.toByteArray()
                  pendingPreOpen.reset()
                  WorkerProtocol.xorInPlace(buffered, encKey)
                  if (!webSocket.send(buffered.toByteString())) {
                    sendFailed = true
                    return@synchronized
                  }
                }
                if (zeroWindowAdvertised && webSocket.queueSize() < WS_BACKPRESSURE_HIGH_WATER_BYTES) {
                  zeroWindowAdvertised = false
                  needWindowResumeAck = true
                }
              }

              if (sendFailed) {
                vpnStateRepository.log(
                  LogLevel.WARN,
                  "TCP",
                  "WebSocket queue refused init/pre-open payload for $targetHost:${key.dstPort}",
                )
                sendRstAck()
                closeInternal()
              } else if (needWindowResumeAck) {
                sendAck(currentAdvertisedWindow(webSocket))
              }
            }

            override fun onMessage(webSocket: WebSocket, bytes: ByteString) {
              touch()
              if (state == State.CLOSED) return
              val raw = bytes.toByteArray()
              if (!ackVerified) {
                if (WorkerProtocol.verifyAck(raw, cryptoKey)) {
                  ackVerified = true
                  if (state == State.CONNECTING) {
                    state = State.ESTABLISHED
                  }
                  val rtt = System.currentTimeMillis() - createdAtMs
                  vpnStateRepository.updateHandshakeRtt(rtt)
                } else {
                  vpnStateRepository.log(
                    LogLevel.ERROR,
                    "TCP",
                    "Invalid Worker ACK for $targetHost:${key.dstPort} (check UUID)",
                  )
                  sendRstAck()
                  closeInternal()
                }
                return
              }

              if (raw.isEmpty()) return
              WorkerProtocol.xorInPlace(raw, cryptoKey)
              rxBytes.addAndGet(raw.size.toLong())
              sendDataChunksToTun(raw)
              maybeScheduleWindowResume(webSocket)
            }

            override fun onClosing(webSocket: WebSocket, code: Int, reason: String) {
              initiateRemoteClose()
            }

            override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
              initiateRemoteClose()
            }

            override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
              if (!ackVerified && state != State.CLOSED) {
                val errDetail =
                  if (response != null) "HTTP ${response.code}" else (t.message ?: t.javaClass.simpleName)
                vpnStateRepository.log(
                  LogLevel.WARN,
                  "TCP",
                  "Dial failed $targetHost:${key.dstPort}: $errDetail",
                )
                sendRstAck()
                closeInternal()
              } else if (state != State.CLOSED) {
                initiateRemoteClose()
              }
            }
          },
        )
    }

    private fun initiateRemoteClose() {
      synchronized(tunTxLock) {
        if (state == State.CLOSED) return
        if (!serverFinSent) {
          serverFinSent = true
          closingAtMs = System.currentTimeMillis()
          state = State.CLOSING
          val pkt =
            Ipv4Packet.buildTcpPacket(
              srcIp = key.dstIp,
              dstIp = key.srcIp,
              srcPort = key.dstPort,
              dstPort = key.srcPort,
              seq = serverSeq,
              ack = clientNextSeq,
              flags = Ipv4Packet.TCP_FIN or Ipv4Packet.TCP_ACK,
              window = currentAdvertisedWindow(ws),
            )
          serverSeq = (serverSeq + 1L) and 0xFFFFFFFFL
          writeToTun(pkt)
        }
      }
      runCatching { ws?.close(1000, "EOF") }
    }

    fun retransmitSynAck() {
      touch()
      synchronized(tunTxLock) {
        if (state != State.CONNECTING && state != State.ESTABLISHED) return
        // Re-emit SYN-ACK with original ISN = serverSeq - 1
        val origSynSeq = (serverSeq - 1L) and 0xFFFFFFFFL
        val pkt =
          Ipv4Packet.buildTcpPacket(
            srcIp = key.dstIp,
            dstIp = key.srcIp,
            srcPort = key.dstPort,
            dstPort = key.srcPort,
            seq = origSynSeq,
            ack = clientNextSeq,
            flags = Ipv4Packet.TCP_SYN or Ipv4Packet.TCP_ACK,
            window = 65535,
            mss = mss,
            windowScale = if (negotiateWindowScale) SERVER_WINDOW_SCALE else null,
          )
        writeToTun(pkt)
      }
    }

    fun handleClientPacket(
      parsed: Ipv4Packet.ParsedPacket,
      payloadData: ByteArray,
    ) {
      touch()
      if (state == State.CLOSED) return

      val flags = parsed.tcpFlags
      if ((flags and Ipv4Packet.TCP_RST) != 0) {
        closeInternal()
        return
      }

      if (payloadData.isNotEmpty() && !clientFinReceived) {
        val expected = clientNextSeq
        if (parsed.tcpSeq == expected) {
          acceptInOrderAndDrainOoo(expected, payloadData, flags)
        } else if (isSeqAfter(parsed.tcpSeq, expected)) {
          val gap = (parsed.tcpSeq - expected) and 0xFFFFFFFFL
          if (gap <= MAX_OOO_GAP_BYTES &&
            oooBuffer.size < MAX_OOO_SEGMENTS &&
            !oooBuffer.containsKey(parsed.tcpSeq)
          ) {
            oooBuffer[parsed.tcpSeq] = payloadData
          }
          unackedClientBytes = 0
          sendAck(currentAdvertisedWindow(ws))
        } else {
          // Pure retransmit or partially overlapping retransmit
          val segEnd = (parsed.tcpSeq + payloadData.size) and 0xFFFFFFFFL
          if (isSeqAfter(segEnd, expected)) {
            val overlapOffset = ((expected - parsed.tcpSeq) and 0xFFFFFFFFL).toInt()
            if (overlapOffset in 1 until payloadData.size) {
              val trimmed = payloadData.copyOfRange(overlapOffset, payloadData.size)
              acceptInOrderAndDrainOoo(expected, trimmed, flags)
            }
          } else {
            // Pure duplicate or Zero-Window probe ACK: answer immediately with current window
            unackedClientBytes = 0
            sendAck(currentAdvertisedWindow(ws))
          }
        }
      } else if (payloadData.isEmpty() && zeroWindowAdvertised) {
        val activeWs = ws
        if (activeWs != null && activeWs.queueSize() <= WS_BACKPRESSURE_LOW_WATER_BYTES) {
          zeroWindowAdvertised = false
          sendAck(currentAdvertisedWindow(activeWs))
        }
      }

      if ((flags and Ipv4Packet.TCP_FIN) != 0 && !clientFinReceived) {
        val finSeq = (parsed.tcpSeq + payloadData.size) and 0xFFFFFFFFL
        if (finSeq == clientNextSeq) {
          clientNextSeq = (finSeq + 1L) and 0xFFFFFFFFL
          clientFinReceived = true
          unackedClientBytes = 0
          sendAck(currentAdvertisedWindow(ws))
          if (serverFinSent && state == State.CLOSING) {
            // Both sides exchanged FIN; keep brief linger in CLOSING so late duplicate ACKs don't trigger RST
            closingAtMs = System.currentTimeMillis()
          }
        }
      }
    }

    private fun acceptInOrderAndDrainOoo(
      startSeq: Long,
      initialChunk: ByteArray,
      flags: Int,
    ) {
      val combined =
        if (oooBuffer.isEmpty()) {
          initialChunk
        } else {
          val batch = ByteArrayOutputStream(initialChunk.size * 2)
          batch.write(initialChunk)
          var nextExpected = (startSeq + initialChunk.size) and 0xFFFFFFFFL
          while (true) {
            val seg = oooBuffer.remove(nextExpected) ?: break
            batch.write(seg)
            nextExpected = (nextExpected + seg.size) and 0xFFFFFFFFL
          }
          // Prune any stale/covered segments from oooBuffer
          while (oooBuffer.isNotEmpty()) {
            val firstEntry = oooBuffer.firstEntry() ?: break
            val segEnd = (firstEntry.key + firstEntry.value.size) and 0xFFFFFFFFL
            if (!isSeqAfter(segEnd, nextExpected)) {
              oooBuffer.pollFirstEntry()
            } else {
              break
            }
          }
          batch.toByteArray()
        }

      val accepted = processInOrderPayload(combined)
      if (!accepted) return

      unackedClientBytes += combined.size
      val hasPsh = (flags and Ipv4Packet.TCP_PSH) != 0
      val activeWs = ws
      val congested = zeroWindowAdvertised || (activeWs != null && activeWs.queueSize() > WS_BACKPRESSURE_LOW_WATER_BYTES)
      if (hasPsh || congested || unackedClientBytes >= mss * 2) {
        unackedClientBytes = 0
        sendAck(currentAdvertisedWindow(activeWs))
      }
    }

    private fun processInOrderPayload(payload: ByteArray): Boolean {
      val activeWs = ws
      var accepted = false
      var sendFailed = false
      synchronized(uploadLock) {
        if (state == State.CLOSED || state == State.CLOSING) return false
        if (!initSent) {
          if (pendingPreOpen.size() + payload.size > MAX_PRE_OPEN_HARD_CAP_BYTES) {
            // Do not advance clientNextSeq and do not allocate unbounded memory; throttle via window=0
            zeroWindowAdvertised = true
            return false
          }
          pendingPreOpen.write(payload)
          clientNextSeq = (clientNextSeq + payload.size) and 0xFFFFFFFFL
          txBytes.addAndGet(payload.size.toLong())
          accepted = true
        } else {
          val queued = activeWs?.queueSize() ?: 0L
          if (queued >= WS_BACKPRESSURE_HIGH_WATER_BYTES) {
            val now = System.currentTimeMillis()
            if (now - lastBackpressureLogMs > 5_000L) {
              lastBackpressureLogMs = now
              vpnStateRepository.log(
                LogLevel.WARN,
                "TCP",
                "Backpressure throttling $targetHost:${key.dstPort} (WS queue ${queued / 1024} KB)",
              )
            }
          }
          WorkerProtocol.xorInPlace(payload, cryptoKey)
          val ok = activeWs?.send(payload.toByteString()) == true
          if (!ok) {
            sendFailed = true
          } else {
            clientNextSeq = (clientNextSeq + payload.size) and 0xFFFFFFFFL
            txBytes.addAndGet(payload.size.toLong())
            accepted = true
          }
        }
      }

      if (sendFailed) {
        vpnStateRepository.log(
          LogLevel.WARN,
          "TCP",
          "WebSocket send buffer rejected ${payload.size}B for $targetHost:${key.dstPort}; resetting TCP stream",
        )
        sendRstAck()
        closeInternal()
        return false
      }
      if (zeroWindowAdvertised) {
        sendAck(0)
      }
      return accepted
    }

    private fun sendSynAck() {
      synchronized(tunTxLock) {
        if (state == State.CLOSED) return
        val pkt =
          Ipv4Packet.buildTcpPacket(
            srcIp = key.dstIp,
            dstIp = key.srcIp,
            srcPort = key.dstPort,
            dstPort = key.srcPort,
            seq = serverSeq,
            ack = clientNextSeq,
            flags = Ipv4Packet.TCP_SYN or Ipv4Packet.TCP_ACK,
            window = 65535,
            mss = mss,
            windowScale = if (negotiateWindowScale) SERVER_WINDOW_SCALE else null,
          )
        serverSeq = (serverSeq + 1L) and 0xFFFFFFFFL
        writeToTun(pkt)
      }
    }

    private fun sendAck(window: Int) {
      synchronized(tunTxLock) {
        if (state == State.CLOSED) return
        val pkt =
          Ipv4Packet.buildTcpPacket(
            srcIp = key.dstIp,
            dstIp = key.srcIp,
            srcPort = key.dstPort,
            dstPort = key.srcPort,
            seq = serverSeq,
            ack = clientNextSeq,
            flags = Ipv4Packet.TCP_ACK,
            window = window,
          )
        writeToTun(pkt)
      }
    }

    private fun sendDataChunksToTun(data: ByteArray) {
      synchronized(tunTxLock) {
        if (state == State.CLOSED) return
        val wnd = currentAdvertisedWindow(ws)
        val seqAck = clientNextSeq
        var off = 0
        while (off < data.size) {
          val chunkLen = (data.size - off).coerceAtMost(mss)
          val isLast = off + chunkLen >= data.size
          val flags =
            if (isLast) Ipv4Packet.TCP_PSH or Ipv4Packet.TCP_ACK
            else Ipv4Packet.TCP_ACK
          val pkt =
            Ipv4Packet.buildTcpPacket(
              srcIp = key.dstIp,
              dstIp = key.srcIp,
              srcPort = key.dstPort,
              dstPort = key.srcPort,
              seq = serverSeq,
              ack = seqAck,
              flags = flags,
              window = wnd,
              payload = data,
              payloadOffset = off,
              payloadLength = chunkLen,
            )
          serverSeq = (serverSeq + chunkLen) and 0xFFFFFFFFL
          writeToTun(pkt)
          off += chunkLen
        }
      }
    }

    private fun sendRstAck() {
      synchronized(tunTxLock) {
        val pkt =
          Ipv4Packet.buildTcpPacket(
            srcIp = key.dstIp,
            dstIp = key.srcIp,
            srcPort = key.dstPort,
            dstPort = key.srcPort,
            seq = serverSeq,
            ack = clientNextSeq,
            flags = Ipv4Packet.TCP_RST or Ipv4Packet.TCP_ACK,
            window = 0,
          )
        writeToTun(pkt)
      }
    }

    fun closeInternal() {
      synchronized(uploadLock) {
        if (state == State.CLOSED) return
        state = State.CLOSED
        pendingPreOpen.reset()
        oooBuffer.clear()
      }
      sessions.remove(key, this)
      runCatching { ws?.close(1000, "Session closed") }
      ws = null
    }
  }

  private val sessions = ConcurrentHashMap<TcpKey, TcpSession>()
  val txBytes = AtomicLong(0L)
  val rxBytes = AtomicLong(0L)

  init {
    scope.launch(Dispatchers.IO) {
      while (isActive && !isShutdown) {
        delay(2_000L)
        val now = System.currentTimeMillis()
        sessions.values.forEach { session ->
          val expired =
            when {
              session.state == State.CLOSING && session.closingAtMs > 0L ->
                now - session.closingAtMs > CLOSING_LINGER_MS
              session.clientFinReceived ->
                now - session.lastActivityMs > HALF_CLOSED_IDLE_MS
              else ->
                now - session.lastActivityMs > SESSION_IDLE_MS
            }
          if (expired) {
            session.closeInternal()
          } else if (session.zeroWindowAdvertised && session.state == State.ESTABLISHED) {
            val activeWs = session.ws
            if (activeWs != null && activeWs.queueSize() <= WS_BACKPRESSURE_LOW_WATER_BYTES) {
              session.handleClientPacket(
                Ipv4Packet.ParsedPacket(
                  version = 4,
                  protocol = Ipv4Packet.PROTO_TCP,
                  ipHeaderLen = 20,
                  totalLength = 40,
                  srcIp = session.key.srcIp,
                  dstIp = session.key.dstIp,
                  srcPort = session.key.srcPort,
                  dstPort = session.key.dstPort,
                  tcpSeq = session.clientNextSeq,
                  tcpAck = session.serverSeq,
                  tcpFlags = Ipv4Packet.TCP_ACK,
                  tcpWindow = 65535,
                  payloadOffset = 40,
                  payloadLength = 0,
                ),
                EMPTY_BYTES,
              )
            }
          }
        }
      }
    }
  }

  fun activeCount(): Int = sessions.size

  fun handleTcpPacket(raw: ByteArray, parsed: Ipv4Packet.ParsedPacket) {
    if (isShutdown) return
    val key = TcpKey(parsed.srcIp, parsed.srcPort, parsed.dstIp, parsed.dstPort)
    val isSynOnly =
      (parsed.tcpFlags and Ipv4Packet.TCP_SYN) != 0 &&
        (parsed.tcpFlags and Ipv4Packet.TCP_ACK) == 0

    // Avoid heap allocations for pure ACKs/FINs/RSTs; only copy TCP options on SYN or payload slice on data
    val synHeaderSlice: ByteArray?
    val payloadSlice: ByteArray
    if (isSynOnly) {
      synHeaderSlice = raw.copyOfRange(0, parsed.totalLength.coerceAtMost(raw.size))
      payloadSlice = EMPTY_BYTES
    } else if (parsed.payloadLength > 0 && parsed.payloadOffset + parsed.payloadLength <= raw.size) {
      synHeaderSlice = null
      payloadSlice = raw.copyOfRange(parsed.payloadOffset, parsed.payloadOffset + parsed.payloadLength)
    } else {
      synHeaderSlice = null
      payloadSlice = EMPTY_BYTES
    }

    val lane = workerLanes[(key.hashCode() and 0x7FFFFFFF) % threadCount]
    runCatching {
      lane.execute {
        if (!isShutdown) {
          processPacketOnLane(key, synHeaderSlice, payloadSlice, parsed, isSynOnly)
        }
      }
    }
  }

  private fun processPacketOnLane(
    key: TcpKey,
    synHeaderSlice: ByteArray?,
    payloadSlice: ByteArray,
    parsed: Ipv4Packet.ParsedPacket,
    isSynOnly: Boolean,
  ) {
    if (isSynOnly) {
      val existing = sessions[key]
      if (existing != null &&
        existing.state != State.CLOSED &&
        existing.initialClientSeq == parsed.tcpSeq
      ) {
        // Kernel SYN retransmission during CONNECTING/OPEN: resend SYN-ACK without killing WebSocket
        existing.retransmitSynAck()
        return
      }
      if (existing != null) {
        sessions.remove(key, existing)
        existing.closeInternal()
      }

      val dstStr = parsed.dstIpString
      val mappedDomain = hostMapper.lookupDomainForIp(dstStr)
      val inSyntheticPool = VirtualHostMapper.isInSyntheticSubnet(parsed.dstIp)
      if (dstStr == VirtualHostMapper.VIRTUAL_TUN_GATEWAY_IP ||
        (inSyntheticPool && (mappedDomain == null || !VirtualHostMapper.isValidSyntheticIp(dstStr)))
      ) {
        vpnStateRepository.log(
          LogLevel.WARN,
          "TCP",
          "Rejected unmapped/invalid synthetic TCP target $dstStr:${parsed.dstPort}",
        )
        val rst =
          Ipv4Packet.buildTcpPacket(
            srcIp = parsed.dstIp,
            dstIp = parsed.srcIp,
            srcPort = parsed.dstPort,
            dstPort = parsed.srcPort,
            seq = 0L,
            ack = (parsed.tcpSeq + 1L) and 0xFFFFFFFFL,
            flags = Ipv4Packet.TCP_RST or Ipv4Packet.TCP_ACK,
            window = 0,
          )
        writeToTun(rst)
        return
      }

      val targetHost = mappedDomain ?: dstStr
      val clientWs =
        if (synHeaderSlice != null) Ipv4Packet.parseTcpWindowScale(synHeaderSlice, parsed) else null
      val session = TcpSession(key, targetHost, parsed.tcpSeq, negotiateWindowScale = clientWs != null)
      sessions[key] = session
      if (vpnStateRepository.wantsTrafficLog()) {
        vpnStateRepository.log(
          LogLevel.TRAFFIC,
          "TUN",
          "0-RTT (${threadCount}T) → $targetHost:${parsed.dstPort}",
        )
      }
      session.startTunnelOptimistic()
      return
    }

    val existing = sessions[key]
    if (existing != null) {
      existing.handleClientPacket(parsed, payloadSlice)
    } else if ((parsed.tcpFlags and Ipv4Packet.TCP_RST) == 0) {
      val rst =
        Ipv4Packet.buildTcpPacket(
          srcIp = parsed.dstIp,
          dstIp = parsed.srcIp,
          srcPort = parsed.dstPort,
          dstPort = parsed.srcPort,
          seq = parsed.tcpAck,
          ack = (parsed.tcpSeq + parsed.payloadLength + if ((parsed.tcpFlags and Ipv4Packet.TCP_FIN) != 0) 1L else 0L) and 0xFFFFFFFFL,
          flags = Ipv4Packet.TCP_RST or Ipv4Packet.TCP_ACK,
          window = 0,
        )
      writeToTun(rst)
    }
  }

  fun shutdown() {
    isShutdown = true
    sessions.values.toList().forEach { it.closeInternal() }
    sessions.clear()
    for (lane in workerLanes) {
      runCatching {
        lane.shutdownNow()
        lane.awaitTermination(200L, TimeUnit.MILLISECONDS)
      }
    }
  }
}
