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
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import kotlin.random.Random

class TcpSessionManager(
  private val scope: CoroutineScope,
  private val parsedWorkerUrl: ParsedWorkerUrl,
  private val uuid: String,
  private val cleanIp: ParsedCleanIp?,
  private val sharedWorkerClient: OkHttpClient,
  private val dnsHandler: DnsHandler,
  private val vpnStateRepository: VpnStateRepository,
  workerThreads: Int = 8,
  private val writeToTun: (ByteArray) -> Unit,
) {
  companion object {
    private const val MSS = 1400
    private const val SERVER_WINDOW_SCALE = 7 // 128x multiplier -> 16384 * 128 = 2 MB window
    private const val SCALED_ACK_WINDOW = 16384
    private const val SESSION_IDLE_MS = 120_000L
    private const val WS_BACKPRESSURE_LIMIT_BYTES = 3 * 1024 * 1024L
    private const val MAX_OOO_SEGMENTS = 32
  }

  private val threadCount = workerThreads.coerceIn(2, 32)
  private val laneIdCounter = AtomicInteger(0)
  private val workerLanes: Array<ExecutorService> =
    Array(threadCount) {
      Executors.newSingleThreadExecutor { runnable ->
        Thread(runnable, "CloudNG-Lane-${laneIdCounter.incrementAndGet()}").apply {
          isDaemon = true
          priority = Thread.MAX_PRIORITY
        }
      }
    }

  @Volatile private var isShutdown = false

  data class TcpKey(
    val srcIp: Int,
    val srcPort: Int,
    val dstIp: Int,
    val dstPort: Int,
  )

  private enum class State {
    CONNECTING,
    ESTABLISHED,
    CLOSED,
  }

  private inner class TcpSession(
    val key: TcpKey,
    val targetHost: String,
    initialClientSeq: Long,
    private val negotiateWindowScale: Boolean,
  ) {
    val createdAtMs = System.currentTimeMillis()
    @Volatile var lastActivityMs = createdAtMs
    @Volatile var state = State.CONNECTING
    @Volatile var clientNextSeq = (initialClientSeq + 1L) and 0xFFFFFFFFL
    @Volatile var serverSeq = Random.nextLong(10_000L, 0x7FFF_FFFFL)
    @Volatile var ws: WebSocket? = null
    @Volatile var cryptoKey: ByteArray = ByteArray(0)
    @Volatile var initSent = false
    @Volatile var ackVerified = false
    @Volatile var clientFinReceived = false
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
      val congested = activeWs != null && activeWs.queueSize() > WS_BACKPRESSURE_LIMIT_BYTES
      return if (negotiateWindowScale) {
        if (congested) 64 else SCALED_ACK_WINDOW
      } else {
        if (congested) 4096 else 65535
      }
    }

    /**
     * 0-RTT Optimistic Handshake with RFC 1323 Window Scaling and zero-copy XOR.
     */
    fun startTunnelOptimistic() {
      sendSynAck()

      val request = WorkerProtocol.buildWebSocketRequest(parsedWorkerUrl, cleanIp)
      ws =
        sharedWorkerClient.newWebSocket(
          request,
          object : WebSocketListener() {
            override fun onOpen(webSocket: WebSocket, response: Response) {
              synchronized(uploadLock) {
                if (state == State.CLOSED) {
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
                webSocket.send(initFrame.toByteString())

                if (pendingPreOpen.size() > 0) {
                  val buffered = pendingPreOpen.toByteArray()
                  pendingPreOpen.reset()
                  WorkerProtocol.xorInPlace(buffered, encKey)
                  webSocket.send(buffered.toByteString())
                }
              }
            }

            override fun onMessage(webSocket: WebSocket, bytes: ByteString) {
              touch()
              if (state == State.CLOSED) return
              val raw = bytes.toByteArray()
              if (!ackVerified) {
                if (WorkerProtocol.verifyAck(raw, cryptoKey)) {
                  ackVerified = true
                  state = State.ESTABLISHED
                  val rtt = System.currentTimeMillis() - createdAtMs
                  vpnStateRepository.updateHandshakeRtt(rtt)
                } else {
                  vpnStateRepository.log(
                    LogLevel.ERROR,
                    "TCP",
                    "Invalid Worker ACK for $targetHost:${key.dstPort}",
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
            }

            override fun onClosing(webSocket: WebSocket, code: Int, reason: String) {
              if (state != State.CLOSED) {
                sendFinAck()
              }
              closeInternal()
            }

            override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
              if (state != State.CLOSED) {
                sendFinAck()
              }
              closeInternal()
            }

            override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
              if (!ackVerified && state != State.CLOSED) {
                vpnStateRepository.log(
                  LogLevel.WARN,
                  "TCP",
                  "Dial failed $targetHost:${key.dstPort}: ${t.message}",
                )
                sendRstAck()
              } else if (state != State.CLOSED) {
                sendFinAck()
              }
              closeInternal()
            }
          },
        )
    }

    fun handleClientPacket(raw: ByteArray, parsed: Ipv4Packet.ParsedPacket) {
      touch()
      if (state == State.CLOSED) return

      val flags = parsed.tcpFlags
      if ((flags and Ipv4Packet.TCP_RST) != 0) {
        closeInternal()
        return
      }

      if (parsed.payloadLength > 0) {
        val expected = clientNextSeq
        if (parsed.tcpSeq == expected) {
          val firstPayload =
            raw.copyOfRange(parsed.payloadOffset, parsed.payloadOffset + parsed.payloadLength)

          // Coalesce contiguous out-of-order segments into a single WebSocket binary frame
          val combined =
            if (oooBuffer.isEmpty()) {
              firstPayload
            } else {
              val batch = ByteArrayOutputStream(firstPayload.size * 2)
              batch.write(firstPayload)
              var nextExpected = (expected + firstPayload.size) and 0xFFFFFFFFL
              while (true) {
                val seg = oooBuffer.remove(nextExpected) ?: break
                batch.write(seg)
                nextExpected = (nextExpected + seg.size) and 0xFFFFFFFFL
              }
              batch.toByteArray()
            }

          processInOrderPayload(combined)
          unackedClientBytes += combined.size

          val hasPsh = (flags and Ipv4Packet.TCP_PSH) != 0
          val activeWs = ws
          val congested = activeWs != null && activeWs.queueSize() > WS_BACKPRESSURE_LIMIT_BYTES
          if (hasPsh || congested || unackedClientBytes >= MSS * 2) {
            unackedClientBytes = 0
            sendAck(currentAdvertisedWindow(activeWs))
          }
        } else if (isSeqAfter(parsed.tcpSeq, expected)) {
          val gap = (parsed.tcpSeq - expected) and 0xFFFFFFFFL
          if (gap <= 262_144L && oooBuffer.size < MAX_OOO_SEGMENTS && !oooBuffer.containsKey(parsed.tcpSeq)) {
            oooBuffer[parsed.tcpSeq] =
              raw.copyOfRange(parsed.payloadOffset, parsed.payloadOffset + parsed.payloadLength)
          }
          unackedClientBytes = 0
          sendAck(currentAdvertisedWindow(ws))
        } else if (isSeqBefore(parsed.tcpSeq, expected)) {
          unackedClientBytes = 0
          sendAck(currentAdvertisedWindow(ws))
        }
      }

      if ((flags and Ipv4Packet.TCP_FIN) != 0 && !clientFinReceived) {
        val finSeq = (parsed.tcpSeq + parsed.payloadLength) and 0xFFFFFFFFL
        if (finSeq == clientNextSeq) {
          clientNextSeq = (finSeq + 1L) and 0xFFFFFFFFL
          clientFinReceived = true
          unackedClientBytes = 0
          sendAck(currentAdvertisedWindow(ws))
        }
      }
    }

    private fun processInOrderPayload(payload: ByteArray) {
      clientNextSeq = (clientNextSeq + payload.size) and 0xFFFFFFFFL
      txBytes.addAndGet(payload.size.toLong())
      val activeWs = ws
      synchronized(uploadLock) {
        if (state == State.CLOSED) return
        if (!initSent) {
          pendingPreOpen.write(payload)
        } else {
          WorkerProtocol.xorInPlace(payload, cryptoKey)
          activeWs?.send(payload.toByteString())
        }
      }
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
            mss = MSS,
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
          val chunkLen = (data.size - off).coerceAtMost(MSS)
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

    private fun sendFinAck() {
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
            flags = Ipv4Packet.TCP_FIN or Ipv4Packet.TCP_ACK,
            window = currentAdvertisedWindow(ws),
          )
        serverSeq = (serverSeq + 1L) and 0xFFFFFFFFL
        writeToTun(pkt)
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
      sessions.remove(key)
      runCatching { ws?.close(1000, "Session closed") }
      ws = null
    }
  }

  private val sessions = ConcurrentHashMap<TcpKey, TcpSession>()
  val txBytes = AtomicLong(0L)
  val rxBytes = AtomicLong(0L)

  init {
    scope.launch(Dispatchers.IO) {
      while (isActive) {
        delay(15_000L)
        val now = System.currentTimeMillis()
        sessions.values.forEach { session ->
          if (now - session.lastActivityMs > SESSION_IDLE_MS) {
            session.closeInternal()
          }
        }
      }
    }
  }

  fun activeCount(): Int = sessions.size

  fun handleTcpPacket(raw: ByteArray, parsed: Ipv4Packet.ParsedPacket) {
    if (isShutdown) return
    val key = TcpKey(parsed.srcIp, parsed.srcPort, parsed.dstIp, parsed.dstPort)
    val packetCopy = raw.copyOfRange(0, parsed.totalLength)
    val lane = workerLanes[(key.hashCode() and 0x7FFFFFFF) % threadCount]

    runCatching {
      lane.execute {
        if (!isShutdown) {
          processPacketOnLane(key, packetCopy, parsed)
        }
      }
    }
  }

  private fun processPacketOnLane(
    key: TcpKey,
    raw: ByteArray,
    parsed: Ipv4Packet.ParsedPacket,
  ) {
    val isSynOnly =
      (parsed.tcpFlags and Ipv4Packet.TCP_SYN) != 0 &&
        (parsed.tcpFlags and Ipv4Packet.TCP_ACK) == 0

    if (isSynOnly) {
      sessions.remove(key)?.closeInternal()
      val dstStr = parsed.dstIpString
      val targetHost = dnsHandler.lookupDomainForIp(dstStr) ?: dstStr
      val clientWs = Ipv4Packet.parseTcpWindowScale(raw, parsed)
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
      existing.handleClientPacket(raw, parsed)
    } else if ((parsed.tcpFlags and Ipv4Packet.TCP_RST) == 0) {
      val rst =
        Ipv4Packet.buildTcpPacket(
          srcIp = parsed.dstIp,
          dstIp = parsed.srcIp,
          srcPort = parsed.dstPort,
          dstPort = parsed.srcPort,
          seq = parsed.tcpAck,
          ack = (parsed.tcpSeq + parsed.payloadLength + 1L) and 0xFFFFFFFFL,
          flags = Ipv4Packet.TCP_RST or Ipv4Packet.TCP_ACK,
        )
      writeToTun(rst)
    }
  }

  fun shutdown() {
    isShutdown = true
    sessions.values.toList().forEach { it.closeInternal() }
    sessions.clear()
    for (lane in workerLanes) {
      runCatching { lane.shutdownNow() }
    }
  }

  private fun isSeqBefore(a: Long, b: Long): Boolean {
    val diff = ((a - b) and 0xFFFFFFFFL).toInt()
    return diff < 0
  }

  private fun isSeqAfter(a: Long, b: Long): Boolean {
    val diff = ((a - b) and 0xFFFFFFFFL).toInt()
    return diff > 0
  }
}
