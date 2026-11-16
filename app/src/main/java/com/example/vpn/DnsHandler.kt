package com.example.vpn

import com.example.model.LogLevel
import com.example.protocol.ParsedCleanIp
import com.example.protocol.ParsedWorkerUrl
import com.example.protocol.WorkerProtocol
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import okhttp3.OkHttpClient
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import okio.ByteString
import okio.ByteString.Companion.toByteString
import java.io.ByteArrayOutputStream
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import kotlin.coroutines.resume

class DnsHandler(
  private val scope: CoroutineScope,
  private val parsedWorkerUrl: ParsedWorkerUrl,
  private val uuid: String,
  private val cleanIp: ParsedCleanIp?,
  private val dnsServerIp: String,
  private val sharedWorkerClient: OkHttpClient,
  private val vpnStateRepository: VpnStateRepository,
  private val writeToTun: (ByteArray) -> Unit,
) {
  private val reverseIpToDomain = ConcurrentHashMap<String, String>()
  private val queryCache = ConcurrentHashMap<String, Pair<ByteArray, Long>>()
  private val inFlightDedup = ConcurrentHashMap<String, CompletableDeferred<ByteArray?>>()

  /**
   * Keeps 1 warm, persistent WebSocket tunnel open to `dnsServerIp:53` for pipelined
   * DNS-over-TCP queries (RFC 7766), awaiting handshake readiness instead of spawning
   * redundant cold WebSocket connections during startup bursts.
   */
  private inner class PersistentDnsTunnel {
    private val lock = Any()
    private val nextInternalId = AtomicInteger(1)
    private val pending = ConcurrentHashMap<Int, CompletableDeferred<ByteArray?>>()
    private val rxStream = ByteArrayOutputStream()
    private var ws: WebSocket? = null
    private var key = ByteArray(0)
    @Volatile private var acked = false
    @Volatile private var connecting = false
    @Volatile private var ackReady: CompletableDeferred<Boolean>? = null
    private val lastConnectAttemptMs = AtomicLong(0L)

    fun ensureConnected(forceNow: Boolean = false): CompletableDeferred<Boolean>? {
      val readySignal: CompletableDeferred<Boolean>
      synchronized(lock) {
        if (acked && ws != null) return CompletableDeferred(true)
        if (connecting && ackReady != null) return ackReady
        val now = System.currentTimeMillis()
        if (!forceNow && now - lastConnectAttemptMs.get() < 1_000L) return ackReady
        lastConnectAttemptMs.set(now)
        connecting = true
        acked = false
        rxStream.reset()
        readySignal = CompletableDeferred()
        ackReady = readySignal
      }

      val request = WorkerProtocol.buildWebSocketRequest(parsedWorkerUrl, cleanIp)
      val newWs =
        sharedWorkerClient.newWebSocket(
          request,
          object : WebSocketListener() {
            override fun onOpen(webSocket: WebSocket, response: Response) {
              val (initPkt, k) =
                WorkerProtocol.buildInitPacket(
                  uuid = uuid,
                  targetHost = dnsServerIp,
                  targetPort = 53,
                )
              synchronized(lock) {
                key = k
                ws = webSocket
                connecting = false
              }
              webSocket.send(initPkt.toByteString())
            }

            override fun onMessage(webSocket: WebSocket, bytes: ByteString) {
              val data = bytes.toByteArray()
              if (!acked) {
                if (WorkerProtocol.verifyAck(data, key)) {
                  acked = true
                  ackReady?.complete(true)
                } else {
                  ackReady?.complete(false)
                  reset(webSocket)
                }
                return
              }

              WorkerProtocol.xorInPlace(data, key)
              val completed = mutableListOf<Pair<Int, ByteArray>>()
              synchronized(lock) {
                rxStream.write(data)
                val buf = rxStream.toByteArray()
                var off = 0
                while (off + 2 <= buf.size) {
                  val msgLen = ((buf[off].toInt() and 0xFF) shl 8) or (buf[off + 1].toInt() and 0xFF)
                  if (msgLen <= 0 || msgLen > 4096) {
                    rxStream.reset()
                    return
                  }
                  if (off + 2 + msgLen > buf.size) break
                  val msg = buf.copyOfRange(off + 2, off + 2 + msgLen)
                  if (msg.size >= 2) {
                    val txId = ((msg[0].toInt() and 0xFF) shl 8) or (msg[1].toInt() and 0xFF)
                    completed.add(txId to msg)
                  }
                  off += 2 + msgLen
                }
                if (off > 0) {
                  val rem = buf.size - off
                  rxStream.reset()
                  if (rem > 0) rxStream.write(buf, off, rem)
                }
              }
              for ((id, resp) in completed) {
                pending.remove(id)?.complete(resp)
              }
            }

            override fun onClosing(webSocket: WebSocket, code: Int, reason: String) {
              ackReady?.complete(false)
              reset(webSocket)
            }

            override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
              ackReady?.complete(false)
              reset(webSocket)
            }

            override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
              ackReady?.complete(false)
              reset(webSocket)
            }
          },
        )
      synchronized(lock) {
        if (ws == null && connecting) {
          ws = newWs
        }
      }
      return readySignal
    }

    suspend fun query(dnsQuery: ByteArray): ByteArray? {
      if (!acked || ws == null) {
        val ready = ensureConnected(forceNow = true)
        val ok = ready?.let { withTimeoutOrNull(3_000L) { it.await() } } ?: false
        if (!ok || !acked) return null
      }

      val activeWs: WebSocket
      val activeKey: ByteArray
      synchronized(lock) {
        if (!acked || ws == null) return null
        activeWs = ws!!
        activeKey = key
      }

      val origId0 = dnsQuery[0]
      val origId1 = dnsQuery[1]
      val internalId = nextInternalId.getAndIncrement() and 0xFFFF
      val deferred = CompletableDeferred<ByteArray?>()
      pending[internalId] = deferred

      val framed = ByteArray(2 + dnsQuery.size)
      framed[0] = ((dnsQuery.size ushr 8) and 0xFF).toByte()
      framed[1] = (dnsQuery.size and 0xFF).toByte()
      System.arraycopy(dnsQuery, 0, framed, 2, dnsQuery.size)
      framed[2] = ((internalId ushr 8) and 0xFF).toByte()
      framed[3] = (internalId and 0xFF).toByte()
      WorkerProtocol.xorInPlace(framed, activeKey)

      if (!activeWs.send(framed.toByteString())) {
        pending.remove(internalId)
        reset(activeWs)
        return null
      }

      val resp = withTimeoutOrNull(2_500L) { deferred.await() }
      pending.remove(internalId)
      if (resp == null || resp.size < 12) return null
      resp[0] = origId0
      resp[1] = origId1
      return resp
    }

    private fun reset(target: WebSocket?) {
      synchronized(lock) {
        if (target != null && ws != null && ws !== target) return
        runCatching { ws?.cancel() }
        ws = null
        acked = false
        connecting = false
        ackReady?.complete(false)
        ackReady = null
        rxStream.reset()
      }
      pending.values.forEach { it.complete(null) }
      pending.clear()
    }

    fun close() {
      reset(null)
    }
  }

  private val persistentTunnel = PersistentDnsTunnel()

  init {
    scope.launch(Dispatchers.IO) {
      persistentTunnel.ensureConnected(forceNow = true)
    }
  }

  fun lookupDomainForIp(ip: String): String? = reverseIpToDomain[ip]

  fun handleUdpPacket(raw: ByteArray, parsed: Ipv4Packet.ParsedPacket) {
    if (parsed.payloadLength < 12) return
    val dnsQuery = raw.copyOfRange(parsed.payloadOffset, parsed.payloadOffset + parsed.payloadLength)
    val qname = extractQname(dnsQuery)
    val qtype = extractQtype(dnsQuery)

    // TUN is IPv4-only: return instant NODATA for AAAA (28) and HTTPS (65)
    if (qtype == 28 || qtype == 65) {
      val noDataReply = buildNoDataResponse(dnsQuery)
      if (noDataReply != null) {
        val udpReply =
          Ipv4Packet.buildUdpPacket(
            srcIp = parsed.dstIp,
            dstIp = parsed.srcIp,
            srcPort = parsed.dstPort,
            dstPort = parsed.srcPort,
            payload = noDataReply,
          )
        writeToTun(udpReply)
        return
      }
    }

    val cacheKey = "$qname:$qtype"
    val now = System.currentTimeMillis()
    val cached = queryCache[cacheKey]
    if (cached != null && now < cached.second) {
      val udpReply =
        Ipv4Packet.buildUdpPacket(
          srcIp = parsed.dstIp,
          dstIp = parsed.srcIp,
          srcPort = parsed.dstPort,
          dstPort = parsed.srcPort,
          payload = patchTransactionId(cached.first, dnsQuery),
        )
      writeToTun(udpReply)
      return
    }

    scope.launch(Dispatchers.IO) {
      val existingInFlight = inFlightDedup[cacheKey]
      val resolved =
        if (existingInFlight != null) {
          existingInFlight.await()?.let { patchTransactionId(it, dnsQuery) }
        } else {
          val mine = CompletableDeferred<ByteArray?>()
          val raceWinner = inFlightDedup.putIfAbsent(cacheKey, mine)
          if (raceWinner != null) {
            raceWinner.await()?.let { patchTransactionId(it, dnsQuery) }
          } else {
            try {
              val ans =
                persistentTunnel.query(dnsQuery)
                  ?: resolveViaWorkerTcp(dnsQuery)
              if (ans != null && ans.size >= 12) {
                queryCache[cacheKey] = ans to (System.currentTimeMillis() + 300_000L)
                recordReverseMappings(qname, ans)
              }
              mine.complete(ans)
              ans
            } catch (_: Throwable) {
              mine.complete(null)
              null
            } finally {
              inFlightDedup.remove(cacheKey, mine)
            }
          }
        }

      if (resolved != null && resolved.size >= 12) {
        val udpReply =
          Ipv4Packet.buildUdpPacket(
            srcIp = parsed.dstIp,
            dstIp = parsed.srcIp,
            srcPort = parsed.dstPort,
            dstPort = parsed.srcPort,
            payload = resolved,
          )
        writeToTun(udpReply)
      }
    }
  }

  private suspend fun resolveViaWorkerTcp(dnsQuery: ByteArray): ByteArray? {
    val tcpPrefixed = ByteArray(2 + dnsQuery.size)
    tcpPrefixed[0] = ((dnsQuery.size ushr 8) and 0xFF).toByte()
    tcpPrefixed[1] = (dnsQuery.size and 0xFF).toByte()
    System.arraycopy(dnsQuery, 0, tcpPrefixed, 2, dnsQuery.size)

    val request = WorkerProtocol.buildWebSocketRequest(parsedWorkerUrl, cleanIp)
    return try {
      withTimeout(3_000L) {
        suspendCancellableCoroutine { cont ->
          var acked = false
          var key = ByteArray(0)
          val acc = ByteArrayOutputStream()
          var expectedLen = -1

          val ws =
            sharedWorkerClient.newWebSocket(
              request,
              object : WebSocketListener() {
                override fun onOpen(webSocket: WebSocket, response: Response) {
                  val (initPkt, k) =
                    WorkerProtocol.buildInitPacket(
                      uuid = uuid,
                      targetHost = dnsServerIp,
                      targetPort = 53,
                    )
                  key = k
                  webSocket.send(initPkt.toByteString())
                  webSocket.send(WorkerProtocol.xorBuf(tcpPrefixed, k).toByteString())
                }

                override fun onMessage(webSocket: WebSocket, bytes: ByteString) {
                  val data = bytes.toByteArray()
                  if (!acked) {
                    if (WorkerProtocol.verifyAck(data, key)) {
                      acked = true
                    } else {
                      webSocket.close(1002, "Bad ACK")
                      if (cont.isActive) cont.resume(null)
                    }
                    return
                  }
                  WorkerProtocol.xorInPlace(data, key)
                  acc.write(data)
                  val buf = acc.toByteArray()
                  if (expectedLen < 0 && buf.size >= 2) {
                    expectedLen = ((buf[0].toInt() and 0xFF) shl 8) or (buf[1].toInt() and 0xFF)
                  }
                  if (expectedLen > 0 && buf.size >= 2 + expectedLen) {
                    val dnsPayload = buf.copyOfRange(2, 2 + expectedLen)
                    webSocket.close(1000, "DNS OK")
                    if (cont.isActive) cont.resume(dnsPayload)
                  }
                }

                override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                  if (cont.isActive) cont.resume(null)
                }

                override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
                  if (cont.isActive) cont.resume(null)
                }
              },
            )
          cont.invokeOnCancellation { ws.cancel() }
        }
      }
    } catch (e: Exception) {
      vpnStateRepository.log(LogLevel.WARN, "DNS", "TCP DNS timeout: ${e.message}")
      null
    }
  }

  private fun buildNoDataResponse(query: ByteArray): ByteArray? {
    if (query.size < 12) return null
    val qEnd = skipName(query, 12) + 4
    if (qEnd > query.size) return null
    val resp = query.copyOfRange(0, qEnd)
    resp[2] = 0x81.toByte()
    resp[3] = 0x80.toByte()
    resp[6] = 0
    resp[7] = 0
    resp[8] = 0
    resp[9] = 0
    resp[10] = 0
    resp[11] = 0
    return resp
  }

  private fun patchTransactionId(cachedResp: ByteArray, query: ByteArray): ByteArray {
    val out = cachedResp.copyOf()
    if (out.size >= 2 && query.size >= 2) {
      out[0] = query[0]
      out[1] = query[1]
    }
    return out
  }

  private fun extractQname(dns: ByteArray): String {
    if (dns.size < 13) return ""
    var off = 12
    val labels = mutableListOf<String>()
    while (off < dns.size) {
      val len = dns[off].toInt() and 0xFF
      if (len == 0) break
      if ((len and 0xC0) == 0xC0) break
      off++
      if (off + len > dns.size) break
      labels.add(String(dns, off, len, Charsets.UTF_8))
      off += len
    }
    return labels.joinToString(".")
  }

  private fun extractQtype(dns: ByteArray): Int {
    if (dns.size < 16) return 1
    var off = 12
    while (off < dns.size) {
      val len = dns[off].toInt() and 0xFF
      if (len == 0) {
        off++
        break
      }
      if ((len and 0xC0) == 0xC0) {
        off += 2
        break
      }
      off += 1 + len
    }
    return if (off + 2 <= dns.size) {
      ((dns[off].toInt() and 0xFF) shl 8) or (dns[off + 1].toInt() and 0xFF)
    } else 1
  }

  private fun recordReverseMappings(qname: String, resp: ByteArray) {
    if (qname.isBlank() || resp.size < 12) return
    val qdCount = ((resp[4].toInt() and 0xFF) shl 8) or (resp[5].toInt() and 0xFF)
    val anCount = ((resp[6].toInt() and 0xFF) shl 8) or (resp[7].toInt() and 0xFF)
    var off = 12
    for (i in 0 until qdCount) {
      off = skipName(resp, off)
      off += 4
      if (off > resp.size) return
    }
    for (i in 0 until anCount) {
      off = skipName(resp, off)
      if (off + 10 > resp.size) return
      val type = ((resp[off].toInt() and 0xFF) shl 8) or (resp[off + 1].toInt() and 0xFF)
      val rdlen = ((resp[off + 8].toInt() and 0xFF) shl 8) or (resp[off + 9].toInt() and 0xFF)
      off += 10
      if (off + rdlen > resp.size) return
      if (type == 1 && rdlen == 4) {
        val ipStr = WorkerProtocol.ipv4ToString(resp, off)
        reverseIpToDomain[ipStr] = qname
      }
      off += rdlen
    }
  }

  private fun skipName(buf: ByteArray, start: Int): Int {
    var off = start
    while (off < buf.size) {
      val b = buf[off].toInt() and 0xFF
      if (b == 0) return off + 1
      if ((b and 0xC0) == 0xC0) return off + 2
      off += 1 + b
    }
    return buf.size
  }

  fun shutdown() {
    persistentTunnel.close()
    inFlightDedup.values.forEach { it.complete(null) }
    inFlightDedup.clear()
  }
}
