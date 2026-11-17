package com.example.protocol

import com.example.model.CleanIpTestResult
import com.example.model.HandshakeTestResult
import com.example.model.LogLevel
import com.example.model.VpnConfig
import com.example.vpn.VpnStateRepository
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import okio.ByteString
import okio.ByteString.Companion.toByteString
import kotlin.coroutines.resume

class WorkerTester(
  private val vpnStateRepository: VpnStateRepository,
) {
  suspend fun testWorkerHandshake(config: VpnConfig): HandshakeTestResult =
    withContext(Dispatchers.IO) {
      val parsedUrl = WorkerProtocol.parseWorkerUrl(config.workerUrl)
        ?: return@withContext HandshakeTestResult(
          success = false,
          errorMessage = "Invalid Worker URL",
        )
      if (config.uuid.isBlank()) {
        return@withContext HandshakeTestResult(
          success = false,
          errorMessage = "UUID is required",
        )
      }

      val cleanIp = WorkerProtocol.parseCleanIp(config.cleanIp)
      if (cleanIp != null) {
        val cleanIpResult =
          runSingleHandshakeAttempt(
            parsedUrl = parsedUrl,
            uuid = config.uuid,
            cleanIp = cleanIp,
            preferIpv6Fallback = false,
            label = cleanIp.host,
          )
        if (cleanIpResult.success == true || cleanIpResult.errorMessage?.contains("UUID", ignoreCase = true) == true) {
          return@withContext cleanIpResult
        }
        vpnStateRepository.log(
          LogLevel.WARN,
          "TEST",
          "Clean IP ${cleanIp.host} failed (${cleanIpResult.errorMessage}); falling back to ${parsedUrl.host} (IPv6-first)…",
        )
      }

      runSingleHandshakeAttempt(
        parsedUrl = parsedUrl,
        uuid = config.uuid,
        cleanIp = null,
        preferIpv6Fallback = cleanIp != null,
        label = "${parsedUrl.host} (Direct)",
      )
    }

  private suspend fun runSingleHandshakeAttempt(
    parsedUrl: ParsedWorkerUrl,
    uuid: String,
    cleanIp: ParsedCleanIp?,
    preferIpv6Fallback: Boolean,
    label: String,
  ): HandshakeTestResult {
    val listenerFactory =
      okhttp3.EventListener.Factory {
        object : okhttp3.EventListener() {
          @Volatile private var tlsStartMs = 0L

          override fun connectStart(
            call: okhttp3.Call,
            inetSocketAddress: java.net.InetSocketAddress,
            proxy: java.net.Proxy,
          ) {
            val addr = "${inetSocketAddress.address?.hostAddress ?: inetSocketAddress.hostString}:${inetSocketAddress.port}"
            vpnStateRepository.log(LogLevel.INFO, "TEST", "TCP connecting → $addr")
          }

          override fun secureConnectStart(call: okhttp3.Call) {
            tlsStartMs = System.currentTimeMillis()
          }

          override fun secureConnectEnd(call: okhttp3.Call, handshake: okhttp3.Handshake?) {
            if (handshake != null) {
              val ms = (System.currentTimeMillis() - tlsStartMs).coerceAtLeast(0L)
              vpnStateRepository.log(
                LogLevel.INFO,
                "TEST",
                "TLS ${handshake.tlsVersion.javaName} (${handshake.cipherSuite.javaName}) OK (${ms}ms)",
              )
            }
          }

          override fun responseHeadersEnd(call: okhttp3.Call, response: Response) {
            if (response.code == 101) {
              val proto = response.header("Sec-WebSocket-Protocol") ?: "<none>"
              vpnStateRepository.log(LogLevel.INFO, "TEST", "HTTP 101 WS Upgrade (subproto=$proto)")
            }
          }
        }
      }

    val startMs = System.currentTimeMillis()
    val client = WorkerProtocol.createWorkerOkHttpClient(
      workerHost = parsedUrl.host,
      cleanIp = cleanIp,
      connectTimeoutSec = 8L,
      preferIpv6Fallback = preferIpv6Fallback,
      eventListenerFactory = listenerFactory,
    )
    val request = WorkerProtocol.buildWebSocketRequest(parsedUrl, cleanIp)

    return try {
      withTimeout(12_000L) {
        suspendCancellableCoroutine<HandshakeTestResult> { cont ->
          var wsOpenMs = 0L
          var ackVerified = false
          var sessionKey = ByteArray(0)

          val ws =
            client.newWebSocket(
              request,
              object : WebSocketListener() {
                override fun onOpen(webSocket: WebSocket, response: Response) {
                  val negProto = response.header("Sec-WebSocket-Protocol")
                  if (negProto != null && !negProto.equals(WorkerProtocol.SUBPROTOCOL, ignoreCase = true)) {
                    webSocket.close(1002, "Subprotocol mismatch")
                    if (cont.isActive) {
                      cont.resume(
                        HandshakeTestResult(
                          success = false,
                          resolvedIp = label,
                          errorMessage = "Subprotocol mismatch: $negProto",
                        )
                      )
                    }
                    return
                  }
                  wsOpenMs = System.currentTimeMillis() - startMs
                  val httpProbe =
                    "HEAD /generate_204 HTTP/1.1\r\nHost: cp.cloudflare.com\r\nConnection: close\r\n\r\n"
                      .toByteArray(Charsets.UTF_8)
                  val (initFrame, key) =
                    WorkerProtocol.buildInitPacket(
                      uuid = uuid,
                      targetHost = "cp.cloudflare.com",
                      targetPort = 80,
                    )
                  sessionKey = key
                  webSocket.send(initFrame.toByteString())
                  webSocket.send(WorkerProtocol.xorBuf(httpProbe, key).toByteString())
                }

                override fun onMessage(webSocket: WebSocket, bytes: ByteString) {
                  val data = bytes.toByteArray()
                  if (!ackVerified) {
                    if (WorkerProtocol.verifyAck(data, sessionKey)) {
                      ackVerified = true
                      vpnStateRepository.log(
                        LogLevel.INFO,
                        "TEST",
                        "Worker ACK verified via $label (${System.currentTimeMillis() - startMs}ms)",
                      )
                    } else {
                      webSocket.close(1002, "Bad ACK")
                      if (cont.isActive) {
                        cont.resume(
                          HandshakeTestResult(
                            success = false,
                            wsConnectMs = wsOpenMs,
                            resolvedIp = label,
                            errorMessage = "UUID mismatch or invalid Worker ACK",
                          )
                        )
                      }
                    }
                  } else {
                    val decrypted = WorkerProtocol.xorBuf(data, sessionKey)
                    val text = decrypted.toString(Charsets.UTF_8)
                    val statusLine = text.lineSequence().firstOrNull()?.trim() ?: "OK"
                    val totalMs = System.currentTimeMillis() - startMs
                    webSocket.close(1000, "Done")
                    if (cont.isActive) {
                      cont.resume(
                        HandshakeTestResult(
                          success = true,
                          wsConnectMs = wsOpenMs,
                          totalRttMs = totalMs,
                          resolvedIp = label,
                          httpStatus = statusLine,
                        )
                      )
                    }
                  }
                }

                override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                  val msg =
                    if (response != null) "HTTP ${response.code}: ${t.message}"
                    else t.message ?: "Connection failed"
                  vpnStateRepository.log(LogLevel.ERROR, "TEST", "Worker test failed ($label): $msg")
                  if (cont.isActive) {
                    cont.resume(
                      HandshakeTestResult(
                        success = false,
                        wsConnectMs = if (wsOpenMs > 0) wsOpenMs else null,
                        resolvedIp = label,
                        errorMessage = msg,
                      )
                    )
                  }
                }

                override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
                  if (cont.isActive) {
                    val totalMs = System.currentTimeMillis() - startMs
                    cont.resume(
                      HandshakeTestResult(
                        success = ackVerified,
                        wsConnectMs = if (wsOpenMs > 0) wsOpenMs else null,
                        totalRttMs = if (ackVerified) totalMs else null,
                        resolvedIp = label,
                        errorMessage = if (ackVerified) null else "Closed ($code): $reason",
                      )
                    )
                  }
                }
              },
            )
          cont.invokeOnCancellation { ws.cancel() }
        }
      }
    } catch (e: Exception) {
      HandshakeTestResult(
        success = false,
        resolvedIp = label,
        errorMessage = e.message ?: "Timeout",
      )
    } finally {
      client.dispatcher.cancelAll()
      client.dispatcher.executorService.shutdown()
      client.connectionPool.evictAll()
    }
  }

  suspend fun benchmarkCleanIp(
    workerUrl: String,
    uuid: String,
    candidateIp: String,
  ): CleanIpTestResult =
    withContext(Dispatchers.IO) {
      val parsedUrl = WorkerProtocol.parseWorkerUrl(workerUrl)
        ?: return@withContext CleanIpTestResult(ip = candidateIp, error = "Invalid Worker URL")
      val parsedClean = WorkerProtocol.parseCleanIp(candidateIp)
        ?: return@withContext CleanIpTestResult(ip = candidateIp, error = "Invalid IP")
      if (!WorkerProtocol.isIpLiteral(parsedClean.host)) {
        return@withContext CleanIpTestResult(ip = candidateIp, error = "IP address required (no DNS)")
      }
      if (uuid.isBlank()) {
        return@withContext CleanIpTestResult(ip = candidateIp, error = "UUID missing")
      }

      val startMs = System.currentTimeMillis()
      val client = WorkerProtocol.createWorkerOkHttpClient(
        workerHost = parsedUrl.host,
        cleanIp = parsedClean,
        connectTimeoutSec = 5L,
      )
      val request = WorkerProtocol.buildWebSocketRequest(parsedUrl, parsedClean)

      try {
        withTimeout(6_000L) {
          suspendCancellableCoroutine<CleanIpTestResult> { cont ->
            var sessionKey = ByteArray(0)
            val ws =
              client.newWebSocket(
                request,
                object : WebSocketListener() {
                  override fun onOpen(webSocket: WebSocket, response: Response) {
                    val (initFrame, key) =
                      WorkerProtocol.buildInitPacket(
                        uuid = uuid,
                        targetHost = "example.com",
                        targetPort = 80,
                      )
                    sessionKey = key
                    webSocket.send(initFrame.toByteString())
                  }

                  override fun onMessage(webSocket: WebSocket, bytes: ByteString) {
                    val ok = WorkerProtocol.verifyAck(bytes.toByteArray(), sessionKey)
                    val rtt = System.currentTimeMillis() - startMs
                    webSocket.close(1000, "Ping done")
                    if (cont.isActive) {
                      cont.resume(
                        CleanIpTestResult(
                          ip = candidateIp,
                          latencyMs = if (ok) rtt else null,
                          handshakeOk = ok,
                          error = if (ok) null else "Invalid ACK",
                        )
                      )
                    }
                  }

                  override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                    if (cont.isActive) {
                      cont.resume(
                        CleanIpTestResult(
                          ip = candidateIp,
                          handshakeOk = false,
                          error = t.message ?: "Unreachable",
                        )
                      )
                    }
                  }
                },
              )
            cont.invokeOnCancellation { ws.cancel() }
          }
        }
      } catch (e: Exception) {
        CleanIpTestResult(
          ip = candidateIp,
          handshakeOk = false,
          error = e.message ?: "Timeout",
        )
      } finally {
        client.dispatcher.executorService.shutdown()
        client.connectionPool.evictAll()
      }
    }
}
