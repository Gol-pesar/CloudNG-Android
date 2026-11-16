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
      val targetIp =
        WorkerProtocol.resolveTargetIp(parsedUrl, cleanIp)
          ?: return@withContext HandshakeTestResult(
            success = false,
            errorMessage = "Clean IP (IPv4/IPv6) is required — DNS is disabled",
          )
      val startMs = System.currentTimeMillis()
      val resolvedIpDisplay = targetIp

      val client = WorkerProtocol.createWorkerOkHttpClient(
        workerHost = parsedUrl.host,
        cleanIp = cleanIp,
        connectTimeoutSec = 8L,
      )
      val request = WorkerProtocol.buildWebSocketRequest(parsedUrl, cleanIp)

      try {
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
                    wsOpenMs = System.currentTimeMillis() - startMs
                    val httpProbe =
                      "HEAD /generate_204 HTTP/1.1\r\nHost: cp.cloudflare.com\r\nConnection: close\r\n\r\n"
                        .toByteArray(Charsets.UTF_8)
                    val (initFrame, key) =
                      WorkerProtocol.buildInitPacket(
                        uuid = config.uuid,
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
                          "Worker ACK verified via ${resolvedIpDisplay ?: parsedUrl.host} (${System.currentTimeMillis() - startMs}ms)",
                        )
                      } else {
                        webSocket.close(1002, "Bad ACK")
                        if (cont.isActive) {
                          cont.resume(
                            HandshakeTestResult(
                              success = false,
                              wsConnectMs = wsOpenMs,
                              resolvedIp = resolvedIpDisplay,
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
                            resolvedIp = resolvedIpDisplay,
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
                    vpnStateRepository.log(LogLevel.ERROR, "TEST", "Worker test failed: $msg")
                    if (cont.isActive) {
                      cont.resume(
                        HandshakeTestResult(
                          success = false,
                          wsConnectMs = if (wsOpenMs > 0) wsOpenMs else null,
                          resolvedIp = resolvedIpDisplay,
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
                          resolvedIp = resolvedIpDisplay,
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
          resolvedIp = resolvedIpDisplay,
          errorMessage = e.message ?: "Timeout",
        )
      } finally {
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
                        targetHost = "1.1.1.1",
                        targetPort = 443,
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
