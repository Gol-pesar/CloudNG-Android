package com.example.protocol

import okhttp3.Dns
import okhttp3.OkHttpClient
import okhttp3.Request
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.net.URI
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.concurrent.TimeUnit
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import javax.net.SocketFactory

data class ParsedWorkerUrl(
  val scheme: String,
  val host: String,
  val port: Int,
  val pathAndQuery: String,
) {
  val isTls: Boolean get() = scheme == "wss"
  val httpScheme: String get() = if (isTls) "https" else "http"
}

data class ParsedCleanIp(
  val host: String,
  val port: Int?,
)

object WorkerProtocol {
  const val SUBPROTOCOL = "chat.v2"
  private val random = SecureRandom()

  fun xorBuf(data: ByteArray, key: ByteArray): ByteArray {
    if (key.isEmpty()) return data.copyOf()
    val out = ByteArray(data.size)
    val kLen = key.size
    if (kLen == 16) {
      for (i in data.indices) {
        out[i] = (data[i].toInt() xor key[i and 15].toInt()).toByte()
      }
    } else {
      for (i in data.indices) {
        out[i] = (data[i].toInt() xor key[i % kLen].toInt()).toByte()
      }
    }
    return out
  }

  fun xorInPlace(data: ByteArray, key: ByteArray): ByteArray {
    if (key.isEmpty()) return data
    val kLen = key.size
    if (kLen == 16) {
      for (i in data.indices) {
        data[i] = (data[i].toInt() xor key[i and 15].toInt()).toByte()
      }
    } else {
      for (i in data.indices) {
        data[i] = (data[i].toInt() xor key[i % kLen].toInt()).toByte()
      }
    }
    return data
  }

  fun deriveKey(uuid: String, nonce: ByteArray): ByteArray {
    val tb = uuid.trim().toByteArray(Charsets.UTF_8)
    require(tb.isNotEmpty()) { "UUID/token must not be empty" }
    val key = ByteArray(16)
    for (i in 0 until 16) {
      key[i] = (tb[i % tb.size].toInt() xor nonce[i].toInt()).toByte()
    }
    return key
  }

  /**
   * Encodes the exact init frame expected by worker.js `parseInit(data, token)`:
   * [16 bytes nonce] + XOR([1 byte cmd][2 bytes BE port][1 byte addrType][addr bytes][initialPayload], key) + [8 bytes padding]
   */
  fun buildInitPacket(
    uuid: String,
    targetHost: String,
    targetPort: Int,
    initialPayload: ByteArray = ByteArray(0),
    cmd: Int = 1,
  ): Pair<ByteArray, ByteArray> {
    val nonce = ByteArray(16).also { random.nextBytes(it) }
    val key = deriveKey(uuid, nonce)

    val hostTrimmed = targetHost.trim()
    val addrType: Int
    val addrBytes: ByteArray

    val ipv4 = parseIpv4Bytes(hostTrimmed)
    if (ipv4 != null) {
      addrType = 1
      addrBytes = ipv4
    } else if (hostTrimmed.contains(":")) {
      val cleanV6 = hostTrimmed.removePrefix("[").removeSuffix("]")
      val inet6 = InetAddress.getByName(cleanV6) as? Inet6Address
        ?: throw IllegalArgumentException("Invalid IPv6 host: $hostTrimmed")
      addrType = 3
      addrBytes = inet6.address
    } else {
      val domainBytes = hostTrimmed.toByteArray(Charsets.UTF_8)
      require(domainBytes.isNotEmpty() && domainBytes.size <= 255) {
        "Domain length out of range: ${domainBytes.size}"
      }
      addrType = 2
      addrBytes = ByteArray(1 + domainBytes.size).apply {
        this[0] = domainBytes.size.toByte()
        System.arraycopy(domainBytes, 0, this, 1, domainBytes.size)
      }
    }

    val body = ByteArray(1 + 2 + 1 + addrBytes.size + initialPayload.size)
    var p = 0
    body[p++] = cmd.toByte()
    body[p++] = ((targetPort ushr 8) and 0xFF).toByte()
    body[p++] = (targetPort and 0xFF).toByte()
    body[p++] = addrType.toByte()
    System.arraycopy(addrBytes, 0, body, p, addrBytes.size)
    p += addrBytes.size
    if (initialPayload.isNotEmpty()) {
      System.arraycopy(initialPayload, 0, body, p, initialPayload.size)
    }

    val encrypted = xorBuf(body, key)
    val trailer = ByteArray(8).also { random.nextBytes(it) }

    val packet = ByteArray(16 + encrypted.size + 8)
    System.arraycopy(nonce, 0, packet, 0, 16)
    System.arraycopy(encrypted, 0, packet, 16, encrypted.size)
    System.arraycopy(trailer, 0, packet, 16 + encrypted.size, 8)
    return packet to key
  }

  /**
   * Verifies the 16-byte ACK returned by worker.js:
   * xorBuf(hmacSha256(key, "OK").slice(0, 16), key)
   */
  fun verifyAck(ackFrame: ByteArray, key: ByteArray): Boolean {
    if (ackFrame.size != 16) return false
    val mac = Mac.getInstance("HmacSHA256")
    mac.init(SecretKeySpec(key, "HmacSHA256"))
    val digest = mac.doFinal("OK".toByteArray(Charsets.UTF_8))
    val expected = xorBuf(digest.copyOfRange(0, 16), key)
    return MessageDigest.isEqual(ackFrame, expected)
  }

  fun parseWorkerUrl(rawUrl: String): ParsedWorkerUrl? {
    val trimmed = rawUrl.trim()
    if (trimmed.isEmpty()) return null
    val normalized =
      when {
        trimmed.startsWith("https://", ignoreCase = true) -> "wss://" + trimmed.substring(8)
        trimmed.startsWith("http://", ignoreCase = true) -> "ws://" + trimmed.substring(7)
        trimmed.startsWith("wss://", ignoreCase = true) ||
          trimmed.startsWith("ws://", ignoreCase = true) -> trimmed
        else -> "wss://$trimmed"
      }
    return try {
      val uri = URI(normalized)
      val host = uri.host ?: return null
      if (host.isBlank()) return null
      val scheme = uri.scheme?.lowercase() ?: "wss"
      val port =
        if (uri.port != -1) uri.port
        else if (scheme == "ws") 80 else 443
      val path = uri.rawPath.takeIf { !it.isNullOrEmpty() } ?: "/"
      val query = uri.rawQuery?.takeIf { it.isNotEmpty() }?.let { "?$it" } ?: ""
      ParsedWorkerUrl(
        scheme = scheme,
        host = host,
        port = port,
        pathAndQuery = path + query,
      )
    } catch (_: Exception) {
      null
    }
  }

  fun parseCleanIp(rawCleanIp: String): ParsedCleanIp? {
    val trimmed = rawCleanIp.trim()
    if (trimmed.isEmpty()) return null
    if (trimmed.startsWith("[")) {
      val closeIdx = trimmed.indexOf(']')
      if (closeIdx <= 1) return null
      val host = trimmed.substring(1, closeIdx)
      val rest = trimmed.substring(closeIdx + 1)
      val port =
        if (rest.startsWith(":")) rest.substring(1).toIntOrNull() else null
      return ParsedCleanIp(host = host, port = port)
    }
    val colonCount = trimmed.count { it == ':' }
    return if (colonCount == 1) {
      val idx = trimmed.lastIndexOf(':')
      val host = trimmed.substring(0, idx).trim()
      val port = trimmed.substring(idx + 1).trim().toIntOrNull()
      if (host.isEmpty()) null else ParsedCleanIp(host = host, port = port)
    } else {
      ParsedCleanIp(host = trimmed, port = null)
    }
  }

  fun isValidUuidFormat(uuid: String): Boolean {
    val regex = Regex("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
    return regex.matches(uuid.trim())
  }

  fun createWorkerOkHttpClient(
    workerHost: String,
    cleanIp: ParsedCleanIp?,
    socketFactory: SocketFactory? = null,
    connectTimeoutSec: Long = 8L,
    workerThreads: Int = 8,
    fallbackDnsLookup: ((String) -> List<InetAddress>)? = null,
  ): OkHttpClient {
    val threads = workerThreads.coerceIn(2, 32)
    val executor =
      java.util.concurrent.ThreadPoolExecutor(
        threads,
        (threads * 4).coerceAtLeast(32),
        60L,
        TimeUnit.SECONDS,
        java.util.concurrent.SynchronousQueue(),
        okhttp3.internal.threadFactory("CloudNG-Worker", false),
      )
    val dispatcher =
      okhttp3.Dispatcher(executor).apply {
        maxRequests = (threads * 16).coerceIn(128, 512)
        maxRequestsPerHost = (threads * 8).coerceIn(32, 256)
      }
    val builder =
      OkHttpClient.Builder()
        .dispatcher(dispatcher)
        .connectionPool(
          okhttp3.ConnectionPool((threads * 2).coerceIn(12, 64), 120L, TimeUnit.SECONDS)
        )
        .protocols(listOf(okhttp3.Protocol.HTTP_1_1))
        .connectTimeout(connectTimeoutSec, TimeUnit.SECONDS)
        .readTimeout(0, TimeUnit.SECONDS)
        .writeTimeout(15, TimeUnit.SECONDS)
        .pingInterval(25, TimeUnit.SECONDS)

    if (socketFactory != null) {
      builder.socketFactory(socketFactory)
    }

    builder.dns(
      object : Dns {
        override fun lookup(hostname: String): List<InetAddress> {
          if (cleanIp != null && hostname.equals(workerHost, ignoreCase = true)) {
            return InetAddress.getAllByName(cleanIp.host).toList()
          }
          if (fallbackDnsLookup != null) {
            val resolved = runCatching { fallbackDnsLookup(hostname) }.getOrNull()
            if (!resolved.isNullOrEmpty()) return resolved
          }
          return Dns.SYSTEM.lookup(hostname)
        }
      }
    )

    return builder.build()
  }

  fun buildWebSocketRequest(
    parsedUrl: ParsedWorkerUrl,
    cleanIp: ParsedCleanIp?,
  ): Request {
    val effectivePort = cleanIp?.port ?: parsedUrl.port
    val defaultPort = if (parsedUrl.isTls) 443 else 80
    val urlPortSuffix = if (effectivePort != defaultPort) ":$effectivePort" else ""
    val targetUrl = "${parsedUrl.httpScheme}://${parsedUrl.host}$urlPortSuffix${parsedUrl.pathAndQuery}"

    val hostHeader =
      if (parsedUrl.port != defaultPort) "${parsedUrl.host}:${parsedUrl.port}"
      else parsedUrl.host

    return Request.Builder()
      .url(targetUrl)
      .header("Host", hostHeader)
      .header("Sec-WebSocket-Protocol", SUBPROTOCOL)
      .header("User-Agent", "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36")
      .build()
  }

  fun parseIpv4Bytes(ip: String): ByteArray? {
    val parts = ip.split('.')
    if (parts.size != 4) return null
    val out = ByteArray(4)
    for (i in 0 until 4) {
      val n = parts[i].toIntOrNull() ?: return null
      if (n < 0 || n > 255) return null
      out[i] = n.toByte()
    }
    return out
  }

  fun ipv4ToString(addr: ByteArray, offset: Int = 0): String {
    return "${addr[offset].toInt() and 0xFF}.${addr[offset + 1].toInt() and 0xFF}.${addr[offset + 2].toInt() and 0xFF}.${addr[offset + 3].toInt() and 0xFF}"
  }

  fun ipv4IntToString(ip: Int): String {
    return "${(ip ushr 24) and 0xFF}.${(ip ushr 16) and 0xFF}.${(ip ushr 8) and 0xFF}.${ip and 0xFF}"
  }

  data class ImportedShareConfig(
    val name: String,
    val workerUrl: String,
    val uuid: String,
    val cleanIp: String,
  )

  fun parseShareConfigUri(raw: String): ImportedShareConfig? {
    val text = raw.trim()
    val isHostScheme =
      text.startsWith("cloudng://", ignoreCase = true) ||
        text.startsWith("amir://", ignoreCase = true)
    if (!isHostScheme && !text.startsWith("edgetunnel://", ignoreCase = true)) {
      return null
    }
    return try {
      val uri = URI(text)
      val queryParams =
        uri.rawQuery
          ?.split('&')
          ?.mapNotNull { pair ->
            val idx = pair.indexOf('=')
            if (idx <= 0) null
            else {
              val k = java.net.URLDecoder.decode(pair.substring(0, idx), "UTF-8")
              val v = java.net.URLDecoder.decode(pair.substring(idx + 1), "UTF-8")
              k to v
            }
          }
          ?.toMap()
          ?: emptyMap()

      val cleanIp =
        queryParams["cleanIp"]
          ?: queryParams["cleanip"]
          ?: ""
      val rawFragment = uri.rawFragment
      val name =
        if (!rawFragment.isNullOrBlank()) {
          java.net.URLDecoder.decode(rawFragment, "UTF-8")
        } else {
          "CloudNG Node"
        }

      if (isHostScheme) {
        val uuid = uri.userInfo?.takeIf { it.isNotBlank() } ?: return null
        val host = uri.host?.takeIf { it.isNotBlank() } ?: return null
        val portSuffix = if (uri.port != -1 && uri.port != 443) ":${uri.port}" else ""
        val path = queryParams["path"]?.takeIf { it.isNotBlank() } ?: uri.rawPath?.takeIf { it.isNotBlank() } ?: ""
        val normalizedPath = if (path.isNotEmpty() && !path.startsWith("/")) "/$path" else path
        val workerUrl = "https://$host$portSuffix$normalizedPath"
        ImportedShareConfig(
          name = name,
          workerUrl = workerUrl,
          uuid = uuid,
          cleanIp = cleanIp,
        )
      } else {
        val uuid = uri.userInfo?.takeIf { it.isNotBlank() } ?: uri.host.orEmpty()
        val worker = queryParams["worker"].orEmpty()
        if (uuid.isBlank() && worker.isBlank()) null
        else
          ImportedShareConfig(
            name = name,
            workerUrl = worker,
            uuid = uuid,
            cleanIp = cleanIp,
          )
      }
    } catch (_: Exception) {
      null
    }
  }
}
