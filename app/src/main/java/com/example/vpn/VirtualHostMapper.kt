package com.example.vpn

import com.example.model.LogLevel
import com.example.protocol.WorkerProtocol
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong

/**
 * Pure local in-memory domain-to-synthetic-IPv4 mapper (RFC 2544 range 198.18.0.0/15).
 * Answers TUN UDP/53 A and AAAA queries immediately from memory with ZERO external DNS servers
 * (no 1.1.1.1, 8.8.8.8, DoH, or ISP DNS). TCP flows to synthetic IPs are mapped back
 * to their exact domain name and forwarded inside WorkerProtocol.buildInitPacket,
 * matching Cl2.py SOCKS5 domain tunneling directly on Cloudflare Worker.
 */
class VirtualHostMapper(
  private val cacheTtlMs: Long = DEFAULT_CACHE_TTL_MS,
  private val clockMs: () -> Long = System::currentTimeMillis,
  private val onDiagnostic: ((LogLevel, String) -> Unit)? = null,
) {

  companion object {
    const val VIRTUAL_TUN_GATEWAY_IP = "198.18.0.1"
    const val POOL_START = 0xC612000AL // 198.18.0.10
    const val POOL_END = 0xC613FFFEL   // 198.19.255.254
    private const val MAX_CACHED_HOSTS = 65_536
    private const val DNS_ANSWER_TTL_SEC = 15
    const val DEFAULT_CACHE_TTL_MS = 300_000L // 5 min sliding TTL for active session reuse
    private const val DNS_TYPE_A = 1
    private const val DNS_TYPE_AAAA = 28
    private const val DNS_CLASS_IN = 1

    fun isValidSyntheticIp(ip: String): Boolean {
      val bytes = WorkerProtocol.parseIpv4Bytes(ip.trim()) ?: return false
      val asLong =
        (((bytes[0].toLong() and 0xFFL) shl 24) or
          ((bytes[1].toLong() and 0xFFL) shl 16) or
          ((bytes[2].toLong() and 0xFFL) shl 8) or
          (bytes[3].toLong() and 0xFFL))
      return asLong in POOL_START..POOL_END
    }

    fun isInSyntheticSubnet(ipInt: Int): Boolean {
      return (ipInt and 0xFFFE0000.toInt()) == 0xC6120000.toInt()
    }
  }

  private data class MappingEntry(
    val ip: String,
    val domain: String,
    @Volatile var expiresAtMs: Long,
  )

  private val lock = Any()
  private val nextIpCursor = AtomicLong(POOL_START)
  private val domainToEntry = ConcurrentHashMap<String, MappingEntry>()
  private val ipToEntry = ConcurrentHashMap<String, MappingEntry>()
  private val insertionOrder = ArrayDeque<MappingEntry>()

  fun lookupDomainForIp(ip: String): String? {
    if (!isValidSyntheticIp(ip)) return null
    val now = clockMs()
    val entry = ipToEntry[ip] ?: return null
    if (now >= entry.expiresAtMs) {
      synchronized(lock) {
        val current = ipToEntry[ip] ?: return null
        if (now >= current.expiresAtMs) {
          evictEntryLocked(current)
          return null
        }
        current.expiresAtMs = now + cacheTtlMs
        return current.domain
      }
    }
    entry.expiresAtMs = now + cacheTtlMs
    return entry.domain
  }

  fun pruneExpired(): Int {
    val now = clockMs()
    var removed = 0
    synchronized(lock) {
      val iter = insertionOrder.iterator()
      while (iter.hasNext()) {
        val entry = iter.next()
        if (now >= entry.expiresAtMs) {
          iter.remove()
          ipToEntry.remove(entry.ip, entry)
          domainToEntry.remove(entry.domain, entry)
          removed++
        }
      }
    }
    return removed
  }

  fun handleQueryPacket(raw: ByteArray, parsed: Ipv4Packet.ParsedPacket): ByteArray? {
    if (parsed.payloadLength < 12 || parsed.payloadOffset + parsed.payloadLength > raw.size) {
      onDiagnostic?.invoke(LogLevel.WARN, "Malformed DNS query rejected (too short: ${parsed.payloadLength}B)")
      return null
    }
    val query = raw.copyOfRange(parsed.payloadOffset, parsed.payloadOffset + parsed.payloadLength)
    val qdCount = ((query[4].toInt() and 0xFF) shl 8) or (query[5].toInt() and 0xFF)
    if (qdCount != 1) {
      onDiagnostic?.invoke(LogLevel.WARN, "DNS query rejected (QDCOUNT=$qdCount)")
      val errPayload = buildErrorResponse(query, query.size.coerceAtMost(12), rcode = 1)
      return buildReplyUdp(parsed, errPayload)
    }

    val nameEnd = skipNameSafe(query, 12)
    val questionEnd = if (nameEnd > 12) nameEnd + 4 else -1
    if (questionEnd <= 12 || questionEnd > query.size) {
      onDiagnostic?.invoke(LogLevel.WARN, "DNS query rejected (invalid QNAME/question bounds)")
      val errPayload = buildErrorResponse(query, 12, rcode = 1) // FORMERR
      return buildReplyUdp(parsed, errPayload)
    }

    val qname = extractQnameSafe(query).trim().lowercase().trimEnd('.')
    val qtype = ((query[nameEnd].toInt() and 0xFF) shl 8) or (query[nameEnd + 1].toInt() and 0xFF)
    val qclass = ((query[nameEnd + 2].toInt() and 0xFF) shl 8) or (query[nameEnd + 3].toInt() and 0xFF)

    val replyPayload =
      when {
        qclass != DNS_CLASS_IN -> {
          onDiagnostic?.invoke(LogLevel.WARN, "DNS non-IN class ($qclass) for $qname")
          buildNoDataResponse(query, questionEnd)
        }
        qtype == DNS_TYPE_A && qname == "localhost" ->
          buildSyntheticAResponse(query, questionEnd, byteArrayOf(127, 0, 0, 1))
        qtype == DNS_TYPE_A && qname.isNotEmpty() -> {
          val literalIpv4 = WorkerProtocol.parseIpv4Bytes(qname)
          val ipv4Bytes =
            literalIpv4 ?: WorkerProtocol.parseIpv4Bytes(getOrAssignSyntheticIp(qname))
          if (ipv4Bytes != null) {
            buildSyntheticAResponse(query, questionEnd, ipv4Bytes)
          } else {
            onDiagnostic?.invoke(LogLevel.WARN, "DNS A assignment failed for '$qname'")
            buildNoDataResponse(query, questionEnd)
          }
        }
        qtype == DNS_TYPE_AAAA && qname == "localhost" ->
          buildSyntheticAaaaResponse(query, questionEnd, byteArrayOf(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1))
        qtype == DNS_TYPE_AAAA ->
          // IPv4 TUN tunnel: return fast NOERROR NODATA for AAAA so Happy Eyeballs uses A immediately
          buildNoDataResponse(query, questionEnd)
        else -> buildNoDataResponse(query, questionEnd)
      }

    return buildReplyUdp(parsed, replyPayload)
  }

  private fun buildReplyUdp(
    parsed: Ipv4Packet.ParsedPacket,
    replyPayload: ByteArray,
  ): ByteArray =
    Ipv4Packet.buildUdpPacket(
      srcIp = parsed.dstIp,
      dstIp = parsed.srcIp,
      srcPort = parsed.dstPort,
      dstPort = parsed.srcPort,
      payload = replyPayload,
    )

  private fun getOrAssignSyntheticIp(domain: String): String {
    val now = clockMs()
    domainToEntry[domain]?.let { existing ->
      if (now < existing.expiresAtMs && ipToEntry[existing.ip] === existing) {
        existing.expiresAtMs = now + cacheTtlMs
        return existing.ip
      }
    }

    synchronized(lock) {
      domainToEntry[domain]?.let { existing ->
        if (now < existing.expiresAtMs && ipToEntry[existing.ip] === existing) {
          existing.expiresAtMs = now + cacheTtlMs
          return existing.ip
        }
        evictEntryLocked(existing)
      }

      pruneExpiredLocked(now)

      while (insertionOrder.size >= MAX_CACHED_HOSTS) {
        val oldest = insertionOrder.removeFirst()
        ipToEntry.remove(oldest.ip, oldest)
        domainToEntry.remove(oldest.domain, oldest)
      }

      var candidateLong = nextIpCursor.getAndIncrement()
      if (candidateLong < POOL_START || candidateLong > POOL_END) {
        nextIpCursor.set(POOL_START + 1L)
        candidateLong = POOL_START
      }
      val ipStr = WorkerProtocol.ipv4IntToString(candidateLong.toInt())
      val newEntry = MappingEntry(ip = ipStr, domain = domain, expiresAtMs = now + cacheTtlMs)

      ipToEntry.put(ipStr, newEntry)?.let { previous ->
        domainToEntry.remove(previous.domain, previous)
      }
      domainToEntry[domain] = newEntry
      insertionOrder.addLast(newEntry)
      return ipStr
    }
  }

  private fun evictEntryLocked(entry: MappingEntry) {
    ipToEntry.remove(entry.ip, entry)
    domainToEntry.remove(entry.domain, entry)
    insertionOrder.remove(entry)
  }

  private fun pruneExpiredLocked(now: Long) {
    while (insertionOrder.isNotEmpty()) {
      val head = insertionOrder.first()
      if (now < head.expiresAtMs) break
      insertionOrder.removeFirst()
      ipToEntry.remove(head.ip, head)
      domainToEntry.remove(head.domain, head)
    }
  }

  private fun buildSyntheticAResponse(
    query: ByteArray,
    questionEnd: Int,
    ipv4Bytes: ByteArray,
  ): ByteArray {
    // 12-byte header + Question section + 16-byte A Answer RR
    val resp = ByteArray(questionEnd + 16)
    System.arraycopy(query, 0, resp, 0, questionEnd)
    resp[2] = (0x80 or (query[2].toInt() and 0x79)).toByte() // QR=1, keep Opcode & RD
    resp[3] = 0x80.toByte() // RA=1, RCODE=0 (NOERROR)
    resp[4] = 0
    resp[5] = 1             // QDCOUNT = 1
    resp[6] = 0
    resp[7] = 1             // ANCOUNT = 1
    resp[8] = 0
    resp[9] = 0             // NSCOUNT = 0
    resp[10] = 0
    resp[11] = 0            // ARCOUNT = 0

    var p = questionEnd
    resp[p++] = 0xC0.toByte()
    resp[p++] = 0x0C        // Name pointer to offset 12
    resp[p++] = 0
    resp[p++] = 1           // TYPE = A
    resp[p++] = 0
    resp[p++] = 1           // CLASS = IN
    resp[p++] = ((DNS_ANSWER_TTL_SEC ushr 24) and 0xFF).toByte()
    resp[p++] = ((DNS_ANSWER_TTL_SEC ushr 16) and 0xFF).toByte()
    resp[p++] = ((DNS_ANSWER_TTL_SEC ushr 8) and 0xFF).toByte()
    resp[p++] = (DNS_ANSWER_TTL_SEC and 0xFF).toByte()
    resp[p++] = 0
    resp[p++] = 4           // RDLENGTH = 4
    System.arraycopy(ipv4Bytes, 0, resp, p, 4)
    return resp
  }

  private fun buildSyntheticAaaaResponse(
    query: ByteArray,
    questionEnd: Int,
    ipv6Bytes: ByteArray,
  ): ByteArray {
    val resp = ByteArray(questionEnd + 28)
    System.arraycopy(query, 0, resp, 0, questionEnd)
    resp[2] = (0x80 or (query[2].toInt() and 0x79)).toByte()
    resp[3] = 0x80.toByte()
    resp[4] = 0
    resp[5] = 1
    resp[6] = 0
    resp[7] = 1
    resp[8] = 0
    resp[9] = 0
    resp[10] = 0
    resp[11] = 0

    var p = questionEnd
    resp[p++] = 0xC0.toByte()
    resp[p++] = 0x0C
    resp[p++] = 0
    resp[p++] = 28 // TYPE = AAAA
    resp[p++] = 0
    resp[p++] = 1  // CLASS = IN
    resp[p++] = ((DNS_ANSWER_TTL_SEC ushr 24) and 0xFF).toByte()
    resp[p++] = ((DNS_ANSWER_TTL_SEC ushr 16) and 0xFF).toByte()
    resp[p++] = ((DNS_ANSWER_TTL_SEC ushr 8) and 0xFF).toByte()
    resp[p++] = (DNS_ANSWER_TTL_SEC and 0xFF).toByte()
    resp[p++] = 0
    resp[p++] = 16 // RDLENGTH = 16
    System.arraycopy(ipv6Bytes, 0, resp, p, 16)
    return resp
  }

  private fun buildNoDataResponse(query: ByteArray, questionEnd: Int): ByteArray {
    val resp = ByteArray(questionEnd)
    System.arraycopy(query, 0, resp, 0, questionEnd)
    resp[2] = (0x80 or (query[2].toInt() and 0x79)).toByte()
    resp[3] = 0x80.toByte()
    resp[4] = 0
    resp[5] = 1
    resp[6] = 0
    resp[7] = 0
    resp[8] = 0
    resp[9] = 0
    resp[10] = 0
    resp[11] = 0
    return resp
  }

  private fun buildErrorResponse(query: ByteArray, copyLen: Int, rcode: Int): ByteArray {
    val len = copyLen.coerceAtLeast(12)
    val resp = ByteArray(len)
    System.arraycopy(query, 0, resp, 0, copyLen.coerceAtMost(query.size))
    resp[2] = (0x80 or (query[2].toInt() and 0x79)).toByte()
    resp[3] = (0x80 or (rcode and 0x0F)).toByte()
    resp[4] = 0
    resp[5] = 0
    resp[6] = 0
    resp[7] = 0
    resp[8] = 0
    resp[9] = 0
    resp[10] = 0
    resp[11] = 0
    return resp
  }

  private fun extractQnameSafe(buf: ByteArray): String {
    if (buf.size < 13) return ""
    var off = 12
    var steps = 0
    val labels = mutableListOf<String>()
    while (off < buf.size && steps++ < 128) {
      val len = buf[off].toInt() and 0xFF
      if (len == 0) break
      if ((len and 0xC0) == 0xC0 || len > 63) break
      off++
      if (off + len > buf.size) break
      labels.add(String(buf, off, len, Charsets.UTF_8))
      off += len
    }
    return labels.joinToString(".")
  }

  private fun skipNameSafe(buf: ByteArray, start: Int): Int {
    var off = start
    var steps = 0
    while (off < buf.size && steps++ < 128) {
      val b = buf[off].toInt() and 0xFF
      if (b == 0) return off + 1
      if ((b and 0xC0) == 0xC0) {
        return if (off + 1 < buf.size) off + 2 else -1
      }
      if (b > 63) return -1
      off += 1 + b
      if (off > buf.size) return -1
    }
    return -1
  }

  fun clear() {
    synchronized(lock) {
      domainToEntry.clear()
      ipToEntry.clear()
      insertionOrder.clear()
      nextIpCursor.set(POOL_START)
    }
  }
}
