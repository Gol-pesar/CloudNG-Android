package com.example.vpn

import com.example.protocol.WorkerProtocol
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong

/**
 * Pure local in-memory domain-to-synthetic-IPv4 mapper (RFC 2544 range 198.18.0.0/15).
 * Answers TUN UDP/53 queries immediately from memory with ZERO external DNS servers
 * (no 1.1.1.1, 8.8.8.8, DoH, or ISP DNS). TCP flows to synthetic IPs are mapped back
 * to their exact domain name and forwarded inside WorkerProtocol.buildInitPacket,
 * matching Cl2.py SOCKS5 domain tunneling directly on Cloudflare Worker.
 */
class VirtualHostMapper {

  companion object {
    const val VIRTUAL_TUN_GATEWAY_IP = "198.18.0.1"
    private const val POOL_START = 0xC612000AL // 198.18.0.10
    private const val POOL_END = 0xC613FFFEL   // 198.19.255.254
    private const val MAX_CACHED_HOSTS = 65_536
    private const val SYNTHETIC_TTL_SEC = 15
  }

  private val lock = Any()
  private val nextIpCursor = AtomicLong(POOL_START)
  private val domainToIp = ConcurrentHashMap<String, String>()
  private val ipToDomain = ConcurrentHashMap<String, String>()
  private val insertionOrder = ArrayDeque<Pair<String, String>>()

  fun lookupDomainForIp(ip: String): String? = ipToDomain[ip]

  fun handleQueryPacket(raw: ByteArray, parsed: Ipv4Packet.ParsedPacket): ByteArray? {
    if (parsed.payloadLength < 12) return null
    val query = raw.copyOfRange(parsed.payloadOffset, parsed.payloadOffset + parsed.payloadLength)
    val qname = extractQname(query).trim().lowercase().trimEnd('.')
    val questionEnd = findQuestionEnd(query)
    if (questionEnd <= 12 || questionEnd > query.size) return null
    val qtype = extractQtype(query)

    val replyPayload =
      when {
        qtype == 1 && qname == "localhost" ->
          buildSyntheticAResponse(query, questionEnd, byteArrayOf(127, 0, 0, 1))
        qtype == 1 && qname.isNotEmpty() -> {
          val ipv4Bytes =
            WorkerProtocol.parseIpv4Bytes(qname)
              ?: WorkerProtocol.parseIpv4Bytes(getOrAssignSyntheticIp(qname))
          if (ipv4Bytes != null) {
            buildSyntheticAResponse(query, questionEnd, ipv4Bytes)
          } else {
            buildNoDataResponse(query, questionEnd)
          }
        }
        else -> buildNoDataResponse(query, questionEnd)
      }

    return Ipv4Packet.buildUdpPacket(
      srcIp = parsed.dstIp,
      dstIp = parsed.srcIp,
      srcPort = parsed.dstPort,
      dstPort = parsed.srcPort,
      payload = replyPayload,
    )
  }

  private fun getOrAssignSyntheticIp(domain: String): String {
    domainToIp[domain]?.let { existing ->
      if (ipToDomain[existing] == domain) return existing
    }
    synchronized(lock) {
      domainToIp[domain]?.let { existing ->
        if (ipToDomain[existing] == domain) return existing
      }

      if (insertionOrder.size >= MAX_CACHED_HOSTS) {
        val oldest = insertionOrder.removeFirst()
        ipToDomain.remove(oldest.first, oldest.second)
        domainToIp.remove(oldest.second, oldest.first)
      }

      var candidateLong = nextIpCursor.getAndIncrement()
      if (candidateLong < POOL_START || candidateLong > POOL_END) {
        nextIpCursor.set(POOL_START + 1L)
        candidateLong = POOL_START
      }
      val ipStr = WorkerProtocol.ipv4IntToString(candidateLong.toInt())
      ipToDomain.put(ipStr, domain)?.let { oldDomain ->
        if (oldDomain != domain) {
          domainToIp.remove(oldDomain, ipStr)
        }
      }
      domainToIp[domain] = ipStr
      insertionOrder.addLast(ipStr to domain)
      return ipStr
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
    resp[2] = 0x81.toByte() // QR=1, RD=1
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
    resp[p++] = ((SYNTHETIC_TTL_SEC ushr 24) and 0xFF).toByte()
    resp[p++] = ((SYNTHETIC_TTL_SEC ushr 16) and 0xFF).toByte()
    resp[p++] = ((SYNTHETIC_TTL_SEC ushr 8) and 0xFF).toByte()
    resp[p++] = (SYNTHETIC_TTL_SEC and 0xFF).toByte()
    resp[p++] = 0
    resp[p++] = 4           // RDLENGTH = 4
    System.arraycopy(ipv4Bytes, 0, resp, p, 4)
    return resp
  }

  private fun buildNoDataResponse(query: ByteArray, questionEnd: Int): ByteArray {
    val resp = ByteArray(questionEnd)
    System.arraycopy(query, 0, resp, 0, questionEnd)
    resp[2] = 0x81.toByte()
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

  private fun findQuestionEnd(buf: ByteArray): Int {
    val nameEnd = skipName(buf, 12)
    return nameEnd + 4
  }

  private fun extractQname(buf: ByteArray): String {
    if (buf.size < 13) return ""
    var off = 12
    val labels = mutableListOf<String>()
    while (off < buf.size) {
      val len = buf[off].toInt() and 0xFF
      if (len == 0) break
      if ((len and 0xC0) == 0xC0) break
      off++
      if (off + len > buf.size) break
      labels.add(String(buf, off, len, Charsets.UTF_8))
      off += len
    }
    return labels.joinToString(".")
  }

  private fun extractQtype(buf: ByteArray): Int {
    val qtypeOff = skipName(buf, 12)
    return if (qtypeOff + 2 <= buf.size) {
      ((buf[qtypeOff].toInt() and 0xFF) shl 8) or (buf[qtypeOff + 1].toInt() and 0xFF)
    } else {
      1
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

  fun clear() {
    synchronized(lock) {
      domainToIp.clear()
      ipToDomain.clear()
      insertionOrder.clear()
      nextIpCursor.set(POOL_START)
    }
  }
}
