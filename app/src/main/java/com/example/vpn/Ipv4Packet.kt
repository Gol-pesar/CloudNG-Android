package com.example.vpn

import com.example.protocol.WorkerProtocol

object Ipv4Packet {
  const val PROTO_ICMP = 1
  const val PROTO_TCP = 6
  const val PROTO_UDP = 17

  const val TCP_FIN = 0x01
  const val TCP_SYN = 0x02
  const val TCP_RST = 0x04
  const val TCP_PSH = 0x08
  const val TCP_ACK = 0x10

  data class ParsedPacket(
    val version: Int,
    val protocol: Int,
    val ipHeaderLen: Int,
    val totalLength: Int,
    val srcIp: Int,
    val dstIp: Int,
    val srcPort: Int,
    val dstPort: Int,
    val tcpSeq: Long,
    val tcpAck: Long,
    val tcpFlags: Int,
    val tcpWindow: Int,
    val payloadOffset: Int,
    val payloadLength: Int,
  ) {
    val srcIpString: String get() = WorkerProtocol.ipv4IntToString(srcIp)
    val dstIpString: String get() = WorkerProtocol.ipv4IntToString(dstIp)
  }

  fun parse(buf: ByteArray, length: Int): ParsedPacket? {
    if (length < 20) return null
    val version = (buf[0].toInt() ushr 4) and 0x0F
    if (version != 4) return null
    val ihl = (buf[0].toInt() and 0x0F) * 4
    if (ihl < 20 || length < ihl) return null
    val totalLength = readU16(buf, 2).coerceAtMost(length)
    val protocol = buf[9].toInt() and 0xFF
    val srcIp = readI32(buf, 12)
    val dstIp = readI32(buf, 16)

    return when (protocol) {
      PROTO_TCP -> {
        if (totalLength < ihl + 20) return null
        val srcPort = readU16(buf, ihl)
        val dstPort = readU16(buf, ihl + 2)
        val seq = readU32(buf, ihl + 4)
        val ack = readU32(buf, ihl + 8)
        val dataOffset = ((buf[ihl + 12].toInt() ushr 4) and 0x0F) * 4
        if (dataOffset < 20 || totalLength < ihl + dataOffset) return null
        val flags = buf[ihl + 13].toInt() and 0x3F
        val window = readU16(buf, ihl + 14)
        val payloadOffset = ihl + dataOffset
        val payloadLength = (totalLength - payloadOffset).coerceAtLeast(0)
        ParsedPacket(
          version = 4,
          protocol = protocol,
          ipHeaderLen = ihl,
          totalLength = totalLength,
          srcIp = srcIp,
          dstIp = dstIp,
          srcPort = srcPort,
          dstPort = dstPort,
          tcpSeq = seq,
          tcpAck = ack,
          tcpFlags = flags,
          tcpWindow = window,
          payloadOffset = payloadOffset,
          payloadLength = payloadLength,
        )
      }
      PROTO_UDP -> {
        if (totalLength < ihl + 8) return null
        val srcPort = readU16(buf, ihl)
        val dstPort = readU16(buf, ihl + 2)
        val udpLen = readU16(buf, ihl + 4)
        val payloadOffset = ihl + 8
        val payloadLength = (udpLen - 8).coerceIn(0, (totalLength - payloadOffset).coerceAtLeast(0))
        ParsedPacket(
          version = 4,
          protocol = protocol,
          ipHeaderLen = ihl,
          totalLength = totalLength,
          srcIp = srcIp,
          dstIp = dstIp,
          srcPort = srcPort,
          dstPort = dstPort,
          tcpSeq = 0L,
          tcpAck = 0L,
          tcpFlags = 0,
          tcpWindow = 0,
          payloadOffset = payloadOffset,
          payloadLength = payloadLength,
        )
      }
      else ->
        ParsedPacket(
          version = 4,
          protocol = protocol,
          ipHeaderLen = ihl,
          totalLength = totalLength,
          srcIp = srcIp,
          dstIp = dstIp,
          srcPort = 0,
          dstPort = 0,
          tcpSeq = 0L,
          tcpAck = 0L,
          tcpFlags = 0,
          tcpWindow = 0,
          payloadOffset = ihl,
          payloadLength = (totalLength - ihl).coerceAtLeast(0),
        )
    }
  }

  fun buildUdpPacket(
    srcIp: Int,
    dstIp: Int,
    srcPort: Int,
    dstPort: Int,
    payload: ByteArray,
    ipId: Int = 0,
  ): ByteArray {
    val udpLen = 8 + payload.size
    val totalLen = 20 + udpLen
    val pkt = ByteArray(totalLen)

    writeIpv4Header(pkt, totalLen, PROTO_UDP, srcIp, dstIp, ipId)
    writeU16(pkt, 20, srcPort)
    writeU16(pkt, 22, dstPort)
    writeU16(pkt, 24, udpLen)
    writeU16(pkt, 26, 0)
    System.arraycopy(payload, 0, pkt, 28, payload.size)

    val udpChecksum = transportChecksum(srcIp, dstIp, PROTO_UDP, pkt, 20, udpLen)
    writeU16(pkt, 26, if (udpChecksum == 0) 0xFFFF else udpChecksum)
    return pkt
  }

  fun parseTcpWindowScale(buf: ByteArray, parsed: ParsedPacket): Int? {
    if (parsed.protocol != PROTO_TCP) return null
    val optStart = parsed.ipHeaderLen + 20
    val optEnd = parsed.payloadOffset
    var i = optStart
    while (i < optEnd) {
      val kind = buf[i].toInt() and 0xFF
      if (kind == 0) break // End of options
      if (kind == 1) {
        i++
        continue
      }
      if (i + 1 >= optEnd) break
      val len = buf[i + 1].toInt() and 0xFF
      if (len < 2 || i + len > optEnd) break
      if (kind == 3 && len == 3 && i + 2 < optEnd) {
        return (buf[i + 2].toInt() and 0xFF).coerceIn(0, 14)
      }
      i += len
    }
    return null
  }

  fun buildTcpPacket(
    srcIp: Int,
    dstIp: Int,
    srcPort: Int,
    dstPort: Int,
    seq: Long,
    ack: Long,
    flags: Int,
    window: Int = 65535,
    payload: ByteArray = ByteArray(0),
    payloadOffset: Int = 0,
    payloadLength: Int = payload.size,
    mss: Int? = null,
    windowScale: Int? = null,
    ipId: Int = 0,
  ): ByteArray {
    val mssLen = if (mss != null) 4 else 0
    val wsLen = if (windowScale != null) 4 else 0
    val optionsLen = mssLen + wsLen
    val tcpHeaderLen = 20 + optionsLen
    val tcpLen = tcpHeaderLen + payloadLength
    val totalLen = 20 + tcpLen
    val pkt = ByteArray(totalLen)

    writeIpv4Header(pkt, totalLen, PROTO_TCP, srcIp, dstIp, ipId)

    writeU16(pkt, 20, srcPort)
    writeU16(pkt, 22, dstPort)
    writeU32(pkt, 24, seq)
    writeU32(pkt, 28, ack)
    pkt[32] = (((tcpHeaderLen / 4) shl 4) and 0xF0).toByte()
    pkt[33] = (flags and 0x3F).toByte()
    writeU16(pkt, 34, window.coerceIn(0, 65535))
    writeU16(pkt, 36, 0) // checksum
    writeU16(pkt, 38, 0) // urgent

    var optOff = 40
    if (mss != null) {
      pkt[optOff++] = 0x02
      pkt[optOff++] = 0x04
      writeU16(pkt, optOff, mss)
      optOff += 2
    }
    if (windowScale != null) {
      pkt[optOff++] = 0x01 // NOP
      pkt[optOff++] = 0x03 // Window Scale kind
      pkt[optOff++] = 0x03 // Length
      pkt[optOff] = windowScale.coerceIn(0, 14).toByte()
    }

    if (payloadLength > 0) {
      System.arraycopy(payload, payloadOffset, pkt, 20 + tcpHeaderLen, payloadLength)
    }

    val tcpChecksum = transportChecksum(srcIp, dstIp, PROTO_TCP, pkt, 20, tcpLen)
    writeU16(pkt, 36, tcpChecksum)
    return pkt
  }

  fun buildIcmpPortUnreachable(
    origRaw: ByteArray,
    origLen: Int,
    parsed: ParsedPacket,
  ): ByteArray {
    val quotedLen = (parsed.ipHeaderLen + 8).coerceAtMost(origLen)
    val icmpLen = 8 + quotedLen
    val totalLen = 20 + icmpLen
    val pkt = ByteArray(totalLen)

    writeIpv4Header(pkt, totalLen, PROTO_ICMP, parsed.dstIp, parsed.srcIp, 0)
    pkt[20] = 3 // Type: Destination Unreachable
    pkt[21] = 3 // Code: Port Unreachable
    writeU16(pkt, 22, 0) // Checksum placeholder
    writeI32(pkt, 24, 0) // Unused
    System.arraycopy(origRaw, 0, pkt, 28, quotedLen)

    val sum = ipChecksum(pkt, 20, icmpLen)
    writeU16(pkt, 22, sum)
    return pkt
  }

  private fun writeIpv4Header(
    pkt: ByteArray,
    totalLen: Int,
    protocol: Int,
    srcIp: Int,
    dstIp: Int,
    ipId: Int,
  ) {
    pkt[0] = 0x45.toByte()
    pkt[1] = 0x00
    writeU16(pkt, 2, totalLen)
    writeU16(pkt, 4, ipId and 0xFFFF)
    writeU16(pkt, 6, 0x4000) // Don't Fragment
    pkt[8] = 64.toByte() // TTL
    pkt[9] = protocol.toByte()
    writeU16(pkt, 10, 0)
    writeI32(pkt, 12, srcIp)
    writeI32(pkt, 16, dstIp)
    val ipSum = ipChecksum(pkt, 0, 20)
    writeU16(pkt, 10, ipSum)
  }

  private fun ipChecksum(buf: ByteArray, offset: Int, len: Int): Int {
    var sum = 0
    var i = offset
    val end = offset + len
    while (i + 1 < end) {
      sum += ((buf[i].toInt() and 0xFF) shl 8) or (buf[i + 1].toInt() and 0xFF)
      i += 2
    }
    if (i < end) {
      sum += (buf[i].toInt() and 0xFF) shl 8
    }
    while ((sum ushr 16) != 0) {
      sum = (sum and 0xFFFF) + (sum ushr 16)
    }
    return sum.inv() and 0xFFFF
  }

  private fun transportChecksum(
    srcIp: Int,
    dstIp: Int,
    protocol: Int,
    buf: ByteArray,
    offset: Int,
    len: Int,
  ): Int {
    var sum = 0
    sum += (srcIp ushr 16) and 0xFFFF
    sum += srcIp and 0xFFFF
    sum += (dstIp ushr 16) and 0xFFFF
    sum += dstIp and 0xFFFF
    sum += protocol and 0xFF
    sum += len and 0xFFFF

    var i = offset
    val end = offset + len
    while (i + 1 < end) {
      sum += ((buf[i].toInt() and 0xFF) shl 8) or (buf[i + 1].toInt() and 0xFF)
      i += 2
    }
    if (i < end) {
      sum += (buf[i].toInt() and 0xFF) shl 8
    }
    while ((sum ushr 16) != 0) {
      sum = (sum and 0xFFFF) + (sum ushr 16)
    }
    return sum.inv() and 0xFFFF
  }

  private fun readU16(buf: ByteArray, off: Int): Int =
    ((buf[off].toInt() and 0xFF) shl 8) or (buf[off + 1].toInt() and 0xFF)

  private fun readI32(buf: ByteArray, off: Int): Int =
    ((buf[off].toInt() and 0xFF) shl 24) or
      ((buf[off + 1].toInt() and 0xFF) shl 16) or
      ((buf[off + 2].toInt() and 0xFF) shl 8) or
      (buf[off + 3].toInt() and 0xFF)

  private fun readU32(buf: ByteArray, off: Int): Long = readI32(buf, off).toLong() and 0xFFFFFFFFL

  private fun writeU16(buf: ByteArray, off: Int, value: Int) {
    buf[off] = ((value ushr 8) and 0xFF).toByte()
    buf[off + 1] = (value and 0xFF).toByte()
  }

  private fun writeI32(buf: ByteArray, off: Int, value: Int) {
    buf[off] = ((value ushr 24) and 0xFF).toByte()
    buf[off + 1] = ((value ushr 16) and 0xFF).toByte()
    buf[off + 2] = ((value ushr 8) and 0xFF).toByte()
    buf[off + 3] = (value and 0xFF).toByte()
  }

  private fun writeU32(buf: ByteArray, off: Int, value: Long) = writeI32(buf, off, value.toInt())
}
