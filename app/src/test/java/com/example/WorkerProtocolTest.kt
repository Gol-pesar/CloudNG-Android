package com.example

import com.example.protocol.WorkerProtocol
import com.example.vpn.Ipv4Packet
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

class WorkerProtocolTest {

  @Test
  fun `init packet decodes identically to worker parseInit`() {
    val uuid = "63ae8279-fafa-4dd0-b2ef-9d6a4ec3ffdd"
    val payload = "GET / HTTP/1.1\r\n\r\n".toByteArray(Charsets.UTF_8)
    val (packet, key) =
      WorkerProtocol.buildInitPacket(
        uuid = uuid,
        targetHost = "example.com",
        targetPort = 443,
        initialPayload = payload,
      )

    assertTrue(packet.size >= 16 + 1 + 2 + 1 + 8)
    val nonce = packet.copyOfRange(0, 16)
    val tb = uuid.toByteArray(Charsets.UTF_8)
    val derived = ByteArray(16) { i -> (tb[i % tb.size].toInt() xor nonce[i].toInt()).toByte() }
    assertArrayEquals(key, derived)

    val enc = packet.copyOfRange(16, packet.size - 8)
    val body = WorkerProtocol.xorBuf(enc, derived)

    assertEquals(1, body[0].toInt() and 0xFF)
    val port = ((body[1].toInt() and 0xFF) shl 8) or (body[2].toInt() and 0xFF)
    assertEquals(443, port)
    assertEquals(2, body[3].toInt() and 0xFF)
    val domainLen = body[4].toInt() and 0xFF
    val host = String(body, 5, domainLen, Charsets.UTF_8)
    assertEquals("example.com", host)
    val extractedPayload = body.copyOfRange(5 + domainLen, body.size)
    assertArrayEquals(payload, extractedPayload)
  }

  @Test
  fun `verifyAck matches HMAC-SHA256 OK XORed with key`() {
    val key = ByteArray(16) { (it + 7).toByte() }
    val mac = Mac.getInstance("HmacSHA256")
    mac.init(SecretKeySpec(key, "HmacSHA256"))
    val okDigest = mac.doFinal("OK".toByteArray(Charsets.UTF_8)).copyOfRange(0, 16)
    val serverFrame = WorkerProtocol.xorBuf(okDigest, key)

    assertTrue(WorkerProtocol.verifyAck(serverFrame, key))
    assertFalse(WorkerProtocol.verifyAck(ByteArray(16), key))
  }

  @Test
  fun `parseWorkerUrl and parseCleanIp normalize formats`() {
    val parsed1 = WorkerProtocol.parseWorkerUrl("https://my-worker.workers.dev/ws?ed=2048")
    assertNotNull(parsed1)
    assertEquals("wss", parsed1!!.scheme)
    assertEquals("my-worker.workers.dev", parsed1.host)
    assertEquals(443, parsed1.port)
    assertEquals("/ws?ed=2048", parsed1.pathAndQuery)

    val parsed2 = WorkerProtocol.parseWorkerUrl("edge.example.com:8443")
    assertNotNull(parsed2)
    assertEquals("edge.example.com", parsed2!!.host)
    assertEquals(8443, parsed2.port)

    val clean1 = WorkerProtocol.parseCleanIp("104.16.132.229:2053")
    assertNotNull(clean1)
    assertEquals("104.16.132.229", clean1!!.host)
    assertEquals(2053, clean1.port)

    val clean2 = WorkerProtocol.parseCleanIp("[2606:4700::1]:8443")
    assertNotNull(clean2)
    assertEquals("2606:4700::1", clean2!!.host)
    assertEquals(8443, clean2.port)
  }

  @Test
  fun `ipv4 tcp packet build and parse roundtrip`() {
    val srcIp = 0x0A000002 // 10.0.0.2
    val dstIp = 0x01010101 // 1.1.1.1
    val payload = "hello".toByteArray()
    val pkt =
      Ipv4Packet.buildTcpPacket(
        srcIp = srcIp,
        dstIp = dstIp,
        srcPort = 51234,
        dstPort = 443,
        seq = 12345L,
        ack = 67890L,
        flags = Ipv4Packet.TCP_PSH or Ipv4Packet.TCP_ACK,
        payload = payload,
      )
    val parsed = Ipv4Packet.parse(pkt, pkt.size)
    assertNotNull(parsed)
    assertEquals(Ipv4Packet.PROTO_TCP, parsed!!.protocol)
    assertEquals("10.0.0.2", parsed.srcIpString)
    assertEquals("1.1.1.1", parsed.dstIpString)
    assertEquals(51234, parsed.srcPort)
    assertEquals(443, parsed.dstPort)
    assertEquals(12345L, parsed.tcpSeq)
    assertEquals(67890L, parsed.tcpAck)
    assertEquals(payload.size, parsed.payloadLength)
  }

  @Test
  fun `parseShareConfigUri parses amir and cloudng config URIs accurately`() {
    val amirUri =
      "amir://63ae8279-fafa-4dd0-b2ef-9d6a4ec3ffdd@twilight-dream-9e3c.aliahmadiphotoofficial.workers.dev?type=ws&cleanIp=172.67.70.244&subproto=chat.v2&localPort=40446#Amir%20First%20Configuration"
    val parsed = WorkerProtocol.parseShareConfigUri(amirUri)
    assertNotNull(parsed)
    assertEquals("Amir First Configuration", parsed!!.name)
    assertEquals("https://twilight-dream-9e3c.aliahmadiphotoofficial.workers.dev", parsed.workerUrl)
    assertEquals("63ae8279-fafa-4dd0-b2ef-9d6a4ec3ffdd", parsed.uuid)
    assertEquals("172.67.70.244", parsed.cleanIp)

    val cloudNgUri =
      "cloudng://11111111-2222-3333-4444-555555555555@worker.example.workers.dev?type=ws&cleanIp=104.16.132.229&subproto=chat.v2#CloudNG%20Edge"
    val parsedCloud = WorkerProtocol.parseShareConfigUri(cloudNgUri)
    assertNotNull(parsedCloud)
    assertEquals("CloudNG Edge", parsedCloud!!.name)
    assertEquals("https://worker.example.workers.dev", parsedCloud.workerUrl)
    assertEquals("11111111-2222-3333-4444-555555555555", parsedCloud.uuid)
    assertEquals("104.16.132.229", parsedCloud.cleanIp)
  }

  @Test
  fun `buildIcmpPortUnreachable builds valid ICMP type 3 code 3 packet`() {
    val udp =
      Ipv4Packet.buildUdpPacket(
        srcIp = 0x0A000002,
        dstIp = 0x01010101,
        srcPort = 54321,
        dstPort = 443,
        payload = ByteArray(16),
      )
    val parsedUdp = Ipv4Packet.parse(udp, udp.size)!!
    val icmp = Ipv4Packet.buildIcmpPortUnreachable(udp, udp.size, parsedUdp)
    val parsedIcmp = Ipv4Packet.parse(icmp, icmp.size)!!
    assertEquals(Ipv4Packet.PROTO_ICMP, parsedIcmp.protocol)
    assertEquals("1.1.1.1", parsedIcmp.srcIpString)
    assertEquals("10.0.0.2", parsedIcmp.dstIpString)
    assertEquals(3, icmp[20].toInt() and 0xFF)
    assertEquals(3, icmp[21].toInt() and 0xFF)
  }

  @Test
  fun `xorInPlace matches xorBuf identically`() {
    val key = byteArrayOf(0x12, 0x34, 0x56, 0x78, 0x9A.toByte())
    val input = "Cloudflare Worker chat.v2 fast tunnel payload!".toByteArray(Charsets.UTF_8)
    val expected = WorkerProtocol.xorBuf(input, key)
    val copy = input.copyOf()
    WorkerProtocol.xorInPlace(copy, key)
    assertArrayEquals(expected, copy)
    WorkerProtocol.xorInPlace(copy, key)
    assertArrayEquals(input, copy)
  }

  @Test
  fun `tcp syn-ack window scale option roundtrips cleanly`() {
    val pkt =
      Ipv4Packet.buildTcpPacket(
        srcIp = 0x01010101,
        dstIp = 0x0A000002,
        srcPort = 443,
        dstPort = 54321,
        seq = 1000L,
        ack = 2001L,
        flags = Ipv4Packet.TCP_SYN or Ipv4Packet.TCP_ACK,
        window = 16384,
        mss = 1360,
        windowScale = 7,
      )
    val parsed = Ipv4Packet.parse(pkt, pkt.size)
    assertNotNull(parsed)
    assertEquals(16384, parsed!!.tcpWindow)
    assertEquals(7, Ipv4Packet.parseTcpWindowScale(pkt, parsed))
  }
}
