package com.example

import com.example.model.LogLevel
import com.example.protocol.WorkerProtocol
import com.example.vpn.Ipv4Packet
import com.example.vpn.TcpSessionManager
import com.example.vpn.VirtualHostMapper
import com.example.vpn.VpnStateRepository
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import okhttp3.OkHttpClient
import okhttp3.Protocol
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import okio.ByteString
import okio.ByteString.Companion.toByteString
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

class VpnEngineAuditTest {

  private fun buildDnsQuery(txId: Int, domain: String, qtype: Int): ByteArray {
    val labels = domain.split('.').filter { it.isNotEmpty() }
    val qnameLen = labels.sumOf { 1 + it.length } + 1
    val buf = ByteArray(12 + qnameLen + 4)
    buf[0] = ((txId ushr 8) and 0xFF).toByte()
    buf[1] = (txId and 0xFF).toByte()
    buf[2] = 0x01 // RD=1
    buf[5] = 0x01 // QDCOUNT=1
    var p = 12
    for (lbl in labels) {
      val b = lbl.toByteArray(Charsets.UTF_8)
      buf[p++] = b.size.toByte()
      System.arraycopy(b, 0, buf, p, b.size)
      p += b.size
    }
    buf[p++] = 0
    buf[p++] = ((qtype ushr 8) and 0xFF).toByte()
    buf[p++] = (qtype and 0xFF).toByte()
    buf[p++] = 0
    buf[p] = 1 // QCLASS IN
    return buf
  }

  @Test
  fun `ipv6 packet on TUN is detected explicitly and never parsed as ipv4`() {
    val ipv6Packet = ByteArray(40)
    ipv6Packet[0] = 0x60.toByte() // Version 6
    ipv6Packet[6] = 6 // Next Header: TCP
    assertEquals(6, Ipv4Packet.peekIpVersion(ipv6Packet, ipv6Packet.size))
    assertEquals(6, Ipv4Packet.peekIpv6NextHeader(ipv6Packet, ipv6Packet.size))
    assertNull(Ipv4Packet.parse(ipv6Packet, ipv6Packet.size))
  }

  @Test
  fun `ipv4 header checksum and tcp checksum corruption are rejected`() {
    val pkt =
      Ipv4Packet.buildTcpPacket(
        srcIp = 0x0A000002,
        dstIp = 0x01010101,
        srcPort = 40000,
        dstPort = 443,
        seq = 100L,
        ack = 200L,
        flags = Ipv4Packet.TCP_PSH or Ipv4Packet.TCP_ACK,
        payload = "ping".toByteArray(),
      )
    assertNotNull(Ipv4Packet.parse(pkt, pkt.size))

    val badIpSum = pkt.copyOf()
    badIpSum[10] = (badIpSum[10].toInt() xor 0xFF).toByte()
    assertNull(Ipv4Packet.parse(badIpSum, badIpSum.size))

    val badTcpSum = pkt.copyOf()
    badTcpSum[36] = (badTcpSum[36].toInt() xor 0x55).toByte()
    assertNull(Ipv4Packet.parse(badTcpSum, badTcpSum.size))

    // Declared IP length exceeding captured buffer must also fail safely
    assertNull(Ipv4Packet.parse(pkt, pkt.size - 1))
  }

  @Test
  fun `virtual host mapper handles A, AAAA, invalid synthetic IPs, and TTL expiration`() {
    var fakeNowMs = 1_000_000L
    val diagnostics = CopyOnWriteArrayList<String>()
    val mapper =
      VirtualHostMapper(
        cacheTtlMs = 5_000L,
        clockMs = { fakeNowMs },
        onDiagnostic = { _, msg -> diagnostics.add(msg) },
      )

    assertFalse(VirtualHostMapper.isValidSyntheticIp("198.18.0.1"))
    assertFalse(VirtualHostMapper.isValidSyntheticIp("198.18.0.0"))
    assertFalse(VirtualHostMapper.isValidSyntheticIp("198.19.255.255"))
    assertTrue(VirtualHostMapper.isValidSyntheticIp("198.18.0.10"))

    // 1. A query for domain -> assigned IP + TXID preserved
    val dnsA = buildDnsQuery(txId = 0xCAFE, domain = "one.example.org", qtype = 1)
    val udpA = Ipv4Packet.buildUdpPacket(0x0A000002, 0xC6120001.toInt(), 50000, 53, dnsA)
    val replyA = mapper.handleQueryPacket(udpA, Ipv4Packet.parse(udpA, udpA.size)!!)!!
    val parsedReplyA = Ipv4Packet.parse(replyA, replyA.size)!!
    val dnsRespA = replyA.copyOfRange(parsedReplyA.payloadOffset, parsedReplyA.payloadOffset + parsedReplyA.payloadLength)
    assertEquals(0xCA, dnsRespA[0].toInt() and 0xFF)
    assertEquals(0xFE, dnsRespA[1].toInt() and 0xFF)
    assertEquals(1, dnsRespA[7].toInt() and 0xFF)
    val ip1 = WorkerProtocol.ipv4ToString(dnsRespA, dnsRespA.size - 4)
    assertEquals("one.example.org", mapper.lookupDomainForIp(ip1))

    // 2. AAAA query -> fast NODATA (ANCOUNT=0, NOERROR)
    val dnsAaaa = buildDnsQuery(txId = 0xBEEF, domain = "one.example.org", qtype = 28)
    val udpAaaa = Ipv4Packet.buildUdpPacket(0x0A000002, 0xC6120001.toInt(), 50001, 53, dnsAaaa)
    val replyAaaa = mapper.handleQueryPacket(udpAaaa, Ipv4Packet.parse(udpAaaa, udpAaaa.size)!!)!!
    val parsedReplyAaaa = Ipv4Packet.parse(replyAaaa, replyAaaa.size)!!
    val dnsRespAaaa = replyAaaa.copyOfRange(parsedReplyAaaa.payloadOffset, parsedReplyAaaa.payloadOffset + parsedReplyAaaa.payloadLength)
    assertEquals(0xBE, dnsRespAaaa[0].toInt() and 0xFF)
    assertEquals(0xEF, dnsRespAaaa[1].toInt() and 0xFF)
    assertEquals(0, dnsRespAaaa[7].toInt() and 0xFF)

    // 3. TTL expiry after clock advances beyond 5s without lookups
    fakeNowMs += 6_000L
    assertNull(mapper.lookupDomainForIp(ip1))

    // 4. Malformed DNS query logs diagnostic and returns FORMERR
    val badDns = ByteArray(14).apply { this[5] = 1; this[12] = 63 } // Truncated QNAME label
    val udpBad = Ipv4Packet.buildUdpPacket(0x0A000002, 0xC6120001.toInt(), 50002, 53, badDns)
    val replyBad = mapper.handleQueryPacket(udpBad, Ipv4Packet.parse(udpBad, udpBad.size)!!)!!
    val parsedBad = Ipv4Packet.parse(replyBad, replyBad.size)!!
    assertEquals(1, replyBad[parsedBad.payloadOffset + 3].toInt() and 0x0F) // RCODE = FORMERR
    assertTrue(diagnostics.isNotEmpty())
  }

  @Test
  fun `virtual host mapper is thread-safe under concurrent lookups`() {
    val mapper = VirtualHostMapper()
    val pool = Executors.newFixedThreadPool(8)
    val latch = CountDownLatch(32)
    val errors = CopyOnWriteArrayList<Throwable>()

    repeat(32) { idx ->
      pool.submit {
        try {
          val host = "host-${idx % 12}.test.local"
          val q = buildDnsQuery(100 + idx, host, 1)
          val udp = Ipv4Packet.buildUdpPacket(0x0A000002, 0xC6120001.toInt(), 40000 + idx, 53, q)
          val reply = mapper.handleQueryPacket(udp, Ipv4Packet.parse(udp, udp.size)!!)!!
          val parsed = Ipv4Packet.parse(reply, reply.size)!!
          val ip = WorkerProtocol.ipv4ToString(reply, parsed.payloadOffset + parsed.payloadLength - 4)
          assertEquals(host, mapper.lookupDomainForIp(ip))
        } catch (t: Throwable) {
          errors.add(t)
        } finally {
          latch.countDown()
        }
      }
    }

    assertTrue(latch.await(5, TimeUnit.SECONDS))
    pool.shutdownNow()
    assertTrue("Concurrent mapper errors: $errors", errors.isEmpty())
  }

  private class FakeWebSocket(
    var allowSend: Boolean = true,
    var simulatedQueueBytes: Long = 0L,
  ) : WebSocket {
    val sentFrames = CopyOnWriteArrayList<ByteString>()
    @Volatile var closedCode: Int? = null
    @Volatile var canceled = false
    lateinit var listener: WebSocketListener

    override fun queueSize(): Long = simulatedQueueBytes
    override fun request(): Request = Request.Builder().url("https://worker.example.com/").build()
    override fun send(text: String): Boolean = allowSend
    override fun send(bytes: ByteString): Boolean {
      if (!allowSend) return false
      sentFrames.add(bytes)
      return true
    }

    override fun close(code: Int, reason: String?): Boolean {
      closedCode = code
      return true
    }

    override fun cancel() {
      canceled = true
    }

    fun triggerOpen() {
      val resp =
        Response.Builder()
          .request(request())
          .protocol(Protocol.HTTP_1_1)
          .code(101)
          .message("Switching Protocols")
          .header("Sec-WebSocket-Protocol", WorkerProtocol.SUBPROTOCOL)
          .build()
      listener.onOpen(this, resp)
    }

    fun triggerAckForInitFrame(uuid: String) {
      val initBytes = sentFrames.first().toByteArray()
      val nonce = initBytes.copyOfRange(0, 16)
      val key = WorkerProtocol.deriveKey(uuid, nonce)
      val mac = Mac.getInstance("HmacSHA256")
      mac.init(SecretKeySpec(key, "HmacSHA256"))
      val ack = WorkerProtocol.xorBuf(mac.doFinal("OK".toByteArray(Charsets.UTF_8)).copyOfRange(0, 16), key)
      listener.onMessage(this, ack.toByteString())
    }
  }

  @Test
  fun `tcp session manager preserves connecting session on duplicate SYN, handles wraparound and clean FIN`() {
    val uuid = "63ae8279-fafa-4dd0-b2ef-9d6a4ec3ffdd"
    val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    val stateRepo = VpnStateRepository()
    val mapper = VirtualHostMapper()
    val tunOut = CopyOnWriteArrayList<ByteArray>()
    val sockets = CopyOnWriteArrayList<FakeWebSocket>()

    val manager =
      TcpSessionManager(
        scope = scope,
        parsedWorkerUrl = WorkerProtocol.parseWorkerUrl("https://worker.example.com/")!!,
        uuid = uuid,
        cleanIp = null,
        sharedWorkerClient = OkHttpClient(),
        hostMapper = mapper,
        vpnStateRepository = stateRepo,
        workerThreads = 2,
        tunMtu = 1440,
        writeToTun = { tunOut.add(it) },
        webSocketConnector = { _, listener ->
          FakeWebSocket().apply {
            this.listener = listener
            sockets.add(this)
          }
        },
      )

    try {
      // Check 32-bit sequence wraparound comparisons directly
      assertTrue(TcpSessionManager.isSeqAfter(4L, 0xFFFFFFFCL))
      assertTrue(TcpSessionManager.isSeqBefore(0xFFFFFFFCL, 4L))

      // SYN with sequence near 32-bit wraparound boundary
      val synSeq = 0xFFFFFFFCL
      val syn1 =
        Ipv4Packet.buildTcpPacket(
          srcIp = 0x0A000002,
          dstIp = 0x01010101,
          srcPort = 51000,
          dstPort = 443,
          seq = synSeq,
          ack = 0L,
          flags = Ipv4Packet.TCP_SYN,
        )
      manager.handleTcpPacket(syn1, Ipv4Packet.parse(syn1, syn1.size)!!)

      // Wait briefly for lane execution
      val deadline = System.currentTimeMillis() + 2000
      while (sockets.isEmpty() && System.currentTimeMillis() < deadline) Thread.sleep(10)
      assertEquals(1, sockets.size)
      assertEquals(1, manager.activeCount())

      // Duplicate SYN retransmission (same seq) MUST NOT kill existing WebSocket
      manager.handleTcpPacket(syn1, Ipv4Packet.parse(syn1, syn1.size)!!)
      Thread.sleep(60)
      assertEquals(1, sockets.size)
      assertFalse(sockets.first().canceled)
      assertTrue(tunOut.count {
        val p = Ipv4Packet.parse(it, it.size)!!
        (p.tcpFlags and (Ipv4Packet.TCP_SYN or Ipv4Packet.TCP_ACK)) == (Ipv4Packet.TCP_SYN or Ipv4Packet.TCP_ACK)
      } >= 2)

      // Open WS & complete handshake + send wraparound payload ("HELLO" at 0xFFFFFFFD, 5 bytes -> next=2)
      val fakeWs = sockets.first()
      fakeWs.triggerOpen()
      assertTrue(fakeWs.sentFrames.isNotEmpty())
      fakeWs.triggerAckForInitFrame(uuid)

      val payload = "HELLO".toByteArray(Charsets.UTF_8)
      val dataPkt =
        Ipv4Packet.buildTcpPacket(
          srcIp = 0x0A000002,
          dstIp = 0x01010101,
          srcPort = 51000,
          dstPort = 443,
          seq = (synSeq + 1L) and 0xFFFFFFFFL, // 0xFFFFFFFD
          ack = 1L,
          flags = Ipv4Packet.TCP_PSH or Ipv4Packet.TCP_ACK,
          payload = payload,
        )
      manager.handleTcpPacket(dataPkt, Ipv4Packet.parse(dataPkt, dataPkt.size)!!)
      Thread.sleep(60)
      assertEquals(2, fakeWs.sentFrames.size) // init + data

      // Remote closes cleanly -> CLOSING linger should NOT send RST on client's final ACK
      val tunCountBeforeClose = tunOut.size
      fakeWs.listener.onClosing(fakeWs, 1000, "EOF")
      val finFromServer = Ipv4Packet.parse(tunOut.last(), tunOut.last().size)!!
      assertTrue((finFromServer.tcpFlags and Ipv4Packet.TCP_FIN) != 0)

      val clientFinalAck =
        Ipv4Packet.buildTcpPacket(
          srcIp = 0x0A000002,
          dstIp = 0x01010101,
          srcPort = 51000,
          dstPort = 443,
          seq = 2L, // wrapped past 0xFFFFFFFF
          ack = (finFromServer.tcpSeq + 1L) and 0xFFFFFFFFL,
          flags = Ipv4Packet.TCP_ACK,
        )
      val outBeforeFinalAck = tunOut.size
      manager.handleTcpPacket(clientFinalAck, Ipv4Packet.parse(clientFinalAck, clientFinalAck.size)!!)
      Thread.sleep(60)
      val newPacketsAfterFinalAck = tunOut.drop(outBeforeFinalAck)
      assertFalse(
        "Unexpected RST emitted after clean FIN ACK",
        newPacketsAfterFinalAck.any {
          val p = Ipv4Packet.parse(it, it.size)!!
          (p.tcpFlags and Ipv4Packet.TCP_RST) != 0
        },
      )
      assertTrue(tunOut.size > tunCountBeforeClose)

      manager.shutdown()
      assertEquals(0, manager.activeCount())
    } finally {
      manager.shutdown()
      scope.cancel()
    }
  }

  @Test
  fun `tcp session manager sends RST and closes if WebSocket queue rejects payload`() {
    val uuid = "63ae8279-fafa-4dd0-b2ef-9d6a4ec3ffdd"
    val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    val stateRepo = VpnStateRepository()
    val mapper = VirtualHostMapper()
    val tunOut = CopyOnWriteArrayList<ByteArray>()
    val sockets = CopyOnWriteArrayList<FakeWebSocket>()

    val manager =
      TcpSessionManager(
        scope = scope,
        parsedWorkerUrl = WorkerProtocol.parseWorkerUrl("https://worker.example.com/")!!,
        uuid = uuid,
        cleanIp = null,
        sharedWorkerClient = OkHttpClient(),
        hostMapper = mapper,
        vpnStateRepository = stateRepo,
        workerThreads = 2,
        tunMtu = 1440,
        writeToTun = { tunOut.add(it) },
        webSocketConnector = { _, listener ->
          FakeWebSocket().apply {
            this.listener = listener
            sockets.add(this)
          }
        },
      )

    try {
      val syn =
        Ipv4Packet.buildTcpPacket(
          srcIp = 0x0A000002,
          dstIp = 0x01010101,
          srcPort = 52000,
          dstPort = 443,
          seq = 1000L,
          ack = 0L,
          flags = Ipv4Packet.TCP_SYN,
        )
      manager.handleTcpPacket(syn, Ipv4Packet.parse(syn, syn.size)!!)
      val deadline = System.currentTimeMillis() + 2000
      while (sockets.isEmpty() && System.currentTimeMillis() < deadline) Thread.sleep(10)
      val fakeWs = sockets.first()
      fakeWs.triggerOpen()
      fakeWs.triggerAckForInitFrame(uuid)

      // Simulate OkHttp queue full / refusing send()
      fakeWs.allowSend = false
      val dataPkt =
        Ipv4Packet.buildTcpPacket(
          srcIp = 0x0A000002,
          dstIp = 0x01010101,
          srcPort = 52000,
          dstPort = 443,
          seq = 1001L,
          ack = 1L,
          flags = Ipv4Packet.TCP_PSH or Ipv4Packet.TCP_ACK,
          payload = "DATA".toByteArray(),
        )
      manager.handleTcpPacket(dataPkt, Ipv4Packet.parse(dataPkt, dataPkt.size)!!)
      Thread.sleep(80)

      assertEquals(0, manager.activeCount())
      assertTrue(
        tunOut.any {
          val p = Ipv4Packet.parse(it, it.size)!!
          (p.tcpFlags and Ipv4Packet.TCP_RST) != 0
        },
      )
    } finally {
      manager.shutdown()
      scope.cancel()
    }
  }
}
