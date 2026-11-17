package com.example.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.IpPrefix
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import androidx.core.app.NotificationCompat
import com.example.EdgeTunnelApp
import com.example.MainActivity
import com.example.R
import com.example.model.AppSettings
import com.example.model.LogLevel
import com.example.model.PerAppProxyMode
import com.example.model.RamThreadGuide
import com.example.model.VpnConfig
import com.example.model.VpnStatus
import com.example.protocol.ParsedCleanIp
import com.example.protocol.ParsedWorkerUrl
import com.example.protocol.WorkerProtocol
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withTimeout
import okhttp3.Call
import okhttp3.Connection
import okhttp3.EventListener
import okhttp3.Handshake
import okhttp3.OkHttpClient
import okhttp3.Protocol
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import okio.ByteString
import okio.ByteString.Companion.toByteString
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.Socket
import java.nio.ByteBuffer
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import javax.net.SocketFactory
import kotlin.coroutines.resume

class WorkerVpnService : VpnService() {

  companion object {
    const val ACTION_START = "com.example.vpn.START"
    const val ACTION_STOP = "com.example.vpn.STOP"
    const val ACTION_RESTART_IF_RUNNING = "com.example.vpn.RESTART_IF_RUNNING"
    private const val NOTIFICATION_ID = 4102
    private const val CHANNEL_ID = "edgetunnel_vpn_channel"
    private const val OUTBOUND_QUEUE_CAPACITY = 2048

    fun startVpn(context: Context) {
      val intent = Intent(context, WorkerVpnService::class.java).apply { action = ACTION_START }
      if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
        context.startForegroundService(intent)
      } else {
        context.startService(intent)
      }
    }

    fun stopVpn(context: Context) {
      val intent = Intent(context, WorkerVpnService::class.java).apply { action = ACTION_STOP }
      context.startService(intent)
    }

    fun restartIfRunning(context: Context) {
      val intent =
        Intent(context, WorkerVpnService::class.java).apply {
          action = ACTION_RESTART_IF_RUNNING
        }
      runCatching { context.startService(intent) }
    }
  }

  private val appContainer by lazy { (application as EdgeTunnelApp).container }
  private val stateRepo get() = appContainer.vpnStateRepository
  private val configRepo get() = appContainer.configRepository

  private val engineLock = Any()
  private val connectionAttemptSeq = AtomicLong(0L)
  @Volatile private var serviceScope: CoroutineScope? = null
  @Volatile private var tunInterface: ParcelFileDescriptor? = null
  @Volatile private var sharedWorkerClient: OkHttpClient? = null
  @Volatile private var hostMapper: VirtualHostMapper? = null
  @Volatile private var tcpManager: TcpSessionManager? = null
  private var connectivityManager: ConnectivityManager? = null
  @Volatile private var underlyingCallback: ConnectivityManager.NetworkCallback? = null
  @Volatile private var underlyingNetwork: Network? = null
  @Volatile private var tunnelActive: Boolean = false

  private val outboundQueue = ArrayBlockingQueue<ByteArray>(OUTBOUND_QUEUE_CAPACITY)
  private val ipv6DropCount = AtomicLong(0L)
  private val malformedDropCount = AtomicLong(0L)
  private val tunWriteDropCount = AtomicLong(0L)
  @Volatile private var lastIpv6WarnMs = 0L
  @Volatile private var lastMalformedWarnMs = 0L
  @Volatile private var lastUdpLogMs = 0L
  @Volatile private var lastQueueWarnMs = 0L
  @Volatile private var lastProtectWarnMs = 0L

  override fun onCreate() {
    super.onCreate()
    ensureNotificationChannel()
    connectivityManager = getSystemService(ConnectivityManager::class.java)
  }

  override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
    when (intent?.action) {
      ACTION_STOP -> {
        stopTunnel()
        return START_NOT_STICKY
      }
      ACTION_RESTART_IF_RUNNING -> {
        if (!tunnelActive) {
          stopSelf()
          return START_NOT_STICKY
        }
        stateRepo.log(LogLevel.INFO, "VPN", "Applying updated tunnel / Per-App Proxy rules…")
        promoteToForeground(getString(R.string.vpn_notif_connecting_title), "")
        startTunnel()
        return START_STICKY
      }
    }

    promoteToForeground(getString(R.string.vpn_notif_connecting_title), "")
    startTunnel()
    return START_STICKY
  }

  override fun onRevoke() {
    stateRepo.log(LogLevel.WARN, "VPN", "VPN permission revoked by system")
    stopTunnel()
    super.onRevoke()
  }

  override fun onDestroy() {
    stopTunnel()
    super.onDestroy()
  }

  private fun startTunnel() {
    val attemptId: Long
    val scope: CoroutineScope
    synchronized(engineLock) {
      attemptId = connectionAttemptSeq.incrementAndGet()
      cleanupEngineLocked()
      tunnelActive = true
      scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
      serviceScope = scope
    }

    scope.launch {
      val config: VpnConfig? = configRepo.getActiveConfig()
      val settings = configRepo.getSettings()
      val parsedUrl = config?.let { WorkerProtocol.parseWorkerUrl(it.workerUrl) }

      if (config == null || parsedUrl == null || config.uuid.isBlank()) {
        failStartup(attemptId, "Worker URL and UUID are required")
        return@launch
      }

      if (attemptId != connectionAttemptSeq.get() || !tunnelActive) return@launch

      val cleanIp = WorkerProtocol.parseCleanIp(config.cleanIp)
      val initialTargetLabel = cleanIp?.host ?: parsedUrl.host

      stateRepo.updateStatus(
        status = VpnStatus.Connecting,
        workerHost = parsedUrl.host,
        cleanIp = initialTargetLabel,
      )
      stateRepo.log(
        LogLevel.INFO,
        "VPN",
        "[1/6] Service ready (token ${WorkerProtocol.maskUuid(config.uuid)}, target ${parsedUrl.host})",
      )

      // 2. Establish TUN interface before probing sockets so OS VPN routing & self-bypass are bound cleanly
      registerUnderlyingNetworkMonitor()
      val pfd =
        try {
          establishTunInterface(settings, config.mtu)
        } catch (e: Exception) {
          failStartup(attemptId, "TUN establish failed: ${e.message}")
          return@launch
        }

      if (pfd == null) {
        failStartup(attemptId, "VPN permission missing or TUN interface rejected")
        return@launch
      }

      synchronized(engineLock) {
        if (attemptId != connectionAttemptSeq.get() || !tunnelActive) {
          runCatching { pfd.close() }
          return@launch
        }
        tunInterface = pfd
      }
      stateRepo.log(
        LogLevel.INFO,
        "VPN",
        "[2/6] TUN interface established (MTU ${config.mtu}, 10.0.0.2/32, per-app=${settings.perAppMode.key})",
      )

      // 3. Initialize Worker engine components (socket factory, mapper, concurrency)
      val workerThreads =
        settings.workerThreads.coerceIn(RamThreadGuide.MIN_THREADS, RamThreadGuide.MAX_THREADS)
      val protectedFactory = createProtectedSocketFactory()
      val netLabel = describeUnderlyingNetwork(connectivityManager, underlyingNetwork)
      stateRepo.log(
        LogLevel.INFO,
        "VPN",
        "[3/6] Engine initialized (net=$netLabel, lanes=$workerThreads, self-bypass=true)",
      )

      val enqueueToTun: (ByteArray) -> Unit = { pkt ->
        if (tunnelActive && attemptId == connectionAttemptSeq.get()) {
          val offered = outboundQueue.offer(pkt)
          if (!offered) {
            val delayed = runCatching { outboundQueue.offer(pkt, 50L, TimeUnit.MILLISECONDS) }.getOrDefault(false)
            if (!delayed) {
              val dropped = tunWriteDropCount.incrementAndGet()
              val now = System.currentTimeMillis()
              if (now - lastQueueWarnMs > 5_000L) {
                lastQueueWarnMs = now
                stateRepo.log(LogLevel.WARN, "TUN", "Outbound TUN queue saturated (dropped=$dropped)")
              }
            }
          }
        }
      }

      val mapper =
        VirtualHostMapper { level, msg ->
          stateRepo.log(level, "DNS", msg)
        }

      // 4-6. Real WebSocket connection (chat.v2), custom init frame, and Worker ACK verification
      var effectiveCleanIp: ParsedCleanIp? = cleanIp
      var workerClient: OkHttpClient? = null
      var activeRouteLabel = initialTargetLabel
      var lastProbeError: String? = null

      val probeListenerFactory = createDiagnosticEventListenerFactory(logVerboseEvents = true)
      val runtimeListenerFactory = createDiagnosticEventListenerFactory(logVerboseEvents = false)

      if (cleanIp != null) {
        stateRepo.log(
          LogLevel.INFO,
          "VPN",
          "[4/6] Connecting via Clean IP ${cleanIp.host}:${cleanIp.port ?: parsedUrl.port} (Zero-DNS, SNI=${parsedUrl.host})…",
        )
        val probeCleanClient =
          WorkerProtocol.createWorkerOkHttpClient(
            workerHost = parsedUrl.host,
            cleanIp = cleanIp,
            socketFactory = protectedFactory,
            connectTimeoutSec = 8L,
            workerThreads = 2,
            eventListenerFactory = probeListenerFactory,
          )
        val pinnedErr = probeWorkerHandshake(probeCleanClient, parsedUrl, cleanIp, config.uuid)
        shutdownOkHttpClient(probeCleanClient)

        if (pinnedErr == null) {
          workerClient =
            WorkerProtocol.createWorkerOkHttpClient(
              workerHost = parsedUrl.host,
              cleanIp = cleanIp,
              socketFactory = protectedFactory,
              connectTimeoutSec = 10L,
              workerThreads = workerThreads,
              eventListenerFactory = runtimeListenerFactory,
            )
          activeRouteLabel = cleanIp.host
          stateRepo.log(LogLevel.INFO, "VPN", "[5/6] Worker ACK verified via Clean IP ${cleanIp.host}")
        } else {
          lastProbeError = pinnedErr
          stateRepo.log(
            LogLevel.WARN,
            "VPN",
            "Clean IP ${cleanIp.host} failed ($pinnedErr); falling back to ${parsedUrl.host} (IPv6-first)…",
          )
        }
      }

      if (workerClient == null) {
        if (attemptId != connectionAttemptSeq.get() || !tunnelActive) return@launch
        stateRepo.log(
          LogLevel.INFO,
          "VPN",
          "[4/6] Connecting direct → ${parsedUrl.host}:${parsedUrl.port}…",
        )
        val probeFallbackClient =
          WorkerProtocol.createWorkerOkHttpClient(
            workerHost = parsedUrl.host,
            cleanIp = null,
            socketFactory = protectedFactory,
            connectTimeoutSec = 10L,
            workerThreads = 2,
            preferIpv6Fallback = cleanIp != null,
            eventListenerFactory = probeListenerFactory,
          )
        val fallbackErr = probeWorkerHandshake(probeFallbackClient, parsedUrl, null, config.uuid)
        shutdownOkHttpClient(probeFallbackClient)

        if (fallbackErr == null) {
          workerClient =
            WorkerProtocol.createWorkerOkHttpClient(
              workerHost = parsedUrl.host,
              cleanIp = null,
              socketFactory = protectedFactory,
              connectTimeoutSec = 12L,
              workerThreads = workerThreads,
              preferIpv6Fallback = cleanIp != null,
              eventListenerFactory = runtimeListenerFactory,
            )
          effectiveCleanIp = null
          activeRouteLabel =
            if (cleanIp != null) "${parsedUrl.host} (Direct Fallback)"
            else "${parsedUrl.host} (Direct)"
          stateRepo.log(LogLevel.INFO, "VPN", "[5/6] Worker ACK verified via $activeRouteLabel")
        } else {
          val combinedErr =
            if (lastProbeError != null) "Clean IP: $lastProbeError | Fallback: $fallbackErr"
            else fallbackErr
          failStartup(attemptId, "Handshake failed: $combinedErr")
          return@launch
        }
      }

      val tcp =
        TcpSessionManager(
          scope = scope,
          parsedWorkerUrl = parsedUrl,
          uuid = config.uuid,
          cleanIp = effectiveCleanIp,
          sharedWorkerClient = workerClient,
          hostMapper = mapper,
          vpnStateRepository = stateRepo,
          workerThreads = workerThreads,
          tunMtu = config.mtu,
          writeToTun = enqueueToTun,
        )

      synchronized(engineLock) {
        if (attemptId != connectionAttemptSeq.get() || !tunnelActive) {
          tcp.shutdown()
          mapper.clear()
          shutdownOkHttpClient(workerClient)
          return@launch
        }
        sharedWorkerClient = workerClient
        hostMapper = mapper
        tcpManager = tcp
      }

      // 7. Report Connected ONLY after TUN + Engine + Real WS + Init + ACK verification succeeded
      stateRepo.updateStatus(
        status = VpnStatus.Connected,
        workerHost = parsedUrl.host,
        cleanIp = activeRouteLabel,
      )
      val subtitle = "${parsedUrl.host} • $activeRouteLabel"
      promoteToForeground(getString(R.string.vpn_notif_connected_title), subtitle)
      stateRepo.log(LogLevel.INFO, "VPN", "[6/6] Connected: $subtitle")

      // TUN writer loop
      scope.launch(Dispatchers.IO) {
        val out = FileOutputStream(pfd.fileDescriptor)
        try {
          while (isActive && tunnelActive && attemptId == connectionAttemptSeq.get()) {
            val pkt = outboundQueue.poll(250L, TimeUnit.MILLISECONDS) ?: continue
            out.write(pkt)
          }
        } catch (_: InterruptedException) {
        } catch (e: Exception) {
          if (isActive && tunnelActive && attemptId == connectionAttemptSeq.get()) {
            stateRepo.log(LogLevel.ERROR, "TUN", "Write error: ${e.message}")
          }
        }
      }

      // Stats reporter loop
      scope.launch(Dispatchers.IO) {
        var lastTx = 0L
        var lastRx = 0L
        while (isActive && tunnelActive && attemptId == connectionAttemptSeq.get()) {
          delay(1_000L)
          val tx = tcp.txBytes.get()
          val rx = tcp.rxBytes.get()
          val txRate = (tx - lastTx).coerceAtLeast(0L)
          val rxRate = (rx - lastRx).coerceAtLeast(0L)
          lastTx = tx
          lastRx = rx
          stateRepo.updateTrafficStats(
            txBytes = tx,
            rxBytes = rx,
            txRateBps = txRate,
            rxRateBps = rxRate,
            activeConnections = tcp.activeCount(),
          )
        }
      }

      // TUN reader loop (reusable read buffer)
      val input = FileInputStream(pfd.fileDescriptor)
      val readBuffer = ByteBuffer.allocate(32767)
      try {
        while (isActive && tunnelActive && attemptId == connectionAttemptSeq.get()) {
          val len = input.read(readBuffer.array())
          if (len < 0) break
          if (len == 0) continue
          val packetBytes = readBuffer.array()
          val ipVersion = Ipv4Packet.peekIpVersion(packetBytes, len)
          if (ipVersion == 6) {
            val dropped = ipv6DropCount.incrementAndGet()
            val now = System.currentTimeMillis()
            if (now - lastIpv6WarnMs > 10_000L) {
              lastIpv6WarnMs = now
              val nextHdr = Ipv4Packet.peekIpv6NextHeader(packetBytes, len)
              stateRepo.log(
                LogLevel.WARN,
                "TUN",
                "IPv6 packet skipped on IPv4-only TUN (total=$dropped, nextHdr=$nextHdr)",
              )
            }
            continue
          }
          if (ipVersion != 4) {
            logMalformedPacket(ipVersion, len)
            continue
          }

          val parsed = Ipv4Packet.parse(packetBytes, len)
          if (parsed == null) {
            logMalformedPacket(ipVersion, len)
            continue
          }

          when (parsed.protocol) {
            Ipv4Packet.PROTO_TCP -> tcp.handleTcpPacket(packetBytes, parsed)
            Ipv4Packet.PROTO_UDP -> {
              if (parsed.dstPort == 53) {
                mapper.handleQueryPacket(packetBytes, parsed)?.let(enqueueToTun)
              } else {
                // Force non-53 UDP (e.g. QUIC) to fall back immediately to TCP
                val now = System.currentTimeMillis()
                if (now - lastUdpLogMs > 5_000L) {
                  lastUdpLogMs = now
                  stateRepo.log(
                    LogLevel.TRAFFIC,
                    "UDP",
                    "Non-DNS UDP port ${parsed.dstPort} rejected (ICMP Unreachable → TCP fallback)",
                  )
                }
                enqueueToTun(Ipv4Packet.buildIcmpPortUnreachable(packetBytes, len, parsed))
              }
            }
          }
        }
      } catch (e: Exception) {
        if (isActive && tunnelActive && attemptId == connectionAttemptSeq.get()) {
          stateRepo.log(LogLevel.ERROR, "TUN", "Read error: ${e.message}")
        }
      } finally {
        if (attemptId == connectionAttemptSeq.get() && tunnelActive) {
          stopTunnel()
        }
      }
    }
  }

  private fun failStartup(attemptId: Long, errorMsg: String) {
    synchronized(engineLock) {
      if (attemptId != connectionAttemptSeq.get()) return
      tunnelActive = false
      cleanupEngineLocked()
    }
    stateRepo.log(LogLevel.ERROR, "VPN", errorMsg)
    stateRepo.updateStatus(VpnStatus.Error(errorMsg))
    removeForegroundCompat()
    stopSelf()
  }

  private fun logMalformedPacket(version: Int, len: Int) {
    val count = malformedDropCount.incrementAndGet()
    val now = System.currentTimeMillis()
    if (now - lastMalformedWarnMs > 10_000L) {
      lastMalformedWarnMs = now
      stateRepo.log(
        LogLevel.WARN,
        "TUN",
        "Dropped malformed/bad-checksum IP packet (ver=$version, len=$len, count=$count)",
      )
    }
  }

  private fun createDiagnosticEventListenerFactory(logVerboseEvents: Boolean): EventListener.Factory {
    return EventListener.Factory {
      object : EventListener() {
        @Volatile private var tcpStartMs = 0L
        @Volatile private var tlsStartMs = 0L
        @Volatile private var lastSocketLabel = ""

        override fun dnsEnd(call: Call, domainName: String, inetAddressList: List<InetAddress>) {
          if (logVerboseEvents && inetAddressList.isNotEmpty()) {
            val ips = inetAddressList.joinToString(", ") { it.hostAddress ?: "?" }
            stateRepo.log(LogLevel.INFO, "NET", "Target resolved for $domainName → $ips")
          }
        }

        override fun connectStart(call: Call, inetSocketAddress: InetSocketAddress, proxy: Proxy) {
          tcpStartMs = System.currentTimeMillis()
          lastSocketLabel = "${inetSocketAddress.address?.hostAddress ?: inetSocketAddress.hostString}:${inetSocketAddress.port}"
          if (logVerboseEvents) {
            stateRepo.log(LogLevel.INFO, "NET", "TCP connecting → $lastSocketLabel")
          }
        }

        override fun secureConnectStart(call: Call) {
          tlsStartMs = System.currentTimeMillis()
        }

        override fun secureConnectEnd(call: Call, handshake: Handshake?) {
          if (logVerboseEvents && handshake != null) {
            val tlsMs = (System.currentTimeMillis() - tlsStartMs).coerceAtLeast(0L)
            stateRepo.log(
              LogLevel.INFO,
              "TLS",
              "TLS ${handshake.tlsVersion.javaName} (${handshake.cipherSuite.javaName}) verified in ${tlsMs}ms",
            )
          }
        }

        override fun connectEnd(
          call: Call,
          inetSocketAddress: InetSocketAddress,
          proxy: Proxy,
          protocol: Protocol?,
        ) {
          if (logVerboseEvents) {
            val totalMs = (System.currentTimeMillis() - tcpStartMs).coerceAtLeast(0L)
            stateRepo.log(LogLevel.INFO, "NET", "Socket ready ($lastSocketLabel, ${totalMs}ms)")
          }
        }

        override fun connectFailed(
          call: Call,
          inetSocketAddress: InetSocketAddress,
          proxy: Proxy,
          protocol: Protocol?,
          ioe: IOException,
        ) {
          val addr = "${inetSocketAddress.address?.hostAddress ?: inetSocketAddress.hostString}:${inetSocketAddress.port}"
          stateRepo.log(LogLevel.WARN, "NET", "Connect failed ($addr): ${ioe.message}")
        }

        override fun responseHeadersEnd(call: Call, response: Response) {
          if (logVerboseEvents && response.code == 101) {
            val subproto = response.header("Sec-WebSocket-Protocol") ?: "<none>"
            stateRepo.log(LogLevel.INFO, "WS", "HTTP 101 Upgrade (Sec-WebSocket-Protocol: $subproto)")
          }
        }

        override fun connectionAcquired(call: Call, connection: Connection) {
          // Intentionally quiet during normal multiplexed sessions
        }
      }
    }
  }

  private fun registerUnderlyingNetworkMonitor() {
    val cm = connectivityManager ?: return
    val initialNet = findBestUnderlyingNetwork(cm)
    underlyingNetwork = initialNet

    val request =
      NetworkRequest.Builder()
        .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
        .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
        .build()

    val callback =
      object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) {
          val caps = runCatching { cm.getNetworkCapabilities(network) }.getOrNull()
          if (caps != null && caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)) {
            val previous = underlyingNetwork
            if (previous != network) {
              underlyingNetwork = network
              updateServiceUnderlyingNetworks(network)
              onUnderlyingNetworkChanged(cm, network)
            }
          }
        }

        override fun onCapabilitiesChanged(network: Network, networkCapabilities: NetworkCapabilities) {
          if (networkCapabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN) &&
            networkCapabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
            underlyingNetwork == null
          ) {
            underlyingNetwork = network
            updateServiceUnderlyingNetworks(network)
            onUnderlyingNetworkChanged(cm, network)
          }
        }

        override fun onLost(network: Network) {
          if (underlyingNetwork == network) {
            val next = findBestUnderlyingNetwork(cm, exclude = network)
            underlyingNetwork = next
            updateServiceUnderlyingNetworks(next)
            onUnderlyingNetworkChanged(cm, next)
          }
        }
      }

    underlyingCallback = callback
    runCatching { cm.registerNetworkCallback(request, callback) }
    updateServiceUnderlyingNetworks(initialNet)
  }

  private fun onUnderlyingNetworkChanged(cm: ConnectivityManager, next: Network?) {
    sharedWorkerClient?.let { client ->
      runCatching { client.connectionPool.evictAll() }
    }
    if (next != null) {
      stateRepo.log(
        LogLevel.INFO,
        "NET",
        "Underlying network switched → ${describeUnderlyingNetwork(cm, next)}; idle Worker pool reset",
      )
    } else {
      stateRepo.log(
        LogLevel.WARN,
        "NET",
        "Underlying network lost; waiting for physical connectivity…",
      )
    }
  }

  private fun describeUnderlyingNetwork(cm: ConnectivityManager?, network: Network?): String {
    if (cm == null || network == null) return "None"
    val caps = runCatching { cm.getNetworkCapabilities(network) }.getOrNull() ?: return "Unknown"
    return when {
      caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "Wi-Fi"
      caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> "Cellular"
      caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> "Ethernet"
      else -> "Physical"
    }
  }

  private fun findBestUnderlyingNetwork(cm: ConnectivityManager, exclude: Network? = null): Network? {
    val active = cm.activeNetwork
    if (active != null && active != exclude) {
      val caps = runCatching { cm.getNetworkCapabilities(active) }.getOrNull()
      if (caps != null &&
        caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN) &&
        caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
      ) {
        return active
      }
    }
    @Suppress("DEPRECATION")
    val candidates = runCatching { cm.allNetworks }.getOrNull().orEmpty()
    var bestFallback: Network? = null
    for (net in candidates) {
      if (net == exclude) continue
      val caps = runCatching { cm.getNetworkCapabilities(net) }.getOrNull() ?: continue
      if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)) continue
      if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) continue
      if (caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)) {
        return net
      }
      if (bestFallback == null) bestFallback = net
    }
    return bestFallback
  }

  private fun updateServiceUnderlyingNetworks(network: Network?) {
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP_MR1) {
      runCatching {
        setUnderlyingNetworks(if (network != null) arrayOf(network) else null)
      }
    }
  }

  /**
   * Probes 1 chat.v2 WebSocket + init/ACK roundtrip (matching Cl2.py) to verify reachability.
   * Returns null on success or a concise error description on failure.
   */
  private suspend fun probeWorkerHandshake(
    client: OkHttpClient,
    parsedUrl: ParsedWorkerUrl,
    cleanIp: ParsedCleanIp?,
    uuid: String,
  ): String? {
    val req = WorkerProtocol.buildWebSocketRequest(parsedUrl, cleanIp)
    return try {
      withTimeout(8_000L) {
        suspendCancellableCoroutine<String?> { cont ->
          var sessionKey = ByteArray(0)
          val ws =
            client.newWebSocket(
              req,
              object : WebSocketListener() {
                override fun onOpen(webSocket: WebSocket, response: Response) {
                  val negProto = response.header("Sec-WebSocket-Protocol")
                  if (negProto != null && !negProto.equals(WorkerProtocol.SUBPROTOCOL, ignoreCase = true)) {
                    webSocket.close(1002, "Subprotocol mismatch")
                    if (cont.isActive) cont.resume("Subprotocol mismatch: $negProto")
                    return
                  }
                  if (negProto == null) {
                    stateRepo.log(LogLevel.WARN, "WS", "Server omitted Sec-WebSocket-Protocol header (expected chat.v2)")
                  }
                  val (initFrame, key) =
                    WorkerProtocol.buildInitPacket(
                      uuid = uuid,
                      targetHost = "cp.cloudflare.com",
                      targetPort = 80,
                    )
                  sessionKey = key
                  val sent = webSocket.send(initFrame.toByteString())
                  if (!sent) {
                    webSocket.cancel()
                    if (cont.isActive) cont.resume("Failed to send init frame")
                  } else {
                    stateRepo.log(LogLevel.INFO, "WS", "Custom init frame sent (${initFrame.size}B)")
                  }
                }

                override fun onMessage(webSocket: WebSocket, bytes: ByteString) {
                  val ok = WorkerProtocol.verifyAck(bytes.toByteArray(), sessionKey)
                  webSocket.close(1000, "Probe done")
                  if (cont.isActive) {
                    cont.resume(if (ok) null else "Invalid Worker ACK (check UUID)")
                  }
                }

                override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                  if (cont.isActive) {
                    val msg =
                      if (response != null) "HTTP ${response.code}"
                      else (t.message ?: t.javaClass.simpleName)
                    cont.resume(msg)
                  }
                }

                override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
                  if (cont.isActive) {
                    cont.resume("Closed ($code): $reason")
                  }
                }
              },
            )
          cont.invokeOnCancellation { ws.cancel() }
        }
      }
    } catch (e: Exception) {
      e.message ?: "Timeout"
    }
  }

  private fun establishTunInterface(
    settings: AppSettings,
    mtu: Int,
  ): ParcelFileDescriptor? {
    val builder =
      Builder()
        .setSession("CloudNG")
        .setMtu(mtu.coerceIn(1280, 1460))
        .addAddress("10.0.0.2", 32)
        .addRoute("0.0.0.0", 0)
        .addDnsServer(VirtualHostMapper.VIRTUAL_TUN_GATEWAY_IP)

    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
      builder.setMetered(false)
    }

    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP_MR1) {
      underlyingNetwork?.let { net ->
        runCatching { builder.setUnderlyingNetworks(arrayOf(net)) }
      }
    }

    if (settings.bypassLan && Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
      runCatching {
        builder.excludeRoute(IpPrefix(InetAddress.getByAddress(byteArrayOf(10, 0, 0, 0)), 8))
        builder.excludeRoute(IpPrefix(InetAddress.getByAddress(byteArrayOf(172.toByte(), 16, 0, 0)), 12))
        builder.excludeRoute(IpPrefix(InetAddress.getByAddress(byteArrayOf(192.toByte(), 168.toByte(), 0, 0)), 16))
      }
    }

    // Never mix addAllowedApplication and addDisallowedApplication on the same Builder.
    // Self-app (CloudNG) is ALWAYS excluded from the VPN tunnel so it connects directly via Wi-Fi/Cellular.
    val selectedPackages =
      settings.perAppPackages
        .asSequence()
        .map { it.trim() }
        .filter { it.isNotEmpty() && it != packageName }
        .toSet()

    if (settings.perAppMode == PerAppProxyMode.ALLOW_ONLY && selectedPackages.isNotEmpty()) {
      var addedCount = 0
      for (pkg in selectedPackages) {
        if (runCatching { builder.addAllowedApplication(pkg) }.isSuccess) {
          addedCount++
        }
      }
      if (addedCount == 0) {
        runCatching { builder.addDisallowedApplication(packageName) }
      }
    } else {
      runCatching { builder.addDisallowedApplication(packageName) }
      if (settings.perAppMode == PerAppProxyMode.BYPASS) {
        for (pkg in selectedPackages) {
          runCatching { builder.addDisallowedApplication(pkg) }
        }
      }
    }

    return builder.establish()
  }

  private fun createProtectedSocketFactory(): SocketFactory {
    val defaultFactory = SocketFactory.getDefault()
    fun configure(socket: Socket): Socket {
      // protect() excludes the socket from VPN routing while preserving OS 464XLAT (IPv4) & IPv6 routes
      val protectedOk = protect(socket)
      if (!protectedOk) {
        val now = System.currentTimeMillis()
        if (now - lastProtectWarnMs > 5_000L) {
          lastProtectWarnMs = now
          stateRepo.log(LogLevel.WARN, "NET", "VpnService.protect(socket) returned false")
        }
      }
      runCatching { socket.tcpNoDelay = true }
      runCatching { socket.receiveBufferSize = 256 * 1024 }
      runCatching { socket.sendBufferSize = 256 * 1024 }
      return socket
    }
    return object : SocketFactory() {
      override fun createSocket(): Socket = configure(defaultFactory.createSocket())

      override fun createSocket(host: String, port: Int): Socket {
        val socket = configure(defaultFactory.createSocket())
        socket.connect(InetSocketAddress(host, port), 8000)
        return socket
      }

      override fun createSocket(host: String, port: Int, localHost: InetAddress, localPort: Int): Socket {
        val socket = configure(defaultFactory.createSocket())
        socket.bind(InetSocketAddress(localHost, localPort))
        socket.connect(InetSocketAddress(host, port), 8000)
        return socket
      }

      override fun createSocket(host: InetAddress, port: Int): Socket {
        val socket = configure(defaultFactory.createSocket())
        socket.connect(InetSocketAddress(host, port), 8000)
        return socket
      }

      override fun createSocket(address: InetAddress, port: Int, localAddress: InetAddress, localPort: Int): Socket {
        val socket = configure(defaultFactory.createSocket())
        socket.bind(InetSocketAddress(localAddress, localPort))
        socket.connect(InetSocketAddress(address, port), 8000)
        return socket
      }
    }
  }

  private fun stopTunnel() {
    val wasActive: Boolean
    synchronized(engineLock) {
      connectionAttemptSeq.incrementAndGet()
      wasActive = tunnelActive
      tunnelActive = false
      if (wasActive) {
        stateRepo.updateStatus(VpnStatus.Disconnecting)
      }
      cleanupEngineLocked()
    }
    stateRepo.updateStatus(VpnStatus.Disconnected)
    if (wasActive) {
      stateRepo.log(LogLevel.INFO, "VPN", "Tunnel disconnected & resources released")
    }
    removeForegroundCompat()
    stopSelf()
  }

  private fun removeForegroundCompat() {
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
      stopForeground(STOP_FOREGROUND_REMOVE)
    } else {
      @Suppress("DEPRECATION")
      stopForeground(true)
    }
  }

  private fun shutdownOkHttpClient(client: OkHttpClient?) {
    if (client == null) return
    runCatching {
      client.dispatcher.cancelAll()
      client.dispatcher.executorService.shutdown()
      client.connectionPool.evictAll()
    }
  }

  private fun cleanupEngineLocked() {
    underlyingCallback?.let { cb ->
      runCatching { connectivityManager?.unregisterNetworkCallback(cb) }
    }
    underlyingCallback = null
    underlyingNetwork = null

    serviceScope?.cancel()
    serviceScope = null
    tcpManager?.shutdown()
    tcpManager = null
    hostMapper?.clear()
    hostMapper = null
    shutdownOkHttpClient(sharedWorkerClient)
    sharedWorkerClient = null
    outboundQueue.clear()
    runCatching { tunInterface?.close() }
    tunInterface = null
  }

  private fun promoteToForeground(title: String, subtitle: String) {
    val notification = buildNotification(title, subtitle)
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
      startForeground(
        NOTIFICATION_ID,
        notification,
        ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE,
      )
    } else {
      startForeground(NOTIFICATION_ID, notification)
    }
  }

  private fun buildNotification(title: String, subtitle: String): Notification {
    val openIntent =
      PendingIntent.getActivity(
        this,
        0,
        Intent(this, MainActivity::class.java),
        PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
      )
    val stopIntent =
      PendingIntent.getService(
        this,
        1,
        Intent(this, WorkerVpnService::class.java).apply { action = ACTION_STOP },
        PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
      )

    return NotificationCompat.Builder(this, CHANNEL_ID)
      .setSmallIcon(R.drawable.ic_cloudng_notif)
      .setContentTitle(title)
      .setContentText(subtitle.ifBlank { "chat.v2 WebSocket Tunnel" })
      .setOngoing(true)
      .setOnlyAlertOnce(true)
      .setContentIntent(openIntent)
      .addAction(0, getString(R.string.vpn_notif_disconnect), stopIntent)
      .setPriority(NotificationCompat.PRIORITY_LOW)
      .build()
  }

  private fun ensureNotificationChannel() {
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
      val manager = getSystemService(NotificationManager::class.java)
      val channel =
        NotificationChannel(
          CHANNEL_ID,
          getString(R.string.vpn_channel_name),
          NotificationManager.IMPORTANCE_LOW,
        ).apply {
          description = getString(R.string.vpn_channel_desc)
          setShowBadge(false)
        }
      manager.createNotificationChannel(channel)
    }
  }
}
