package com.example.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.IpPrefix
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.os.Process
import androidx.core.app.NotificationCompat
import com.example.EdgeTunnelApp
import com.example.MainActivity
import com.example.R
import com.example.model.LogLevel
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
import okhttp3.ConnectionPool
import okhttp3.OkHttpClient
import okhttp3.Request
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.ByteBuffer
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.TimeUnit
import javax.net.SocketFactory

class WorkerVpnService : VpnService() {

  companion object {
    const val ACTION_START = "com.example.vpn.START"
    const val ACTION_STOP = "com.example.vpn.STOP"
    private const val NOTIFICATION_ID = 4102
    private const val CHANNEL_ID = "edgetunnel_vpn_channel"

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
  }

  private val appContainer by lazy { (application as EdgeTunnelApp).container }
  private val stateRepo get() = appContainer.vpnStateRepository
  private val configRepo get() = appContainer.configRepository

  private var serviceScope: CoroutineScope? = null
  private var tunInterface: ParcelFileDescriptor? = null
  private var sharedWorkerClient: OkHttpClient? = null
  private var tcpManager: TcpSessionManager? = null
  private var dnsHandler: DnsHandler? = null
  private val outboundQueue = ArrayBlockingQueue<ByteArray>(8192)

  override fun onCreate() {
    super.onCreate()
    ensureNotificationChannel()
  }

  override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
    if (intent?.action == ACTION_STOP) {
      stopTunnel()
      return START_NOT_STICKY
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
    cleanupEngine()
    val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    serviceScope = scope

    scope.launch {
      val config: VpnConfig? = configRepo.getActiveConfig()
      val settings = configRepo.getSettings()
      val parsedUrl = config?.let { WorkerProtocol.parseWorkerUrl(it.workerUrl) }

      if (config == null || parsedUrl == null || config.uuid.isBlank()) {
        val errMsg = "Worker URL and UUID are required"
        stateRepo.log(LogLevel.ERROR, "VPN", errMsg)
        stateRepo.updateStatus(VpnStatus.Error(errMsg))
        stopSelf()
        return@launch
      }

      val cleanIp = WorkerProtocol.parseCleanIp(config.cleanIp)
      stateRepo.updateStatus(
        status = VpnStatus.Connecting,
        workerHost = parsedUrl.host,
        cleanIp = cleanIp?.host ?: "",
      )
      stateRepo.log(
        LogLevel.INFO,
        "VPN",
        "Starting tunnel → ${parsedUrl.host} (Clean IP: ${cleanIp?.host ?: "Direct DNS"})",
      )

      val pfd =
        try {
          establishTunInterface(settings.dnsServer, settings.bypassLan, config.mtu)
        } catch (e: Exception) {
          val msg = "TUN establish failed: ${e.message}"
          stateRepo.log(LogLevel.ERROR, "VPN", msg)
          stateRepo.updateStatus(VpnStatus.Error(msg))
          stopSelf()
          return@launch
        }

      if (pfd == null) {
        val msg = "VPN interface not authorized"
        stateRepo.log(LogLevel.ERROR, "VPN", msg)
        stateRepo.updateStatus(VpnStatus.Error(msg))
        stopSelf()
        return@launch
      }
      tunInterface = pfd

      val protectedFactory = createProtectedSocketFactory()
      val workerClient =
        WorkerProtocol.createWorkerOkHttpClient(
          workerHost = parsedUrl.host,
          cleanIp = cleanIp,
          socketFactory = protectedFactory,
          connectTimeoutSec = 6L,
        ).newBuilder()
          .connectionPool(ConnectionPool(32, 90, TimeUnit.SECONDS))
          .build()
      sharedWorkerClient = workerClient

      // Pre-warm TLS 1.3 session ticket & Cloudflare Worker isolate immediately
      scope.launch(Dispatchers.IO) {
        prewarmWorkerTls(workerClient, parsedUrl, cleanIp)
      }

      val enqueueToTun: (ByteArray) -> Unit = { pkt ->
        if (!outboundQueue.offer(pkt)) {
          outboundQueue.poll()
          outboundQueue.offer(pkt)
        }
      }

      val dns =
        DnsHandler(
          scope = scope,
          parsedWorkerUrl = parsedUrl,
          uuid = config.uuid,
          cleanIp = cleanIp,
          dnsServerIp = settings.dnsServer.ifBlank { "1.1.1.1" },
          protectedSocketFactory = protectedFactory,
          sharedWorkerClient = workerClient,
          vpnStateRepository = stateRepo,
          writeToTun = enqueueToTun,
        )
      dnsHandler = dns

      val tcp =
        TcpSessionManager(
          scope = scope,
          parsedWorkerUrl = parsedUrl,
          uuid = config.uuid,
          cleanIp = cleanIp,
          sharedWorkerClient = workerClient,
          dnsHandler = dns,
          vpnStateRepository = stateRepo,
          writeToTun = enqueueToTun,
        )
      tcpManager = tcp

      stateRepo.updateStatus(
        status = VpnStatus.Connected,
        workerHost = parsedUrl.host,
        cleanIp = cleanIp?.host ?: "",
      )
      val subtitle =
        if (cleanIp != null) "${parsedUrl.host} • ${cleanIp.host}" else parsedUrl.host
      promoteToForeground(getString(R.string.vpn_notif_connected_title), subtitle)
      stateRepo.log(LogLevel.INFO, "VPN", "TUN interface established (MTU ${config.mtu})")

      // High-priority TUN writer loop
      scope.launch(Dispatchers.IO) {
        runCatching { Process.setThreadPriority(Process.THREAD_PRIORITY_URGENT_AUDIO) }
        val out = FileOutputStream(pfd.fileDescriptor)
        try {
          while (isActive) {
            val pkt = outboundQueue.take()
            out.write(pkt)
          }
        } catch (_: InterruptedException) {
        } catch (e: Exception) {
          if (isActive) {
            stateRepo.log(LogLevel.ERROR, "TUN", "Write error: ${e.message}")
          }
        }
      }

      // Stats reporter loop
      scope.launch(Dispatchers.IO) {
        var lastTx = 0L
        var lastRx = 0L
        while (isActive) {
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

      // High-priority TUN reader loop
      runCatching { Process.setThreadPriority(Process.THREAD_PRIORITY_URGENT_AUDIO) }
      val input = FileInputStream(pfd.fileDescriptor)
      val readBuffer = ByteBuffer.allocate(32767)
      try {
        while (isActive) {
          val len = input.read(readBuffer.array())
          if (len < 0) break
          if (len == 0) continue
          val packetBytes = readBuffer.array()
          val parsed = Ipv4Packet.parse(packetBytes, len) ?: continue
          when (parsed.protocol) {
            Ipv4Packet.PROTO_TCP -> tcp.handleTcpPacket(packetBytes, parsed)
            Ipv4Packet.PROTO_UDP -> {
              if (parsed.dstPort == 53) {
                dns.handleUdpPacket(packetBytes, parsed)
              } else {
                // Force QUIC/HTTP3 (UDP 443) to fall back immediately to TCP 443
                enqueueToTun(Ipv4Packet.buildIcmpPortUnreachable(packetBytes, len, parsed))
              }
            }
          }
        }
      } catch (e: Exception) {
        if (isActive) {
          stateRepo.log(LogLevel.ERROR, "TUN", "Read error: ${e.message}")
        }
      } finally {
        if (isActive) {
          stopTunnel()
        }
      }
    }
  }

  private fun prewarmWorkerTls(
    client: OkHttpClient,
    parsedUrl: ParsedWorkerUrl,
    cleanIp: ParsedCleanIp?,
  ) {
    val start = System.currentTimeMillis()
    val effectivePort = cleanIp?.port ?: parsedUrl.port
    val defaultPort = if (parsedUrl.isTls) 443 else 80
    val portSuffix = if (effectivePort != defaultPort) ":$effectivePort" else ""
    val req =
      Request.Builder()
        .url("${parsedUrl.httpScheme}://${parsedUrl.host}$portSuffix/")
        .head()
        .build()
    runCatching {
      client.newCall(req).execute().use { resp ->
        val elapsed = System.currentTimeMillis() - start
        stateRepo.log(
          LogLevel.INFO,
          "WARM",
          "TLS & Worker isolate pre-warmed in ${elapsed}ms (HTTP ${resp.code})",
        )
      }
    }
  }

  private fun establishTunInterface(
    dnsServer: String,
    bypassLan: Boolean,
    mtu: Int,
  ): ParcelFileDescriptor? {
    val builder =
      Builder()
        .setSession("CloudNG")
        .setMtu(mtu.coerceIn(1280, 1460))
        .addAddress("10.0.0.2", 32)
        .addRoute("0.0.0.0", 0)
        .addDnsServer(dnsServer.ifBlank { "1.1.1.1" })

    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
      builder.setMetered(false)
    }

    if (bypassLan && Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
      runCatching {
        builder.excludeRoute(IpPrefix(InetAddress.getByName("10.0.0.0"), 8))
        builder.excludeRoute(IpPrefix(InetAddress.getByName("172.16.0.0"), 12))
        builder.excludeRoute(IpPrefix(InetAddress.getByName("192.168.0.0"), 16))
      }
    }

    runCatching {
      builder.addDisallowedApplication(packageName)
    }

    return builder.establish()
  }

  private fun createProtectedSocketFactory(): SocketFactory {
    val defaultFactory = SocketFactory.getDefault()
    fun configure(socket: Socket): Socket {
      protect(socket)
      runCatching { socket.tcpNoDelay = true }
      return socket
    }
    return object : SocketFactory() {
      override fun createSocket(): Socket = configure(defaultFactory.createSocket())

      override fun createSocket(host: String, port: Int): Socket {
        val socket = configure(defaultFactory.createSocket())
        socket.connect(InetSocketAddress(host, port), 6000)
        return socket
      }

      override fun createSocket(host: String, port: Int, localHost: InetAddress, localPort: Int): Socket {
        val socket = configure(defaultFactory.createSocket())
        socket.bind(InetSocketAddress(localHost, localPort))
        socket.connect(InetSocketAddress(host, port), 6000)
        return socket
      }

      override fun createSocket(host: InetAddress, port: Int): Socket {
        val socket = configure(defaultFactory.createSocket())
        socket.connect(InetSocketAddress(host, port), 6000)
        return socket
      }

      override fun createSocket(address: InetAddress, port: Int, localAddress: InetAddress, localPort: Int): Socket {
        val socket = configure(defaultFactory.createSocket())
        socket.bind(InetSocketAddress(localAddress, localPort))
        socket.connect(InetSocketAddress(address, port), 6000)
        return socket
      }
    }
  }

  private fun stopTunnel() {
    cleanupEngine()
    stateRepo.updateStatus(VpnStatus.Disconnected)
    stateRepo.log(LogLevel.INFO, "VPN", "Tunnel stopped")
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
      stopForeground(STOP_FOREGROUND_REMOVE)
    } else {
      @Suppress("DEPRECATION")
      stopForeground(true)
    }
    stopSelf()
  }

  private fun cleanupEngine() {
    serviceScope?.cancel()
    serviceScope = null
    tcpManager?.shutdown()
    tcpManager = null
    dnsHandler?.shutdown()
    dnsHandler = null
    sharedWorkerClient?.let { client ->
      runCatching {
        client.dispatcher.executorService.shutdown()
        client.connectionPool.evictAll()
      }
    }
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
