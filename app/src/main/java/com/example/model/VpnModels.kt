package com.example.model

import java.util.UUID

enum class AppLanguage(val code: String, val label: String) {
  FA("fa", "فارسی"),
  EN("en", "English"),
}

enum class DarkThemeMode(val key: String) {
  DARK("dark"),
  SYSTEM("system"),
  LIGHT("light"),
}

enum class PerAppProxyMode(val key: String) {
  ALL("all"),
  BYPASS("bypass"),
  ALLOW_ONLY("allow_only"),
}

data class InstalledAppInfo(
  val packageName: String,
  val label: String,
)

data class VpnConfig(
  val id: String = UUID.randomUUID().toString(),
  val name: String = "CloudNG Node",
  val workerUrl: String = "",
  val uuid: String = "",
  val cleanIp: String = "",
  val dnsServer: String = "1.1.1.1",
  val bypassLan: Boolean = true,
  val mtu: Int = 1440,
  val lastPingMs: Long? = null,
)

sealed interface VpnStatus {
  data object Disconnected : VpnStatus

  data object Connecting : VpnStatus

  data object Connected : VpnStatus

  data object Disconnecting : VpnStatus

  data class Error(val message: String) : VpnStatus
}

data class VpnTelemetry(
  val status: VpnStatus = VpnStatus.Disconnected,
  val connectedSinceMs: Long = 0L,
  val txBytes: Long = 0L,
  val rxBytes: Long = 0L,
  val txRateBps: Long = 0L,
  val rxRateBps: Long = 0L,
  val activeConnections: Int = 0,
  val handshakeRttMs: Long? = null,
  val activeWorkerHost: String = "",
  val activeCleanIp: String = "",
)

enum class LogLevel {
  INFO,
  WARN,
  ERROR,
  TRAFFIC,
}

data class LogEntry(
  val id: Long,
  val timestampMs: Long,
  val level: LogLevel,
  val tag: String,
  val message: String,
)

data class AppSettings(
  val language: AppLanguage = AppLanguage.FA,
  val dnsServer: String = "1.1.1.1",
  val bypassLan: Boolean = true,
  val themeMode: DarkThemeMode = DarkThemeMode.LIGHT,
  val perAppMode: PerAppProxyMode = PerAppProxyMode.ALL,
  val perAppPackages: Set<String> = emptySet(),
  val workerThreads: Int = 8,
)

data class RamTierSpec(
  val tierLabel: String,
  val minThreads: Int,
  val recommendedThreads: Int,
  val maxSafeThreads: Int,
)

object RamThreadGuide {
  const val MIN_THREADS = 2
  const val MAX_THREADS = 32

  fun specForRamGb(ramGb: Int): RamTierSpec =
    when {
      ramGb <= 2 -> RamTierSpec("2 GB", minThreads = 2, recommendedThreads = 4, maxSafeThreads = 6)
      ramGb <= 4 -> RamTierSpec("4 GB", minThreads = 4, recommendedThreads = 6, maxSafeThreads = 10)
      ramGb <= 6 -> RamTierSpec("6 GB", minThreads = 6, recommendedThreads = 10, maxSafeThreads = 16)
      else -> RamTierSpec("8+ GB", minThreads = 8, recommendedThreads = 16, maxSafeThreads = 24)
    }
}

data class HandshakeTestResult(
  val isRunning: Boolean = false,
  val success: Boolean? = null,
  val wsConnectMs: Long? = null,
  val totalRttMs: Long? = null,
  val resolvedIp: String? = null,
  val httpStatus: String? = null,
  val errorMessage: String? = null,
)

data class CleanIpTestResult(
  val ip: String,
  val latencyMs: Long? = null,
  val handshakeOk: Boolean = false,
  val isTesting: Boolean = false,
  val error: String? = null,
)
