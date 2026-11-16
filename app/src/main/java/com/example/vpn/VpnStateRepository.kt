package com.example.vpn

import com.example.model.LogEntry
import com.example.model.LogLevel
import com.example.model.VpnStatus
import com.example.model.VpnTelemetry
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import java.util.concurrent.atomic.AtomicLong

class VpnStateRepository {
  private val _telemetry = MutableStateFlow(VpnTelemetry())
  val telemetry: StateFlow<VpnTelemetry> = _telemetry.asStateFlow()

  private val _logs = MutableStateFlow<List<LogEntry>>(emptyList())
  val logs: StateFlow<List<LogEntry>> = _logs.asStateFlow()

  private val logCounter = AtomicLong(0)
  @Volatile private var lastTrafficLogMs = 0L

  fun updateStatus(
    status: VpnStatus,
    workerHost: String = _telemetry.value.activeWorkerHost,
    cleanIp: String = _telemetry.value.activeCleanIp,
  ) {
    _telemetry.update { current ->
      val connectedSince =
        when (status) {
          is VpnStatus.Connected ->
            if (current.connectedSinceMs > 0L) current.connectedSinceMs else System.currentTimeMillis()
          is VpnStatus.Disconnected, is VpnStatus.Error -> 0L
          else -> current.connectedSinceMs
        }
      current.copy(
        status = status,
        connectedSinceMs = connectedSince,
        activeWorkerHost = workerHost,
        activeCleanIp = cleanIp,
        txBytes = if (status is VpnStatus.Disconnected) 0L else current.txBytes,
        rxBytes = if (status is VpnStatus.Disconnected) 0L else current.rxBytes,
        txRateBps = if (status is VpnStatus.Connected) current.txRateBps else 0L,
        rxRateBps = if (status is VpnStatus.Connected) current.rxRateBps else 0L,
        activeConnections = if (status is VpnStatus.Connected) current.activeConnections else 0,
      )
    }
  }

  fun updateTrafficStats(
    txBytes: Long,
    rxBytes: Long,
    txRateBps: Long,
    rxRateBps: Long,
    activeConnections: Int,
  ) {
    _telemetry.update {
      it.copy(
        txBytes = txBytes,
        rxBytes = rxBytes,
        txRateBps = txRateBps,
        rxRateBps = rxRateBps,
        activeConnections = activeConnections,
      )
    }
  }

  fun updateHandshakeRtt(rttMs: Long) {
    _telemetry.update { it.copy(handshakeRttMs = rttMs) }
  }

  fun wantsTrafficLog(): Boolean = System.currentTimeMillis() - lastTrafficLogMs >= 400L

  fun log(level: LogLevel, tag: String, message: String) {
    val now = System.currentTimeMillis()
    if (level == LogLevel.TRAFFIC) {
      if (now - lastTrafficLogMs < 400L) return
      lastTrafficLogMs = now
    }
    val entry =
      LogEntry(
        id = logCounter.incrementAndGet(),
        timestampMs = now,
        level = level,
        tag = tag,
        message = message,
      )
    _logs.update { current ->
      (listOf(entry) + current).take(200)
    }
  }

  fun clearLogs() {
    _logs.value = emptyList()
  }
}
