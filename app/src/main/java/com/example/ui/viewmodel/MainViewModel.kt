package com.example.ui.viewmodel

import android.app.ActivityManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import com.example.AppContainer
import com.example.model.AppLanguage
import com.example.model.AppSettings
import com.example.model.CleanIpTestResult
import com.example.model.DarkThemeMode
import com.example.model.HandshakeTestResult
import com.example.model.InstalledAppInfo
import com.example.model.LogEntry
import com.example.model.LogLevel
import com.example.model.PerAppProxyMode
import com.example.model.RamThreadGuide
import com.example.model.VpnConfig
import com.example.model.VpnStatus
import com.example.model.VpnTelemetry
import com.example.protocol.WorkerProtocol
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.util.UUID

data class DraftFieldsState(
  val profileId: String = "",
  val workerUrl: String = "",
  val uuid: String = "",
  val cleanIp: String = "",
  val isDirty: Boolean = false,
  val validationError: String? = null,
)

class MainViewModel(
  private val container: AppContainer,
) : ViewModel() {

  private val configRepo = container.configRepository
  private val stateRepo = container.vpnStateRepository
  private val tester = container.workerTester

  val telemetry: StateFlow<VpnTelemetry> = stateRepo.telemetry
  val logs: StateFlow<List<LogEntry>> = stateRepo.logs

  val profiles: StateFlow<List<VpnConfig>> =
    configRepo.profilesFlow.stateIn(
      scope = viewModelScope,
      started = SharingStarted.WhileSubscribed(5_000),
      initialValue = emptyList(),
    )

  val activeConfig: StateFlow<VpnConfig?> =
    configRepo.activeConfigFlow.stateIn(
      scope = viewModelScope,
      started = SharingStarted.WhileSubscribed(5_000),
      initialValue = null,
    )

  val settings: StateFlow<AppSettings> =
    configRepo.settingsFlow.stateIn(
      scope = viewModelScope,
      started = SharingStarted.WhileSubscribed(5_000),
      initialValue = AppSettings(),
    )

  private val _draft = MutableStateFlow(DraftFieldsState())
  val draft: StateFlow<DraftFieldsState> = _draft.asStateFlow()

  private val _handshakeTest = MutableStateFlow(HandshakeTestResult())
  val handshakeTest: StateFlow<HandshakeTestResult> = _handshakeTest.asStateFlow()

  private val _elapsedSeconds = MutableStateFlow(0L)
  val elapsedSeconds: StateFlow<Long> = _elapsedSeconds.asStateFlow()

  private val _installedApps = MutableStateFlow<List<InstalledAppInfo>>(emptyList())
  val installedApps: StateFlow<List<InstalledAppInfo>> = _installedApps.asStateFlow()

  private val _isLoadingApps = MutableStateFlow(false)
  val isLoadingApps: StateFlow<Boolean> = _isLoadingApps.asStateFlow()

  private val _deviceRamGb = MutableStateFlow(4)
  val deviceRamGb: StateFlow<Int> = _deviceRamGb.asStateFlow()

  private val defaultCleanIps =
    listOf(
      "172.67.70.244",
      "104.16.132.229",
      "104.17.148.22",
      "104.18.2.161",
      "172.67.182.91",
      "162.159.135.42",
      "104.21.48.84",
      "188.114.96.3",
      "104.26.10.233",
    )

  private val _cleanIpResults =
    MutableStateFlow(defaultCleanIps.map { CleanIpTestResult(ip = it) })
  val cleanIpResults: StateFlow<List<CleanIpTestResult>> = _cleanIpResults.asStateFlow()

  private val _isScanningCleanIps = MutableStateFlow(false)
  val isScanningCleanIps: StateFlow<Boolean> = _isScanningCleanIps.asStateFlow()

  private var lastSyncedProfileId: String? = null

  init {
    viewModelScope.launch {
      configRepo.activeConfigFlow.collectLatest { cfg ->
        if (cfg == null) {
          if (lastSyncedProfileId != null || !_draft.value.isDirty) {
            lastSyncedProfileId = null
            _draft.value = DraftFieldsState()
          }
        } else if (cfg.id != lastSyncedProfileId || !_draft.value.isDirty) {
          lastSyncedProfileId = cfg.id
          _draft.value =
            DraftFieldsState(
              profileId = cfg.id,
              workerUrl = cfg.workerUrl,
              uuid = cfg.uuid,
              cleanIp = cfg.cleanIp,
              isDirty = false,
              validationError = null,
            )
        }
      }
    }

    viewModelScope.launch {
      telemetry.collectLatest { t ->
        if (t.status is VpnStatus.Connected && t.connectedSinceMs > 0L) {
          while (true) {
            _elapsedSeconds.value =
              ((System.currentTimeMillis() - t.connectedSinceMs) / 1000L).coerceAtLeast(0L)
            delay(1_000L)
          }
        } else {
          _elapsedSeconds.value = 0L
        }
      }
    }
  }

  fun loadInstalledApps(context: Context) {
    if (_isLoadingApps.value) return
    val selfPackage = context.packageName
    viewModelScope.launch {
      _isLoadingApps.value = true
      val apps =
        withContext(Dispatchers.IO) {
          runCatching {
            val pm = context.packageManager
            val launcherIntent =
              Intent(Intent.ACTION_MAIN).apply {
                addCategory(Intent.CATEGORY_LAUNCHER)
              }
            val resolveInfos =
              if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                pm.queryIntentActivities(
                  launcherIntent,
                  PackageManager.ResolveInfoFlags.of(0L),
                )
              } else {
                @Suppress("DEPRECATION")
                pm.queryIntentActivities(launcherIntent, 0)
              }

            val uniqueByPackage = LinkedHashMap<String, InstalledAppInfo>()
            for (info in resolveInfos) {
              val pkg = info.activityInfo?.packageName ?: continue
              if (pkg == selfPackage || uniqueByPackage.containsKey(pkg)) continue
              val label =
                runCatching { info.loadLabel(pm).toString() }
                  .getOrNull()
                  ?.takeIf { it.isNotBlank() }
                  ?: pkg
              uniqueByPackage[pkg] = InstalledAppInfo(packageName = pkg, label = label)
            }
            uniqueByPackage.values.sortedBy { it.label.lowercase() }
          }.getOrDefault(emptyList())
        }
      _installedApps.value = apps
      _isLoadingApps.value = false
    }
  }

  fun detectDeviceRam(context: Context) {
    runCatching {
      val am = context.getSystemService(Context.ACTIVITY_SERVICE) as? ActivityManager ?: return
      val memInfo = ActivityManager.MemoryInfo()
      am.getMemoryInfo(memInfo)
      val totalGb = kotlin.math.ceil(memInfo.totalMem / (1024.0 * 1024.0 * 1024.0)).toInt().coerceAtLeast(2)
      _deviceRamGb.value = totalGb
    }
  }

  fun setWorkerThreads(count: Int, onSaved: (() -> Unit)? = null) {
    val clamped = count.coerceIn(RamThreadGuide.MIN_THREADS, RamThreadGuide.MAX_THREADS)
    viewModelScope.launch {
      configRepo.setWorkerThreads(clamped)
      stateRepo.log(LogLevel.INFO, "PERF", "Worker threads updated → $clamped concurrent workers")
      onSaved?.invoke()
    }
  }

  fun setPerAppProxy(
    mode: PerAppProxyMode,
    packages: Set<String>,
    onSaved: (() -> Unit)? = null,
  ) {
    viewModelScope.launch {
      configRepo.setPerAppProxy(mode, packages)
      stateRepo.log(
        LogLevel.INFO,
        "PERAPP",
        "Per-App Proxy updated → mode=${mode.key}, selected=${packages.size}",
      )
      onSaved?.invoke()
    }
  }

  fun onWorkerUrlChange(value: String) {
    _draft.update { it.copy(workerUrl = value, isDirty = true, validationError = null) }
  }

  fun onUuidChange(value: String) {
    _draft.update { it.copy(uuid = value, isDirty = true, validationError = null) }
  }

  fun onCleanIpChange(value: String) {
    _draft.update { it.copy(cleanIp = value, isDirty = true, validationError = null) }
  }

  fun saveDraftConfig(onSaved: (() -> Unit)? = null) {
    val cur = _draft.value
    viewModelScope.launch {
      val saved =
        configRepo.updateActiveFields(
          workerUrl = cur.workerUrl,
          uuid = cur.uuid,
          cleanIp = cur.cleanIp,
        )
      lastSyncedProfileId = saved.id
      _draft.update { it.copy(profileId = saved.id, isDirty = false, validationError = null) }
      onSaved?.invoke()
    }
  }

  suspend fun validateAndSaveForConnect(
    workerRequiredMsg: String,
    uuidRequiredMsg: String,
    cleanIpRequiredMsg: String,
  ): Boolean {
    val cur = _draft.value
    val parsedUrl = WorkerProtocol.parseWorkerUrl(cur.workerUrl)
    if (parsedUrl == null) {
      _draft.update { it.copy(validationError = workerRequiredMsg) }
      return false
    }
    if (cur.uuid.isBlank()) {
      _draft.update { it.copy(validationError = uuidRequiredMsg) }
      return false
    }
    val parsedCleanIp = WorkerProtocol.parseCleanIp(cur.cleanIp)
    if (WorkerProtocol.resolveTargetIp(parsedUrl, parsedCleanIp) == null) {
      _draft.update { it.copy(validationError = cleanIpRequiredMsg) }
      return false
    }
    val saved =
      configRepo.updateActiveFields(
        workerUrl = cur.workerUrl,
        uuid = cur.uuid,
        cleanIp = cur.cleanIp,
      )
    lastSyncedProfileId = saved.id
    _draft.update { it.copy(profileId = saved.id, isDirty = false, validationError = null) }
    return true
  }

  fun testActiveWorker(
    workerRequiredMsg: String,
    uuidRequiredMsg: String,
    cleanIpRequiredMsg: String,
  ) {
    val cur = _draft.value
    val parsedUrl = WorkerProtocol.parseWorkerUrl(cur.workerUrl)
    if (parsedUrl == null) {
      _draft.update { it.copy(validationError = workerRequiredMsg) }
      return
    }
    if (cur.uuid.isBlank()) {
      _draft.update { it.copy(validationError = uuidRequiredMsg) }
      return
    }
    val parsedCleanIp = WorkerProtocol.parseCleanIp(cur.cleanIp)
    if (WorkerProtocol.resolveTargetIp(parsedUrl, parsedCleanIp) == null) {
      _draft.update { it.copy(validationError = cleanIpRequiredMsg) }
      return
    }
    viewModelScope.launch {
      val saved = configRepo.updateActiveFields(cur.workerUrl, cur.uuid, cur.cleanIp)
      lastSyncedProfileId = saved.id
      _draft.update { it.copy(profileId = saved.id, isDirty = false, validationError = null) }
      _handshakeTest.value = HandshakeTestResult(isRunning = true)

      val result = tester.testWorkerHandshake(saved)
      _handshakeTest.value = result
      if (result.success == true && result.totalRttMs != null) {
        configRepo.updateLastPing(saved.id, result.totalRttMs)
        stateRepo.updateHandshakeRtt(result.totalRttMs)
      }
    }
  }

  fun selectProfile(id: String) {
    viewModelScope.launch {
      lastSyncedProfileId = null
      _draft.update { it.copy(isDirty = false) }
      configRepo.selectProfile(id)
      _handshakeTest.value = HandshakeTestResult()
    }
  }

  fun saveProfile(
    existingId: String?,
    name: String,
    workerUrl: String,
    uuid: String,
    cleanIp: String,
    makeActive: Boolean = true,
  ) {
    viewModelScope.launch {
      val parsedHost = WorkerProtocol.parseWorkerUrl(workerUrl)?.host
      val cfg =
        VpnConfig(
          id = existingId ?: UUID.randomUUID().toString(),
          name = name.trim().ifBlank { parsedHost ?: "CloudNG Node" },
          workerUrl = workerUrl.trim(),
          uuid = uuid.trim(),
          cleanIp = cleanIp.trim(),
        )
      if (makeActive) {
        lastSyncedProfileId = null
        _draft.update { it.copy(isDirty = false) }
      }
      configRepo.saveProfile(cfg, makeActive = makeActive)
      stateRepo.log(LogLevel.INFO, "PROFILE", "Saved config '${cfg.name}'")
    }
  }

  fun deleteProfile(id: String) {
    viewModelScope.launch {
      if (lastSyncedProfileId == id) {
        lastSyncedProfileId = null
        _draft.update { it.copy(isDirty = false) }
      }
      configRepo.deleteProfile(id)
      stateRepo.log(LogLevel.INFO, "PROFILE", "Deleted config")
    }
  }

  fun importProfiles(rawText: String): Int {
    val parsedList = configRepo.parseImportBatch(rawText)
    if (parsedList.isEmpty()) return 0
    viewModelScope.launch {
      lastSyncedProfileId = null
      _draft.update { it.copy(isDirty = false, validationError = null) }
      configRepo.saveProfilesBatch(parsedList, makeFirstActive = true)
      stateRepo.log(
        LogLevel.INFO,
        "PROFILE",
        "Imported ${parsedList.size} config(s): ${parsedList.first().name}",
      )
    }
    return parsedList.size
  }

  fun exportConfigUri(config: VpnConfig): String = configRepo.exportShareUri(config)

  fun addCustomCleanIp(rawIp: String) {
    val cleaned = rawIp.trim()
    if (cleaned.isEmpty()) return
    _cleanIpResults.update { list ->
      if (list.any { it.ip.equals(cleaned, ignoreCase = true) }) list
      else listOf(CleanIpTestResult(ip = cleaned)) + list
    }
  }

  fun runCleanIpScan(workerRequiredMsg: String, uuidRequiredMsg: String) {
    val cur = _draft.value
    if (WorkerProtocol.parseWorkerUrl(cur.workerUrl) == null) {
      _draft.update { it.copy(validationError = workerRequiredMsg) }
      return
    }
    if (cur.uuid.isBlank()) {
      _draft.update { it.copy(validationError = uuidRequiredMsg) }
      return
    }
    if (_isScanningCleanIps.value) return

    viewModelScope.launch {
      _isScanningCleanIps.value = true
      val candidates = _cleanIpResults.value.map { it.ip }
      _cleanIpResults.value = candidates.map { CleanIpTestResult(ip = it, isTesting = true) }

      val concurrency = settings.value.workerThreads.coerceIn(2, 16)
      val results =
        candidates
          .chunked(concurrency)
          .flatMap { batch ->
            batch
              .map { ip ->
                async {
                  tester.benchmarkCleanIp(cur.workerUrl, cur.uuid, ip)
                }
              }
              .awaitAll()
          }
          .sortedWith(
            compareByDescending<CleanIpTestResult> { it.handshakeOk }
              .thenBy { it.latencyMs ?: Long.MAX_VALUE }
          )

      _cleanIpResults.value = results
      _isScanningCleanIps.value = false
      val best = results.firstOrNull { it.handshakeOk }
      if (best != null) {
        stateRepo.log(
          LogLevel.INFO,
          "SCAN",
          "Fastest Clean IP: ${best.ip} (${best.latencyMs}ms)",
        )
      }
    }
  }

  fun applyCleanIpToActive(ip: String) {
    viewModelScope.launch {
      val cur = _draft.value
      _draft.update { it.copy(cleanIp = ip, isDirty = false, validationError = null) }
      val saved =
        configRepo.updateActiveFields(
          workerUrl = cur.workerUrl,
          uuid = cur.uuid,
          cleanIp = ip,
        )
      lastSyncedProfileId = saved.id
      stateRepo.log(LogLevel.INFO, "CONFIG", "Applied Clean IP: $ip")
    }
  }

  fun toggleLanguage() {
    val next =
      if (settings.value.language == AppLanguage.FA) AppLanguage.EN else AppLanguage.FA
    setLanguage(next)
  }

  fun toggleThemeQuick() {
    val next =
      if (settings.value.themeMode == DarkThemeMode.DARK) DarkThemeMode.LIGHT
      else DarkThemeMode.DARK
    setThemeMode(next)
  }

  fun setLanguage(language: AppLanguage) {
    viewModelScope.launch { configRepo.setLanguage(language) }
  }

  fun setBypassLan(enabled: Boolean) {
    viewModelScope.launch { configRepo.setBypassLan(enabled) }
  }

  fun setThemeMode(mode: DarkThemeMode) {
    viewModelScope.launch { configRepo.setThemeMode(mode) }
  }

  fun clearLogs() {
    stateRepo.clearLogs()
  }

  class Factory(private val container: AppContainer) : ViewModelProvider.Factory {
    @Suppress("UNCHECKED_CAST")
    override fun <T : ViewModel> create(modelClass: Class<T>): T {
      return MainViewModel(container) as T
    }
  }
}
