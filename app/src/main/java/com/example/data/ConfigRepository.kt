package com.example.data

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.intPreferencesKey
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.core.stringSetPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import com.example.model.AppLanguage
import com.example.model.AppSettings
import com.example.model.DarkThemeMode
import com.example.model.PerAppProxyMode
import com.example.model.RamThreadGuide
import com.example.model.VpnConfig
import com.example.protocol.WorkerProtocol
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import org.json.JSONArray
import org.json.JSONObject
import java.net.URLEncoder
import java.util.UUID

private val Context.dataStore: DataStore<Preferences> by preferencesDataStore(name = "cloudng_prefs")

class ConfigRepository(private val context: Context) {

  private object Keys {
    val PROFILES_JSON = stringPreferencesKey("profiles_json")
    val ACTIVE_PROFILE_ID = stringPreferencesKey("active_profile_id")
    val LANGUAGE = stringPreferencesKey("language")
    val DNS_SERVER = stringPreferencesKey("dns_server")
    val BYPASS_LAN = booleanPreferencesKey("bypass_lan")
    val THEME_MODE = stringPreferencesKey("theme_mode")
    val PER_APP_MODE = stringPreferencesKey("per_app_mode")
    val PER_APP_PACKAGES = stringSetPreferencesKey("per_app_packages")
    val WORKER_THREADS = intPreferencesKey("worker_threads")
  }

  val profilesFlow: Flow<List<VpnConfig>> =
    context.dataStore.data.map { prefs ->
      val raw = prefs[Keys.PROFILES_JSON]
      if (raw.isNullOrBlank()) emptyList() else parseProfilesJson(raw)
    }

  val activeProfileIdFlow: Flow<String?> =
    context.dataStore.data.map { prefs ->
      prefs[Keys.ACTIVE_PROFILE_ID]
    }

  val activeConfigFlow: Flow<VpnConfig?> =
    context.dataStore.data.map { prefs ->
      val profiles =
        prefs[Keys.PROFILES_JSON]?.takeIf { it.isNotBlank() }?.let(::parseProfilesJson)
          ?: emptyList()
      if (profiles.isEmpty()) return@map null
      val activeId = prefs[Keys.ACTIVE_PROFILE_ID]
      profiles.firstOrNull { it.id == activeId } ?: profiles.firstOrNull()
    }

  val settingsFlow: Flow<AppSettings> =
    context.dataStore.data.map { prefs ->
      val langCode = prefs[Keys.LANGUAGE] ?: AppLanguage.FA.code
      val lang = AppLanguage.entries.firstOrNull { it.code == langCode } ?: AppLanguage.FA
      val themeKey = prefs[Keys.THEME_MODE] ?: DarkThemeMode.LIGHT.key
      val theme = DarkThemeMode.entries.firstOrNull { it.key == themeKey } ?: DarkThemeMode.LIGHT
      val perAppKey = prefs[Keys.PER_APP_MODE] ?: PerAppProxyMode.ALL.key
      val perAppMode = PerAppProxyMode.entries.firstOrNull { it.key == perAppKey } ?: PerAppProxyMode.ALL
      val perAppPackages = prefs[Keys.PER_APP_PACKAGES] ?: emptySet()
      val workerThreads =
        (prefs[Keys.WORKER_THREADS] ?: 8).coerceIn(
          RamThreadGuide.MIN_THREADS,
          RamThreadGuide.MAX_THREADS,
        )
      AppSettings(
        language = lang,
        dnsServer = prefs[Keys.DNS_SERVER] ?: "1.1.1.1",
        bypassLan = prefs[Keys.BYPASS_LAN] ?: true,
        themeMode = theme,
        perAppMode = perAppMode,
        perAppPackages = perAppPackages,
        workerThreads = workerThreads,
      )
    }

  suspend fun getActiveConfig(): VpnConfig? = activeConfigFlow.first()

  suspend fun getSettings(): AppSettings = settingsFlow.first()

  suspend fun updateActiveFields(
    workerUrl: String,
    uuid: String,
    cleanIp: String,
    name: String? = null,
  ): VpnConfig {
    var saved: VpnConfig? = null
    context.dataStore.edit { prefs ->
      val list =
        prefs[Keys.PROFILES_JSON]?.takeIf { it.isNotBlank() }?.let(::parseProfilesJson)?.toMutableList()
          ?: mutableListOf()
      if (list.isEmpty()) {
        val parsedHost = WorkerProtocol.parseWorkerUrl(workerUrl)?.host
        val newConfig =
          VpnConfig(
            id = UUID.randomUUID().toString(),
            name = name?.takeIf { it.isNotBlank() } ?: parsedHost ?: "CloudNG Node",
            workerUrl = workerUrl.trim(),
            uuid = uuid.trim(),
            cleanIp = cleanIp.trim(),
          )
        list.add(newConfig)
        prefs[Keys.PROFILES_JSON] = serializeProfilesJson(list)
        prefs[Keys.ACTIVE_PROFILE_ID] = newConfig.id
        saved = newConfig
      } else {
        val activeId = prefs[Keys.ACTIVE_PROFILE_ID] ?: list.first().id
        val idx = list.indexOfFirst { it.id == activeId }.let { if (it >= 0) it else 0 }
        val current = list[idx]
        val updated =
          current.copy(
            name = name?.takeIf { it.isNotBlank() } ?: current.name,
            workerUrl = workerUrl.trim(),
            uuid = uuid.trim(),
            cleanIp = cleanIp.trim(),
          )
        list[idx] = updated
        prefs[Keys.PROFILES_JSON] = serializeProfilesJson(list)
        prefs[Keys.ACTIVE_PROFILE_ID] = updated.id
        saved = updated
      }
    }
    return saved!!
  }

  suspend fun saveProfile(config: VpnConfig, makeActive: Boolean = true) {
    context.dataStore.edit { prefs ->
      val list =
        prefs[Keys.PROFILES_JSON]?.takeIf { it.isNotBlank() }?.let(::parseProfilesJson)?.toMutableList()
          ?: mutableListOf()
      val idx = list.indexOfFirst { it.id == config.id }
      if (idx >= 0) {
        list[idx] = config
      } else {
        list.add(config)
      }
      prefs[Keys.PROFILES_JSON] = serializeProfilesJson(list)
      if (makeActive) {
        prefs[Keys.ACTIVE_PROFILE_ID] = config.id
      }
    }
  }

  suspend fun saveProfilesBatch(configs: List<VpnConfig>, makeFirstActive: Boolean = true) {
    if (configs.isEmpty()) return
    context.dataStore.edit { prefs ->
      val list =
        prefs[Keys.PROFILES_JSON]?.takeIf { it.isNotBlank() }?.let(::parseProfilesJson)?.toMutableList()
          ?: mutableListOf()
      list.addAll(configs)
      prefs[Keys.PROFILES_JSON] = serializeProfilesJson(list)
      if (makeFirstActive) {
        prefs[Keys.ACTIVE_PROFILE_ID] = configs.first().id
      }
    }
  }

  suspend fun selectProfile(id: String) {
    context.dataStore.edit { prefs ->
      prefs[Keys.ACTIVE_PROFILE_ID] = id
    }
  }

  suspend fun deleteProfile(id: String) {
    context.dataStore.edit { prefs ->
      val list =
        prefs[Keys.PROFILES_JSON]?.takeIf { it.isNotBlank() }?.let(::parseProfilesJson)?.toMutableList()
          ?: mutableListOf()
      list.removeAll { it.id == id }
      prefs[Keys.PROFILES_JSON] = serializeProfilesJson(list)
      if (prefs[Keys.ACTIVE_PROFILE_ID] == id) {
        if (list.isNotEmpty()) {
          prefs[Keys.ACTIVE_PROFILE_ID] = list.first().id
        } else {
          prefs.remove(Keys.ACTIVE_PROFILE_ID)
        }
      }
    }
  }

  suspend fun updateLastPing(profileId: String, pingMs: Long?) {
    context.dataStore.edit { prefs ->
      val list =
        prefs[Keys.PROFILES_JSON]?.takeIf { it.isNotBlank() }?.let(::parseProfilesJson)?.toMutableList()
          ?: return@edit
      val idx = list.indexOfFirst { it.id == profileId }
      if (idx >= 0) {
        list[idx] = list[idx].copy(lastPingMs = pingMs)
        prefs[Keys.PROFILES_JSON] = serializeProfilesJson(list)
      }
    }
  }

  suspend fun setLanguage(language: AppLanguage) {
    context.dataStore.edit { it[Keys.LANGUAGE] = language.code }
  }

  suspend fun setDnsServer(dnsServer: String) {
    context.dataStore.edit { it[Keys.DNS_SERVER] = dnsServer.trim() }
  }

  suspend fun setBypassLan(enabled: Boolean) {
    context.dataStore.edit { it[Keys.BYPASS_LAN] = enabled }
  }

  suspend fun setThemeMode(mode: DarkThemeMode) {
    context.dataStore.edit { it[Keys.THEME_MODE] = mode.key }
  }

  suspend fun setPerAppProxy(mode: PerAppProxyMode, packages: Set<String>) {
    context.dataStore.edit { prefs ->
      prefs[Keys.PER_APP_MODE] = mode.key
      prefs[Keys.PER_APP_PACKAGES] = packages
    }
  }

  suspend fun setWorkerThreads(count: Int) {
    val clamped = count.coerceIn(RamThreadGuide.MIN_THREADS, RamThreadGuide.MAX_THREADS)
    context.dataStore.edit { it[Keys.WORKER_THREADS] = clamped }
  }

  fun exportShareUri(config: VpnConfig): String {
    val parsed = WorkerProtocol.parseWorkerUrl(config.workerUrl)
    val encodedCleanIp = URLEncoder.encode(config.cleanIp.trim(), "UTF-8").replace("+", "%20")
    val encodedName = URLEncoder.encode(config.name.trim(), "UTF-8").replace("+", "%20")
    return if (parsed != null) {
      val portPart = if (parsed.port != 443) ":${parsed.port}" else ""
      val pathParam =
        if (parsed.pathAndQuery.isNotBlank() && parsed.pathAndQuery != "/") {
          "&path=${URLEncoder.encode(parsed.pathAndQuery, "UTF-8")}"
        } else {
          ""
        }
      "cloudng://${config.uuid.trim()}@${parsed.host}$portPart?type=ws&cleanIp=$encodedCleanIp&subproto=chat.v2$pathParam#$encodedName"
    } else {
      val encodedWorker = URLEncoder.encode(config.workerUrl.trim(), "UTF-8")
      "edgetunnel://${config.uuid.trim()}?worker=$encodedWorker&cleanip=$encodedCleanIp#$encodedName"
    }
  }

  fun parseImportText(raw: String): VpnConfig? = parseImportBatch(raw).firstOrNull()

  fun parseImportBatch(raw: String): List<VpnConfig> {
    val text = raw.trim()
    if (text.isEmpty()) return emptyList()
    if (text.startsWith("[")) {
      return parseProfilesJson(text).map { it.copy(id = UUID.randomUUID().toString()) }
    }
    if (text.startsWith("{")) {
      return try {
        val obj = JSONObject(text)
        val worker = obj.optString("workerUrl", obj.optString("worker", ""))
        val uuid = obj.optString("uuid", "")
        if (worker.isBlank() && uuid.isBlank()) return emptyList()
        listOf(
          VpnConfig(
            id = UUID.randomUUID().toString(),
            name = obj.optString("name", "CloudNG Node").ifBlank { "CloudNG Node" },
            workerUrl = worker,
            uuid = uuid,
            cleanIp = obj.optString("cleanIp", obj.optString("cleanip", "")),
          )
        )
      } catch (_: Exception) {
        emptyList()
      }
    }

    return text
      .lines()
      .map { it.trim() }
      .filter { it.isNotEmpty() }
      .mapNotNull { line ->
        WorkerProtocol.parseShareConfigUri(line)?.let { parsed ->
          VpnConfig(
            id = UUID.randomUUID().toString(),
            name = parsed.name,
            workerUrl = parsed.workerUrl,
            uuid = parsed.uuid,
            cleanIp = parsed.cleanIp,
          )
        }
      }
  }

  private fun parseProfilesJson(raw: String): List<VpnConfig> {
    return try {
      val arr = JSONArray(raw)
      buildList {
        for (i in 0 until arr.length()) {
          val obj = arr.getJSONObject(i)
          add(
            VpnConfig(
              id = obj.optString("id", UUID.randomUUID().toString()),
              name = obj.optString("name", "CloudNG Node"),
              workerUrl = obj.optString("workerUrl", ""),
              uuid = obj.optString("uuid", ""),
              cleanIp = obj.optString("cleanIp", ""),
              dnsServer = obj.optString("dnsServer", "1.1.1.1"),
              bypassLan = obj.optBoolean("bypassLan", true),
              mtu = obj.optInt("mtu", 1400),
              lastPingMs = if (obj.has("lastPingMs") && !obj.isNull("lastPingMs")) obj.getLong("lastPingMs") else null,
            )
          )
        }
      }
    } catch (_: Exception) {
      emptyList()
    }
  }

  private fun serializeProfilesJson(list: List<VpnConfig>): String {
    val arr = JSONArray()
    for (item in list) {
      val obj = JSONObject()
      obj.put("id", item.id)
      obj.put("name", item.name)
      obj.put("workerUrl", item.workerUrl)
      obj.put("uuid", item.uuid)
      obj.put("cleanIp", item.cleanIp)
      obj.put("dnsServer", item.dnsServer)
      obj.put("bypassLan", item.bypassLan)
      obj.put("mtu", item.mtu)
      if (item.lastPingMs != null) {
        obj.put("lastPingMs", item.lastPingMs)
      }
      arr.put(obj)
    }
    return arr.toString()
  }
}
