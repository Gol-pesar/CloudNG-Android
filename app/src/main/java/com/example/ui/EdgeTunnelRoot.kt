package com.example.ui

import android.Manifest
import android.app.Activity
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.navigationBars
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Dns
import androidx.compose.material.icons.outlined.Shield
import androidx.compose.material.icons.outlined.Tune
import androidx.compose.material.icons.rounded.DarkMode
import androidx.compose.material.icons.rounded.Dns
import androidx.compose.material.icons.rounded.Language
import androidx.compose.material.icons.rounded.LightMode
import androidx.compose.material.icons.rounded.Shield
import androidx.compose.material.icons.rounded.Tune
import androidx.compose.material3.CenterAlignedTopAppBar
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationRail
import androidx.compose.material3.NavigationRailItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.material3.minimumInteractiveComponentSize
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.navigation.NavGraph.Companion.findStartDestination
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import com.example.model.AppLanguage
import com.example.model.DarkThemeMode
import com.example.model.VpnConfig
import com.example.model.VpnStatus
import com.example.ui.components.CloudNgBrandMark
import com.example.ui.components.QrExportDialog
import com.example.ui.components.QrScannerDialog
import com.example.ui.screens.ConnectScreen
import com.example.ui.screens.LogsSettingsScreen
import com.example.ui.screens.ProfilesScreen
import com.example.ui.strings.LocalAppStrings
import com.example.ui.strings.stringsFor
import com.example.ui.theme.CloudNgTheme
import com.example.ui.theme.SpaceGroteskFontFamily
import com.example.ui.viewmodel.MainViewModel
import com.example.vpn.WorkerVpnService
import kotlinx.coroutines.launch

const val ROUTE_CONNECT = "connect"
const val ROUTE_PROFILES = "profiles"
const val ROUTE_LOGS = "logs"

private data class NavTab(
  val route: String,
  val label: String,
  val selectedIcon: ImageVector,
  val unselectedIcon: ImageVector,
  val testTag: String,
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun EdgeTunnelRoot(viewModel: MainViewModel) {
  val context = LocalContext.current
  val clipboard = LocalClipboardManager.current
  val coroutineScope = rememberCoroutineScope()
  val snackbarHostState = remember { SnackbarHostState() }

  val settings by viewModel.settings.collectAsStateWithLifecycle()
  val activeConfig by viewModel.activeConfig.collectAsStateWithLifecycle()
  val profiles by viewModel.profiles.collectAsStateWithLifecycle()
  val draft by viewModel.draft.collectAsStateWithLifecycle()
  val telemetry by viewModel.telemetry.collectAsStateWithLifecycle()
  val elapsedSeconds by viewModel.elapsedSeconds.collectAsStateWithLifecycle()
  val handshakeTest by viewModel.handshakeTest.collectAsStateWithLifecycle()
  val cleanIpResults by viewModel.cleanIpResults.collectAsStateWithLifecycle()
  val isScanningCleanIps by viewModel.isScanningCleanIps.collectAsStateWithLifecycle()
  val logs by viewModel.logs.collectAsStateWithLifecycle()

  var qrExportTarget by remember { mutableStateOf<VpnConfig?>(null) }
  var showQrScanner by remember { mutableStateOf(false) }

  val strings = stringsFor(settings.language)
  val layoutDirection =
    if (settings.language == AppLanguage.FA) LayoutDirection.Rtl else LayoutDirection.Ltr

  val vpnPermissionLauncher =
    rememberLauncherForActivityResult(
      contract = ActivityResultContracts.StartActivityForResult(),
    ) { result ->
      if (result.resultCode == Activity.RESULT_OK) {
        WorkerVpnService.startVpn(context)
      }
    }

  val notificationPermissionLauncher =
    rememberLauncherForActivityResult(
      contract = ActivityResultContracts.RequestPermission(),
    ) { _ ->
      val prepareIntent = VpnService.prepare(context)
      if (prepareIntent != null) {
        vpnPermissionLauncher.launch(prepareIntent)
      } else {
        WorkerVpnService.startVpn(context)
      }
    }

  fun showMsg(msg: String) {
    coroutineScope.launch { snackbarHostState.showSnackbar(msg) }
  }

  fun importFromRaw(raw: String): Boolean {
    val count = viewModel.importProfiles(raw)
    if (count > 0) {
      showMsg(strings.importedCountMsg(count))
      return true
    }
    showMsg(strings.invalidConfigFormat)
    return false
  }

  fun importFromClipboard() {
    val text = clipboard.getText()?.text?.trim().orEmpty()
    if (text.isEmpty()) {
      showMsg(strings.clipboardEmpty)
    } else {
      importFromRaw(text)
    }
  }

  fun exportToClipboard(config: VpnConfig) {
    val uri = viewModel.exportConfigUri(config)
    clipboard.setText(AnnotatedString(uri))
    showMsg(strings.copiedToClipboard)
  }

  fun startOrStopVpn() {
    val currentStatus = telemetry.status
    if (currentStatus is VpnStatus.Connected || currentStatus is VpnStatus.Connecting) {
      WorkerVpnService.stopVpn(context)
      return
    }
    coroutineScope.launch {
      val valid =
        viewModel.validateAndSaveForConnect(
          workerRequiredMsg = strings.workerRequiredError,
          uuidRequiredMsg = strings.uuidRequiredError,
        )
      if (!valid) return@launch

      if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
        val granted =
          ContextCompat.checkSelfPermission(
            context,
            Manifest.permission.POST_NOTIFICATIONS,
          ) == PackageManager.PERMISSION_GRANTED
        if (!granted) {
          notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
          return@launch
        }
      }

      val prepareIntent = VpnService.prepare(context)
      if (prepareIntent != null) {
        vpnPermissionLauncher.launch(prepareIntent)
      } else {
        WorkerVpnService.startVpn(context)
      }
    }
  }

  val isDarkEffective =
    when (settings.themeMode) {
      DarkThemeMode.DARK -> true
      DarkThemeMode.LIGHT -> false
      DarkThemeMode.SYSTEM -> isSystemInDarkTheme()
    }

  CloudNgTheme(themeMode = settings.themeMode) {
    CompositionLocalProvider(
      LocalAppStrings provides strings,
      LocalLayoutDirection provides layoutDirection,
    ) {
      val navController = rememberNavController()
      val backStackEntry by navController.currentBackStackEntryAsState()
      val currentRoute = backStackEntry?.destination?.route ?: ROUTE_CONNECT

      val tabs =
        listOf(
          NavTab(
            route = ROUTE_CONNECT,
            label = strings.navConnect,
            selectedIcon = Icons.Rounded.Shield,
            unselectedIcon = Icons.Outlined.Shield,
            testTag = "nav_connect",
          ),
          NavTab(
            route = ROUTE_PROFILES,
            label = strings.navProfiles,
            selectedIcon = Icons.Rounded.Dns,
            unselectedIcon = Icons.Outlined.Dns,
            testTag = "nav_profiles",
          ),
          NavTab(
            route = ROUTE_LOGS,
            label = strings.navLogs,
            selectedIcon = Icons.Rounded.Tune,
            unselectedIcon = Icons.Outlined.Tune,
            testTag = "nav_logs",
          ),
        )

      fun navigateTab(route: String) {
        navController.navigate(route) {
          popUpTo(navController.graph.findStartDestination().id) { saveState = true }
          launchSingleTop = true
          restoreState = true
        }
      }

      BoxWithConstraints(modifier = Modifier.fillMaxSize()) {
        val useRail = maxWidth >= 680.dp

        Scaffold(
          containerColor = MaterialTheme.colorScheme.background,
          snackbarHost = { SnackbarHost(snackbarHostState) },
          topBar = {
            CenterAlignedTopAppBar(
              navigationIcon = {
                IconButton(
                  onClick = { viewModel.toggleThemeQuick() },
                  modifier = Modifier.minimumInteractiveComponentSize().testTag("theme_quick_toggle"),
                ) {
                  Icon(
                    imageVector = if (isDarkEffective) Icons.Rounded.LightMode else Icons.Rounded.DarkMode,
                    contentDescription = strings.toggleThemeDesc,
                    tint = MaterialTheme.colorScheme.primary,
                  )
                }
              },
              title = {
                Row(
                  verticalAlignment = Alignment.CenterVertically,
                  horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                  CloudNgBrandMark(size = 24.dp)
                  Text(
                    text = strings.appTitle,
                    style = MaterialTheme.typography.titleLarge.copy(
                      fontFamily = SpaceGroteskFontFamily,
                    ),
                  )
                }
              },
              actions = {
                FilledTonalButton(
                  onClick = { viewModel.toggleLanguage() },
                  modifier =
                    Modifier
                      .padding(end = 8.dp)
                      .minimumInteractiveComponentSize()
                      .testTag("language_toggle_button"),
                ) {
                  Icon(
                    imageVector = Icons.Rounded.Language,
                    contentDescription = strings.languageLabel,
                    modifier = Modifier.size(16.dp),
                  )
                  Spacer(modifier = Modifier.width(6.dp))
                  Text(
                    text = if (settings.language == AppLanguage.FA) "EN" else "FA",
                    style = MaterialTheme.typography.labelMedium,
                  )
                }
              },
              colors =
                TopAppBarDefaults.centerAlignedTopAppBarColors(
                  containerColor = MaterialTheme.colorScheme.background,
                ),
            )
          },
          bottomBar = {
            if (!useRail) {
              NavigationBar(
                containerColor = MaterialTheme.colorScheme.surface,
                windowInsets = WindowInsets.navigationBars,
              ) {
                tabs.forEach { tab ->
                  val selected = currentRoute == tab.route
                  NavigationBarItem(
                    selected = selected,
                    onClick = { navigateTab(tab.route) },
                    icon = {
                      Icon(
                        imageVector = if (selected) tab.selectedIcon else tab.unselectedIcon,
                        contentDescription = tab.label,
                      )
                    },
                    label = { Text(tab.label, maxLines = 1) },
                    modifier = Modifier.testTag(tab.testTag),
                  )
                }
              }
            }
          },
        ) { innerPadding ->
          Row(
            modifier = Modifier.fillMaxSize().padding(innerPadding),
          ) {
            if (useRail) {
              NavigationRail(
                containerColor = MaterialTheme.colorScheme.surface,
                modifier = Modifier.fillMaxHeight(),
              ) {
                tabs.forEach { tab ->
                  val selected = currentRoute == tab.route
                  NavigationRailItem(
                    selected = selected,
                    onClick = { navigateTab(tab.route) },
                    icon = {
                      Icon(
                        imageVector = if (selected) tab.selectedIcon else tab.unselectedIcon,
                        contentDescription = tab.label,
                      )
                    },
                    label = { Text(tab.label) },
                    modifier = Modifier.testTag(tab.testTag),
                  )
                }
              }
            }

            Box(modifier = Modifier.weight(1f).fillMaxHeight()) {
              NavHost(
                navController = navController,
                startDestination = ROUTE_CONNECT,
              ) {
                composable(ROUTE_CONNECT) {
                  ConnectScreen(
                    activeConfig = activeConfig,
                    draft = draft,
                    telemetry = telemetry,
                    elapsedSeconds = elapsedSeconds,
                    handshakeTest = handshakeTest,
                    onWorkerUrlChange = viewModel::onWorkerUrlChange,
                    onUuidChange = viewModel::onUuidChange,
                    onCleanIpChange = viewModel::onCleanIpChange,
                    onSaveConfig = {
                      viewModel.saveDraftConfig {
                        showMsg(strings.configSaved)
                      }
                    },
                    onTestWorker = {
                      viewModel.testActiveWorker(
                        workerRequiredMsg = strings.workerRequiredError,
                        uuidRequiredMsg = strings.uuidRequiredError,
                      )
                    },
                    onToggleVpn = { startOrStopVpn() },
                    onOpenCleanIpScanner = { navigateTab(ROUTE_PROFILES) },
                    onImportClipboard = { importFromClipboard() },
                    onOpenQrScanner = { showQrScanner = true },
                    onExportClipboard = { exportToClipboard(it) },
                    onExportQr = { qrExportTarget = it },
                  )
                }

                composable(ROUTE_PROFILES) {
                  ProfilesScreen(
                    profiles = profiles,
                    activeProfileId = activeConfig?.id,
                    cleanIpResults = cleanIpResults,
                    isScanningCleanIps = isScanningCleanIps,
                    onSelectProfile = viewModel::selectProfile,
                    onSaveProfile = { id, name, workerUrl, uuid, cleanIp ->
                      viewModel.saveProfile(id, name, workerUrl, uuid, cleanIp)
                    },
                    onDeleteProfile = viewModel::deleteProfile,
                    onImportText = viewModel::importProfiles,
                    onImportFromClipboard = { importFromClipboard() },
                    onOpenQrScanner = { showQrScanner = true },
                    onExportClipboard = { exportToClipboard(it) },
                    onExportQr = { qrExportTarget = it },
                    onScanCleanIps = {
                      viewModel.runCleanIpScan(
                        workerRequiredMsg = strings.workerRequiredError,
                        uuidRequiredMsg = strings.uuidRequiredError,
                      )
                    },
                    onAddCustomCleanIp = viewModel::addCustomCleanIp,
                    onApplyCleanIp = viewModel::applyCleanIpToActive,
                    onShowMessage = { msg -> showMsg(msg) },
                  )
                }

                composable(ROUTE_LOGS) {
                  LogsSettingsScreen(
                    settings = settings,
                    logs = logs,
                    onLanguageChange = viewModel::setLanguage,
                    onDnsChange = viewModel::setDnsServer,
                    onBypassLanChange = viewModel::setBypassLan,
                    onThemeChange = viewModel::setThemeMode,
                    onClearLogs = viewModel::clearLogs,
                    onShowMessage = { msg -> showMsg(msg) },
                  )
                }
              }
            }
          }
        }
      }

      qrExportTarget?.let { target ->
        val shareUri = remember(target) { viewModel.exportConfigUri(target) }
        QrExportDialog(
          profile = target,
          shareUri = shareUri,
          onCopyUri = { exportToClipboard(target) },
          onDismiss = { qrExportTarget = null },
        )
      }

      if (showQrScanner) {
        QrScannerDialog(
          onScannedText = { decoded ->
            showQrScanner = false
            importFromRaw(decoded)
          },
          onPasteClipboard = {
            showQrScanner = false
            importFromClipboard()
          },
          onScanFailed = { err -> showMsg(err) },
          onDismiss = { showQrScanner = false },
        )
      }
    }
  }
}
