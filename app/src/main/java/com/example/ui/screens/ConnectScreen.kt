package com.example.ui.screens

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Apps
import androidx.compose.material.icons.rounded.ArrowDownward
import androidx.compose.material.icons.rounded.ArrowUpward
import androidx.compose.material.icons.rounded.CheckCircle
import androidx.compose.material.icons.rounded.Clear
import androidx.compose.material.icons.rounded.CloudQueue
import androidx.compose.material.icons.rounded.ContentCopy
import androidx.compose.material.icons.rounded.ContentPaste
import androidx.compose.material.icons.rounded.Dns
import androidx.compose.material.icons.rounded.ErrorOutline
import androidx.compose.material.icons.rounded.Hub
import androidx.compose.material.icons.rounded.Key
import androidx.compose.material.icons.rounded.Link
import androidx.compose.material.icons.rounded.QrCode2
import androidx.compose.material.icons.rounded.QrCodeScanner
import androidx.compose.material.icons.rounded.Save
import androidx.compose.material.icons.rounded.Speed
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.minimumInteractiveComponentSize
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp
import com.example.model.AppSettings
import com.example.model.HandshakeTestResult
import com.example.model.VpnConfig
import com.example.model.VpnTelemetry
import com.example.protocol.WorkerProtocol
import com.example.ui.components.ConnectionOrb
import com.example.ui.components.formatBytes
import com.example.ui.components.formatRate
import com.example.ui.strings.LocalAppStrings
import com.example.ui.theme.JetBrainsMonoFontFamily
import com.example.ui.viewmodel.DraftFieldsState

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun ConnectScreen(
  activeConfig: VpnConfig?,
  settings: AppSettings,
  draft: DraftFieldsState,
  telemetry: VpnTelemetry,
  elapsedSeconds: Long,
  handshakeTest: HandshakeTestResult,
  onWorkerUrlChange: (String) -> Unit,
  onUuidChange: (String) -> Unit,
  onCleanIpChange: (String) -> Unit,
  onSaveConfig: () -> Unit,
  onTestWorker: () -> Unit,
  onToggleVpn: () -> Unit,
  onOpenCleanIpScanner: () -> Unit,
  onOpenPerAppProxy: () -> Unit,
  onOpenWorkerThreads: () -> Unit,
  onImportClipboard: () -> Unit,
  onOpenQrScanner: () -> Unit,
  onExportClipboard: (VpnConfig) -> Unit,
  onExportQr: (VpnConfig) -> Unit,
  modifier: Modifier = Modifier,
) {
  BoxWithConstraints(
    modifier = modifier.fillMaxSize(),
  ) {
    val isWide = maxWidth >= 720.dp
    val scrollState = rememberScrollState()

    if (isWide) {
      Row(
        modifier =
          Modifier
            .fillMaxSize()
            .verticalScroll(scrollState)
            .padding(horizontal = 24.dp, vertical = 16.dp),
        horizontalArrangement = Arrangement.spacedBy(24.dp),
        verticalAlignment = Alignment.Top,
      ) {
        Column(
          modifier = Modifier.weight(1f),
          horizontalAlignment = Alignment.CenterHorizontally,
          verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
          ActiveProfileBar(
            activeConfig = activeConfig,
            onImportClipboard = onImportClipboard,
            onOpenQrScanner = onOpenQrScanner,
            onExportClipboard = onExportClipboard,
            onExportQr = onExportQr,
          )
          FlowRow(
            horizontalArrangement = Arrangement.spacedBy(8.dp, Alignment.CenterHorizontally),
            verticalArrangement = Arrangement.spacedBy(8.dp),
          ) {
            PerAppQuickPill(
              settings = settings,
              onClick = onOpenPerAppProxy,
            )
            WorkerThreadsQuickPill(
              threadCount = settings.workerThreads,
              onClick = onOpenWorkerThreads,
            )
          }
          ConnectionOrb(
            status = telemetry.status,
            elapsedSeconds = elapsedSeconds,
            onClick = onToggleVpn,
          )
          TelemetryGrid(telemetry = telemetry)
        }

        Column(
          modifier = Modifier.weight(1.15f),
          verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
          WorkerVariablesCard(
            draft = draft,
            onWorkerUrlChange = onWorkerUrlChange,
            onUuidChange = onUuidChange,
            onCleanIpChange = onCleanIpChange,
            onSaveConfig = onSaveConfig,
            onTestWorker = onTestWorker,
            onOpenCleanIpScanner = onOpenCleanIpScanner,
            handshakeTest = handshakeTest,
          )
        }
      }
    } else {
      Column(
        modifier =
          Modifier
            .fillMaxSize()
            .verticalScroll(scrollState)
            .padding(horizontal = 16.dp, vertical = 12.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(16.dp),
      ) {
        ActiveProfileBar(
          activeConfig = activeConfig,
          onImportClipboard = onImportClipboard,
          onOpenQrScanner = onOpenQrScanner,
          onExportClipboard = onExportClipboard,
          onExportQr = onExportQr,
          modifier = Modifier.widthIn(max = 560.dp),
        )

        FlowRow(
          horizontalArrangement = Arrangement.spacedBy(8.dp, Alignment.CenterHorizontally),
          verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
          PerAppQuickPill(
            settings = settings,
            onClick = onOpenPerAppProxy,
          )
          WorkerThreadsQuickPill(
            threadCount = settings.workerThreads,
            onClick = onOpenWorkerThreads,
          )
        }

        ConnectionOrb(
          status = telemetry.status,
          elapsedSeconds = elapsedSeconds,
          onClick = onToggleVpn,
        )

        TelemetryGrid(
          telemetry = telemetry,
          modifier = Modifier.widthIn(max = 560.dp),
        )

        WorkerVariablesCard(
          draft = draft,
          onWorkerUrlChange = onWorkerUrlChange,
          onUuidChange = onUuidChange,
          onCleanIpChange = onCleanIpChange,
          onSaveConfig = onSaveConfig,
          onTestWorker = onTestWorker,
          onOpenCleanIpScanner = onOpenCleanIpScanner,
          handshakeTest = handshakeTest,
          modifier = Modifier.widthIn(max = 560.dp),
        )

        Spacer(modifier = Modifier.height(12.dp))
      }
    }
  }
}

@Composable
private fun WorkerThreadsQuickPill(
  threadCount: Int,
  onClick: () -> Unit,
) {
  val strings = LocalAppStrings.current
  Surface(
    onClick = onClick,
    color = MaterialTheme.colorScheme.surface,
    shape = MaterialTheme.shapes.extraLarge,
    border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant),
    modifier = Modifier.testTag("connect_worker_threads_pill"),
  ) {
    Row(
      modifier = Modifier.padding(horizontal = 14.dp, vertical = 8.dp),
      verticalAlignment = Alignment.CenterVertically,
      horizontalArrangement = Arrangement.spacedBy(6.dp),
    ) {
      Icon(
        imageVector = Icons.Rounded.Speed,
        contentDescription = strings.workerThreadsTitle,
        tint = MaterialTheme.colorScheme.secondary,
        modifier = Modifier.size(16.dp),
      )
      Text(
        text = strings.workerThreadsShortPill(threadCount),
        style = MaterialTheme.typography.labelMedium,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        maxLines = 1,
        overflow = TextOverflow.Ellipsis,
      )
    }
  }
}

@Composable
private fun PerAppQuickPill(
  settings: AppSettings,
  onClick: () -> Unit,
) {
  val strings = LocalAppStrings.current
  Surface(
    onClick = onClick,
    color = MaterialTheme.colorScheme.surface,
    shape = MaterialTheme.shapes.extraLarge,
    border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant),
    modifier = Modifier.testTag("connect_per_app_pill"),
  ) {
    Row(
      modifier = Modifier.padding(horizontal = 14.dp, vertical = 8.dp),
      verticalAlignment = Alignment.CenterVertically,
      horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
      Icon(
        imageVector = Icons.Rounded.Apps,
        contentDescription = strings.perAppProxyTitle,
        tint = MaterialTheme.colorScheme.primary,
        modifier = Modifier.size(16.dp),
      )
      Text(
        text = strings.perAppSummary(settings.perAppMode, settings.perAppPackages.size),
        style = MaterialTheme.typography.labelMedium,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        maxLines = 1,
        overflow = TextOverflow.Ellipsis,
      )
    }
  }
}

@Composable
private fun ActiveProfileBar(
  activeConfig: VpnConfig?,
  onImportClipboard: () -> Unit,
  onOpenQrScanner: () -> Unit,
  onExportClipboard: (VpnConfig) -> Unit,
  onExportQr: (VpnConfig) -> Unit,
  modifier: Modifier = Modifier,
) {
  val strings = LocalAppStrings.current
  if (activeConfig == null) {
    Surface(
      color = MaterialTheme.colorScheme.surfaceVariant,
      shape = MaterialTheme.shapes.large,
      border = BorderStroke(1.dp, MaterialTheme.colorScheme.primary.copy(alpha = 0.45f)),
      modifier = modifier.fillMaxWidth(),
    ) {
      Column(
        modifier = Modifier.padding(14.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp),
      ) {
        Text(
          text = strings.noConfigTitle,
          style = MaterialTheme.typography.titleSmall.copy(fontWeight = FontWeight.Bold),
          color = MaterialTheme.colorScheme.onSurface,
        )
        Text(
          text = strings.noConfigSubtitle,
          style = MaterialTheme.typography.bodySmall,
          color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Row(
          modifier = Modifier.fillMaxWidth(),
          horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
          FilledTonalButton(
            onClick = onImportClipboard,
            modifier = Modifier.weight(1f).minimumInteractiveComponentSize().testTag("quick_import_clipboard"),
          ) {
            Icon(Icons.Rounded.ContentPaste, contentDescription = null, modifier = Modifier.size(16.dp))
            Spacer(modifier = Modifier.width(6.dp))
            Text(strings.importClipboard, maxLines = 1, overflow = TextOverflow.Ellipsis)
          }
          OutlinedButton(
            onClick = onOpenQrScanner,
            modifier = Modifier.weight(1f).minimumInteractiveComponentSize().testTag("quick_import_qr"),
          ) {
            Icon(Icons.Rounded.QrCodeScanner, contentDescription = null, modifier = Modifier.size(16.dp))
            Spacer(modifier = Modifier.width(6.dp))
            Text(strings.importQr, maxLines = 1, overflow = TextOverflow.Ellipsis)
          }
        }
      }
    }
  } else {
    Surface(
      color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.85f),
      shape = MaterialTheme.shapes.extraLarge,
      border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline),
    ) {
      Row(
        modifier = Modifier.padding(start = 14.dp, end = 6.dp, top = 4.dp, bottom = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(6.dp),
      ) {
        Icon(
          imageVector = Icons.Rounded.CloudQueue,
          contentDescription = null,
          tint = MaterialTheme.colorScheme.primary,
          modifier = Modifier.size(18.dp),
        )
        Text(
          text = activeConfig.name,
          style = MaterialTheme.typography.labelLarge,
          color = MaterialTheme.colorScheme.onSurface,
          maxLines = 1,
          overflow = TextOverflow.Ellipsis,
          modifier = Modifier.widthIn(max = 170.dp),
        )
        IconButton(
          onClick = { onExportClipboard(activeConfig) },
          modifier = Modifier.minimumInteractiveComponentSize().testTag("active_copy_uri_button"),
        ) {
          Icon(
            imageVector = Icons.Rounded.ContentCopy,
            contentDescription = strings.exportConfig,
            tint = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.size(18.dp),
          )
        }
        IconButton(
          onClick = { onExportQr(activeConfig) },
          modifier = Modifier.minimumInteractiveComponentSize().testTag("active_qr_export_button"),
        ) {
          Icon(
            imageVector = Icons.Rounded.QrCode2,
            contentDescription = strings.exportQr,
            tint = MaterialTheme.colorScheme.primary,
            modifier = Modifier.size(20.dp),
          )
        }
      }
    }
  }
}

@Composable
private fun TelemetryGrid(
  telemetry: VpnTelemetry,
  modifier: Modifier = Modifier,
) {
  val strings = LocalAppStrings.current
  Column(
    modifier = modifier.fillMaxWidth(),
    verticalArrangement = Arrangement.spacedBy(10.dp),
  ) {
    Row(
      modifier = Modifier.fillMaxWidth(),
      horizontalArrangement = Arrangement.spacedBy(10.dp),
    ) {
      StatTile(
        label = strings.downloadLabel,
        value = formatBytes(telemetry.rxBytes),
        subValue = formatRate(telemetry.rxRateBps),
        icon = Icons.Rounded.ArrowDownward,
        accent = MaterialTheme.colorScheme.tertiary,
        modifier = Modifier.weight(1f),
      )
      StatTile(
        label = strings.uploadLabel,
        value = formatBytes(telemetry.txBytes),
        subValue = formatRate(telemetry.txRateBps),
        icon = Icons.Rounded.ArrowUpward,
        accent = MaterialTheme.colorScheme.primary,
        modifier = Modifier.weight(1f),
      )
    }
    Row(
      modifier = Modifier.fillMaxWidth(),
      horizontalArrangement = Arrangement.spacedBy(10.dp),
    ) {
      StatTile(
        label = strings.latencyLabel,
        value = telemetry.handshakeRttMs?.let { "$it ms" } ?: "—",
        subValue = telemetry.activeCleanIp.ifBlank { telemetry.activeWorkerHost.ifBlank { "Edge" } },
        icon = Icons.Rounded.Speed,
        accent = MaterialTheme.colorScheme.secondary,
        modifier = Modifier.weight(1f),
      )
      StatTile(
        label = strings.activeTunnelsLabel,
        value = telemetry.activeConnections.toString(),
        subValue = "TCP / DoH",
        icon = Icons.Rounded.Hub,
        accent = MaterialTheme.colorScheme.primary,
        modifier = Modifier.weight(1f),
      )
    }
  }
}

@Composable
private fun StatTile(
  label: String,
  value: String,
  subValue: String,
  icon: ImageVector,
  accent: Color,
  modifier: Modifier = Modifier,
) {
  Card(
    modifier = modifier,
    colors =
      CardDefaults.cardColors(
        containerColor = MaterialTheme.colorScheme.surface,
      ),
    elevation = CardDefaults.cardElevation(defaultElevation = 1.dp),
    border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant),
    shape = MaterialTheme.shapes.medium,
  ) {
    Column(
      modifier = Modifier.padding(12.dp),
      verticalArrangement = Arrangement.spacedBy(4.dp),
    ) {
      Row(
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(6.dp),
      ) {
        Icon(
          imageVector = icon,
          contentDescription = null,
          tint = accent,
          modifier = Modifier.size(16.dp),
        )
        Text(
          text = label,
          style = MaterialTheme.typography.labelMedium,
          color = MaterialTheme.colorScheme.onSurfaceVariant,
          maxLines = 1,
          overflow = TextOverflow.Ellipsis,
        )
      }
      CompositionLocalProvider(LocalLayoutDirection provides LayoutDirection.Ltr) {
        Text(
          text = value,
          style = MaterialTheme.typography.titleMedium.copy(
            fontFamily = JetBrainsMonoFontFamily,
            fontWeight = FontWeight.Bold,
          ),
          color = MaterialTheme.colorScheme.onSurface,
          maxLines = 1,
          overflow = TextOverflow.Ellipsis,
        )
        Text(
          text = subValue,
          style = MaterialTheme.typography.labelSmall,
          color = MaterialTheme.colorScheme.onSurfaceVariant,
          maxLines = 1,
          overflow = TextOverflow.Ellipsis,
        )
      }
    }
  }
}

@Composable
private fun WorkerVariablesCard(
  draft: DraftFieldsState,
  onWorkerUrlChange: (String) -> Unit,
  onUuidChange: (String) -> Unit,
  onCleanIpChange: (String) -> Unit,
  onSaveConfig: () -> Unit,
  onTestWorker: () -> Unit,
  onOpenCleanIpScanner: () -> Unit,
  handshakeTest: HandshakeTestResult,
  modifier: Modifier = Modifier,
) {
  val strings = LocalAppStrings.current
  val clipboard = LocalClipboardManager.current

  Card(
    modifier = modifier.fillMaxWidth(),
    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
    elevation = CardDefaults.cardElevation(defaultElevation = 1.dp),
    border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline),
    shape = MaterialTheme.shapes.large,
  ) {
    Column(
      modifier = Modifier.padding(18.dp),
      verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
      Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically,
      ) {
        Text(
          text = strings.clientVariablesTitle,
          style = MaterialTheme.typography.titleMedium,
          color = MaterialTheme.colorScheme.onSurface,
        )
        if (draft.isDirty || (draft.workerUrl.isNotBlank() && draft.profileId.isBlank())) {
          FilledTonalButton(
            onClick = onSaveConfig,
            modifier = Modifier.testTag("save_config_button"),
          ) {
            Icon(
              imageVector = Icons.Rounded.Save,
              contentDescription = strings.saveConfig,
              modifier = Modifier.size(16.dp),
            )
            Spacer(modifier = Modifier.width(6.dp))
            Text(text = strings.saveConfig, style = MaterialTheme.typography.labelMedium)
          }
        }
      }

      // 1. Worker URL
      CompositionLocalProvider(LocalLayoutDirection provides LayoutDirection.Ltr) {
        OutlinedTextField(
          value = draft.workerUrl,
          onValueChange = onWorkerUrlChange,
          label = { Text(strings.workerUrlLabel) },
          placeholder = {
            Text(
              strings.workerUrlHint,
              style = MaterialTheme.typography.bodySmall.copy(fontFamily = JetBrainsMonoFontFamily),
            )
          },
          leadingIcon = {
            Icon(
              imageVector = Icons.Rounded.Link,
              contentDescription = null,
              tint = MaterialTheme.colorScheme.primary,
            )
          },
          trailingIcon = {
            if (draft.workerUrl.isNotEmpty()) {
              IconButton(
                onClick = { onWorkerUrlChange("") },
                modifier = Modifier.minimumInteractiveComponentSize(),
              ) {
                Icon(Icons.Rounded.Clear, contentDescription = "Clear Worker URL")
              }
            } else {
              IconButton(
                onClick = {
                  clipboard.getText()?.text?.let { onWorkerUrlChange(it.trim()) }
                },
                modifier = Modifier.minimumInteractiveComponentSize(),
              ) {
                Icon(Icons.Rounded.ContentPaste, contentDescription = "Paste Worker URL")
              }
            }
          },
          singleLine = true,
          textStyle = MaterialTheme.typography.bodyMedium.copy(fontFamily = JetBrainsMonoFontFamily),
          keyboardOptions =
            KeyboardOptions(
              keyboardType = KeyboardType.Uri,
              imeAction = ImeAction.Next,
            ),
          modifier = Modifier.fillMaxWidth().testTag("worker_url_input"),
        )

        // 2. UUID
        val uuidFormatted = draft.uuid.isBlank() || WorkerProtocol.isValidUuidFormat(draft.uuid)
        OutlinedTextField(
          value = draft.uuid,
          onValueChange = onUuidChange,
          label = { Text(strings.uuidLabel) },
          placeholder = {
            Text(
              strings.uuidHint,
              style = MaterialTheme.typography.bodySmall.copy(fontFamily = JetBrainsMonoFontFamily),
            )
          },
          leadingIcon = {
            Icon(
              imageVector = Icons.Rounded.Key,
              contentDescription = null,
              tint = MaterialTheme.colorScheme.secondary,
            )
          },
          trailingIcon = {
            if (draft.uuid.isNotEmpty()) {
              IconButton(
                onClick = { onUuidChange("") },
                modifier = Modifier.minimumInteractiveComponentSize(),
              ) {
                Icon(Icons.Rounded.Clear, contentDescription = "Clear UUID")
              }
            } else {
              IconButton(
                onClick = {
                  clipboard.getText()?.text?.let { onUuidChange(it.trim()) }
                },
                modifier = Modifier.minimumInteractiveComponentSize(),
              ) {
                Icon(Icons.Rounded.ContentPaste, contentDescription = "Paste UUID")
              }
            }
          },
          supportingText =
            if (!uuidFormatted) {
              { Text("Custom token (non-standard UUID format)", color = MaterialTheme.colorScheme.secondary) }
            } else null,
          singleLine = true,
          textStyle = MaterialTheme.typography.bodyMedium.copy(fontFamily = JetBrainsMonoFontFamily),
          keyboardOptions =
            KeyboardOptions(
              keyboardType = KeyboardType.Ascii,
              imeAction = ImeAction.Next,
            ),
          modifier = Modifier.fillMaxWidth().testTag("uuid_input"),
        )

        // 3. CLEAN IP Cloudflare
        OutlinedTextField(
          value = draft.cleanIp,
          onValueChange = onCleanIpChange,
          label = { Text(strings.cleanIpLabel) },
          placeholder = {
            Text(
              strings.cleanIpHint,
              style = MaterialTheme.typography.bodySmall.copy(fontFamily = JetBrainsMonoFontFamily),
            )
          },
          leadingIcon = {
            Icon(
              imageVector = Icons.Rounded.Dns,
              contentDescription = null,
              tint = MaterialTheme.colorScheme.tertiary,
            )
          },
          trailingIcon = {
            if (draft.cleanIp.isNotEmpty()) {
              IconButton(
                onClick = { onCleanIpChange("") },
                modifier = Modifier.minimumInteractiveComponentSize(),
              ) {
                Icon(Icons.Rounded.Clear, contentDescription = "Clear Clean IP")
              }
            } else {
              IconButton(
                onClick = {
                  clipboard.getText()?.text?.let { onCleanIpChange(it.trim()) }
                },
                modifier = Modifier.minimumInteractiveComponentSize(),
              ) {
                Icon(Icons.Rounded.ContentPaste, contentDescription = "Paste Clean IP")
              }
            }
          },
          supportingText = {
            Text(
              text = strings.cleanIpHelper,
              style = MaterialTheme.typography.bodySmall,
              color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
          },
          singleLine = true,
          textStyle = MaterialTheme.typography.bodyMedium.copy(fontFamily = JetBrainsMonoFontFamily),
          keyboardOptions =
            KeyboardOptions(
              keyboardType = KeyboardType.Ascii,
              imeAction = ImeAction.Done,
            ),
          modifier = Modifier.fillMaxWidth().testTag("clean_ip_input"),
        )
      }

      AnimatedVisibility(
        visible = draft.validationError != null,
        enter = fadeIn(),
        exit = fadeOut(),
      ) {
        draft.validationError?.let { err ->
          Surface(
            color = MaterialTheme.colorScheme.errorContainer,
            shape = MaterialTheme.shapes.small,
            modifier = Modifier.fillMaxWidth(),
          ) {
            Row(
              modifier = Modifier.padding(12.dp),
              verticalAlignment = Alignment.CenterVertically,
              horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
              Icon(
                imageVector = Icons.Rounded.ErrorOutline,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.error,
              )
              Text(
                text = err,
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onErrorContainer,
              )
            }
          }
        }
      }

      Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(10.dp),
      ) {
        Button(
          onClick = onTestWorker,
          enabled = !handshakeTest.isRunning,
          colors =
            ButtonDefaults.buttonColors(
              containerColor = MaterialTheme.colorScheme.primaryContainer,
              contentColor = MaterialTheme.colorScheme.onPrimaryContainer,
            ),
          modifier = Modifier.weight(1f).minimumInteractiveComponentSize().testTag("test_worker_button"),
        ) {
          if (handshakeTest.isRunning) {
            CircularProgressIndicator(
              modifier = Modifier.size(16.dp),
              strokeWidth = 2.dp,
              color = MaterialTheme.colorScheme.onPrimaryContainer,
            )
            Spacer(modifier = Modifier.width(8.dp))
            Text(strings.testingWorker, maxLines = 1, overflow = TextOverflow.Ellipsis)
          } else {
            Icon(
              imageVector = Icons.Rounded.Speed,
              contentDescription = null,
              modifier = Modifier.size(18.dp),
            )
            Spacer(modifier = Modifier.width(6.dp))
            Text(strings.testWorkerButton, maxLines = 1, overflow = TextOverflow.Ellipsis)
          }
        }

        OutlinedButton(
          onClick = onOpenCleanIpScanner,
          modifier = Modifier.minimumInteractiveComponentSize().testTag("open_ip_scanner_button"),
        ) {
          Text("Clean IP")
        }
      }

      AnimatedVisibility(
        visible = handshakeTest.success != null,
        enter = fadeIn(),
        exit = fadeOut(),
      ) {
        val ok = handshakeTest.success == true
        val bg =
          if (ok) MaterialTheme.colorScheme.tertiaryContainer
          else MaterialTheme.colorScheme.errorContainer
        val fg =
          if (ok) MaterialTheme.colorScheme.onTertiaryContainer
          else MaterialTheme.colorScheme.onErrorContainer
        val accent =
          if (ok) MaterialTheme.colorScheme.tertiary
          else MaterialTheme.colorScheme.error

        Surface(
          color = bg,
          shape = MaterialTheme.shapes.medium,
          modifier = Modifier.fillMaxWidth(),
        ) {
          Row(
            modifier = Modifier.padding(12.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(10.dp),
          ) {
            Icon(
              imageVector = if (ok) Icons.Rounded.CheckCircle else Icons.Rounded.ErrorOutline,
              contentDescription = null,
              tint = accent,
            )
            Column(modifier = Modifier.weight(1f)) {
              Text(
                text = if (ok) strings.testPassed else strings.testFailed,
                style = MaterialTheme.typography.labelLarge,
                color = fg,
              )
              CompositionLocalProvider(LocalLayoutDirection provides LayoutDirection.Ltr) {
                val details =
                  if (ok) {
                    "WS ${handshakeTest.wsConnectMs ?: 0}ms • RTT ${handshakeTest.totalRttMs ?: 0}ms • ${handshakeTest.resolvedIp.orEmpty()} (${handshakeTest.httpStatus.orEmpty()})"
                  } else {
                    handshakeTest.errorMessage ?: "Unknown error"
                  }
                Text(
                  text = details,
                  style = MaterialTheme.typography.labelSmall,
                  color = fg.copy(alpha = 0.88f),
                )
              }
            }
          }
        }
      }
    }
  }
}
