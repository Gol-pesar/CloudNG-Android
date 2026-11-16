package com.example.ui.screens

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Apps
import androidx.compose.material.icons.rounded.ContentCopy
import androidx.compose.material.icons.rounded.DeleteSweep
import androidx.compose.material.icons.rounded.Terminal
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.minimumInteractiveComponentSize
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp
import com.example.model.AppLanguage
import com.example.model.AppSettings
import com.example.model.DarkThemeMode
import com.example.model.LogEntry
import com.example.model.LogLevel
import com.example.ui.strings.LocalAppStrings
import com.example.ui.theme.JetBrainsMonoFontFamily
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@Composable
fun LogsSettingsScreen(
  settings: AppSettings,
  logs: List<LogEntry>,
  onLanguageChange: (AppLanguage) -> Unit,
  onDnsChange: (String) -> Unit,
  onBypassLanChange: (Boolean) -> Unit,
  onOpenPerAppProxy: () -> Unit,
  onThemeChange: (DarkThemeMode) -> Unit,
  onClearLogs: () -> Unit,
  onShowMessage: (String) -> Unit,
  modifier: Modifier = Modifier,
) {
  val strings = LocalAppStrings.current
  val clipboard = LocalClipboardManager.current
  val timeFormatter = remember { SimpleDateFormat("HH:mm:ss", Locale.US) }

  LazyColumn(
    modifier = modifier.fillMaxSize(),
    contentPadding = PaddingValues(horizontal = 16.dp, vertical = 12.dp),
    verticalArrangement = Arrangement.spacedBy(14.dp),
    horizontalAlignment = Alignment.CenterHorizontally,
  ) {
    item {
      Card(
        modifier = Modifier.fillMaxWidth().widthIn(max = 680.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline),
        shape = MaterialTheme.shapes.large,
      ) {
        Column(
          modifier = Modifier.padding(16.dp),
          verticalArrangement = Arrangement.spacedBy(14.dp),
        ) {
          Text(
            text = strings.settingsTitle,
            style = MaterialTheme.typography.titleMedium,
            color = MaterialTheme.colorScheme.onSurface,
          )

          // Language
          Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Text(
              text = strings.languageLabel,
              style = MaterialTheme.typography.labelLarge,
              color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            SingleChoiceSegmentedButtonRow(modifier = Modifier.fillMaxWidth()) {
              AppLanguage.entries.forEachIndexed { index, lang ->
                SegmentedButton(
                  selected = settings.language == lang,
                  onClick = { onLanguageChange(lang) },
                  shape = SegmentedButtonDefaults.itemShape(index, AppLanguage.entries.size),
                  modifier = Modifier.testTag("lang_option_${lang.code}"),
                ) {
                  Text(lang.label)
                }
              }
            }
          }

          // DNS Server
          Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Text(
              text = strings.dnsLabel,
              style = MaterialTheme.typography.labelLarge,
              color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            val dnsChoices = listOf("1.1.1.1", "8.8.8.8", "9.9.9.9")
            CompositionLocalProvider(LocalLayoutDirection provides LayoutDirection.Ltr) {
              Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
              ) {
                dnsChoices.forEach { dns ->
                  FilterChip(
                    selected = settings.dnsServer == dns,
                    onClick = { onDnsChange(dns) },
                    label = {
                      Text(
                        text = dns,
                        style = MaterialTheme.typography.labelMedium.copy(
                          fontFamily = JetBrainsMonoFontFamily,
                        ),
                      )
                    },
                    modifier = Modifier.minimumInteractiveComponentSize().testTag("dns_chip_$dns"),
                  )
                }
              }
            }
          }

          // Bypass LAN
          Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
          ) {
            Column(modifier = Modifier.weight(1f).padding(end = 12.dp)) {
              Text(
                text = strings.bypassLanLabel,
                style = MaterialTheme.typography.bodyLarge,
                color = MaterialTheme.colorScheme.onSurface,
              )
              Text(
                text = strings.bypassLanDesc,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
              )
            }
            Switch(
              checked = settings.bypassLan,
              onCheckedChange = onBypassLanChange,
              modifier = Modifier.testTag("bypass_lan_switch"),
            )
          }

          HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)

          // Per-App Proxy
          Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
          ) {
            Column(modifier = Modifier.weight(1f).padding(end = 12.dp)) {
              Text(
                text = strings.perAppProxyTitle,
                style = MaterialTheme.typography.bodyLarge,
                color = MaterialTheme.colorScheme.onSurface,
              )
              Text(
                text = strings.perAppSummary(settings.perAppMode, settings.perAppPackages.size),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.primary,
              )
              Text(
                text = strings.perAppProxyDesc,
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
              )
            }
            OutlinedButton(
              onClick = onOpenPerAppProxy,
              modifier = Modifier.minimumInteractiveComponentSize().testTag("open_per_app_settings_button"),
            ) {
              Icon(
                imageVector = Icons.Rounded.Apps,
                contentDescription = null,
                modifier = Modifier.size(16.dp),
              )
              Spacer(modifier = Modifier.width(6.dp))
              Text(strings.perAppManageButton)
            }
          }

          // Theme
          Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Text(
              text = strings.themeLabel,
              style = MaterialTheme.typography.labelLarge,
              color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            val themes =
              listOf(
                DarkThemeMode.DARK to strings.themeDark,
                DarkThemeMode.LIGHT to strings.themeLight,
                DarkThemeMode.SYSTEM to strings.themeSystem,
              )
            SingleChoiceSegmentedButtonRow(modifier = Modifier.fillMaxWidth()) {
              themes.forEachIndexed { index, (mode, label) ->
                SegmentedButton(
                  selected = settings.themeMode == mode,
                  onClick = { onThemeChange(mode) },
                  shape = SegmentedButtonDefaults.itemShape(index, themes.size),
                  modifier = Modifier.testTag("theme_option_${mode.key}"),
                ) {
                  Text(label)
                }
              }
            }
          }
        }
      }
    }

    // Logs header
    item {
      Row(
        modifier = Modifier.fillMaxWidth().widthIn(max = 680.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically,
      ) {
        Row(
          verticalAlignment = Alignment.CenterVertically,
          horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
          Icon(
            imageVector = Icons.Rounded.Terminal,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.primary,
          )
          Text(
            text = strings.logsTitle,
            style = MaterialTheme.typography.titleMedium,
            color = MaterialTheme.colorScheme.onBackground,
          )
        }
        Row {
          IconButton(
            onClick = {
              val text =
                logs.joinToString("\n") {
                  "[${timeFormatter.format(Date(it.timestampMs))}] ${it.level}/${it.tag}: ${it.message}"
                }
              clipboard.setText(AnnotatedString(text))
              onShowMessage(strings.copiedToClipboard)
            },
            modifier = Modifier.minimumInteractiveComponentSize().testTag("copy_logs_button"),
          ) {
            Icon(Icons.Rounded.ContentCopy, contentDescription = strings.copyLogs)
          }
          IconButton(
            onClick = onClearLogs,
            modifier = Modifier.minimumInteractiveComponentSize().testTag("clear_logs_button"),
          ) {
            Icon(Icons.Rounded.DeleteSweep, contentDescription = strings.clearLogs)
          }
        }
      }
    }

    if (logs.isEmpty()) {
      item {
        Surface(
          color = MaterialTheme.colorScheme.surface,
          shape = MaterialTheme.shapes.medium,
          border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant),
          modifier = Modifier.fillMaxWidth().widthIn(max = 680.dp),
        ) {
          Column(
            modifier = Modifier.padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
          ) {
            Icon(
              imageVector = Icons.Rounded.Terminal,
              contentDescription = null,
              tint = MaterialTheme.colorScheme.onSurfaceVariant,
              modifier = Modifier.size(32.dp),
            )
            Spacer(modifier = Modifier.height(8.dp))
            Text(
              text = strings.noLogsYet,
              style = MaterialTheme.typography.bodyMedium,
              color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
          }
        }
      }
    } else {
      items(logs, key = { it.id }) { entry ->
        val levelColor =
          when (entry.level) {
            LogLevel.INFO -> MaterialTheme.colorScheme.tertiary
            LogLevel.WARN -> MaterialTheme.colorScheme.secondary
            LogLevel.ERROR -> MaterialTheme.colorScheme.error
            LogLevel.TRAFFIC -> MaterialTheme.colorScheme.primary
          }
        Surface(
          color = MaterialTheme.colorScheme.surface,
          shape = MaterialTheme.shapes.small,
          border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant),
          modifier = Modifier.fillMaxWidth().widthIn(max = 680.dp),
        ) {
          CompositionLocalProvider(LocalLayoutDirection provides LayoutDirection.Ltr) {
            Row(
              modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp),
              verticalAlignment = Alignment.Top,
              horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
              Text(
                text = timeFormatter.format(Date(entry.timestampMs)),
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
              )
              Text(
                text = entry.tag,
                style = MaterialTheme.typography.labelSmall,
                color = levelColor,
                modifier = Modifier.width(48.dp),
              )
              Text(
                text = entry.message,
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurface,
                modifier = Modifier.weight(1f),
              )
            }
          }
        }
      }
    }
  }
}
