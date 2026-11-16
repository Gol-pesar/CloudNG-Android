package com.example.ui.screens

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
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
import androidx.compose.material.icons.rounded.Add
import androidx.compose.material.icons.rounded.Check
import androidx.compose.material.icons.rounded.ContentCopy
import androidx.compose.material.icons.rounded.ContentPaste
import androidx.compose.material.icons.rounded.DeleteOutline
import androidx.compose.material.icons.rounded.Download
import androidx.compose.material.icons.rounded.Edit
import androidx.compose.material.icons.rounded.QrCode2
import androidx.compose.material.icons.rounded.QrCodeScanner
import androidx.compose.material.icons.rounded.Radar
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.minimumInteractiveComponentSize
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp
import com.example.model.CleanIpTestResult
import com.example.model.VpnConfig
import com.example.ui.components.CloudNgBrandMark
import com.example.ui.strings.LocalAppStrings
import com.example.ui.theme.JetBrainsMonoFontFamily

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun ProfilesScreen(
  profiles: List<VpnConfig>,
  activeProfileId: String?,
  cleanIpResults: List<CleanIpTestResult>,
  isScanningCleanIps: Boolean,
  onSelectProfile: (String) -> Unit,
  onSaveProfile: (id: String?, name: String, workerUrl: String, uuid: String, cleanIp: String) -> Unit,
  onDeleteProfile: (String) -> Unit,
  onImportText: (String) -> Int,
  onImportFromClipboard: () -> Unit,
  onOpenQrScanner: () -> Unit,
  onExportClipboard: (VpnConfig) -> Unit,
  onExportQr: (VpnConfig) -> Unit,
  onScanCleanIps: () -> Unit,
  onAddCustomCleanIp: (String) -> Unit,
  onApplyCleanIp: (String) -> Unit,
  onShowMessage: (String) -> Unit,
  modifier: Modifier = Modifier,
) {
  val strings = LocalAppStrings.current
  var editingProfile by remember { mutableStateOf<VpnConfig?>(null) }
  var showEditorDialog by remember { mutableStateOf(false) }
  var showImportDialog by remember { mutableStateOf(false) }
  var customIpInput by remember { mutableStateOf("") }

  LazyColumn(
    modifier = modifier.fillMaxSize(),
    contentPadding = PaddingValues(horizontal = 16.dp, vertical = 12.dp),
    verticalArrangement = Arrangement.spacedBy(12.dp),
    horizontalAlignment = Alignment.CenterHorizontally,
  ) {
    item {
      Column(
        modifier = Modifier.fillMaxWidth().widthIn(max = 680.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp),
      ) {
        Text(
          text = strings.profilesTitle,
          style = MaterialTheme.typography.titleLarge,
          color = MaterialTheme.colorScheme.onBackground,
        )

        FlowRow(
          modifier = Modifier.fillMaxWidth(),
          horizontalArrangement = Arrangement.spacedBy(8.dp),
          verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
          FilledTonalButton(
            onClick = onImportFromClipboard,
            modifier = Modifier.minimumInteractiveComponentSize().testTag("import_clipboard_button"),
          ) {
            Icon(Icons.Rounded.ContentPaste, contentDescription = null, modifier = Modifier.size(16.dp))
            Spacer(modifier = Modifier.width(6.dp))
            Text(strings.importClipboard)
          }

          FilledTonalButton(
            onClick = onOpenQrScanner,
            modifier = Modifier.minimumInteractiveComponentSize().testTag("import_qr_button"),
          ) {
            Icon(Icons.Rounded.QrCodeScanner, contentDescription = null, modifier = Modifier.size(16.dp))
            Spacer(modifier = Modifier.width(6.dp))
            Text(strings.importQr)
          }

          OutlinedButton(
            onClick = { showImportDialog = true },
            modifier = Modifier.minimumInteractiveComponentSize().testTag("import_profile_button"),
          ) {
            Icon(Icons.Rounded.Download, contentDescription = null, modifier = Modifier.size(16.dp))
            Spacer(modifier = Modifier.width(6.dp))
            Text(strings.importConfig)
          }

          Button(
            onClick = {
              editingProfile = null
              showEditorDialog = true
            },
            modifier = Modifier.minimumInteractiveComponentSize().testTag("add_profile_button"),
          ) {
            Icon(Icons.Rounded.Add, contentDescription = null, modifier = Modifier.size(18.dp))
            Spacer(modifier = Modifier.width(4.dp))
            Text(strings.addProfile)
          }
        }
      }
    }

    if (profiles.isEmpty()) {
      item {
        Card(
          modifier = Modifier.fillMaxWidth().widthIn(max = 680.dp),
          colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
          border = BorderStroke(1.dp, MaterialTheme.colorScheme.primary.copy(alpha = 0.45f)),
          shape = MaterialTheme.shapes.large,
        ) {
          Column(
            modifier = Modifier.fillMaxWidth().padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(10.dp),
          ) {
            CloudNgBrandMark(size = 48.dp)
            Text(
              text = strings.noConfigTitle,
              style = MaterialTheme.typography.titleMedium,
              color = MaterialTheme.colorScheme.onSurface,
              textAlign = TextAlign.Center,
            )
            Text(
              text = strings.noConfigSubtitle,
              style = MaterialTheme.typography.bodySmall,
              color = MaterialTheme.colorScheme.onSurfaceVariant,
              textAlign = TextAlign.Center,
            )
          }
        }
      }
    } else {
      items(profiles, key = { it.id }) { profile ->
        val isActive = profile.id == activeProfileId
        ProfileCard(
          profile = profile,
          isActive = isActive,
          onSelect = { onSelectProfile(profile.id) },
          onEdit = {
            editingProfile = profile
            showEditorDialog = true
          },
          onCopyUri = { onExportClipboard(profile) },
          onShowQr = { onExportQr(profile) },
          onDelete = { onDeleteProfile(profile.id) },
          modifier = Modifier.widthIn(max = 680.dp),
        )
      }
    }

    item {
      Spacer(modifier = Modifier.height(6.dp))
      HorizontalDivider(
        modifier = Modifier.widthIn(max = 680.dp),
        color = MaterialTheme.colorScheme.outlineVariant,
      )
      Spacer(modifier = Modifier.height(6.dp))
    }

    item {
      Card(
        modifier = Modifier.fillMaxWidth().widthIn(max = 680.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
        elevation = CardDefaults.cardElevation(defaultElevation = 1.dp),
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline),
        shape = MaterialTheme.shapes.large,
      ) {
        Column(
          modifier = Modifier.padding(16.dp),
          verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
          Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
          ) {
            Column(modifier = Modifier.weight(1f)) {
              Text(
                text = strings.cleanIpScannerTitle,
                style = MaterialTheme.typography.titleMedium,
                color = MaterialTheme.colorScheme.onSurface,
              )
              Text(
                text = strings.cleanIpScannerDesc,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
              )
            }
            Spacer(modifier = Modifier.width(8.dp))
            Button(
              onClick = onScanCleanIps,
              enabled = !isScanningCleanIps,
              modifier = Modifier.minimumInteractiveComponentSize().testTag("scan_clean_ips_button"),
            ) {
              if (isScanningCleanIps) {
                CircularProgressIndicator(
                  modifier = Modifier.size(16.dp),
                  strokeWidth = 2.dp,
                  color = MaterialTheme.colorScheme.onPrimary,
                )
                Spacer(modifier = Modifier.width(6.dp))
                Text(strings.scanningCleanIps)
              } else {
                Icon(Icons.Rounded.Radar, contentDescription = null, modifier = Modifier.size(18.dp))
                Spacer(modifier = Modifier.width(6.dp))
                Text(strings.scanCleanIps)
              }
            }
          }

          Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalAlignment = Alignment.CenterVertically,
          ) {
            CompositionLocalProvider(LocalLayoutDirection provides LayoutDirection.Ltr) {
              OutlinedTextField(
                value = customIpInput,
                onValueChange = { customIpInput = it },
                placeholder = { Text(strings.customCleanIpHint, style = MaterialTheme.typography.bodySmall) },
                singleLine = true,
                textStyle = MaterialTheme.typography.bodyMedium.copy(fontFamily = JetBrainsMonoFontFamily),
                modifier = Modifier.weight(1f).testTag("custom_clean_ip_input"),
              )
            }
            FilledTonalButton(
              onClick = {
                if (customIpInput.isNotBlank()) {
                  onAddCustomCleanIp(customIpInput)
                  customIpInput = ""
                }
              },
              modifier = Modifier.minimumInteractiveComponentSize().testTag("add_custom_ip_button"),
            ) {
              Text(strings.addCustomIp)
            }
          }

          cleanIpResults.forEach { res ->
            CleanIpRow(
              result = res,
              onApply = {
                onApplyCleanIp(res.ip)
                onShowMessage("${strings.applyCleanIp}: ${res.ip}")
              },
            )
          }
        }
      }
    }
  }

  if (showEditorDialog) {
    ProfileEditorDialog(
      initial = editingProfile,
      onDismiss = { showEditorDialog = false },
      onConfirm = { name, workerUrl, uuid, cleanIp ->
        onSaveProfile(editingProfile?.id, name, workerUrl, uuid, cleanIp)
        showEditorDialog = false
      },
    )
  }

  if (showImportDialog) {
    ImportProfileDialog(
      onDismiss = { showImportDialog = false },
      onImport = { raw ->
        val count = onImportText(raw)
        if (count > 0) {
          showImportDialog = false
          onShowMessage(strings.importedCountMsg(count))
        } else {
          onShowMessage(strings.invalidConfigFormat)
        }
      },
    )
  }
}

@Composable
private fun ProfileCard(
  profile: VpnConfig,
  isActive: Boolean,
  onSelect: () -> Unit,
  onEdit: () -> Unit,
  onCopyUri: () -> Unit,
  onShowQr: () -> Unit,
  onDelete: () -> Unit,
  modifier: Modifier = Modifier,
) {
  val strings = LocalAppStrings.current
  val borderColor =
    if (isActive) MaterialTheme.colorScheme.primary
    else MaterialTheme.colorScheme.outlineVariant

  Card(
    modifier =
      modifier
        .fillMaxWidth()
        .clickable(onClick = onSelect)
        .testTag("profile_card_${profile.id}"),
    colors =
      CardDefaults.cardColors(
        containerColor =
          if (isActive) MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.34f)
          else MaterialTheme.colorScheme.surface,
      ),
    elevation = CardDefaults.cardElevation(defaultElevation = if (isActive) 2.dp else 1.dp),
    border = BorderStroke(if (isActive) 1.5.dp else 1.dp, borderColor),
    shape = MaterialTheme.shapes.medium,
  ) {
    Column(
      modifier = Modifier.fillMaxWidth().padding(14.dp),
      verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
      Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceBetween,
      ) {
        Column(
          modifier = Modifier.weight(1f),
          verticalArrangement = Arrangement.spacedBy(4.dp),
        ) {
          Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp),
          ) {
            Text(
              text = profile.name,
              style = MaterialTheme.typography.titleMedium,
              color = MaterialTheme.colorScheme.onSurface,
              maxLines = 1,
              overflow = TextOverflow.Ellipsis,
            )
            if (isActive) {
              Surface(
                color = MaterialTheme.colorScheme.primary,
                shape = MaterialTheme.shapes.extraSmall,
              ) {
                Text(
                  text = strings.activeBadge,
                  style = MaterialTheme.typography.labelSmall,
                  color = MaterialTheme.colorScheme.onPrimary,
                  modifier = Modifier.padding(horizontal = 8.dp, vertical = 2.dp),
                )
              }
            }
            profile.lastPingMs?.let { ping ->
              Text(
                text = "${ping}ms",
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.tertiary,
              )
            }
          }
          CompositionLocalProvider(LocalLayoutDirection provides LayoutDirection.Ltr) {
            Text(
              text = profile.workerUrl.ifBlank { "Worker URL not set" },
              style = MaterialTheme.typography.bodySmall.copy(fontFamily = JetBrainsMonoFontFamily),
              color = MaterialTheme.colorScheme.onSurfaceVariant,
              maxLines = 1,
              overflow = TextOverflow.Ellipsis,
            )
            Text(
              text = "Clean IP: ${profile.cleanIp.ifBlank { "Direct DNS" }}",
              style = MaterialTheme.typography.labelSmall,
              color = MaterialTheme.colorScheme.secondary,
              maxLines = 1,
              overflow = TextOverflow.Ellipsis,
            )
          }
        }
      }

      Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.End,
        verticalAlignment = Alignment.CenterVertically,
      ) {
        IconButton(
          onClick = onShowQr,
          modifier = Modifier.minimumInteractiveComponentSize().testTag("profile_qr_${profile.id}"),
        ) {
          Icon(
            imageVector = Icons.Rounded.QrCode2,
            contentDescription = strings.exportQr,
            tint = MaterialTheme.colorScheme.primary,
          )
        }
        IconButton(
          onClick = onCopyUri,
          modifier = Modifier.minimumInteractiveComponentSize().testTag("profile_copy_${profile.id}"),
        ) {
          Icon(
            imageVector = Icons.Rounded.ContentCopy,
            contentDescription = strings.exportConfig,
            tint = MaterialTheme.colorScheme.onSurfaceVariant,
          )
        }
        IconButton(
          onClick = onEdit,
          modifier = Modifier.minimumInteractiveComponentSize().testTag("profile_edit_${profile.id}"),
        ) {
          Icon(
            imageVector = Icons.Rounded.Edit,
            contentDescription = strings.editProfile,
            tint = MaterialTheme.colorScheme.secondary,
          )
        }
        IconButton(
          onClick = onDelete,
          modifier = Modifier.minimumInteractiveComponentSize().testTag("profile_delete_${profile.id}"),
        ) {
          Icon(
            imageVector = Icons.Rounded.DeleteOutline,
            contentDescription = strings.delete,
            tint = MaterialTheme.colorScheme.error,
          )
        }
      }
    }
  }
}

@Composable
private fun CleanIpRow(
  result: CleanIpTestResult,
  onApply: () -> Unit,
) {
  val strings = LocalAppStrings.current
  Surface(
    color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.65f),
    shape = MaterialTheme.shapes.small,
    modifier = Modifier.fillMaxWidth(),
  ) {
    Row(
      modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 8.dp),
      verticalAlignment = Alignment.CenterVertically,
      horizontalArrangement = Arrangement.SpaceBetween,
    ) {
      CompositionLocalProvider(LocalLayoutDirection provides LayoutDirection.Ltr) {
        Column(modifier = Modifier.weight(1f)) {
          Text(
            text = result.ip,
            style = MaterialTheme.typography.bodyMedium.copy(
              fontFamily = JetBrainsMonoFontFamily,
              fontWeight = FontWeight.Medium,
            ),
            color = MaterialTheme.colorScheme.onSurface,
          )
          when {
            result.isTesting ->
              Text(
                text = "Testing chat.v2...",
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.secondary,
              )
            result.handshakeOk && result.latencyMs != null ->
              Text(
                text = "${result.latencyMs} ms • ACK OK",
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.tertiary,
              )
            result.error != null ->
              Text(
                text = result.error,
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.error,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
              )
          }
        }
      }

      if (result.isTesting) {
        CircularProgressIndicator(modifier = Modifier.size(20.dp), strokeWidth = 2.dp)
      } else {
        FilledTonalButton(
          onClick = onApply,
          modifier = Modifier.minimumInteractiveComponentSize(),
        ) {
          Icon(Icons.Rounded.Check, contentDescription = null, modifier = Modifier.size(16.dp))
          Spacer(modifier = Modifier.width(4.dp))
          Text(strings.applyCleanIp)
        }
      }
    }
  }
}

@Composable
private fun ProfileEditorDialog(
  initial: VpnConfig?,
  onDismiss: () -> Unit,
  onConfirm: (name: String, workerUrl: String, uuid: String, cleanIp: String) -> Unit,
) {
  val strings = LocalAppStrings.current
  var name by remember { mutableStateOf(initial?.name ?: "") }
  var workerUrl by remember { mutableStateOf(initial?.workerUrl ?: "") }
  var uuid by remember { mutableStateOf(initial?.uuid ?: "") }
  var cleanIp by remember { mutableStateOf(initial?.cleanIp ?: "") }

  AlertDialog(
    onDismissRequest = onDismiss,
    title = { Text(if (initial == null) strings.addProfile else strings.editProfile) },
    text = {
      Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
        OutlinedTextField(
          value = name,
          onValueChange = { name = it },
          label = { Text(strings.profileNameLabel) },
          placeholder = { Text("CloudNG Node") },
          singleLine = true,
          modifier = Modifier.fillMaxWidth(),
        )
        CompositionLocalProvider(LocalLayoutDirection provides LayoutDirection.Ltr) {
          OutlinedTextField(
            value = workerUrl,
            onValueChange = { workerUrl = it },
            label = { Text(strings.workerUrlLabel) },
            placeholder = { Text(strings.workerUrlHint) },
            singleLine = true,
            textStyle = MaterialTheme.typography.bodySmall.copy(fontFamily = JetBrainsMonoFontFamily),
            modifier = Modifier.fillMaxWidth(),
          )
          OutlinedTextField(
            value = uuid,
            onValueChange = { uuid = it },
            label = { Text(strings.uuidLabel) },
            placeholder = { Text(strings.uuidHint) },
            singleLine = true,
            textStyle = MaterialTheme.typography.bodySmall.copy(fontFamily = JetBrainsMonoFontFamily),
            modifier = Modifier.fillMaxWidth(),
          )
          OutlinedTextField(
            value = cleanIp,
            onValueChange = { cleanIp = it },
            label = { Text(strings.cleanIpLabel) },
            placeholder = { Text(strings.cleanIpHint) },
            singleLine = true,
            textStyle = MaterialTheme.typography.bodySmall.copy(fontFamily = JetBrainsMonoFontFamily),
            modifier = Modifier.fillMaxWidth(),
          )
        }
      }
    },
    confirmButton = {
      Button(onClick = { onConfirm(name, workerUrl, uuid, cleanIp) }) {
        Text(strings.save)
      }
    },
    dismissButton = {
      TextButton(onClick = onDismiss) {
        Text(strings.cancel)
      }
    },
  )
}

@Composable
private fun ImportProfileDialog(
  onDismiss: () -> Unit,
  onImport: (String) -> Unit,
) {
  val strings = LocalAppStrings.current
  val clipboard = LocalClipboardManager.current
  var rawText by remember { mutableStateOf("") }

  AlertDialog(
    onDismissRequest = onDismiss,
    title = { Text(strings.importConfig) },
    text = {
      Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
        CompositionLocalProvider(LocalLayoutDirection provides LayoutDirection.Ltr) {
          OutlinedTextField(
            value = rawText,
            onValueChange = { rawText = it },
            placeholder = { Text(strings.importHint) },
            minLines = 3,
            maxLines = 6,
            textStyle = MaterialTheme.typography.bodySmall.copy(fontFamily = JetBrainsMonoFontFamily),
            modifier = Modifier.fillMaxWidth(),
          )
        }
        OutlinedButton(
          onClick = {
            clipboard.getText()?.text?.let { rawText = it }
          },
          modifier = Modifier.fillMaxWidth().minimumInteractiveComponentSize(),
        ) {
          Icon(Icons.Rounded.ContentPaste, contentDescription = null, modifier = Modifier.size(16.dp))
          Spacer(modifier = Modifier.width(6.dp))
          Text(strings.importClipboard)
        }
      }
    },
    confirmButton = {
      Button(onClick = { onImport(rawText) }) {
        Text(strings.importAction)
      }
    },
    dismissButton = {
      TextButton(onClick = onDismiss) {
        Text(strings.cancel)
      }
    },
  )
}
