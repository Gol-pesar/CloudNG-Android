package com.example.ui.components

import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.drawable.BitmapDrawable
import android.graphics.drawable.Drawable
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Image
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Apps
import androidx.compose.material.icons.rounded.Clear
import androidx.compose.material.icons.rounded.Close
import androidx.compose.material.icons.rounded.Search
import androidx.compose.material.icons.rounded.VerifiedUser
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.minimumInteractiveComponentSize
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import com.example.model.InstalledAppInfo
import com.example.model.PerAppProxyMode
import com.example.ui.strings.LocalAppStrings
import com.example.ui.theme.JetBrainsMonoFontFamily

@Composable
fun PerAppProxyDialog(
  initialMode: PerAppProxyMode,
  initialPackages: Set<String>,
  installedApps: List<InstalledAppInfo>,
  isLoadingApps: Boolean,
  onRefreshApps: () -> Unit,
  onSave: (PerAppProxyMode, Set<String>) -> Unit,
  onDismiss: () -> Unit,
) {
  val strings = LocalAppStrings.current
  var selectedMode by remember(initialMode) { mutableStateOf(initialMode) }
  var selectedPackages by remember(initialPackages) { mutableStateOf(initialPackages) }
  var query by remember { mutableStateOf("") }

  LaunchedEffect(Unit) {
    if (installedApps.isEmpty()) {
      onRefreshApps()
    }
  }

  val filteredApps =
    remember(installedApps, selectedPackages, query) {
      val q = query.trim().lowercase()
      installedApps
        .asSequence()
        .filter { app ->
          q.isEmpty() ||
            app.label.lowercase().contains(q) ||
            app.packageName.lowercase().contains(q)
        }
        .sortedWith(
          compareByDescending<InstalledAppInfo> { it.packageName in selectedPackages }
            .thenBy { it.label.lowercase() }
        )
        .toList()
    }

  Dialog(
    onDismissRequest = onDismiss,
    properties = DialogProperties(usePlatformDefaultWidth = false),
  ) {
    Surface(
      shape = MaterialTheme.shapes.extraLarge,
      color = MaterialTheme.colorScheme.surface,
      border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline),
      tonalElevation = 4.dp,
      modifier =
        Modifier
          .fillMaxWidth(0.94f)
          .widthIn(max = 560.dp)
          .heightIn(max = 680.dp),
    ) {
      Column(
        modifier = Modifier.padding(18.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
      ) {
        // Header
        Row(
          modifier = Modifier.fillMaxWidth(),
          horizontalArrangement = Arrangement.SpaceBetween,
          verticalAlignment = Alignment.CenterVertically,
        ) {
          Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            modifier = Modifier.weight(1f),
          ) {
            Icon(
              imageVector = Icons.Rounded.Apps,
              contentDescription = null,
              tint = MaterialTheme.colorScheme.primary,
            )
            Text(
              text = strings.perAppProxyTitle,
              style = MaterialTheme.typography.titleMedium,
              maxLines = 1,
              overflow = TextOverflow.Ellipsis,
            )
          }
          IconButton(
            onClick = onDismiss,
            modifier = Modifier.minimumInteractiveComponentSize(),
          ) {
            Icon(Icons.Rounded.Close, contentDescription = strings.cancel)
          }
        }

        // Guaranteed self-bypass notice
        Surface(
          color = MaterialTheme.colorScheme.tertiaryContainer,
          shape = MaterialTheme.shapes.medium,
          modifier = Modifier.fillMaxWidth(),
        ) {
          Row(
            modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp),
          ) {
            Icon(
              imageVector = Icons.Rounded.VerifiedUser,
              contentDescription = null,
              tint = MaterialTheme.colorScheme.tertiary,
              modifier = Modifier.size(18.dp),
            )
            Text(
              text = strings.perAppSelfBypassNotice,
              style = MaterialTheme.typography.labelSmall,
              color = MaterialTheme.colorScheme.onTertiaryContainer,
            )
          }
        }

        // Mode switcher
        val modes =
          listOf(
            PerAppProxyMode.ALL to strings.perAppModeAll,
            PerAppProxyMode.BYPASS to strings.perAppModeBypass,
            PerAppProxyMode.ALLOW_ONLY to strings.perAppModeAllowOnly,
          )
        SingleChoiceSegmentedButtonRow(modifier = Modifier.fillMaxWidth()) {
          modes.forEachIndexed { index, (mode, label) ->
            SegmentedButton(
              selected = selectedMode == mode,
              onClick = { selectedMode = mode },
              shape = SegmentedButtonDefaults.itemShape(index, modes.size),
              modifier = Modifier.testTag("per_app_mode_${mode.key}"),
            ) {
              Text(label, maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
          }
        }

        if (selectedMode != PerAppProxyMode.ALL) {
          OutlinedTextField(
            value = query,
            onValueChange = { query = it },
            placeholder = { Text(strings.perAppSearchHint) },
            leadingIcon = { Icon(Icons.Rounded.Search, contentDescription = null) },
            trailingIcon = {
              if (query.isNotEmpty()) {
                IconButton(
                  onClick = { query = "" },
                  modifier = Modifier.minimumInteractiveComponentSize(),
                ) {
                  Icon(Icons.Rounded.Clear, contentDescription = strings.cancel)
                }
              }
            },
            singleLine = true,
            modifier = Modifier.fillMaxWidth().testTag("per_app_search_input"),
          )

          Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
          ) {
            Text(
              text = strings.perAppSelectedCount(selectedPackages.size),
              style = MaterialTheme.typography.labelMedium,
              color = MaterialTheme.colorScheme.primary,
            )
            if (selectedPackages.isNotEmpty()) {
              TextButton(
                onClick = { selectedPackages = emptySet() },
                modifier = Modifier.testTag("per_app_clear_button"),
              ) {
                Text(strings.perAppClearSelection)
              }
            }
          }

          Box(
            modifier = Modifier.fillMaxWidth().weight(1f, fill = false).heightIn(min = 180.dp, max = 330.dp),
          ) {
            when {
              isLoadingApps && installedApps.isEmpty() -> {
                Box(
                  modifier = Modifier.fillMaxWidth().height(180.dp),
                  contentAlignment = Alignment.Center,
                ) {
                  CircularProgressIndicator(modifier = Modifier.size(28.dp))
                }
              }
              filteredApps.isEmpty() -> {
                Box(
                  modifier = Modifier.fillMaxWidth().height(140.dp),
                  contentAlignment = Alignment.Center,
                ) {
                  Text(
                    text = strings.perAppNoAppsMatch,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                  )
                }
              }
              else -> {
                LazyColumn(
                  modifier = Modifier.fillMaxWidth(),
                  verticalArrangement = Arrangement.spacedBy(2.dp),
                ) {
                  items(filteredApps, key = { it.packageName }) { app ->
                    val checked = app.packageName in selectedPackages
                    AppToggleRow(
                      app = app,
                      checked = checked,
                      onToggle = {
                        selectedPackages =
                          if (checked) selectedPackages - app.packageName
                          else selectedPackages + app.packageName
                      },
                    )
                    HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.5f))
                  }
                }
              }
            }
          }
        } else {
          Spacer(modifier = Modifier.height(4.dp))
          Text(
            text = strings.perAppSummary(PerAppProxyMode.ALL, 0),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
          )
          Spacer(modifier = Modifier.height(4.dp))
        }

        // Actions
        Row(
          modifier = Modifier.fillMaxWidth(),
          horizontalArrangement = Arrangement.End,
          verticalAlignment = Alignment.CenterVertically,
        ) {
          TextButton(
            onClick = onDismiss,
            modifier = Modifier.minimumInteractiveComponentSize(),
          ) {
            Text(strings.cancel)
          }
          Button(
            onClick = { onSave(selectedMode, selectedPackages) },
            modifier = Modifier.minimumInteractiveComponentSize().testTag("per_app_save_button"),
          ) {
            Text(strings.save)
          }
        }
      }
    }
  }
}

@Composable
private fun AppToggleRow(
  app: InstalledAppInfo,
  checked: Boolean,
  onToggle: () -> Unit,
) {
  val context = LocalContext.current
  val iconBitmap =
    remember(app.packageName) {
      runCatching {
        val drawable = context.packageManager.getApplicationIcon(app.packageName)
        drawableToImageBitmap(drawable, 72)
      }.getOrNull()
    }

  Row(
    modifier =
      Modifier
        .fillMaxWidth()
        .clickable(onClick = onToggle)
        .padding(horizontal = 4.dp, vertical = 8.dp)
        .testTag("per_app_row_${app.packageName}"),
    verticalAlignment = Alignment.CenterVertically,
    horizontalArrangement = Arrangement.spacedBy(10.dp),
  ) {
    if (iconBitmap != null) {
      Image(
        bitmap = iconBitmap,
        contentDescription = app.label,
        modifier = Modifier.size(34.dp).clip(RoundedCornerShape(8.dp)),
      )
    } else {
      Surface(
        shape = RoundedCornerShape(8.dp),
        color = MaterialTheme.colorScheme.surfaceVariant,
        modifier = Modifier.size(34.dp),
      ) {
        Box(contentAlignment = Alignment.Center) {
          Icon(
            imageVector = Icons.Rounded.Apps,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.primary,
            modifier = Modifier.size(18.dp),
          )
        }
      }
    }

    Column(modifier = Modifier.weight(1f)) {
      Text(
        text = app.label,
        style = MaterialTheme.typography.bodyMedium,
        color = MaterialTheme.colorScheme.onSurface,
        maxLines = 1,
        overflow = TextOverflow.Ellipsis,
      )
      CompositionLocalProvider(LocalLayoutDirection provides LayoutDirection.Ltr) {
        Text(
          text = app.packageName,
          style = MaterialTheme.typography.labelSmall.copy(fontFamily = JetBrainsMonoFontFamily),
          color = MaterialTheme.colorScheme.onSurfaceVariant,
          maxLines = 1,
          overflow = TextOverflow.Ellipsis,
        )
      }
    }

    Checkbox(
      checked = checked,
      onCheckedChange = { onToggle() },
    )
  }
}

private fun drawableToImageBitmap(drawable: Drawable, sizePx: Int): ImageBitmap {
  if (drawable is BitmapDrawable && drawable.bitmap != null) {
    val bmp = drawable.bitmap
    return if (bmp.width > sizePx || bmp.height > sizePx) {
      Bitmap.createScaledBitmap(bmp, sizePx, sizePx, true).asImageBitmap()
    } else {
      bmp.asImageBitmap()
    }
  }
  val bitmap = Bitmap.createBitmap(sizePx, sizePx, Bitmap.Config.ARGB_8888)
  val canvas = Canvas(bitmap)
  drawable.setBounds(0, 0, canvas.width, canvas.height)
  drawable.draw(canvas)
  return bitmap.asImageBitmap()
}
