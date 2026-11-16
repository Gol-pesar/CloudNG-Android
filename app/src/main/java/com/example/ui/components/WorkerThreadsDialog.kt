package com.example.ui.components

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.AutoFixHigh
import androidx.compose.material.icons.rounded.CheckCircle
import androidx.compose.material.icons.rounded.Close
import androidx.compose.material.icons.rounded.Memory
import androidx.compose.material.icons.rounded.Speed
import androidx.compose.material.icons.rounded.WarningAmber
import androidx.compose.material3.Button
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Slider
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.minimumInteractiveComponentSize
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import com.example.model.AppLanguage
import com.example.model.RamThreadGuide
import com.example.ui.strings.LocalAppStrings
import com.example.ui.theme.JetBrainsMonoFontFamily
import kotlin.math.roundToInt

private data class RamGuideEntry(
  val ramLabel: String,
  val rangeFa: String,
  val rangeEn: String,
  val recommended: Int,
  val noteFa: String,
  val noteEn: String,
  val matchCheck: (Int) -> Boolean,
)

private val ramGuideEntries =
  listOf(
    RamGuideEntry(
      ramLabel = "2 GB RAM",
      rangeFa = "مجاز: ۲ تا ۴ (حداکثر ۶)",
      rangeEn = "Allowed: 2–4 (Max 6)",
      recommended = 4,
      noteFa = "جلوگیری از بسته شدن سرویس در رم پایین",
      noteEn = "Prevents OS background kill on low-RAM phones",
      matchCheck = { it <= 2 },
    ),
    RamGuideEntry(
      ramLabel = "4 GB RAM",
      rangeFa = "مجاز: ۴ تا ۸ (حداکثر ۱۰)",
      rangeEn = "Allowed: 4–8 (Max 10)",
      recommended = 6,
      noteFa = "تعادل مناسب برای وب‌گردی و مصرف پایدار",
      noteEn = "Balanced speed and stable memory usage",
      matchCheck = { it in 3..4 },
    ),
    RamGuideEntry(
      ramLabel = "6 GB RAM",
      rangeFa = "مجاز: ۸ تا ۱۲ (حداکثر ۱۶)",
      rangeEn = "Allowed: 8–12 (Max 16)",
      recommended = 10,
      noteFa = "مناسب استریم، دانلود سریع و اتصال‌های همزمان",
      noteEn = "Great for streaming and parallel downloads",
      matchCheck = { it in 5..6 },
    ),
    RamGuideEntry(
      ramLabel = "8+ GB RAM",
      rangeFa = "مجاز: ۱۲ تا ۲۴ (تا ۳۲)",
      rangeEn = "Allowed: 12–24 (Up to 32)",
      recommended = 16,
      noteFa = "حداکثر سرعت و موازی‌سازی ورکرها",
      noteEn = "Maximum concurrent Worker throughput",
      matchCheck = { it >= 7 },
    ),
  )

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun WorkerThreadsDialog(
  initialThreads: Int,
  deviceRamGb: Int,
  language: AppLanguage,
  onSave: (Int) -> Unit,
  onDismiss: () -> Unit,
) {
  val strings = LocalAppStrings.current
  val spec = remember(deviceRamGb) { RamThreadGuide.specForRamGb(deviceRamGb) }
  var selectedThreads by remember(initialThreads) {
    mutableIntStateOf(initialThreads.coerceIn(RamThreadGuide.MIN_THREADS, RamThreadGuide.MAX_THREADS))
  }
  val isOverSafeLimit = selectedThreads > spec.maxSafeThreads

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
          .heightIn(max = 700.dp),
    ) {
      Column(
        modifier = Modifier.verticalScroll(rememberScrollState()).padding(18.dp),
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
              imageVector = Icons.Rounded.Speed,
              contentDescription = null,
              tint = MaterialTheme.colorScheme.primary,
            )
            Text(
              text = strings.workerThreadsTitle,
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

        // Device RAM Banner
        Surface(
          color = MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.7f),
          shape = MaterialTheme.shapes.medium,
          modifier = Modifier.fillMaxWidth(),
        ) {
          Row(
            modifier = Modifier.padding(horizontal = 12.dp, vertical = 10.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(10.dp),
          ) {
            Icon(
              imageVector = Icons.Rounded.Memory,
              contentDescription = null,
              tint = MaterialTheme.colorScheme.primary,
            )
            Text(
              text = strings.workerThreadsDeviceRam(deviceRamGb, spec.recommendedThreads),
              style = MaterialTheme.typography.labelLarge,
              color = MaterialTheme.colorScheme.onPrimaryContainer,
              modifier = Modifier.weight(1f),
            )
          }
        }

        // Live Slider + Counter
        Surface(
          color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.55f),
          shape = MaterialTheme.shapes.large,
          border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant),
          modifier = Modifier.fillMaxWidth(),
        ) {
          Column(
            modifier = Modifier.padding(14.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
          ) {
            Row(
              modifier = Modifier.fillMaxWidth(),
              horizontalArrangement = Arrangement.SpaceBetween,
              verticalAlignment = Alignment.CenterVertically,
            ) {
              Text(
                text = strings.workerThreadsDesc,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.weight(1f).padding(end = 8.dp),
              )
              Surface(
                color = MaterialTheme.colorScheme.primary,
                shape = MaterialTheme.shapes.medium,
              ) {
                CompositionLocalProvider(LocalLayoutDirection provides LayoutDirection.Ltr) {
                  Text(
                    text = "${selectedThreads}T",
                    style = MaterialTheme.typography.titleLarge.copy(
                      fontFamily = JetBrainsMonoFontFamily,
                      fontWeight = FontWeight.Bold,
                    ),
                    color = MaterialTheme.colorScheme.onPrimary,
                    modifier = Modifier.padding(horizontal = 14.dp, vertical = 6.dp),
                  )
                }
              }
            }

            CompositionLocalProvider(LocalLayoutDirection provides LayoutDirection.Ltr) {
              Slider(
                value = selectedThreads.toFloat(),
                onValueChange = { selectedThreads = it.roundToInt() },
                valueRange = RamThreadGuide.MIN_THREADS.toFloat()..RamThreadGuide.MAX_THREADS.toFloat(),
                steps = RamThreadGuide.MAX_THREADS - RamThreadGuide.MIN_THREADS - 1,
                modifier = Modifier.fillMaxWidth().testTag("worker_threads_slider"),
              )
            }

            FlowRow(
              horizontalArrangement = Arrangement.spacedBy(8.dp),
              verticalArrangement = Arrangement.spacedBy(4.dp),
            ) {
              listOf(4, 6, 10, 16, 24).forEach { preset ->
                FilterChip(
                  selected = selectedThreads == preset,
                  onClick = { selectedThreads = preset },
                  label = {
                    Text(
                      text = "${preset}T",
                      style = MaterialTheme.typography.labelMedium.copy(fontFamily = JetBrainsMonoFontFamily),
                    )
                  },
                  modifier = Modifier.testTag("threads_preset_$preset"),
                )
              }
              OutlinedButton(
                onClick = { selectedThreads = spec.recommendedThreads },
                modifier = Modifier.minimumInteractiveComponentSize().testTag("threads_auto_button"),
              ) {
                Icon(
                  imageVector = Icons.Rounded.AutoFixHigh,
                  contentDescription = null,
                  modifier = Modifier.size(16.dp),
                )
                Spacer(modifier = Modifier.width(6.dp))
                Text(strings.workerThreadsAutoButton(spec.recommendedThreads))
              }
            }
          }
        }

        // Status Feedback (Safe vs Warning)
        Surface(
          color =
            if (isOverSafeLimit) MaterialTheme.colorScheme.errorContainer
            else MaterialTheme.colorScheme.tertiaryContainer,
          shape = MaterialTheme.shapes.medium,
          modifier = Modifier.fillMaxWidth(),
        ) {
          Row(
            modifier = Modifier.padding(horizontal = 12.dp, vertical = 9.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp),
          ) {
            Icon(
              imageVector = if (isOverSafeLimit) Icons.Rounded.WarningAmber else Icons.Rounded.CheckCircle,
              contentDescription = null,
              tint = if (isOverSafeLimit) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.tertiary,
              modifier = Modifier.size(18.dp),
            )
            Text(
              text =
                if (isOverSafeLimit) {
                  strings.workerThreadsOverLimitWarning(selectedThreads, spec.maxSafeThreads)
                } else {
                  strings.workerThreadsOptimalBadge
                },
              style = MaterialTheme.typography.labelSmall,
              color =
                if (isOverSafeLimit) MaterialTheme.colorScheme.onErrorContainer
                else MaterialTheme.colorScheme.onTertiaryContainer,
            )
          }
        }

        HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)

        // RAM Recommendation Table (2, 4, 6, 8+ GB)
        Text(
          text = strings.workerThreadsRamGuideTitle,
          style = MaterialTheme.typography.titleSmall.copy(fontWeight = FontWeight.SemiBold),
          color = MaterialTheme.colorScheme.onSurface,
        )

        Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
          ramGuideEntries.forEach { entry ->
            val isUserTier = entry.matchCheck(deviceRamGb)
            Surface(
              onClick = { selectedThreads = entry.recommended },
              color =
                if (isUserTier) MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.45f)
                else MaterialTheme.colorScheme.surface,
              border =
                BorderStroke(
                  width = if (isUserTier) 1.5.dp else 1.dp,
                  color = if (isUserTier) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.outlineVariant,
                ),
              shape = MaterialTheme.shapes.medium,
              modifier = Modifier.fillMaxWidth(),
            ) {
              Row(
                modifier = Modifier.padding(horizontal = 12.dp, vertical = 10.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween,
              ) {
                Column(modifier = Modifier.weight(1f).padding(end = 8.dp)) {
                  Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                  ) {
                    Text(
                      text = entry.ramLabel,
                      style = MaterialTheme.typography.labelLarge.copy(
                        fontFamily = JetBrainsMonoFontFamily,
                        fontWeight = FontWeight.Bold,
                      ),
                      color = if (isUserTier) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurface,
                    )
                    if (isUserTier) {
                      Surface(
                        color = MaterialTheme.colorScheme.primary,
                        shape = MaterialTheme.shapes.extraSmall,
                      ) {
                        Text(
                          text = if (language == AppLanguage.FA) "رم شما" else "Yours",
                          style = MaterialTheme.typography.labelSmall,
                          color = MaterialTheme.colorScheme.onPrimary,
                          modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp),
                        )
                      }
                    }
                  }
                  Text(
                    text = if (language == AppLanguage.FA) entry.rangeFa else entry.rangeEn,
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.onSurface,
                  )
                  Text(
                    text = if (language == AppLanguage.FA) entry.noteFa else entry.noteEn,
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                  )
                }

                Surface(
                  color = MaterialTheme.colorScheme.secondaryContainer,
                  shape = MaterialTheme.shapes.small,
                ) {
                  Text(
                    text = "${entry.recommended}T",
                    style = MaterialTheme.typography.labelLarge.copy(
                      fontFamily = JetBrainsMonoFontFamily,
                      fontWeight = FontWeight.Bold,
                    ),
                    color = MaterialTheme.colorScheme.onSecondaryContainer,
                    modifier = Modifier.padding(horizontal = 10.dp, vertical = 6.dp),
                  )
                }
              }
            }
          }
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
            onClick = { onSave(selectedThreads) },
            modifier = Modifier.minimumInteractiveComponentSize().testTag("worker_threads_save_button"),
          ) {
            Text(strings.save)
          }
        }
      }
    }
  }
}
