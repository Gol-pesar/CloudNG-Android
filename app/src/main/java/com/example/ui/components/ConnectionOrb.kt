package com.example.ui.components

import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.Spring
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.spring
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.collectIsPressedAsState
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Bolt
import androidx.compose.material.icons.rounded.PowerSettingsNew
import androidx.compose.material.icons.rounded.Shield
import androidx.compose.material.icons.rounded.Sync
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.scale
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.PathEffect
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.drawscope.rotate
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.example.model.VpnStatus
import com.example.ui.strings.LocalAppStrings
import com.example.ui.theme.JetBrainsMonoFontFamily

@Composable
fun ConnectionOrb(
  status: VpnStatus,
  elapsedSeconds: Long,
  onClick: () -> Unit,
  modifier: Modifier = Modifier,
) {
  val strings = LocalAppStrings.current
  val interactionSource = remember { MutableInteractionSource() }
  val isPressed by interactionSource.collectIsPressedAsState()

  val pressScale by
    animateFloatAsState(
      targetValue = if (isPressed) 0.94f else 1f,
      animationSpec = spring(dampingRatio = Spring.DampingRatioMediumBouncy),
      label = "orbPressScale",
    )

  val accentColor by
    animateColorAsState(
      targetValue =
        when (status) {
          is VpnStatus.Connected -> MaterialTheme.colorScheme.tertiary
          is VpnStatus.Connecting, is VpnStatus.Disconnecting -> MaterialTheme.colorScheme.secondary
          is VpnStatus.Error -> MaterialTheme.colorScheme.error
          is VpnStatus.Disconnected -> MaterialTheme.colorScheme.primary
        },
      animationSpec = tween(400),
      label = "orbAccent",
    )

  val infinite = rememberInfiniteTransition(label = "orbPulse")
  val pulse by
    infinite.animateFloat(
      initialValue = 0f,
      targetValue = 1f,
      animationSpec =
        infiniteRepeatable(
          animation = tween(2200, easing = FastOutSlowInEasing),
          repeatMode = RepeatMode.Restart,
        ),
      label = "pulse",
    )

  val spin by
    infinite.animateFloat(
      initialValue = 0f,
      targetValue = 360f,
      animationSpec =
        infiniteRepeatable(
          animation = tween(3200, easing = LinearEasing),
          repeatMode = RepeatMode.Restart,
        ),
      label = "spin",
    )

  val isActive = status is VpnStatus.Connected
  val isBusy = status is VpnStatus.Connecting || status is VpnStatus.Disconnecting

  val statusLabel =
    when (status) {
      is VpnStatus.Connected -> strings.statusConnected
      is VpnStatus.Connecting -> strings.statusConnecting
      is VpnStatus.Disconnecting -> strings.statusDisconnecting
      is VpnStatus.Error -> strings.statusError
      is VpnStatus.Disconnected -> strings.statusDisconnected
    }

  val actionHint =
    when (status) {
      is VpnStatus.Connected, is VpnStatus.Connecting -> strings.tapToDisconnect
      else -> strings.tapToConnect
    }

  Column(
    horizontalAlignment = Alignment.CenterHorizontally,
    verticalArrangement = Arrangement.Center,
    modifier = modifier,
  ) {
    Box(
      contentAlignment = Alignment.Center,
      modifier = Modifier.size(216.dp),
    ) {
      Canvas(modifier = Modifier.matchParentSize()) {
        val center = Offset(size.width / 2f, size.height / 2f)
        val maxRadius = size.minDimension / 2f

        // Ambient radial glow
        drawCircle(
          brush =
            Brush.radialGradient(
              colors =
                listOf(
                  accentColor.copy(alpha = if (isActive) 0.24f else 0.12f),
                  Color.Transparent,
                ),
              center = center,
              radius = maxRadius,
            ),
          radius = maxRadius,
          center = center,
        )

        // Expanding pulse wave when connected or connecting
        if (isActive || isBusy) {
          val waveRadius = maxRadius * (0.64f + 0.34f * pulse)
          val waveAlpha = (1f - pulse) * 0.45f
          drawCircle(
            color = accentColor.copy(alpha = waveAlpha),
            radius = waveRadius,
            center = center,
            style = Stroke(width = 2.dp.toPx()),
          )
        }

        // Rotating dashed outer telemetry ring
        rotate(degrees = if (isBusy || isActive) spin else 0f, pivot = center) {
          drawCircle(
            color = accentColor.copy(alpha = if (isActive || isBusy) 0.55f else 0.22f),
            radius = maxRadius * 0.78f,
            center = center,
            style =
              Stroke(
                width = 2.dp.toPx(),
                cap = StrokeCap.Round,
                pathEffect = PathEffect.dashPathEffect(floatArrayOf(18f, 14f), 0f),
              ),
          )
        }
      }

      // Main tappable orb button (>= 48dp, here 144dp)
      Box(
        contentAlignment = Alignment.Center,
        modifier =
          Modifier
            .size(144.dp)
            .scale(pressScale)
            .clip(CircleShape)
            .background(
              brush =
                Brush.linearGradient(
                  colors =
                    listOf(
                      accentColor.copy(alpha = if (isActive) 0.26f else 0.14f),
                      MaterialTheme.colorScheme.surfaceVariant,
                    ),
                )
            )
            .border(
              width = 2.dp,
              color = accentColor.copy(alpha = 0.85f),
              shape = CircleShape,
            )
            .clickable(
              interactionSource = interactionSource,
              indication = null,
              role = Role.Button,
              onClick = onClick,
            )
            .semantics { contentDescription = "$statusLabel. $actionHint" }
            .testTag("vpn_connect_button"),
      ) {
        Column(
          horizontalAlignment = Alignment.CenterHorizontally,
          verticalArrangement = Arrangement.Center,
        ) {
          Icon(
            imageVector =
              when (status) {
                is VpnStatus.Connected -> Icons.Rounded.Shield
                is VpnStatus.Connecting, is VpnStatus.Disconnecting -> Icons.Rounded.Sync
                is VpnStatus.Error -> Icons.Rounded.Bolt
                is VpnStatus.Disconnected -> Icons.Rounded.PowerSettingsNew
              },
            contentDescription = null,
            tint = accentColor,
            modifier = Modifier.size(44.dp),
          )
          Spacer(modifier = Modifier.height(6.dp))
          if (isActive) {
            Text(
              text = formatDuration(elapsedSeconds),
              style = MaterialTheme.typography.labelLarge.copy(
                fontFamily = JetBrainsMonoFontFamily,
                fontWeight = FontWeight.Bold,
              ),
              color = MaterialTheme.colorScheme.onSurface,
            )
          } else {
            Text(
              text = if (isBusy) "..." else "CONNECT",
              style = MaterialTheme.typography.labelSmall.copy(fontWeight = FontWeight.Bold),
              color = accentColor,
            )
          }
        }
      }
    }

    Spacer(modifier = Modifier.height(8.dp))

    Surface(
      color = accentColor.copy(alpha = 0.14f),
      shape = MaterialTheme.shapes.extraLarge,
      modifier = Modifier.border(1.dp, accentColor.copy(alpha = 0.35f), MaterialTheme.shapes.extraLarge),
    ) {
      Text(
        text = statusLabel,
        style = MaterialTheme.typography.labelLarge,
        color = accentColor,
        modifier = Modifier.padding(horizontal = 16.dp, vertical = 6.dp),
      )
    }

    Spacer(modifier = Modifier.height(4.dp))

    Text(
      text =
        if (status is VpnStatus.Error) status.message
        else actionHint,
      style = MaterialTheme.typography.bodySmall,
      color =
        if (status is VpnStatus.Error) MaterialTheme.colorScheme.error
        else MaterialTheme.colorScheme.onSurfaceVariant,
    )
  }
}

fun formatDuration(seconds: Long): String {
  val h = seconds / 3600
  val m = (seconds % 3600) / 60
  val s = seconds % 60
  return if (h > 0) "%02d:%02d:%02d".format(h, m, s)
  else "%02d:%02d".format(m, s)
}

fun formatBytes(bytes: Long): String {
  if (bytes < 1024L) return "$bytes B"
  val kb = bytes / 1024.0
  if (kb < 1024.0) return "%.1f KB".format(kb)
  val mb = kb / 1024.0
  if (mb < 1024.0) return "%.2f MB".format(mb)
  val gb = mb / 1024.0
  return "%.2f GB".format(gb)
}

fun formatRate(bps: Long): String {
  if (bps < 1024L) return "$bps B/s"
  val kb = bps / 1024.0
  if (kb < 1024.0) return "%.1f KB/s".format(kb)
  return "%.2f MB/s".format(kb / 1024.0)
}
