package com.example.ui.components

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.size
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp

/**
 * Minimalist CloudNG mark: a clean cloud silhouette cleaved down the middle
 * by a vivid pumpkin-yellow lightning bolt.
 */
@Composable
fun CloudNgBrandMark(
  size: Dp = 28.dp,
  cloudColor: Color = MaterialTheme.colorScheme.onBackground,
  boltColor: Color = MaterialTheme.colorScheme.primary,
  modifier: Modifier = Modifier,
) {
  Canvas(modifier = modifier.size(size)) {
    val sx = this.size.width / 66f
    val sy = this.size.height / 66f
    val ox = -21f
    val oy = -21f

    fun px(x: Float) = (x + ox) * sx
    fun py(y: Float) = (y + oy) * sy

    // Left cloud half
    val leftCloud =
      Path().apply {
        moveTo(px(34f), py(68f))
        cubicTo(px(26.2f), py(68f), px(21f), py(62.2f), px(21f), py(54.8f))
        cubicTo(px(21f), py(48.2f), px(25.8f), py(42.8f), px(32.4f), py(41.8f))
        cubicTo(px(34.6f), py(33.4f), px(42f), py(27.5f), px(50.6f), py(27.5f))
        cubicTo(px(52f), py(27.5f), px(53.3f), py(27.7f), px(54.5f), py(28.1f))
        lineTo(px(42.2f), py(52.6f))
        lineTo(px(50f), py(52.6f))
        lineTo(px(45.2f), py(68f))
        close()
      }

    // Right cloud half
    val rightCloud =
      Path().apply {
        moveTo(px(64.2f), py(33f))
        cubicTo(px(68.4f), py(36.2f), px(71.4f), py(40.8f), px(72.3f), py(46f))
        cubicTo(px(79.8f), py(46.5f), px(85.8f), py(51.8f), px(85.8f), py(58.5f))
        cubicTo(px(85.8f), py(64f), px(81.2f), py(68f), px(74.8f), py(68f))
        lineTo(px(57.5f), py(68f))
        lineTo(px(68.2f), py(47.2f))
        lineTo(px(60f), py(47.2f))
        close()
      }

    // Pumpkin-yellow lightning bolt
    val bolt =
      Path().apply {
        moveTo(px(60.6f), py(23.2f))
        lineTo(px(45.6f), py(51f))
        lineTo(px(54f), py(51f))
        lineTo(px(46.8f), py(82.2f))
        lineTo(px(63.6f), py(49.2f))
        lineTo(px(55.4f), py(49.2f))
        close()
      }

    drawPath(path = leftCloud, color = cloudColor)
    drawPath(path = rightCloud, color = cloudColor)
    drawPath(path = bolt, color = boltColor)
  }
}
