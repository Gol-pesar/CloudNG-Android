package com.example.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Shapes
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import com.example.model.DarkThemeMode

private val CloudNgLightColorScheme =
  lightColorScheme(
    primary = PumpkinYellow,
    onPrimary = OnPumpkinDarkText,
    primaryContainer = PumpkinContainerLight,
    onPrimaryContainer = OnPumpkinContainerLight,
    secondary = PumpkinAmberDeep,
    onSecondary = Color.White,
    secondaryContainer = PumpkinSecondaryContainerLight,
    onSecondaryContainer = OnPumpkinSecondaryContainerLight,
    tertiary = ConnectedEmerald,
    onTertiary = Color.White,
    tertiaryContainer = ConnectedEmeraldContainerLight,
    onTertiaryContainer = OnConnectedEmeraldLight,
    background = CloudWhiteBg,
    onBackground = CloudInkPrimary,
    surface = CloudWhiteSurface,
    onSurface = CloudInkPrimary,
    surfaceVariant = CloudWarmAlabaster,
    onSurfaceVariant = CloudInkSecondary,
    outline = CloudOutline,
    outlineVariant = CloudOutlineVariant,
    error = CrimsonError,
    onError = Color.White,
    errorContainer = CrimsonErrorContainerLight,
    onErrorContainer = Color(0xFF7F1D1D),
  )

private val CloudNgDarkColorScheme =
  darkColorScheme(
    primary = PumpkinGlowDark,
    onPrimary = OnPumpkinDarkMode,
    primaryContainer = PumpkinContainerDark,
    onPrimaryContainer = OnPumpkinContainerDark,
    secondary = PumpkinSecondaryDark,
    onSecondary = Color(0xFF241A00),
    secondaryContainer = PumpkinSecondaryContainerDark,
    onSecondaryContainer = OnPumpkinSecondaryContainerDark,
    tertiary = ConnectedEmeraldDark,
    onTertiary = Color(0xFF032A12),
    tertiaryContainer = ConnectedEmeraldContainerDark,
    onTertiaryContainer = Color(0xFFBBF7D0),
    background = DarkCanvasBg,
    onBackground = DarkTextPrimary,
    surface = DarkSurface,
    onSurface = DarkTextPrimary,
    surfaceVariant = DarkSurfaceVariant,
    onSurfaceVariant = DarkTextSecondary,
    outline = DarkOutline,
    outlineVariant = DarkOutlineVariant,
    error = CrimsonErrorDark,
    onError = Color(0xFF450A0A),
    errorContainer = CrimsonErrorContainerDark,
    onErrorContainer = Color(0xFFFECACA),
  )

val EdgeShapes =
  Shapes(
    extraSmall = RoundedCornerShape(8.dp),
    small = RoundedCornerShape(12.dp),
    medium = RoundedCornerShape(18.dp),
    large = RoundedCornerShape(24.dp),
    extraLarge = RoundedCornerShape(32.dp),
  )

@Composable
fun CloudNgTheme(
  themeMode: DarkThemeMode = DarkThemeMode.LIGHT,
  content: @Composable () -> Unit,
) {
  val useDark =
    when (themeMode) {
      DarkThemeMode.DARK -> true
      DarkThemeMode.LIGHT -> false
      DarkThemeMode.SYSTEM -> isSystemInDarkTheme()
    }
  val colorScheme = if (useDark) CloudNgDarkColorScheme else CloudNgLightColorScheme

  MaterialTheme(
    colorScheme = colorScheme,
    typography = EdgeTypography,
    shapes = EdgeShapes,
    content = content,
  )
}
