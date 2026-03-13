package com.securepasswd.mgmt.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

// Nord Dark color scheme (from dark.qss)
private val DarkColorScheme = darkColorScheme(
    primary = NordFrost1,           // #88C0D0 — progress accents
    secondary = NordFrost3,         // #5E81AC — button hover
    tertiary = NordFrost2,          // #81A1C1 — button pressed
    background = NordPolarNight0,   // #2E3440 — main background
    surface = NordPolarNight1,      // #3B4252 — cards / surfaces
    surfaceVariant = NordPolarNight2, // #434C5E — hover states
    outline = NordPolarNight3,      // #4C566A — borders / button bg
    onPrimary = NordPolarNight0,
    onSecondary = NordSnow0,
    onTertiary = NordSnow0,
    onBackground = NordSnow0,       // #D8DEE9 — text on background
    onSurface = NordSnow0,          // #D8DEE9 — text on surface
    onSurfaceVariant = NordSnow0,
)

// Light color scheme (from light.qss)
private val LightColorScheme = lightColorScheme(
    primary = LightAccent,          // #d97dbc — pink accent
    secondary = LightAccentHover,   // #c77575 — button hover
    tertiary = LightAccentPressed,  // #8b8484 — button pressed
    background = LightBg,           // #ECEFF4 — main background
    surface = LightSurface,         // #FFFFFF — cards / surfaces
    surfaceVariant = NordSnow1,     // #E5E9F0 — hover states
    outline = NordSnow0,            // #D8DEE9 — borders
    onPrimary = Color.White,
    onSecondary = Color.White,
    onTertiary = Color.White,
    onBackground = LightText,       // #434343 — text on background
    onSurface = LightText,          // #434343 — text on surface
    onSurfaceVariant = LightText,
)

@Composable
fun SecurePasswdTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    content: @Composable () -> Unit
) {
    val colorScheme = if (darkTheme) DarkColorScheme else LightColorScheme

    MaterialTheme(
        colorScheme = colorScheme,
        typography = Typography,
        content = content
    )
}
