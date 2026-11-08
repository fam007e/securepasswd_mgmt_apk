package com.securepasswd.mgmt.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Shapes
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp

// Nord Dark color scheme (default — mirrors desktop dark.qss tokens)
private val NordDarkColorScheme = darkColorScheme(
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

// Nord Light color scheme (Snow Storm + app-icon accent)
private val NordLightColorScheme = lightColorScheme(
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

// Dracula Dark color scheme
private val DraculaDarkColorScheme = darkColorScheme(
    primary = DraculaPrimary,            // #BD93F9
    secondary = DraculaPrimaryHover,     // #9D7BE8
    tertiary = DraculaPrimaryActive,     // #6272A4
    background = DraculaBg,              // #282A36
    surface = DraculaSurface,            // #343746
    surfaceVariant = DraculaSurfaceVariant,
    outline = DraculaOutline,            // #44475A
    onPrimary = DraculaBg,
    onSecondary = DraculaBg,
    onTertiary = DraculaText,
    onBackground = DraculaText,          // #F8F8F2
    onSurface = DraculaText,
    onSurfaceVariant = DraculaText,
)

// Dracula Light ("Dracula Paper") color scheme
private val DraculaLightColorScheme = lightColorScheme(
    primary = DraculaLightPrimary,       // #6C4FC4
    secondary = DraculaLightPrimaryHover,
    tertiary = DraculaOutline,
    background = DraculaLightBg,         // #F8F8F2
    surface = DraculaLightSurface,       // #FFFFFF
    surfaceVariant = DraculaLightSurfaceVariant,
    outline = DraculaLightOutline,
    onPrimary = Color.White,
    onSecondary = Color.White,
    onTertiary = DraculaLightBg,
    onBackground = DraculaLightText,     // #3B3D4E
    onSurface = DraculaLightText,
    onSurfaceVariant = DraculaLightText,
)

// Solarized Dark color scheme
private val SolarDarkColorScheme = darkColorScheme(
    primary = SolarPrimary,              // #268BD2
    secondary = SolarPrimaryHover,
    tertiary = SolarPrimaryActive,
    background = SolarBg,                // #002B36
    surface = SolarSurface,              // #073642
    surfaceVariant = SolarSurfaceVariant,
    outline = SolarOutline,              // #586E75
    onPrimary = SolarBg,
    onSecondary = SolarBg,
    onTertiary = SolarBg,
    onBackground = SolarText,            // #93A1A1
    onSurface = SolarText,
    onSurfaceVariant = SolarText,
)

// Solarized Light color scheme
private val SolarLightColorScheme = lightColorScheme(
    primary = SolarPrimary,              // #268BD2
    secondary = SolarPrimaryHover,
    tertiary = SolarPrimaryActive,
    background = SolarLightBg,           // #FDF6E3
    surface = SolarLightSurface,         // #EEE8D5
    surfaceVariant = SolarLightSurfaceVariant,
    outline = SolarOutline,
    onPrimary = SolarLightBg,
    onSecondary = SolarLightBg,
    onTertiary = SolarLightBg,
    onBackground = SolarLightText,       // #586E75
    onSurface = SolarLightText,
    onSurfaceVariant = SolarLightText,
)

/** Stable palette ids, mirrored by the desktop palette registry (themes.cpp). */
object Palettes {
    const val NORD = "nord"
    const val DRACULA = "dracula"
    const val SOLARIZED = "solarized"
    val ALL = listOf(NORD, DRACULA, SOLARIZED)
}

private fun colorSchemeFor(palette: String, dark: Boolean) = when (palette) {
    Palettes.DRACULA -> if (dark) DraculaDarkColorScheme else DraculaLightColorScheme
    Palettes.SOLARIZED -> if (dark) SolarDarkColorScheme else SolarLightColorScheme
    else -> if (dark) NordDarkColorScheme else NordLightColorScheme
}

@Composable
fun SecurePasswdTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    palette: String = Palettes.NORD,
    content: @Composable () -> Unit
) {
    val colorScheme = colorSchemeFor(palette, darkTheme)

    // Corner radii mirror the desktop QSS tokens (docs/DESIGN_TOKENS.md):
    // controls 8dp, cards/sheets 12dp, large surfaces 16dp.
    val shapes = Shapes(
        extraSmall = RoundedCornerShape(4.dp),
        small = RoundedCornerShape(8.dp),
        medium = RoundedCornerShape(12.dp),
        large = RoundedCornerShape(16.dp),
        extraLarge = RoundedCornerShape(20.dp)
    )

    MaterialTheme(
        colorScheme = colorScheme,
        typography = Typography,
        shapes = shapes,
        content = content
    )
}
