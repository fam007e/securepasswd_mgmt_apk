package com.securepasswd.mgmt.ui.theme

import androidx.compose.ui.graphics.Color

// ── Nord Dark (from dark.qss) ──
val NordPolarNight0 = Color(0xFF2E3440)  // Main background
val NordPolarNight1 = Color(0xFF3B4252)  // Surface / cards
val NordPolarNight2 = Color(0xFF434C5E)  // Surface hover
val NordPolarNight3 = Color(0xFF4C566A)  // Borders / buttons

// ── Nord Snow Storm (text) ──
val NordSnow0 = Color(0xFFD8DEE9)  // Primary text (dark mode)
val NordSnow1 = Color(0xFFE5E9F0)  // Secondary text / hover (light mode)
val NordSnow2 = Color(0xFFECEFF4)  // Light background

// ── Nord Frost (accents) ──
val NordFrost0 = Color(0xFF8FBCBB)
val NordFrost1 = Color(0xFF88C0D0)  // Progress bar accent (dark)
val NordFrost2 = Color(0xFF81A1C1)  // Button pressed
val NordFrost3 = Color(0xFF5E81AC)  // Button hover

// ── Light Theme Accent (from light.qss, based on app icon) ──
val LightAccent = Color(0xFFd97dbc)    // Pink accent / buttons / selected
val LightAccentHover = Color(0xFFc77575)
val LightAccentPressed = Color(0xFF8b8484)

// ── Light Theme Surfaces ──
val LightBg = NordSnow2              // #ECEFF4
val LightSurface = Color.White       // #FFFFFF
val LightText = Color(0xFF434343)    // Text color

// ── Semantic aliases used across screens ──
val AccentCyan = NordFrost1          // Keep old name pointing to Nord equivalent
val AccentPurple = NordFrost3        // Keep old name pointing to Nord equivalent

// ── Dracula Dark ──
val DraculaBg = Color(0xFF282A36)
val DraculaSurface = Color(0xFF343746)
val DraculaSurfaceVariant = Color(0xFF3B3D4E)
val DraculaOutline = Color(0xFF44475A)
val DraculaText = Color(0xFFF8F8F2)
val DraculaPrimary = Color(0xFFBD93F9)   // purple
val DraculaPrimaryHover = Color(0xFF9D7BE8)
val DraculaPrimaryActive = Color(0xFF6272A4)

// ── Dracula Light ("Dracula Paper") ──
val DraculaLightBg = Color(0xFFF8F8F2)
val DraculaLightSurface = Color(0xFFFFFFFF)
val DraculaLightSurfaceVariant = Color(0xFFE6E6E0)
val DraculaLightOutline = Color(0xFFD8D8D0)
val DraculaLightText = Color(0xFF3B3D4E)
val DraculaLightPrimary = Color(0xFF6C4FC4)
val DraculaLightPrimaryHover = Color(0xFF5A3FB0)

// ── Solarized Dark ──
val SolarBg = Color(0xFF002B36)
val SolarSurface = Color(0xFF073642)
val SolarSurfaceVariant = Color(0xFF0E4450)
val SolarOutline = Color(0xFF586E75)
val SolarText = Color(0xFF93A1A1)
val SolarPrimary = Color(0xFF268BD2)     // blue
val SolarPrimaryHover = Color(0xFF1E6FA8)
val SolarPrimaryActive = Color(0xFF6C71C4)

// ── Solarized Light ──
val SolarLightBg = Color(0xFFFDF6E3)
val SolarLightSurface = Color(0xFFEEE8D5)
val SolarLightSurfaceVariant = Color(0xFFE4DDC8)
val SolarLightText = Color(0xFF586E75)
