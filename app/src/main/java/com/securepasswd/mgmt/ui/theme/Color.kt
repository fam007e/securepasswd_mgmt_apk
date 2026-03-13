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
