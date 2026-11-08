package com.securepasswd.mgmt

import android.content.ComponentName
import android.content.Context
import android.content.pm.PackageManager

/**
 * Icon masquerading: the launcher icon is one of several activity-aliases
 * (each with its own icon and launcher label); exactly one is enabled at a
 * time via PackageManager.setComponentEnabledSetting. The real MainActivity
 * is never disabled, so navigation and VIEW intents keep working. The
 * component state persists across reboots and app updates.
 */
object AppIconManager {

    data class IconOption(
        val aliasSuffix: String,   // component suffix inside the package
        val displayName: String,   // shown in the picker
        val launcherLabel: String, // shown under the icon in the launcher
        val iconRes: Int           // preview drawable (adaptive/vector/mipmap)
    )

    val options = listOf(
        IconOption("IconVault", "SecurePasswd", "SecurePasswd", R.mipmap.ic_launcher),
        IconOption("IconMono", "Minimal (black & white)", "SecurePasswd", R.drawable.ic_launcher_mono),
        IconOption("IconCalculator", "Calculator disguise", "Calculator", R.drawable.ic_launcher_calc),
        IconOption("IconNotes", "Notes disguise", "Notes", R.drawable.ic_launcher_notes),
        IconOption("IconFiles", "Files disguise", "Files", R.drawable.ic_launcher_files)
    )

    const val PREF_KEY = "app_icon_alias"

    private fun componentName(context: Context, suffix: String) =
        ComponentName(context, "${context.packageName}.$suffix")

    /** Alias that is currently enabled in PackageManager (authoritative). */
    fun currentAlias(context: Context): String {
        val pm = context.packageManager
        for (option in options) {
            val state = pm.getComponentEnabledSetting(componentName(context, option.aliasSuffix))
            if (state == PackageManager.COMPONENT_ENABLED_STATE_ENABLED) {
                return option.aliasSuffix
            }
        }
        return options[0].aliasSuffix
    }

    fun currentOption(context: Context): IconOption =
        options.firstOrNull { it.aliasSuffix == currentAlias(context) } ?: options[0]

    /**
     * Enables [option]'s alias and disables every other one. Uses
     * DONT_KILL_APP; the launcher refreshes within a few seconds.
     */
    fun apply(context: Context, option: IconOption) {
        val pm = context.packageManager
        for (candidate in options) {
            val component = componentName(context, candidate.aliasSuffix)
            val wanted = if (candidate.aliasSuffix == option.aliasSuffix)
                PackageManager.COMPONENT_ENABLED_STATE_ENABLED
            else
                PackageManager.COMPONENT_ENABLED_STATE_DISABLED
            if (pm.getComponentEnabledSetting(component) != wanted) {
                pm.setComponentEnabledSetting(
                    component, wanted, PackageManager.DONT_KILL_APP
                )
            }
        }
        context.getSharedPreferences("secure_passwd_prefs", Context.MODE_PRIVATE)
            .edit().putString(PREF_KEY, option.aliasSuffix).apply()
    }
}
