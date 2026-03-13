package com.securepasswd.mgmt

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

object SecureClipboardManager {
    private const val CLEAR_DELAY_MS = 30000L // 30 seconds

    @OptIn(kotlinx.coroutines.DelicateCoroutinesApi::class)
    fun copyToClipboard(context: Context, label: String, text: String, onCleared: () -> Unit = {}) {
        val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        val clip = ClipData.newPlainText(label, text)
        
        // Mark as sensitive for Android 13+
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.N) {
            clip.description.extras = android.os.PersistableBundle().apply {
                if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.TIRAMISU) {
                    putBoolean("android.content.extra.IS_SENSITIVE", true)
                } else {
                    putBoolean("android.content.extra.IS_SENSITIVE", true)
                }
            }
        }
        
        clipboard.setPrimaryClip(clip)

        // Clear clipboard after delay
        kotlinx.coroutines.GlobalScope.launch {
            delay(CLEAR_DELAY_MS)
            clearClipboard(context)
            onCleared()
        }
    }

    fun clearClipboard(context: Context) {
        val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.P) {
            clipboard.clearPrimaryClip()
        } else {
            clipboard.setPrimaryClip(ClipData.newPlainText("", ""))
        }
    }
}
