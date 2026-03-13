package com.securepasswd.mgmt.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.securepasswd.mgmt.CoreInterop
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import java.util.Calendar

class TotpViewModel : ViewModel() {
    private val _remainingSeconds = MutableStateFlow(30)
    val remainingSeconds: StateFlow<Int> = _remainingSeconds

    private val _refreshTrigger = MutableStateFlow(0)
    val refreshTrigger: StateFlow<Int> = _refreshTrigger

    init {
        startTimer()
    }

    private fun startTimer() {
        viewModelScope.launch {
            while (true) {
                val second = Calendar.getInstance().get(Calendar.SECOND)
                val remaining = 30 - (second % 30)
                _remainingSeconds.value = remaining
                
                if (remaining == 30) {
                    _refreshTrigger.value += 1
                }
                
                delay(1000)
            }
        }
    }

    fun getTotp(secret: ByteArray): String {
        return if (secret.isNotEmpty()) {
            val codeBytes = CoreInterop.generateTotp(secret)
            val code = String(codeBytes, Charsets.UTF_8)
            codeBytes.fill(0)
            code
        } else {
            ""
        }
    }
}
