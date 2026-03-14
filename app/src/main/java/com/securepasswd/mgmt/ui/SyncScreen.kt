package com.securepasswd.mgmt.ui

import androidx.compose.foundation.layout.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import com.securepasswd.mgmt.SyncManager
import kotlinx.coroutines.launch

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SyncScreen(onBack: () -> Unit, onSyncComplete: () -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var statusMessage by remember { mutableStateOf("Scan the QR code on your Desktop app to begin sync.") }
    var isSyncing by remember { mutableStateOf(false) }
    var showScanner by remember { mutableStateOf(true) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Vault Sync") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                }
            )
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .padding(padding)
                .fillMaxSize(),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center
        ) {
            if (showScanner) {
                Box(modifier = Modifier.weight(1f)) {
                    QRScannerView(
                        onQrCodeScanned = { qrContent ->
                            if (qrContent.startsWith("vsync:")) {
                                showScanner = false
                                isSyncing = true
                                scope.launch {
                                    handleSync(qrContent, context, { msg ->
                                        statusMessage = msg
                                    }, onSyncComplete)
                                    isSyncing = false
                                }
                            }
                        },
                        onClose = { onBack() }
                    )
                }
            } else {
                Spacer(modifier = Modifier.height(32.dp))
                if (isSyncing) {
                    CircularProgressIndicator()
                    Spacer(modifier = Modifier.height(16.dp))
                }
                Text(
                    text = statusMessage,
                    style = MaterialTheme.typography.bodyLarge,
                    modifier = Modifier.padding(16.dp),
                    textAlign = androidx.compose.ui.text.style.TextAlign.Center
                )
                if (!isSyncing) {
                    Button(onClick = { showScanner = true }) {
                        Text("Retry")
                    }
                }
            }
        }
    }
}

private suspend fun handleSync(
    qrContent: String,
    context: android.content.Context,
    onProgress: (String) -> Unit,
    onSyncComplete: () -> Unit
) {
    // vsync:[IP]:[PORT]:[KEY_HEX]
    val parts = qrContent.removePrefix("vsync:").split(":")
    if (parts.size != 3) {
        onProgress("Invalid QR code format.")
        return
    }

    val ip = parts[0]
    val port = parts[1].toIntOrNull() ?: 8080
    val keyHex = parts[2]

    val success = SyncManager.performSync(context, ip, port, keyHex, onProgress)
    if (success) {
        onProgress("Vault synced successfully! Redirecting to login...")
        kotlinx.coroutines.delay(1500)
        kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.Main) {
            onSyncComplete()
        }
    } else {
        onProgress("Sync failed. Ensure devices are on the same network.")
    }
}
