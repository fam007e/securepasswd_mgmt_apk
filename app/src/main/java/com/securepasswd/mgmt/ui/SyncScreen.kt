package com.securepasswd.mgmt.ui

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.ContentPaste
import androidx.compose.material.icons.filled.QrCodeScanner
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.securepasswd.mgmt.SyncManager
import com.securepasswd.mgmt.SyncQrPayload
import com.securepasswd.mgmt.SyncResult
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SyncScreen(
    onBack: () -> Unit,
    onSyncComplete: () -> Unit
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val clipboardManager = LocalClipboardManager.current

    var statusMessage by remember { mutableStateOf("Scan the QR code shown on your Desktop app to begin secure two-way sync.") }
    var isSyncing by remember { mutableStateOf(false) }
    var showScanner by remember { mutableStateOf(true) }
    var showManualInputDialog by remember { mutableStateOf(false) }
    var manualInputText by remember { mutableStateOf("") }
    var syncSuccessSummary by remember { mutableStateOf<String?>(null) }

    fun startSyncWithPayload(qrContent: String) {
        if (SyncQrPayload.isLegacyPayload(qrContent)) {
            showScanner = false
            statusMessage = "Legacy sync protocol detected. Please update your desktop app to use secure 2-way sync."
            return
        }

        val payload = SyncQrPayload.parse(qrContent)
        if (payload == null) {
            showScanner = false
            statusMessage = "Invalid QR code format. Please ensure you are scanning a 'vsync2:' code from SecurePasswd Desktop."
            return
        }

        showScanner = false
        isSyncing = true
        syncSuccessSummary = null

        scope.launch {
            val result = SyncManager.performSync(
                context = context,
                ip = payload.ip,
                port = payload.port,
                psk = payload.psk,
                onProgress = { msg -> statusMessage = msg }
            )

            isSyncing = false
            when (result) {
                is SyncResult.Success -> {
                    val summary = "Sync successful!\nAdded: ${result.additions} | Updated: ${result.updates} | Deleted: ${result.deletions}"
                    syncSuccessSummary = summary
                    statusMessage = summary
                    delay(1800)
                    onSyncComplete()
                }
                is SyncResult.Failure -> {
                    statusMessage = result.message
                }
            }
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Secure Two-Way Sync") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
                actions = {
                    if (showScanner) {
                        IconButton(onClick = {
                            val clip = clipboardManager.getText()?.text?.trim()
                            if (!clip.isNullOrEmpty() && clip.startsWith("vsync2:")) {
                                startSyncWithPayload(clip)
                            } else {
                                manualInputText = clip ?: ""
                                showManualInputDialog = true
                            }
                        }) {
                            Icon(Icons.Default.ContentPaste, contentDescription = "Paste or enter sync code")
                        }
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
                            startSyncWithPayload(qrContent)
                        },
                        onClose = { onBack() }
                    )
                }
                Surface(
                    tonalElevation = 2.dp,
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(16.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            text = "Point camera at the QR code on Desktop",
                            style = MaterialTheme.typography.bodyMedium,
                            modifier = Modifier.weight(1f)
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        OutlinedButton(onClick = {
                            manualInputText = ""
                            showManualInputDialog = true
                        }) {
                            Text("Enter Code")
                        }
                    }
                }
            } else {
                Column(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(24.dp)
                        .verticalScroll(rememberScrollState()),
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.Center
                ) {
                    if (isSyncing) {
                        CircularProgressIndicator(modifier = Modifier.size(56.dp))
                        Spacer(modifier = Modifier.height(24.dp))
                    }

                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        colors = CardDefaults.cardColors(
                            containerColor = if (syncSuccessSummary != null)
                                MaterialTheme.colorScheme.primaryContainer
                            else
                                MaterialTheme.colorScheme.surfaceVariant
                        )
                    ) {
                        Text(
                            text = statusMessage,
                            style = MaterialTheme.typography.bodyLarge,
                            modifier = Modifier.padding(20.dp),
                            textAlign = TextAlign.Center
                        )
                    }

                    Spacer(modifier = Modifier.height(24.dp))

                    if (!isSyncing && syncSuccessSummary == null) {
                        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                            Button(onClick = { showScanner = true }) {
                                Icon(Icons.Default.QrCodeScanner, contentDescription = null)
                                Spacer(modifier = Modifier.width(8.dp))
                                Text("Scan Again")
                            }
                            OutlinedButton(onClick = {
                                manualInputText = ""
                                showManualInputDialog = true
                            }) {
                                Text("Manual Input")
                            }
                        }
                    }
                }
            }
        }
    }

    if (showManualInputDialog) {
        AlertDialog(
            onDismissRequest = { showManualInputDialog = false },
            title = { Text("Enter Sync Payload") },
            text = {
                Column {
                    Text(
                        "Paste or type the vsync2 code shown on your Desktop sync window:",
                        style = MaterialTheme.typography.bodySmall
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    OutlinedTextField(
                        value = manualInputText,
                        onValueChange = { manualInputText = it },
                        modifier = Modifier.fillMaxWidth(),
                        placeholder = { Text("vsync2:192.168.1.X:33261:...") },
                        maxLines = 4
                    )
                }
            },
            confirmButton = {
                Button(
                    onClick = {
                        showManualInputDialog = false
                        val text = manualInputText.trim()
                        if (text.isNotEmpty()) {
                            startSyncWithPayload(text)
                        }
                    },
                    enabled = manualInputText.isNotBlank()
                ) {
                    Text("Connect")
                }
            },
            dismissButton = {
                TextButton(onClick = { showManualInputDialog = false }) {
                    Text("Cancel")
                }
            }
        )
    }
}
