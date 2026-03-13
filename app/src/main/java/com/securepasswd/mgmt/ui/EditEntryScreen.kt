package com.securepasswd.mgmt.ui

import androidx.compose.foundation.layout.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.QrCodeScanner
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.Alignment
import androidx.compose.ui.graphics.Color
import com.securepasswd.mgmt.PasswordEntry
import com.securepasswd.mgmt.CoreInterop
import com.securepasswd.mgmt.HealthCheckLogic
import com.securepasswd.mgmt.HealthStatus

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun EditEntryScreen(
    entry: PasswordEntry,
    allEntries: List<PasswordEntry>,
    onSave: (Int, String, String, String, String, String, Int) -> Unit,
    onBack: () -> Unit
) {
    var service by remember { mutableStateOf(entry.service) }
    var username by remember { mutableStateOf(entry.username) }
    var password by remember { mutableStateOf(String(entry.password, Charsets.UTF_8)) }
    var totpSecret by remember { mutableStateOf(String(entry.totpSecret, Charsets.UTF_8)) }
    var recoveryCodes by remember { mutableStateOf(String(entry.recoveryCodes, Charsets.UTF_8)) }
    var showScanner by remember { mutableStateOf(false) }
    var showPasswordDialog by remember { mutableStateOf(false) }
    val colors = MaterialTheme.colorScheme

    if (showScanner) {
        QRScannerView(
            onQrCodeScanned = { qrContent ->
                var secret = qrContent
                if (qrContent.startsWith("otpauth://")) {
                    try {
                        val uri = android.net.Uri.parse(qrContent)
                        val s = uri.getQueryParameter("secret")
                        if (s != null) secret = s
                    } catch (e: Exception) {}
                }
                totpSecret = secret
                showScanner = false
            },
            onClose = {
                showScanner = false
            }
        )
        return
    }

    if (showPasswordDialog) {
        var pwLength by remember { mutableStateOf(16f) }
        var useUpper by remember { mutableStateOf(true) }
        var useNum by remember { mutableStateOf(true) }
        var useSpecial by remember { mutableStateOf(true) }

        AlertDialog(
            onDismissRequest = { showPasswordDialog = false },
            title = { Text("Generate Password", color = colors.onSurface) },
            text = {
                Column {
                    Text("Length: ${pwLength.toInt()}", color = colors.onSurface)
                    Slider(
                        value = pwLength,
                        onValueChange = { pwLength = it },
                        valueRange = 8f..128f,
                        steps = 120
                    )
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Checkbox(checked = useUpper, onCheckedChange = { useUpper = it })
                        Text("Uppercase (A-Z)", color = colors.onSurface)
                    }
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Checkbox(checked = useNum, onCheckedChange = { useNum = it })
                        Text("Numbers (0-9)", color = colors.onSurface)
                    }
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Checkbox(checked = useSpecial, onCheckedChange = { useSpecial = it })
                        Text("Special (!@#...)", color = colors.onSurface)
                    }
                }
            },
            containerColor = colors.surface,
            confirmButton = {
                TextButton(onClick = {
                    val passBytes = CoreInterop.generatePassword(
                        pwLength.toInt(),
                        useUpper,
                        useNum,
                        useSpecial
                    )
                    password = String(passBytes, Charsets.UTF_8)
                    passBytes.fill(0)
                    showPasswordDialog = false
                }) {
                    Text("Generate", color = colors.primary)
                }
            },
            dismissButton = {
                TextButton(onClick = { showPasswordDialog = false }) {
                    Text("Cancel", color = colors.onSurface.copy(alpha = 0.6f))
                }
            }
        )
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Edit Entry", fontWeight = FontWeight.Bold) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            painter = androidx.compose.ui.res.painterResource(id = com.securepasswd.mgmt.R.drawable.ic_arrow_back_custom),
                            contentDescription = "Back",
                            tint = colors.onBackground
                        )
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = colors.background,
                    titleContentColor = colors.onBackground
                )
            )
        },
        containerColor = colors.background
    ) { padding ->
        Column(
            modifier = Modifier
                .padding(padding)
                .fillMaxSize()
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            OutlinedTextField(
                value = service,
                onValueChange = { service = it },
                label = { Text("Service (e.g. Google)", color = colors.onSurface.copy(alpha = 0.6f)) },
                modifier = Modifier.fillMaxWidth(),
                colors = OutlinedTextFieldDefaults.colors(
                    focusedBorderColor = colors.primary,
                    unfocusedBorderColor = colors.outline,
                    focusedTextColor = colors.onSurface,
                    unfocusedTextColor = colors.onSurface
                )
            )

            OutlinedTextField(
                value = username,
                onValueChange = { username = it },
                label = { Text("Username or Email", color = colors.onSurface.copy(alpha = 0.6f)) },
                modifier = Modifier.fillMaxWidth(),
                colors = OutlinedTextFieldDefaults.colors(
                    focusedBorderColor = colors.primary,
                    unfocusedBorderColor = colors.outline,
                    focusedTextColor = colors.onSurface,
                    unfocusedTextColor = colors.onSurface
                )
            )

            OutlinedTextField(
                value = password,
                onValueChange = { password = it },
                label = { Text("Password", color = colors.onSurface.copy(alpha = 0.6f)) },
                modifier = Modifier.fillMaxWidth(),
                trailingIcon = {
                    IconButton(onClick = { showPasswordDialog = true }) {
                        Icon(Icons.Default.Refresh, contentDescription = "Generate Password", tint = colors.primary)
                    }
                },
                colors = OutlinedTextFieldDefaults.colors(
                    focusedBorderColor = colors.primary,
                    unfocusedBorderColor = colors.outline,
                    focusedTextColor = colors.onSurface,
                    unfocusedTextColor = colors.onSurface
                )
            )

            // Health Preview
            if (password.isNotEmpty()) {
                val health = remember(password, allEntries) {
                    val passBytes = password.toByteArray(Charsets.UTF_8)
                    val h = HealthCheckLogic.analyzePassword(passBytes, allEntries)
                    passBytes.fill(0)
                    h
                }
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        text = "Strength: ${health.label}",
                        color = when(health.label) {
                            "Strong" -> Color(0xFF4CAF50)
                            "Moderate" -> Color(0xFFFFC107)
                            else -> Color(0xFFF44336)
                        },
                        fontSize = 12.sp,
                        fontWeight = FontWeight.Bold
                    )
                }
            }

            OutlinedTextField(
                value = totpSecret,
                onValueChange = { totpSecret = it },
                label = { Text("TOTP Secret (optional)", color = colors.onSurface.copy(alpha = 0.6f)) },
                modifier = Modifier.fillMaxWidth(),
                trailingIcon = {
                    IconButton(onClick = { showScanner = true }) {
                        Icon(Icons.Default.QrCodeScanner, contentDescription = "Scan QR Code", tint = colors.primary)
                    }
                },
                colors = OutlinedTextFieldDefaults.colors(
                    focusedBorderColor = colors.primary,
                    unfocusedBorderColor = colors.outline,
                    focusedTextColor = colors.onSurface,
                    unfocusedTextColor = colors.onSurface
                )
            )

            OutlinedTextField(
                value = recoveryCodes,
                onValueChange = { recoveryCodes = it },
                label = { Text("Recovery Codes (optional)", color = colors.onSurface.copy(alpha = 0.6f)) },
                modifier = Modifier.fillMaxWidth(),
                colors = OutlinedTextFieldDefaults.colors(
                    focusedBorderColor = colors.primary,
                    unfocusedBorderColor = colors.outline,
                    focusedTextColor = colors.onSurface,
                    unfocusedTextColor = colors.onSurface
                )
            )

            Spacer(modifier = Modifier.weight(1f))

            Button(
                onClick = { onSave(entry.id, service, username, password, totpSecret, recoveryCodes, entry.pwnedCount) },
                modifier = Modifier
                    .fillMaxWidth()
                    .height(50.dp),
                colors = ButtonDefaults.buttonColors(containerColor = colors.primary),
                enabled = service.isNotBlank() && username.isNotBlank() && password.isNotBlank()
            ) {
                Text("Update Entry", color = colors.onPrimary, fontWeight = FontWeight.Bold)
            }
        }
    }
}
