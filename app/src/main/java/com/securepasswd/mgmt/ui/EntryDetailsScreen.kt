package com.securepasswd.mgmt.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.viewmodel.compose.viewModel
import com.securepasswd.mgmt.HealthCheckLogic
import com.securepasswd.mgmt.PasswordEntry
import com.securepasswd.mgmt.CoreInterop
import com.securepasswd.mgmt.SecureClipboardManager
import androidx.compose.ui.platform.LocalContext
import kotlinx.coroutines.launch

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun EntryDetailsScreen(
    entry: PasswordEntry,
    allEntries: List<PasswordEntry>,
    onBack: () -> Unit,
    onEdit: () -> Unit,
    totpViewModel: TotpViewModel = viewModel()
) {
    var passwordVisible by remember { mutableStateOf(false) }
    val remainingSeconds by totpViewModel.remainingSeconds.collectAsState()
    val refreshTrigger by totpViewModel.refreshTrigger.collectAsState()
    val context = LocalContext.current
    val coroutineScope = rememberCoroutineScope()
    var pwnedCount by remember { mutableStateOf<Int?>(null) }
    var isCheckingPwned by remember { mutableStateOf(false) }
    val colors = MaterialTheme.colorScheme

    // Generate TOTP code reactively
    val totpCode = remember(entry.totpSecret, refreshTrigger) {
        if (entry.totpSecret.isNotEmpty()) totpViewModel.getTotp(entry.totpSecret) else ""
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(entry.service, fontWeight = FontWeight.Bold) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            painter = androidx.compose.ui.res.painterResource(id = com.securepasswd.mgmt.R.drawable.ic_arrow_back_custom),
                            contentDescription = "Back",
                            tint = colors.onBackground,
                            modifier = Modifier.size(24.dp)
                        )
                    }
                },
                actions = {
                    IconButton(onClick = onEdit) {
                        Icon(
                            painter = androidx.compose.ui.res.painterResource(id = com.securepasswd.mgmt.R.drawable.ic_edit_custom),
                            contentDescription = "Edit",
                            tint = colors.onBackground,
                            modifier = Modifier.size(24.dp)
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
            // Health section
            val health = HealthCheckLogic.analyzePassword(entry.password, allEntries, pwnedCount)
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .background(colors.surface, RoundedCornerShape(8.dp))
                    .padding(16.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Column {
                    Text(
                        text = "Strength: ${health.label}", 
                        color = when(health.label) {
                            "Compromised" -> Color.Red
                            "Strong" -> Color(0xFF4CAF50)
                            "Moderate" -> Color(0xFFFFC107)
                            else -> Color(0xFFF44336)
                        }, 
                        fontWeight = FontWeight.Bold
                    )
                    if (pwnedCount != null) {
                        if (pwnedCount!! > 0) {
                            Text(text = "Pwned $pwnedCount times!", color = Color.Red, fontSize = 12.sp)
                        } else if (pwnedCount == 0) {
                            Text(text = "Safe (0 leaks)", color = Color.Green, fontSize = 12.sp)
                        } else {
                            Text(text = "Check failed", color = colors.onSurface.copy(alpha = 0.5f), fontSize = 12.sp)
                        }
                    } else {
                        Text(text = "Not checked vs leaks", color = colors.onSurface.copy(alpha = 0.5f), fontSize = 12.sp)
                    }
                }

                Button(
                    onClick = {
                        isCheckingPwned = true
                        coroutineScope.launch {
                            val result = HealthCheckLogic.checkPwned(entry.password)
                            pwnedCount = result
                            // Persist the result to database
                            CoreInterop.databaseUpdatePwnedCount(entry.id, result)
                            
                            isCheckingPwned = false
                        }
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = colors.primary),
                    enabled = !isCheckingPwned
                ) {
                    Icon(
                        painter = androidx.compose.ui.res.painterResource(id = com.securepasswd.mgmt.R.drawable.ic_health_check_custom),
                        contentDescription = "Check Pwned",
                        tint = colors.onPrimary,
                        modifier = Modifier.size(16.dp)
                    )
                    Spacer(Modifier.width(8.dp))
                    Text(if (isCheckingPwned) "Checking..." else "Check", color = colors.onPrimary)
                }
            }

            DetailField(
                label = "Username", 
                value = entry.username,
                onCopy = { SecureClipboardManager.copyToClipboard(context, "Username", entry.username) }
            )

            DetailField(
                label = "Password",
                value = if (passwordVisible) String(entry.password, Charsets.UTF_8) else "••••••••",
                isPassword = true,
                onToggleVisibility = { passwordVisible = !passwordVisible },
                onCopy = { 
                    val passStr = String(entry.password, Charsets.UTF_8)
                    SecureClipboardManager.copyToClipboard(context, "Password", passStr)
                }
            )

            if (entry.totpSecret.isNotEmpty()) {
                TotpSection(
                    code = totpCode,
                    remainingSeconds = remainingSeconds,
                    onCopy = { SecureClipboardManager.copyToClipboard(context, "TOTP", totpCode) }
                )
            }
        }
    }
}

@Composable
fun TotpSection(code: String, remainingSeconds: Int, onCopy: () -> Unit) {
    val colors = MaterialTheme.colorScheme

    Column(modifier = Modifier.fillMaxWidth()) {
        Text(text = "TOTP Code", color = colors.onSurface.copy(alpha = 0.6f), fontSize = 12.sp)
        Spacer(modifier = Modifier.height(8.dp))
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .background(colors.surface, RoundedCornerShape(12.dp))
                .padding(16.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            Column {
                Text(
                    text = code.chunked(3).joinToString(" "),
                    color = colors.primary,
                    fontSize = 32.sp,
                    fontWeight = FontWeight.Bold,
                    letterSpacing = 2.sp
                )
                Spacer(modifier = Modifier.height(8.dp))
                LinearProgressIndicator(
                    progress = { remainingSeconds / 30f },
                    modifier = Modifier.width(120.dp),
                    color = colors.primary,
                    trackColor = colors.surfaceVariant
                )
            }
            
            IconButton(onClick = onCopy) {
                Icon(
                    painter = androidx.compose.ui.res.painterResource(id = com.securepasswd.mgmt.R.drawable.ic_copy_custom),
                    contentDescription = "Copy TOTP",
                    tint = colors.onSurface.copy(alpha = 0.6f),
                    modifier = Modifier.size(24.dp)
                )
            }
        }
    }
}

@Composable
fun DetailField(
    label: String,
    value: String,
    isPassword: Boolean = false,
    onToggleVisibility: (() -> Unit)? = null,
    onCopy: () -> Unit
) {
    val colors = MaterialTheme.colorScheme

    Column(modifier = Modifier.fillMaxWidth()) {
        Text(text = label, color = colors.onSurface.copy(alpha = 0.6f), fontSize = 12.sp)
        Spacer(modifier = Modifier.height(4.dp))
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .background(colors.surface, RoundedCornerShape(8.dp))
                .padding(12.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            Text(text = value, color = colors.onSurface, fontSize = 16.sp, fontWeight = FontWeight.Medium)

            Row {
                if (isPassword && onToggleVisibility != null) {
                    IconButton(onClick = onToggleVisibility) {
                        val iconId = if (value.contains("•") || value.contains("*"))
                            com.securepasswd.mgmt.R.drawable.ic_eye_custom
                        else
                            com.securepasswd.mgmt.R.drawable.ic_eye_off_custom

                        Icon(
                            painter = androidx.compose.ui.res.painterResource(id = iconId),
                            contentDescription = null,
                            tint = colors.primary,
                            modifier = Modifier.size(20.dp)
                        )
                    }
                }
                IconButton(onClick = onCopy) {
                    Icon(
                        painter = androidx.compose.ui.res.painterResource(id = com.securepasswd.mgmt.R.drawable.ic_copy_custom),
                        contentDescription = "Copy",
                        tint = colors.onSurface.copy(alpha = 0.6f),
                        modifier = Modifier.size(20.dp)
                    )
                }
            }
        }
    }
}
