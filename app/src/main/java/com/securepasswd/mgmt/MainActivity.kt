package com.securepasswd.mgmt

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.BackHandler
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import android.content.Intent
import android.widget.Toast
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import com.securepasswd.mgmt.ui.theme.SecurePasswdTheme
import com.securepasswd.mgmt.ui.LoginScreen
import com.securepasswd.mgmt.ui.VaultScreen
import com.securepasswd.mgmt.ui.EntryDetailsScreen
import com.securepasswd.mgmt.ui.AddEntryScreen
import com.securepasswd.mgmt.ui.EditEntryScreen
import androidx.compose.ui.platform.LocalContext
import android.content.ClipboardManager
import android.content.Context
import android.content.ClipData
import androidx.compose.foundation.isSystemInDarkTheme
import android.view.WindowManager

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Block screenshots and screen recording for security
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)

        // Handle incoming sync file if app was opened via intent
        intent?.data?.let { uri ->
            if (VaultSyncManager.importVault(this, uri)) {
                Toast.makeText(this, "Vault imported successfully. Please login.", Toast.LENGTH_LONG).show()
            }
        }

        setContent {
            val prefs = remember { getSharedPreferences("secure_passwd_prefs", Context.MODE_PRIVATE) }
            var isDarkTheme by remember {
                mutableStateOf(
                    if (prefs.contains("dark_theme")) prefs.getBoolean("dark_theme", true) else null
                )
            }
            val systemDark = isSystemInDarkTheme()
            val currentDark = isDarkTheme ?: systemDark

            SecurePasswdTheme(darkTheme = currentDark) {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    AppNavigation(
                        onExport = {
                            VaultSyncManager.exportVault(this)?.let { uri ->
                                val shareIntent = Intent(Intent.ACTION_SEND).apply {
                                    type = "application/octet-stream"
                                    putExtra(Intent.EXTRA_STREAM, uri)
                                    addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                                }
                                startActivity(Intent.createChooser(shareIntent, "Export Secure Vault"))
                            } ?: Toast.makeText(this, "Failed to export vault", Toast.LENGTH_SHORT).show()
                        },
                        isDarkTheme = currentDark,
                        onToggleTheme = {
                            val newDark = !currentDark
                            isDarkTheme = newDark
                            prefs.edit().putBoolean("dark_theme", newDark).apply()
                        }
                    )
                }
            }
        }
    }
}

@Composable
fun AppNavigation(
    onExport: () -> Unit,
    isDarkTheme: Boolean,
    onToggleTheme: () -> Unit
) {
    var currentScreen by remember { mutableStateOf<Screen>(Screen.Login) }
    var entries by remember { mutableStateOf(emptyList<PasswordEntry>()) }
    var isLoggingIn by remember { mutableStateOf(false) }
    var loginError by remember { mutableStateOf<String?>(null) }
    val context = LocalContext.current
    val lifecycleScope = (context as MainActivity).lifecycleScope

    // ── Hardware/gesture back-button routing ──────────────────────────────
    // Login: no BackHandler → system default (exits app) ✓
    // Vault: no BackHandler → system default (exits app) ✓  (multi-select back is handled inside VaultScreen)
    BackHandler(enabled = currentScreen is Screen.Details) {
        entries = CoreInterop.databaseGetAllEntries()?.toList() ?: emptyList()
        currentScreen = Screen.Vault
    }
    BackHandler(enabled = currentScreen is Screen.AddEntry) {
        currentScreen = Screen.Vault
    }
    BackHandler(enabled = currentScreen is Screen.EditEntry) {
        currentScreen = Screen.Details((currentScreen as Screen.EditEntry).entry)
    }
    BackHandler(enabled = currentScreen is Screen.Sync) {
        currentScreen = Screen.Vault
    }

    when (val screen = currentScreen) {
        is Screen.Login -> {
            LoginScreen(
                onLoginAttempt = { pass ->
                    isLoggingIn = true
                    loginError = null
                    lifecycleScope.launch(Dispatchers.IO) {
                        val dbPath = java.io.File(context.filesDir, "vault.db").absolutePath
                        val passBytes = pass.toByteArray(Charsets.UTF_8)
                        val result = CoreInterop.databaseOpen(dbPath, passBytes)
                        passBytes.fill(0) // Securely clear master password

                        withContext(Dispatchers.Main) {
                            isLoggingIn = false
                            if (result == 0) {
                                entries = CoreInterop.databaseGetAllEntries()?.toList() ?: emptyList()
                                currentScreen = Screen.Vault
                            } else {
                                loginError = "Incorrect password or corrupted database"
                            }
                        }
                    }
                },
                isLoading = isLoggingIn,
                externalError = loginError
            )
        }
        is Screen.Vault -> {
            VaultScreen(
                entries = entries,
                onAddEntry = { currentScreen = Screen.AddEntry },
                onEntryClick = { entry ->
                    val fullEntry = CoreInterop.databaseGetEntry(entry.id)
                    if (fullEntry != null) {
                        currentScreen = Screen.Details(fullEntry)
                    }
                },
                onExport = onExport,
                onSync = { currentScreen = Screen.Sync },
                onEntryDelete = { entry ->
                    CoreInterop.databaseDeleteEntry(entry.id)
                    entries = CoreInterop.databaseGetAllEntries()?.toList() ?: emptyList()
                },
                onBulkHealthCheck = { selectedEntries ->
                    lifecycleScope.launch(Dispatchers.IO) {
                        selectedEntries.forEach { entry ->
                            val count = HealthCheckLogic.checkPwned(entry.password)
                            CoreInterop.databaseUpdateEntry(
                                entry.id,
                                entry.service,
                                entry.username,
                                entry.password,
                                entry.totpSecret,
                                entry.recoveryCodes,
                                count
                            )
                        }
                        withContext(Dispatchers.Main) {
                            entries = CoreInterop.databaseGetAllEntries()?.toList() ?: emptyList()
                        }
                    }
                },
                isDarkTheme = isDarkTheme,
                onToggleTheme = onToggleTheme
            )
        }
        is Screen.AddEntry -> {
            AddEntryScreen(
                allEntries = entries,
                onSave = { service, username, password, totpSecret, recoveryCodes, pwnedCount ->
                    val pBytes = password.toByteArray(Charsets.UTF_8)
                    val tBytes = totpSecret.toByteArray(Charsets.UTF_8)
                    val rBytes = recoveryCodes.toByteArray(Charsets.UTF_8)

                    CoreInterop.databaseAddEntry(service, username, pBytes, tBytes, rBytes, pwnedCount)

                    pBytes.fill(0)
                    tBytes.fill(0)
                    rBytes.fill(0)

                    entries = CoreInterop.databaseGetAllEntries()?.toList() ?: emptyList()
                    currentScreen = Screen.Vault
                },
                onBack = { currentScreen = Screen.Vault }
            )
        }
        is Screen.Details -> {
            EntryDetailsScreen(
                entry = screen.entry,
                allEntries = entries,
                onBack = {
                    entries = CoreInterop.databaseGetAllEntries()?.toList() ?: emptyList()
                    currentScreen = Screen.Vault
                },
                onEdit = { currentScreen = Screen.EditEntry(screen.entry) }
            )
        }
        is Screen.EditEntry -> {
            EditEntryScreen(
                entry = screen.entry,
                allEntries = entries,
                onSave = { id, service, username, password, totpSecret, recoveryCodes, pwnedCount ->
                    val pBytes = password.toByteArray(Charsets.UTF_8)
                    val tBytes = totpSecret.toByteArray(Charsets.UTF_8)
                    val rBytes = recoveryCodes.toByteArray(Charsets.UTF_8)

                    CoreInterop.databaseUpdateEntry(id, service, username, pBytes, tBytes, rBytes, pwnedCount)

                    pBytes.fill(0)
                    tBytes.fill(0)
                    rBytes.fill(0)

                    entries = CoreInterop.databaseGetAllEntries()?.toList() ?: emptyList()
                    val fullEntry = CoreInterop.databaseGetEntry(id)
                    if (fullEntry != null) {
                        currentScreen = Screen.Details(fullEntry)
                    } else {
                        currentScreen = Screen.Vault
                    }
                },
                onBack = { currentScreen = Screen.Details(screen.entry) }
            )
        }
        is Screen.Sync -> {
            com.securepasswd.mgmt.ui.SyncScreen(
                onBack = { currentScreen = Screen.Vault },
                onSyncComplete = {
                    CoreInterop.databaseClose()
                    SyncManager.finalizeSyncReplacement(context)
                    currentScreen = Screen.Login
                }
            )
        }
    }
}

sealed class Screen {
    object Login : Screen()
    object Vault : Screen()
    object AddEntry : Screen()
    object Sync : Screen()
    data class Details(val entry: PasswordEntry) : Screen()
    data class EditEntry(val entry: PasswordEntry) : Screen()
}
