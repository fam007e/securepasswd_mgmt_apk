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
import org.woheller69.freeDroidWarn.FreeDroidWarn

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Block screenshots and screen recording for security
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)

        // FreeDroidWarn check
        FreeDroidWarn.showWarningOnUpgrade(this, BuildConfig.VERSION_CODE)

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
            var palette by remember {
                mutableStateOf(prefs.getString("palette", "nord") ?: "nord")
            }

            SecurePasswdTheme(darkTheme = currentDark, palette = palette) {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    AppNavigation(
                        onExportEncrypted = {
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
                        },
                        palette = palette,
                        onSelectPalette = { selected ->
                            palette = selected
                            prefs.edit().putString("palette", selected).apply()
                        }
                    )
                }
            }
        }
    }
}

@Composable
fun AppNavigation(
    onExportEncrypted: () -> Unit,
    isDarkTheme: Boolean,
    onToggleTheme: () -> Unit,
    palette: String,
    onSelectPalette: (String) -> Unit
) {
    var currentScreen by remember { mutableStateOf<Screen>(Screen.Login) }
    var entries by remember { mutableStateOf(emptyList<PasswordEntry>()) }
    var isLoggingIn by remember { mutableStateOf(false) }
    var loginError by remember { mutableStateOf<String?>(null) }
    val context = LocalContext.current
    val lifecycleScope = (context as MainActivity).lifecycleScope

    // CSV Export Launcher
    val csvExportLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.CreateDocument("text/csv")
    ) { uri ->
        uri?.let {
            lifecycleScope.launch(Dispatchers.IO) {
                try {
                    context.contentResolver.openOutputStream(it)?.use { os ->
                        CsvManager.exportToCsv(os, entries)
                    }
                    withContext(Dispatchers.Main) {
                        Toast.makeText(context, "CSV exported successfully", Toast.LENGTH_SHORT).show()
                    }
                } catch (e: Exception) {
                    withContext(Dispatchers.Main) {
                        Toast.makeText(context, "Export failed: ${e.message}", Toast.LENGTH_LONG).show()
                    }
                }
            }
        }
    }

    // CSV Import Launcher
    val csvImportLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocument()
    ) { uri ->
        uri?.let {
            lifecycleScope.launch(Dispatchers.IO) {
                try {
                    val content = context.contentResolver.openInputStream(it)?.bufferedReader()?.use { it.readText() }
                    if (content != null) {
                        val importedEntries = CsvManager.parseCsv(content)
                        val report = MergeManager.analyzeMerge(entries, importedEntries)
                        withContext(Dispatchers.Main) {
                            if (report.additions.isEmpty() && report.conflicts.isEmpty()) {
                                Toast.makeText(context, "No new entries found in CSV", Toast.LENGTH_SHORT).show()
                            } else {
                                currentScreen = Screen.MergeReview(report)
                            }
                        }
                    }
                } catch (e: Exception) {
                    withContext(Dispatchers.Main) {
                        Toast.makeText(context, "Import failed: ${e.message}", Toast.LENGTH_LONG).show()
                    }
                }
            }
        }
    }

    // ── Hardware/gesture back-button routing ──────────────────────────────
    // Login: no BackHandler → system default (exits app) ✓
    // Vault: no BackHandler → system default (exits app) ✓  (multi-select back is handled inside VaultScreen)
    BackHandler(enabled = currentScreen is Screen.Details) {
        (currentScreen as? Screen.Details)?.entry?.wipe()
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
                    lifecycleScope.launch(Dispatchers.IO) {
                        val fullEntry = CoreInterop.databaseGetEntry(entry.id)
                        withContext(Dispatchers.Main) {
                            if (fullEntry != null) {
                                currentScreen = Screen.Details(fullEntry)
                            } else {
                                Toast.makeText(context, "Error loading entry", Toast.LENGTH_SHORT).show()
                            }
                        }
                    }
                },
                onExportEncrypted = onExportEncrypted,
                onExportCsv = { csvExportLauncher.launch("vault_export.csv") },
                onImportCsv = { csvImportLauncher.launch(arrayOf("text/comma-separated-values", "text/csv")) },
                onSync = { currentScreen = Screen.Sync },
                onEntryDelete = { entry ->
                    lifecycleScope.launch(Dispatchers.IO) {
                        CoreInterop.databaseDeleteEntry(entry.id)
                        val updatedEntries = CoreInterop.databaseGetAllEntries()?.toList() ?: emptyList()
                        withContext(Dispatchers.Main) {
                            entries = updatedEntries
                        }
                    }
                },
                onBulkHealthCheck = { selectedEntries ->
                    lifecycleScope.launch(Dispatchers.IO) {
                        selectedEntries.forEach { entry ->
                            val count = HealthCheckLogic.checkPwned(entry.password)
                            CoreInterop.databaseUpdatePwnedCount(entry.id, count)
                        }
                        withContext(Dispatchers.Main) {
                            entries = CoreInterop.databaseGetAllEntries()?.toList() ?: emptyList()
                        }
                    }
                },
                isDarkTheme = isDarkTheme,
                onToggleTheme = onToggleTheme,
                palette = palette,
                onSelectPalette = onSelectPalette,
                onOpenGpgKeys = { currentScreen = Screen.GpgKeys }
            )
        }
        is Screen.AddEntry -> {
            AddEntryScreen(
                allEntries = entries,
                onSave = { service, username, password, totpSecret, recoveryCodes, pwnedCount ->
                    lifecycleScope.launch(Dispatchers.IO) {
                        val pBytes = password.toByteArray(Charsets.UTF_8)
                        val tBytes = totpSecret.toByteArray(Charsets.UTF_8)
                        val rBytes = recoveryCodes.toByteArray(Charsets.UTF_8)

                        val result = CoreInterop.databaseAddEntry(service, username, pBytes, tBytes, rBytes, pwnedCount)

                        pBytes.fill(0)
                        tBytes.fill(0)
                        rBytes.fill(0)

                        withContext(Dispatchers.Main) {
                            if (result > 0) {
                                entries = CoreInterop.databaseGetAllEntries()?.toList() ?: emptyList()
                                currentScreen = Screen.Vault
                            } else {
                                Toast.makeText(context, "Failed to save entry", Toast.LENGTH_LONG).show()
                            }
                        }
                    }
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
                    lifecycleScope.launch(Dispatchers.IO) {
                        val pBytes = password.toByteArray(Charsets.UTF_8)
                        val tBytes = totpSecret.toByteArray(Charsets.UTF_8)
                        val rBytes = recoveryCodes.toByteArray(Charsets.UTF_8)

                        val result = CoreInterop.databaseUpdateEntry(id, service, username, pBytes, tBytes, rBytes, pwnedCount)

                        pBytes.fill(0)
                        tBytes.fill(0)
                        rBytes.fill(0)

                        withContext(Dispatchers.Main) {
                            if (result == 0) {
                                entries = CoreInterop.databaseGetAllEntries()?.toList() ?: emptyList()
                                val fullEntry = CoreInterop.databaseGetEntry(id)
                                if (fullEntry != null) {
                                    currentScreen = Screen.Details(fullEntry)
                                } else {
                                    currentScreen = Screen.Vault
                                }
                            } else {
                                Toast.makeText(context, "Failed to update entry", Toast.LENGTH_LONG).show()
                            }
                        }
                    }
                },
                onBack = { currentScreen = Screen.Details(screen.entry) }
            )
        }
        is Screen.Sync -> {
            com.securepasswd.mgmt.ui.SyncScreen(
                onBack = { currentScreen = Screen.Vault },
                onSyncComplete = {
                    entries = CoreInterop.databaseGetAllEntries()?.toList() ?: emptyList()
                    currentScreen = Screen.Vault
                }
            )
        }
        is Screen.GpgKeys -> {
            com.securepasswd.mgmt.ui.GpgKeysScreen(
                onBack = { currentScreen = Screen.Vault }
            )
        }
        is Screen.MergeReview -> {
            com.securepasswd.mgmt.ui.MergeReviewScreen(
                report = screen.report,
                onCancel = { currentScreen = Screen.Vault },
                onAccept = { acceptedEntries ->
                    lifecycleScope.launch(Dispatchers.IO) {
                        acceptedEntries.forEach { entry ->
                            // If ID is 0, it's a new entry (Addition)
                            // If ID > 0, it's an existing entry being updated (Conflict resolution: Use Incoming)
                            if (entry.id == 0) {
                                CoreInterop.databaseAddEntry(
                                    entry.service, entry.username,
                                    entry.password, entry.totpSecret,
                                    entry.recoveryCodes, entry.pwnedCount,
                                    entry.updatedAt
                                )
                            } else {
                                CoreInterop.databaseUpdateEntry(
                                    entry.id, entry.service, entry.username,
                                    entry.password, entry.totpSecret,
                                    entry.recoveryCodes, entry.pwnedCount,
                                    entry.updatedAt
                                )
                            }
                        }
                        val updated = CoreInterop.databaseGetAllEntries()?.toList() ?: emptyList()
                        withContext(Dispatchers.Main) {
                            entries = updated
                            currentScreen = Screen.Vault
                            Toast.makeText(context, "Successfully merged ${acceptedEntries.size} entries", Toast.LENGTH_SHORT).show()
                        }
                    }
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
    object GpgKeys : Screen()
    data class MergeReview(val report: MergeReport) : Screen()
    data class Details(val entry: PasswordEntry) : Screen()
    data class EditEntry(val entry: PasswordEntry) : Screen()
}
