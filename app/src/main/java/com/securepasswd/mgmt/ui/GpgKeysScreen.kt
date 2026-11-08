package com.securepasswd.mgmt.ui

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Add
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.securepasswd.mgmt.CoreInterop
import com.securepasswd.mgmt.GpgKey

/**
 * OpenPGP key store: lists armored keys stored (encrypted) in the vault,
 * with import/edit/delete. Keys participate in 2-way sync like entries.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun GpgKeysScreen(onBack: () -> Unit) {
    var keys by remember { mutableStateOf(CoreInterop.gpgGetAll()?.toList() ?: emptyList()) }
    var editing by remember { mutableStateOf<GpgKey?>(null) } // null = dialog closed
    var showDeleteConfirm by remember { mutableStateOf<GpgKey?>(null) }
    var message by remember { mutableStateOf<String?>(null) }

    fun reload() {
        keys = CoreInterop.gpgGetAll()?.toList() ?: emptyList()
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("OpenPGP Keys") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
                actions = {
                    IconButton(onClick = { editing = GpgKey(label = "") }) {
                        Icon(Icons.Default.Add, contentDescription = "Add key")
                    }
                }
            )
        },
        containerColor = MaterialTheme.colorScheme.background
    ) { padding ->
        Column(
            modifier = Modifier
                .padding(padding)
                .fillMaxSize()
                .padding(horizontal = 16.dp)
        ) {
            if (message != null) {
                Text(
                    text = message!!,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.padding(vertical = 8.dp)
                )
            }
            if (keys.isEmpty()) {
                Box(
                    modifier = Modifier.fillMaxSize(),
                    contentAlignment = Alignment.Center
                ) {
                    Text(
                        "No OpenPGP keys stored.\nUse + to paste an armored key.",
                        style = MaterialTheme.typography.bodyLarge,
                        color = MaterialTheme.colorScheme.onBackground.copy(alpha = 0.6f)
                    )
                }
            } else {
                LazyColumn(
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                    contentPadding = PaddingValues(vertical = 12.dp)
                ) {
                    items(keys, key = { it.id }) { key ->
                        Card(
                            onClick = { editing = key },
                            colors = CardDefaults.cardColors(
                                containerColor = MaterialTheme.colorScheme.surface
                            )
                        ) {
                            Column(modifier = Modifier.padding(16.dp)) {
                                Text(
                                    key.label,
                                    fontWeight = FontWeight.Bold,
                                    style = MaterialTheme.typography.titleMedium
                                )
                                if (key.email.isNotEmpty()) {
                                    Text(
                                        key.email,
                                        style = MaterialTheme.typography.bodySmall,
                                        color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.7f)
                                    )
                                }
                                if (key.keyId.isNotEmpty()) {
                                    Text(
                                        "Key ID: ${key.keyId}",
                                        style = MaterialTheme.typography.bodySmall,
                                        color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.7f)
                                    )
                                }
                                Text(
                                    if (key.privateKey.isNotEmpty()) "Secret key stored" else "Public key only",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.primary
                                )
                            }
                        }
                    }
                }
            }
        }
    }

    if (editing != null) {
        val current = editing!!
        var label by remember(current) { mutableStateOf(current.label) }
        var email by remember(current) { mutableStateOf(current.email) }
        var keyId by remember(current) { mutableStateOf(current.keyId) }
        var armor by remember(current) {
            mutableStateOf(if (current.publicKey.isNotEmpty()) current.publicKey else current.privateKey)
        }

        AlertDialog(
            onDismissRequest = { editing = null },
            title = { Text(if (current.id == 0) "Add Key" else "Edit Key") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedTextField(
                        value = label,
                        onValueChange = { label = it },
                        label = { Text("Label") },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth()
                    )
                    OutlinedTextField(
                        value = email,
                        onValueChange = { email = it },
                        label = { Text("Email") },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth()
                    )
                    OutlinedTextField(
                        value = keyId,
                        onValueChange = { keyId = it },
                        label = { Text("Key ID") },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth()
                    )
                    OutlinedTextField(
                        value = armor,
                        onValueChange = { armor = it },
                        label = { Text("Armored key block") },
                        minLines = 4,
                        maxLines = 10,
                        modifier = Modifier.fillMaxWidth()
                    )
                }
            },
            confirmButton = {
                Button(
                    enabled = label.isNotBlank() && armor.isNotBlank(),
                    onClick = {
                        val pub = if (armor.contains("BEGIN PGP PRIVATE KEY BLOCK")) "" else armor
                        val priv = if (armor.contains("BEGIN PGP PRIVATE KEY BLOCK")) armor else ""
                        val rc = if (current.id == 0)
                            CoreInterop.gpgAdd(label.trim(), email.trim(), keyId.trim(), pub, priv)
                        else
                            CoreInterop.gpgUpdate(current.id, label.trim(), email.trim(), keyId.trim(), pub, priv)
                        message = if (rc >= 0) "Key stored (encrypted with the vault)." else "Failed to store key."
                        editing = null
                        reload()
                    }
                ) { Text("Save") }
            },
            dismissButton = {
                Row {
                    if (current.id != 0) {
                        TextButton(onClick = {
                            editing = null
                            showDeleteConfirm = current
                        }) { Text("Delete", color = MaterialTheme.colorScheme.error) }
                    }
                    TextButton(onClick = { editing = null }) { Text("Cancel") }
                }
            }
        )
    }

    showDeleteConfirm?.let { target ->
        AlertDialog(
            onDismissRequest = { showDeleteConfirm = null },
            title = { Text("Delete key?") },
            text = { Text("Delete \"${target.label}\" from the vault? The deletion propagates on the next sync.") },
            confirmButton = {
                TextButton(onClick = {
                    CoreInterop.gpgDelete(target.id)
                    showDeleteConfirm = null
                    message = "Key deleted."
                    reload()
                }) { Text("Delete") }
            },
            dismissButton = {
                TextButton(onClick = { showDeleteConfirm = null }) { Text("Cancel") }
            }
        )
    }
}
