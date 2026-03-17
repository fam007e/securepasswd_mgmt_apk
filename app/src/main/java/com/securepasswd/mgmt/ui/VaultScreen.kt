@file:OptIn(ExperimentalMaterial3Api::class)

package com.securepasswd.mgmt.ui

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.viewmodel.compose.viewModel
import com.securepasswd.mgmt.HealthCheckLogic
import com.securepasswd.mgmt.PasswordEntry
import com.securepasswd.mgmt.R

@Composable
fun VaultScreen(
    entries: List<PasswordEntry>,
    onAddEntry: () -> Unit,
    onEntryClick: (PasswordEntry) -> Unit,
    onExportEncrypted: () -> Unit,
    onExportCsv: () -> Unit,
    onImportCsv: () -> Unit,
    onSync: () -> Unit,
    onEntryDelete: (PasswordEntry) -> Unit,
    onBulkHealthCheck: (List<PasswordEntry>) -> Unit = {},
    isDarkTheme: Boolean = true,
    onToggleTheme: () -> Unit = {},
    totpViewModel: TotpViewModel = viewModel()
) {
    val refreshTrigger by totpViewModel.refreshTrigger.collectAsState()
    val colors = MaterialTheme.colorScheme

    // ── Search & Filter state ────────────────────────────────────────────────
    var searchQuery by remember { mutableStateOf("") }
    var isSearchActive by remember { mutableStateOf(false) }

    val filteredAndSortedEntries = remember(entries, searchQuery) {
        entries.filter {
            it.service.contains(searchQuery, ignoreCase = true) ||
            it.username.contains(searchQuery, ignoreCase = true)
        }.sortedWith(compareBy({ it.service.lowercase() }, { it.username.lowercase() }))
    }

    val groupedEntries = remember(filteredAndSortedEntries) {
        filteredAndSortedEntries.groupBy { it.service.take(1).uppercase() }
    }

    // ── Multi-select state ──────────────────────────────────────────────────
    var isMultiSelectMode by remember { mutableStateOf(false) }
    var selectedIds by remember { mutableStateOf(emptySet<Int>()) }

    // ── Delete-confirm state ────────────────────────────────────────────────
    var entryPendingDelete by remember { mutableStateOf<PasswordEntry?>(null) }
    var showBulkDeleteDialog by remember { mutableStateOf(false) }

    // Exit multi-select or search on back press
    BackHandler(enabled = isMultiSelectMode || isSearchActive) {
        if (isMultiSelectMode) {
            isMultiSelectMode = false
            selectedIds = emptySet()
        } else {
            isSearchActive = false
            searchQuery = ""
        }
    }

    // ── Single-delete confirmation dialog ───────────────────────────────────
    entryPendingDelete?.let { pending ->
        AlertDialog(
            onDismissRequest = { entryPendingDelete = null },
            title = { Text("Delete entry?") },
            text = { Text("Delete \"${pending.service}\" for \"${pending.username}\"? This cannot be undone.") },
            confirmButton = {
                TextButton(onClick = {
                    onEntryDelete(pending)
                    entryPendingDelete = null
                }) { Text("Delete", color = Color.Red) }
            },
            dismissButton = {
                TextButton(onClick = { entryPendingDelete = null }) { Text("Cancel") }
            }
        )
    }

    // ── Bulk-delete confirmation dialog ────────────────────────────────────
    if (showBulkDeleteDialog) {
        val count = selectedIds.size
        AlertDialog(
            onDismissRequest = { showBulkDeleteDialog = false },
            title = {
                Text("Delete $count ${if (count == 1) "entry" else "entries"}?")
            },
            text = {
                Text("This will permanently delete the selected ${if (count == 1) "entry" else "entries"} and cannot be undone.")
            },
            confirmButton = {
                TextButton(onClick = {
                    val toDelete = entries.filter { it.id in selectedIds }
                    toDelete.forEach { onEntryDelete(it) }
                    showBulkDeleteDialog = false
                    isMultiSelectMode = false
                    selectedIds = emptySet()
                }) { Text("Delete", color = Color.Red) }
            },
            dismissButton = {
                TextButton(onClick = { showBulkDeleteDialog = false }) { Text("Cancel") }
            }
        )
    }

    Scaffold(
        topBar = {
            if (isMultiSelectMode) {
                TopAppBar(
                    title = {
                        Text("${selectedIds.size} selected", fontWeight = FontWeight.Bold)
                    },
                    navigationIcon = {
                        IconButton(onClick = {
                            isMultiSelectMode = false
                            selectedIds = emptySet()
                        }) {
                            Icon(
                                painter = painterResource(id = R.drawable.ic_arrow_back_custom),
                                contentDescription = "Exit selection",
                                tint = colors.onBackground,
                                modifier = Modifier.size(24.dp)
                            )
                        }
                    },
                    actions = {
                        TextButton(onClick = {
                            selectedIds = if (selectedIds.size == entries.size) {
                                emptySet()
                            } else {
                                entries.map { it.id }.toSet()
                            }
                        }) {
                            Text(
                                if (selectedIds.size == entries.size) "Deselect All" else "Select All",
                                color = colors.primary,
                                fontSize = 13.sp
                            )
                        }
                        IconButton(
                            onClick = {
                                val selected = entries.filter { it.id in selectedIds }
                                onBulkHealthCheck(selected)
                                isMultiSelectMode = false
                                selectedIds = emptySet()
                            },
                            enabled = selectedIds.isNotEmpty()
                        ) {
                            Icon(
                                painter = painterResource(id = R.drawable.ic_health_check_custom),
                                contentDescription = "Health Check Selected",
                                tint = if (selectedIds.isNotEmpty()) colors.primary else colors.onBackground.copy(alpha = 0.3f),
                                modifier = Modifier.size(24.dp)
                            )
                        }
                        IconButton(
                            onClick = {
                                if (selectedIds.isNotEmpty()) showBulkDeleteDialog = true
                            },
                            enabled = selectedIds.isNotEmpty()
                        ) {
                            Icon(
                                painter = painterResource(id = R.drawable.ic_delete_custom),
                                contentDescription = "Delete Selected",
                                tint = if (selectedIds.isNotEmpty()) Color.Red else colors.onBackground.copy(alpha = 0.3f),
                                modifier = Modifier.size(24.dp)
                            )
                        }
                    },
                    colors = TopAppBarDefaults.topAppBarColors(
                        containerColor = colors.surface,
                        titleContentColor = colors.onSurface
                    )
                )
            } else if (isSearchActive) {
                TopAppBar(
                    title = {
                        TextField(
                            value = searchQuery,
                            onValueChange = { searchQuery = it },
                            placeholder = { Text("Search accounts...") },
                            modifier = Modifier.fillMaxWidth(),
                            colors = TextFieldDefaults.colors(
                                focusedContainerColor = Color.Transparent,
                                unfocusedContainerColor = Color.Transparent,
                                disabledContainerColor = Color.Transparent,
                                focusedIndicatorColor = Color.Transparent,
                                unfocusedIndicatorColor = Color.Transparent
                            ),
                            singleLine = true
                        )
                    },
                    navigationIcon = {
                        IconButton(onClick = {
                            isSearchActive = false
                            searchQuery = ""
                        }) {
                            Icon(
                                painter = painterResource(id = R.drawable.ic_arrow_back_custom),
                                contentDescription = "Back",
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
            } else {
                TopAppBar(
                    title = {
                        Text("Your Vault", fontWeight = FontWeight.Bold)
                    },
                    actions = {
                        var showMenu by remember { mutableStateOf(false) }

                        IconButton(onClick = { isSearchActive = true }) {
                            Icon(
                                imageVector = androidx.compose.material.icons.Icons.Default.Search,
                                contentDescription = "Search",
                                tint = colors.onBackground
                            )
                        }
                        IconButton(onClick = onToggleTheme) {
                            Icon(
                                painter = painterResource(
                                    id = if (isDarkTheme) R.drawable.ic_lightmode_custom else R.drawable.ic_darkmode_custom
                                ),
                                contentDescription = if (isDarkTheme) "Switch to Light" else "Switch to Dark",
                                tint = colors.onBackground,
                                modifier = Modifier.size(24.dp)
                            )
                        }
                        
                        Box {
                            IconButton(onClick = { showMenu = true }) {
                                Icon(
                                    imageVector = androidx.compose.material.icons.Icons.Default.MoreVert,
                                    contentDescription = "More Options",
                                    tint = colors.onBackground
                                )
                            }
                            DropdownMenu(
                                expanded = showMenu,
                                onDismissRequest = { showMenu = false }
                            ) {
                                DropdownMenuItem(
                                    text = { Text("Sync from Desktop") },
                                    onClick = {
                                        showMenu = false
                                        onSync()
                                    },
                                    leadingIcon = {
                                        Icon(
                                            painter = painterResource(id = R.drawable.ic_sync_custom),
                                            contentDescription = null,
                                            modifier = Modifier.size(18.dp)
                                        )
                                    }
                                )
                                HorizontalDivider()
                                DropdownMenuItem(
                                    text = { Text("Import CSV") },
                                    onClick = {
                                        showMenu = false
                                        onImportCsv()
                                    }
                                )
                                DropdownMenuItem(
                                    text = { Text("Export CSV (Plaintext)") },
                                    onClick = {
                                        showMenu = false
                                        onExportCsv()
                                    }
                                )
                                DropdownMenuItem(
                                    text = { Text("Backup Vault (Encrypted)") },
                                    onClick = {
                                        showMenu = false
                                        onExportEncrypted()
                                    }
                                )
                            }
                        }
                    },
                    colors = TopAppBarDefaults.topAppBarColors(
                        containerColor = colors.background,
                        titleContentColor = colors.onBackground
                    )
                )
            }
        },
        floatingActionButton = {
            if (!isMultiSelectMode) {
                FloatingActionButton(
                    onClick = onAddEntry,
                    containerColor = colors.primary,
                    contentColor = colors.onPrimary
                ) {
                    Icon(
                        painter = painterResource(id = R.drawable.ic_add_custom),
                        contentDescription = "Add Entry",
                        modifier = Modifier.size(24.dp)
                    )
                }
            }
        },
        containerColor = colors.background
    ) { innerPadding ->
        LazyColumn(
            modifier = Modifier
                .padding(innerPadding)
                .fillMaxSize()
                .padding(horizontal = 16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
            contentPadding = PaddingValues(vertical = 16.dp)
        ) {
            groupedEntries.forEach { (initial, items) ->
                stickyHeader {
                    Box(
                        modifier = Modifier
                            .fillMaxWidth()
                            .background(colors.background)
                            .padding(vertical = 4.dp)
                    ) {
                        Text(
                            text = initial,
                            style = MaterialTheme.typography.titleMedium,
                            color = colors.primary,
                            fontWeight = FontWeight.Bold
                        )
                    }
                }

                items(items, key = { it.id }) { entry ->
                    val isSelected = entry.id in selectedIds

                    if (isMultiSelectMode) {
                        val totpCode = remember(entry.totpSecret, refreshTrigger) {
                            if (entry.totpSecret.isNotEmpty()) totpViewModel.getTotp(entry.totpSecret) else ""
                        }
                        val healthStatus = remember(entry.password, entries.size, entry.pwnedCount) {
                            HealthCheckLogic.analyzePassword(entry.password, entries, entry.pwnedCount)
                        }
                        VaultItem(
                            entry = entry,
                            totpCode = totpCode,
                            healthLabel = healthStatus.label,
                            healthColor = when (healthStatus.label) {
                                "Compromised" -> Color.Red
                                "Strong" -> Color(0xFF4CAF50)
                                "Moderate" -> Color(0xFFFFC107)
                                else -> Color(0xFFF44336)
                            },
                            isSelected = isSelected,
                            onClick = {
                                selectedIds = if (isSelected) selectedIds - entry.id else selectedIds + entry.id
                            },
                            onLongPress = {
                                selectedIds = if (isSelected) selectedIds - entry.id else selectedIds + entry.id
                            }
                        )
                    } else {
                        val dismissState = rememberSwipeToDismissBoxState()

                        LaunchedEffect(dismissState.targetValue) {
                            if (dismissState.targetValue == SwipeToDismissBoxValue.EndToStart) {
                                entryPendingDelete = entry
                                dismissState.snapTo(SwipeToDismissBoxValue.Settled)
                            }
                        }

                        SwipeToDismissBox(
                            state = dismissState,
                            enableDismissFromStartToEnd = false,
                            backgroundContent = {
                                val color = if (dismissState.dismissDirection == SwipeToDismissBoxValue.EndToStart) {
                                    Color.Red
                                } else Color.Transparent

                                Box(
                                    modifier = Modifier
                                        .fillMaxSize()
                                        .background(color, RoundedCornerShape(12.dp))
                                        .padding(horizontal = 20.dp),
                                    contentAlignment = Alignment.CenterEnd
                                ) {
                                    Icon(
                                        painter = painterResource(id = R.drawable.ic_delete_custom),
                                        contentDescription = "Delete",
                                        tint = Color.White,
                                        modifier = Modifier.size(24.dp)
                                    )
                                }
                            },
                            content = {
                                val totpCode = remember(entry.totpSecret, refreshTrigger) {
                                    if (entry.totpSecret.isNotEmpty()) totpViewModel.getTotp(entry.totpSecret) else ""
                                }
                                val healthStatus = remember(entry.password, entries.size, entry.pwnedCount) {
                                    HealthCheckLogic.analyzePassword(entry.password, entries, entry.pwnedCount)
                                }

                                VaultItem(
                                    entry = entry,
                                    totpCode = totpCode,
                                    healthLabel = healthStatus.label,
                                    healthColor = when (healthStatus.label) {
                                        "Compromised" -> Color.Red
                                        "Strong" -> Color(0xFF4CAF50)
                                        "Moderate" -> Color(0xFFFFC107)
                                        else -> Color(0xFFF44336)
                                    },
                                    isSelected = false,
                                    onClick = { onEntryClick(entry) },
                                    onLongPress = {
                                        isMultiSelectMode = true
                                        selectedIds = setOf(entry.id)
                                    }
                                )
                            }
                        )
                    }
                }
            }
        }
    }
}

@OptIn(ExperimentalFoundationApi::class)
@Composable
fun VaultItem(
    entry: PasswordEntry,
    totpCode: String,
    healthLabel: String,
    healthColor: Color,
    isSelected: Boolean = false,
    onClick: () -> Unit,
    onLongPress: () -> Unit = {}
) {
    val colors = MaterialTheme.colorScheme

    Card(
        modifier = Modifier
            .fillMaxWidth()
            .then(
                if (isSelected) Modifier.border(2.dp, colors.primary, RoundedCornerShape(12.dp))
                else Modifier
            )
            .combinedClickable(
                onClick = onClick,
                onLongClick = onLongPress
            ),
        shape = RoundedCornerShape(12.dp),
        colors = CardDefaults.cardColors(
            containerColor = if (isSelected) colors.primary.copy(alpha = 0.12f) else colors.surface
        )
    ) {
        Row(
            modifier = Modifier
                .padding(16.dp)
                .fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Box(
                modifier = Modifier
                    .size(40.dp)
                    .background(
                        if (isSelected) colors.primary else colors.surfaceVariant,
                        RoundedCornerShape(8.dp)
                    ),
                contentAlignment = Alignment.Center
            ) {
                if (isSelected) {
                    Icon(
                        painter = painterResource(id = R.drawable.ic_check_custom),
                        contentDescription = "Selected",
                        tint = colors.onPrimary,
                        modifier = Modifier.size(20.dp)
                    )
                } else {
                    Text(
                        text = entry.service.take(1).uppercase(),
                        color = colors.primary,
                        fontWeight = FontWeight.Bold,
                        fontSize = 20.sp
                    )
                }
            }

            Spacer(modifier = Modifier.width(16.dp))

            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = entry.service,
                    color = colors.onSurface,
                    fontWeight = FontWeight.Bold,
                    fontSize = 16.sp
                )
                Text(
                    text = entry.username,
                    color = colors.onSurface.copy(alpha = 0.6f),
                    fontSize = 14.sp
                )
            }

            Column(horizontalAlignment = Alignment.End) {
                if (totpCode.isNotEmpty()) {
                    Text(
                        text = totpCode,
                        color = colors.primary,
                        fontWeight = FontWeight.Bold,
                        fontSize = 14.sp
                    )
                }
                Text(
                    text = healthLabel,
                    color = healthColor,
                    fontSize = 12.sp,
                    fontWeight = FontWeight.Medium
                )
            }
        }
    }
}
