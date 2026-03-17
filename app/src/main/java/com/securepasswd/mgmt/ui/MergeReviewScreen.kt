@file:OptIn(ExperimentalMaterial3Api::class)

package com.securepasswd.mgmt.ui

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.securepasswd.mgmt.MergeConflict
import com.securepasswd.mgmt.MergeReport
import com.securepasswd.mgmt.PasswordEntry

@Composable
fun MergeReviewScreen(
    report: MergeReport,
    onAccept: (List<PasswordEntry>) -> Unit,
    onCancel: () -> Unit
) {
    val colors = MaterialTheme.colorScheme
    
    // State to track resolutions for each conflict
    // null = pending, true = keep local, false = use incoming
    val resolutions = remember { mutableStateMapOf<Int, Boolean>() }
    
    val pendingConflictsCount = report.conflicts.size - resolutions.size

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Review Changes") },
                navigationIcon = {
                    IconButton(onClick = onCancel) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                }
            )
        },
        bottomBar = {
            Surface(tonalElevation = 8.dp) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(16.dp),
                    horizontalArrangement = Arrangement.spacedBy(16.dp)
                ) {
                    OutlinedButton(
                        onClick = onCancel,
                        modifier = Modifier.weight(1f)
                    ) {
                        Text("Cancel")
                    }
                    Button(
                        onClick = {
                            val accepted = mutableListOf<PasswordEntry>()
                            accepted.addAll(report.additions)
                            report.conflicts.forEachIndexed { index, conflict ->
                                if (resolutions[index] == false) {
                                    accepted.add(conflict.incomingEntry)
                                }
                            }
                            onAccept(accepted)
                        },
                        enabled = pendingConflictsCount == 0,
                        modifier = Modifier.weight(1f)
                    ) {
                        Text("Apply Changes")
                    }
                }
            }
        }
    ) { innerPadding ->
        LazyColumn(
            modifier = Modifier
                .padding(innerPadding)
                .fillMaxSize()
                .padding(horizontal = 16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
            contentPadding = PaddingValues(vertical = 16.dp)
        ) {
            if (report.additions.isNotEmpty()) {
                item {
                    Text(
                        "New Accounts (${report.additions.size})",
                        fontWeight = FontWeight.Bold,
                        color = colors.primary
                    )
                }
                items(report.additions) { entry ->
                    Card(modifier = Modifier.fillMaxWidth()) {
                        Column(modifier = Modifier.padding(12.dp)) {
                            Text(entry.service, fontWeight = FontWeight.Bold)
                            Text(entry.username, fontSize = 14.sp, color = colors.onSurface.copy(alpha = 0.6f))
                        }
                    }
                }
            }

            if (report.conflicts.isNotEmpty()) {
                item {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(Icons.Default.Warning, contentDescription = null, tint = Color(0xFFFF9800))
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            "Conflicts (${report.conflicts.size})",
                            fontWeight = FontWeight.Bold,
                            color = Color(0xFFFF9800)
                        )
                    }
                    Text(
                        "Please choose which version to keep for each account.",
                        fontSize = 12.sp,
                        color = colors.onSurface.copy(alpha = 0.6f)
                    )
                }

                report.conflicts.forEachIndexed { index, conflict ->
                    item {
                        ConflictItem(
                            conflict = conflict,
                            resolution = resolutions[index],
                            onResolve = { resolutions[index] = it }
                        )
                    }
                }
            }

            if (report.identical.isNotEmpty()) {
                item {
                    Text(
                        "Already in Vault (${report.identical.size})",
                        fontWeight = FontWeight.Bold,
                        color = colors.onSurface.copy(alpha = 0.4f)
                    )
                    Text(
                        "These matches will be skipped automatically.",
                        fontSize = 12.sp,
                        color = colors.onSurface.copy(alpha = 0.4f)
                    )
                }
            }
        }
    }
}

@Composable
fun ConflictItem(
    conflict: MergeConflict,
    resolution: Boolean?, // true = local, false = incoming
    onResolve: (Boolean) -> Unit
) {
    val colors = MaterialTheme.colorScheme

    Card(
        modifier = Modifier.fillMaxWidth(),
        border = if (resolution == null) BorderStroke(1.dp, Color(0xFFFF9800)) else null
    ) {
        Column(modifier = Modifier.padding(12.dp)) {
            Text(conflict.localEntry.service, fontWeight = FontWeight.Bold)
            Text(conflict.localEntry.username, fontSize = 14.sp)
            
            Spacer(modifier = Modifier.height(12.dp))
            
            Row(modifier = Modifier.fillMaxWidth()) {
                // Local version
                Column(
                    modifier = Modifier
                        .weight(1f)
                        .background(
                            if (resolution == true) colors.primary.copy(alpha = 0.1f) else Color.Transparent,
                            RoundedCornerShape(8.dp)
                        )
                        .padding(8.dp)
                ) {
                    Text("Local Version", fontSize = 10.sp, fontWeight = FontWeight.Bold)
                    RadioButton(selected = resolution == true, onClick = { onResolve(true) })
                    Text("Keep existing", fontSize = 11.sp)
                }
                
                Spacer(modifier = Modifier.width(8.dp))
                
                // Incoming version
                Column(
                    modifier = Modifier
                        .weight(1f)
                        .background(
                            if (resolution == false) colors.primary.copy(alpha = 0.1f) else Color.Transparent,
                            RoundedCornerShape(8.dp)
                        )
                        .padding(8.dp)
                ) {
                    Text("Incoming Version", fontSize = 10.sp, fontWeight = FontWeight.Bold)
                    RadioButton(selected = resolution == false, onClick = { onResolve(false) })
                    Text("Overwrite local", fontSize = 11.sp)
                }
            }
        }
    }
}
