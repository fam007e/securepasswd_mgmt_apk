package com.securepasswd.mgmt.ui

import android.widget.ImageView
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.compose.ui.text.font.FontWeight
import com.securepasswd.mgmt.AppIconManager

/**
 * App-icon picker (icon masquerading). Shows every registered launcher
 * alias with its real icon; selecting one applies it via PackageManager.
 * The launcher refreshes within a few seconds.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AppIconScreen(onBack: () -> Unit) {
    val context = LocalContext.current
    var current by remember { mutableStateOf(AppIconManager.currentOption(context)) }
    var pending by remember { mutableStateOf<AppIconManager.IconOption?>(null) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("App Icon") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
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
            Text(
                "Choose which icon and name the app shows in your launcher. " +
                    "Useful when you prefer not to advertise that this is a vault. " +
                    "The change may take a few seconds to appear.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onBackground.copy(alpha = 0.7f),
                modifier = Modifier.padding(vertical = 8.dp)
            )
            LazyColumn(
                verticalArrangement = Arrangement.spacedBy(8.dp),
                contentPadding = PaddingValues(vertical = 8.dp)
            ) {
                items(AppIconManager.options, key = { it.aliasSuffix }) { option ->
                    val selected = option.aliasSuffix == current.aliasSuffix
                    Card(
                        onClick = {
                            if (!selected) pending = option
                        },
                        colors = CardDefaults.cardColors(
                            containerColor = if (selected)
                                MaterialTheme.colorScheme.primaryContainer
                            else
                                MaterialTheme.colorScheme.surface
                        )
                    ) {
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(14.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            // Adaptive icons / vectors render reliably via ImageView.
                            AndroidView(
                                factory = { ctx ->
                                    ImageView(ctx).apply {
                                        setImageResource(option.iconRes)
                                    }
                                },
                                modifier = Modifier.size(44.dp)
                            )
                            Spacer(modifier = Modifier.width(14.dp))
                            Column(modifier = Modifier.weight(1f)) {
                                Text(
                                    option.displayName,
                                    style = MaterialTheme.typography.titleMedium,
                                    fontWeight = FontWeight.Bold
                                )
                                Text(
                                    "Launcher name: \"${option.launcherLabel}\"",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.7f)
                                )
                            }
                            RadioButton(
                                selected = selected,
                                onClick = { if (!selected) pending = option }
                            )
                        }
                    }
                }
            }
        }
    }

    pending?.let { option ->
        AlertDialog(
            onDismissRequest = { pending = null },
            title = { Text("Change app icon?") },
            text = {
                Text(
                    "The launcher icon and name become \"${option.launcherLabel}\". " +
                        "The launcher may take a few seconds to refresh, and the " +
                        "app is not killed. Revert any time from the same menu."
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    AppIconManager.apply(context, option)
                    current = AppIconManager.currentOption(context)
                    pending = null
                }) { Text("Apply") }
            },
            dismissButton = {
                TextButton(onClick = { pending = null }) { Text("Cancel") }
            }
        )
    }
}
