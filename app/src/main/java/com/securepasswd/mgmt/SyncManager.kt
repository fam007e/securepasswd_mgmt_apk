package com.securepasswd.mgmt

import android.content.Context
import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.InputStream
import java.net.InetSocketAddress
import java.net.Socket

object SyncManager {
    private const val TAG = "SyncManager"

    suspend fun performSync(
        context: Context,
        ip: String,
        port: Int,
        keyHex: String,
        onProgress: (String) -> Unit
    ): Boolean = withContext(Dispatchers.IO) {
        val key = hexToBytes(keyHex)
        try {
            onProgress("Connecting to $ip:$port...")
            Log.d(TAG, "Attempting connection to $ip:$port")
            
            Socket().use { socket ->
                socket.soTimeout = 10000 // 10s read timeout
                socket.connect(InetSocketAddress(ip, port), 10000) // 10s connect timeout

                onProgress("Connected! Receiving data...")
                val inputStream: InputStream = socket.getInputStream()
                val encryptedBytes = inputStream.readBytes()

                if (encryptedBytes.isEmpty()) {
                    val err = "Received empty data from desktop. Check if the desktop app is still running and the vault is not empty."
                    Log.e(TAG, err)
                    onProgress(err)
                    key.fill(0)
                    return@withContext false
                }

                onProgress("Decrypting vault (${encryptedBytes.size} bytes)...")
                if (key.size != 32) {
                    Log.e(TAG, "Invalid key size: ${key.size}")
                    key.fill(0)
                    return@withContext false
                }

                // Decrypt to a staging file instead of replacing immediately
                val stagingDbPath = context.filesDir.absolutePath + "/vault_sync_staging.db"
                val result = CoreInterop.syncDecryptVault(encryptedBytes, stagingDbPath, key)

                // Zero key immediately after use
                key.fill(0)

                if (result == 0) {
                    onProgress("Decryption successful! Preparing to finalize...")
                    return@withContext true
                } else {
                    val err = "Decryption failed (native code $result). Key mismatch or corrupted data."
                    Log.e(TAG, "Decryption failed with result: $result")
                    onProgress(err)
                }
            }
        } catch (e: java.net.SocketTimeoutException) {
            Log.e(TAG, "Sync timeout", e)
            onProgress("Connection timeout. Ensure both devices are on the same WiFi and no firewall/VPN is blocking the connection (Port: $port).")
            key.fill(0)
        } catch (e: java.net.ConnectException) {
            Log.e(TAG, "Sync connection refused", e)
            onProgress("Connection refused. Check if the Desktop sync server is active and listening on $ip.")
            key.fill(0)
        } catch (e: Exception) {
            Log.e(TAG, "Sync failed", e)
            onProgress("Sync error: ${e.message ?: "Unknown error"}")
            key.fill(0)
        }
        return@withContext false
    }

    fun finalizeSyncReplacement(context: Context): Boolean {
        try {
            val stagingDb = java.io.File(context.filesDir, "vault_sync_staging.db")
            val stagingSalt = java.io.File(context.filesDir, "vault_sync_staging.db.salt")

            val targetDb = java.io.File(context.filesDir, "vault.db")
            val targetSalt = java.io.File(context.filesDir, "vault.db.salt")

            if (stagingDb.exists() && stagingSalt.exists()) {
                Log.d(TAG, "Finalizing sync replacement. Staging DB size: ${stagingDb.length()}")

                // Nuclear option: delete old files first to ensure no locks
                if (targetDb.exists()) targetDb.delete()
                if (targetSalt.exists()) targetSalt.delete()

                stagingDb.copyTo(targetDb, overwrite = true)
                stagingSalt.copyTo(targetSalt, overwrite = true)

                stagingDb.delete()
                stagingSalt.delete()

                Log.d(TAG, "Sync finalization complete.")
                return true
            } else {
                Log.e(TAG, "Staging files missing during finalization!")
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to finalize sync replacement", e)
        }
        return false
    }

    private fun hexToBytes(hex: String): ByteArray {
        val result = ByteArray(hex.length / 2)
        for (i in result.indices) {
            result[i] = hex.substring(i * 2, i * 2 + 2).toInt(16).toByte()
        }
        return result
    }
}
