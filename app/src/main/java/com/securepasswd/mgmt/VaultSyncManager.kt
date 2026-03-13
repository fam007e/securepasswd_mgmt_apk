package com.securepasswd.mgmt

import android.content.Context
import android.net.Uri
import java.io.*
import java.util.zip.ZipEntry
import java.util.zip.ZipInputStream
import java.util.zip.ZipOutputStream

object VaultSyncManager {
    private const val VAULT_NAME = "vault.db"
    private const val SALT_NAME = "vault.db.salt"
    private const val EXPORT_FILENAME = "vault.spmgmt"

    fun exportVault(context: Context): Uri? {
        val vaultFile = File(context.filesDir, VAULT_NAME)
        val saltFile = File(context.filesDir, SALT_NAME)

        if (!vaultFile.exists() || !saltFile.exists()) return null

        val exportFile = File(context.cacheDir, EXPORT_FILENAME)

        try {
            ZipOutputStream(FileOutputStream(exportFile)).use { zos ->
                addToZip(zos, vaultFile, VAULT_NAME)
                addToZip(zos, saltFile, SALT_NAME)
            }
            return androidx.core.content.FileProvider.getUriForFile(
                context,
                "${context.packageName}.fileprovider",
                exportFile
            )
        } catch (e: Exception) {
            e.printStackTrace()
            return null
        }
    }

    fun importVault(context: Context, uri: Uri): Boolean {
        try {
            context.contentResolver.openInputStream(uri)?.use { inputStream ->
                ZipInputStream(inputStream).use { zis ->
                    var entry: ZipEntry? = zis.nextEntry
                    while (entry != null) {
                        val outFile = File(context.filesDir, entry.name)
                        // Safety check: only allow vault and salt files
                        if (entry.name == VAULT_NAME || entry.name == SALT_NAME) {
                            FileOutputStream(outFile).use { fos ->
                                zis.copyTo(fos)
                            }
                        }
                        zis.closeEntry()
                        entry = zis.nextEntry
                    }
                }
            }
            return true
        } catch (e: Exception) {
            e.printStackTrace()
            return false
        }
    }

    private fun addToZip(zos: ZipOutputStream, file: File, entryName: String) {
        val entry = ZipEntry(entryName)
        zos.putNextEntry(entry)
        FileInputStream(file).use { fis ->
            fis.copyTo(zos)
        }
        zos.closeEntry()
    }
}
