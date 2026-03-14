package com.securepasswd.mgmt

import android.util.Log

object CoreInterop {
    init {
        try {
            System.loadLibrary("securepasswd_mgmt_apk")
            Log.d("CoreInterop", "Successfully loaded native library")
        } catch (e: UnsatisfiedLinkError) {
            Log.e("CoreInterop", "Failed to load native library: ${e.message}")
        }
    }

    external fun stringFromJNI(): String

    external fun databaseOpen(dbPath: String, password: ByteArray): Int
    external fun databaseClose()
    external fun databaseGetAllEntries(): Array<PasswordEntry>?
    external fun databaseGetEntry(id: Int): PasswordEntry?
    external fun databaseAddEntry(
        service: String,
        username: String,
        password: ByteArray,
        totpSecret: ByteArray,
        recoveryCodes: ByteArray,
        pwnedCount: Int
    ): Int
    external fun databaseUpdateEntry(
        id: Int,
        service: String,
        username: String,
        password: ByteArray,
        totpSecret: ByteArray,
        recoveryCodes: ByteArray,
        pwnedCount: Int
    ): Int
    external fun databaseUpdatePwnedCount(id: Int, pwnedCount: Int): Int
    external fun databaseDeleteEntry(id: Int): Int
    external fun generateTotp(secret: ByteArray): ByteArray
    external fun generatePassword(length: Int, useUpper: Boolean, useNum: Boolean, useSpecial: Boolean): ByteArray
    
    external fun syncEncryptVault(sourcePath: String, key: ByteArray): ByteArray?
    external fun syncDecryptVault(encryptedData: ByteArray, destinationPath: String, key: ByteArray): Int
}
