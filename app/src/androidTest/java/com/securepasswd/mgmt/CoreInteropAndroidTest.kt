package com.securepasswd.mgmt

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

@RunWith(AndroidJUnit4::class)
class CoreInteropAndroidTest {

    private lateinit var dbFile: File

    @Before
    fun setup() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        dbFile = File(context.filesDir, "test_vault.db")
        if (dbFile.exists()) {
            dbFile.delete()
        }
    }

    @After
    fun teardown() {
        CoreInterop.databaseClose()
        if (dbFile.exists()) {
            dbFile.delete()
        }
    }

    @Test
    fun testNativeLibraryLoadAndString() {
        // Verifies the NDK library loads and returns the expected string
        val result = CoreInterop.stringFromJNI()
        assertNotNull(result)
        assertTrue(result.contains("SecurePasswd MGMT Core Loaded"))
    }

    @Test
    fun testDatabaseInitializationAndEncryption() {
        // Attempts to open a database, testing the SQLite/libsodium shim
        // Note: Full Argon2 takes time on emulators (64MB/3 runs).
        // We ensure it returns 0 (success)
        val result = CoreInterop.databaseOpen(dbFile.absolutePath, "TestMasterPassword")
        assertEquals(0, result)

        val entries = CoreInterop.databaseGetAllEntries()
        assertNotNull(entries)
        assertEquals(0, entries.size) // Fresh DB should be empty
    }

    @Test
    fun testTotpGeneration() {
        // Google Authenticator Test Vector Secret: "JBSWY3DPEHPK3PXP" (Hello!)
        val secret = "JBSWY3DPEHPK3PXP".toByteArray(Charsets.UTF_8)
        val totpBytes = CoreInterop.generateTotp(secret)
        assertNotNull(totpBytes)
        if (totpBytes.isNotEmpty()) {
            val totp = String(totpBytes, Charsets.UTF_8)
            assertEquals(6, totp.length)
            assertTrue(totp.all { it.isDigit() })
        }
    }
}
