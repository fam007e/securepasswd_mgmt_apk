package com.securepasswd.mgmt

import org.junit.Assert.assertEquals
import org.junit.Test

class PasswordEntryTest {
    @Test
    fun testPasswordEntryCreation() {
        val entry = PasswordEntry(
            id = 1,
            service = "ProtonMail",
            username = "user@proton.me",
            password = "SecurePassword123!".toByteArray(),
            totpSecret = "JBSWY3DPEHPK3PXP".toByteArray(),
            recoveryCodes = "1234\n5678".toByteArray()
        )

        assertEquals(1, entry.id)
        assertEquals("ProtonMail", entry.service)
        assertEquals("user@proton.me", entry.username)
        // Ensure defaults work
        val emptyEntry = PasswordEntry(2, "Test", "User")
        assert(emptyEntry.password.isEmpty())
        assert(emptyEntry.totpSecret.isEmpty())
    }
}
