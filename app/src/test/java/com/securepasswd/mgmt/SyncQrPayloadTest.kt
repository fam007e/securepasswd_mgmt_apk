package com.securepasswd.mgmt

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.SecureRandom

class SyncQrPayloadTest {

    @Test
    fun `parses valid vsync2 payload with unpadded base64url`() {
        val psk = ByteArray(64)
        SecureRandom().nextBytes(psk)
        // Unpadded URL-safe encoding, as produced by the desktop app.
        val encoded = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(psk)
        val payload = SyncQrPayload.parse("vsync2:192.168.1.50:33261:$encoded")

        assertEquals("192.168.1.50", payload?.ip)
        assertEquals(33261, payload?.port)
        assertArrayEquals(psk, payload?.psk)
    }

    @Test
    fun `parses padded base64url too`() {
        val psk = ByteArray(64) { it.toByte() }
        val encoded = java.util.Base64.getUrlEncoder().encodeToString(psk)
        val payload = SyncQrPayload.parse("vsync2:10.0.0.2:8080:$encoded")
        assertArrayEquals(psk, payload?.psk)
    }

    @Test
    fun `rejects wrong psk length`() {
        val short = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(32))
        assertNull(SyncQrPayload.parse("vsync2:192.168.1.50:33261:$short"))
    }

    @Test
    fun `rejects legacy vsync payload`() {
        assertNull(SyncQrPayload.parse("vsync:192.168.1.50:33261:aabbccdd"))
        assertTrue(SyncQrPayload.isLegacyPayload("vsync:192.168.1.50:33261:aabbccdd"))
        assertFalse(SyncQrPayload.isLegacyPayload("vsync2:192.168.1.50:33261:AAAA"))
    }

    @Test
    fun `rejects malformed payloads`() {
        assertNull(SyncQrPayload.parse("not-a-sync-code"))
        assertNull(SyncQrPayload.parse("vsync2:192.168.1.50:notaport:AAAA"))
        assertNull(SyncQrPayload.parse("vsync2:192.168.1.50:0:AAAA"))
        assertNull(SyncQrPayload.parse("vsync2:192.168.1.50:70000:AAAA"))
        assertNull(SyncQrPayload.parse("vsync2::33261:AAAA"))
        assertNull(SyncQrPayload.parse("vsync2:192.168.1.50:33261:!!!not-base64!!!"))
    }
}
