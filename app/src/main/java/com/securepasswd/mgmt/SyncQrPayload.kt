package com.securepasswd.mgmt

import java.util.Base64

/**
 * Parser for the vsync2: QR payload produced by the desktop app:
 *
 *   vsync2:[IP]:[PORT]:[BASE64URL(64-byte pairing secret)]
 *
 * The pairing secret is 512 bits of CSPRNG entropy, valid for one session
 * only. The legacy `vsync:` one-way payload is not compatible.
 */
object SyncQrPayload {
    const val PREFIX = "vsync2:"
    const val PSK_LEN = 64 // 512-bit pairing secret

    data class Payload(val ip: String, val port: Int, val psk: ByteArray)

    fun parse(content: String): Payload? {
        if (!content.startsWith(PREFIX)) return null
        val parts = content.removePrefix(PREFIX).split(":")
        if (parts.size != 3) return null

        val ip = parts[0].trim()
        if (ip.isEmpty()) return null

        val port = parts[1].toIntOrNull() ?: return null
        if (port !in 1..65535) return null

        val psk = base64UrlDecode(parts[2]) ?: return null
        if (psk.size != PSK_LEN) return null

        return Payload(ip, port, psk)
    }

    fun isLegacyPayload(content: String): Boolean = content.startsWith("vsync:")

    /** Unpadded URL-safe Base64 (matches the desktop's Base64Url encoding). */
    fun base64UrlDecode(s: String): ByteArray? = try {
        val normalized = s.trim().padEnd((s.length + 3) / 4 * 4, '=')
        Base64.getUrlDecoder().decode(normalized)
    } catch (_: IllegalArgumentException) {
        null
    }
}
