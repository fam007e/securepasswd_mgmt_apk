package com.securepasswd.mgmt

data class PasswordEntry(
    val id: Int,
    val service: String,
    val username: String,
    // NOTE: Secrets are stored as ByteArrays for memory safety.
    // They should be zeroed out as soon as they are no longer needed.
    val password: ByteArray = byteArrayOf(),
    val totpSecret: ByteArray = byteArrayOf(),
    val recoveryCodes: ByteArray = byteArrayOf(),
    val pwnedCount: Int = -1
) {
    fun wipe() {
        password.fill(0)
        totpSecret.fill(0)
        recoveryCodes.fill(0)
    }
}
