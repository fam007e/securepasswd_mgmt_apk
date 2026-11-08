package com.securepasswd.mgmt

/**
 * An OpenPGP key stored in the vault (ASCII-armored). The label is the
 * identity used by 2-way sync; deletions propagate via tombstones.
 */
data class GpgKey(
    val id: Int = 0,
    val label: String,
    val email: String = "",
    val keyId: String = "",
    val publicKey: String = "",
    val privateKey: String = "",
    val updatedAt: Long = 0L
)
