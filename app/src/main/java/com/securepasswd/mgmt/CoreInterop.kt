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
        pwnedCount: Int,
        updatedAt: Long = 0L
    ): Int
    external fun databaseUpdateEntry(
        id: Int,
        service: String,
        username: String,
        password: ByteArray,
        totpSecret: ByteArray,
        recoveryCodes: ByteArray,
        pwnedCount: Int,
        updatedAt: Long = 0L
    ): Int
    external fun databaseUpdatePwnedCount(id: Int, pwnedCount: Int): Int
    external fun databaseDeleteEntry(id: Int): Int
    external fun generateTotp(secret: ByteArray): ByteArray
    external fun generatePassword(length: Int, useUpper: Boolean, useNum: Boolean, useSpecial: Boolean): ByteArray

    // ── Sync protocol v2 (implemented in the shared native module) ──
    /** Frame types, matching sync_frame_type_t in sync_protocol.h. */
    const val FRAME_CONFIRM = 0x01
    const val FRAME_REQUEST = 0x02
    const val FRAME_SNAPSHOT = 0x03
    const val FRAME_ACK = 0x04
    const val FRAME_ERROR = 0x05

    /** @return 64 bytes: 32-byte X25519 public key followed by the private key. */
    external fun syncEphemeralKeygen(): ByteArray?

    /**
     * Derives the session keys for the 2-way sync protocol.
     * @param role 0 = server (desktop), 1 = client (mobile)
     * @return opaque native session handle, or 0 on failure. Must be
     *         released with [syncSessionFree].
     */
    external fun syncSessionDerive(
        role: Int,
        psk: ByteArray,
        clientPub: ByteArray,
        serverPub: ByteArray,
        ownPriv: ByteArray
    ): Long

    /** Encrypts one AEAD frame; null on failure. */
    external fun syncFrameEncrypt(handle: Long, type: Int, payload: ByteArray): ByteArray?

    /** Decrypts and authenticates one AEAD frame; null on failure/replay. */
    external fun syncFrameDecrypt(handle: Long, expectedType: Int, frame: ByteArray): ByteArray?

    /** Zeroes and frees a session handle obtained from [syncSessionDerive]. */
    external fun syncSessionFree(handle: Long)

    /** Fetches this device's deletion tombstones for the outgoing snapshot. */
    external fun syncGetLocalTombstones(): Array<SyncTombstone>?

    /** Fetches the 32-byte transcript hash for the handshake confirmation. */
    external fun syncGetTranscriptHash(handle: Long): ByteArray?

    /** Serializes the current open vault entries and tombstones into snapshot bytes. */
    external fun syncBuildLocalSnapshot(): ByteArray?

    /**
     * Packs entries + tombstones into the platform-independent snapshot format.
     * Array lengths must match (updatedAts.size == services.size, tombTimes.size == tombServices.size).
     */
    external fun syncPackSnapshot(
        services: Array<String>,
        usernames: Array<String>,
        passwords: Array<ByteArray>,
        totpSecrets: Array<ByteArray>,
        recoveryCodes: Array<ByteArray>,
        updatedAts: LongArray,
        tombServices: Array<String>,
        tombUsernames: Array<String>,
        tombTimes: LongArray
    ): ByteArray?

    /** Parses a snapshot into entries and tombstones; null on format errors. */
    external fun syncUnpackSnapshot(data: ByteArray): SyncSnapshot?
}
