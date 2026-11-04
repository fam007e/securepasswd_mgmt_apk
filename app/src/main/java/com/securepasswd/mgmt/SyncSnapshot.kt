package com.securepasswd.mgmt

/**
 * A deletion tombstone received from the peer during 2-way sync.
 * Remembers which identity was deleted there and when, so deletions win
 * over older edits but never over newer ones.
 */
data class SyncTombstone(
    val service: String,
    val username: String,
    val deletedAt: Long
)

/**
 * A platform-independent vault snapshot exchanged during 2-way sync
 * (serialized/deserialized by the shared native sync protocol module).
 */
class SyncSnapshot(
    val entries: Array<PasswordEntry>,
    val tombstones: Array<SyncTombstone>
) {
    /** Zeroes secret material held by the parsed entries. */
    fun wipe() {
        entries.forEach { it.wipe() }
    }
}
