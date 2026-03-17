package com.securepasswd.mgmt

/**
 * Represents a conflict between two entries with the same service and username
 * but different data.
 */
data class MergeConflict(
    val localEntry: PasswordEntry,
    val incomingEntry: PasswordEntry
)

/**
 * The result of a merge analysis.
 */
data class MergeReport(
    val additions: List<PasswordEntry>,
    val identical: List<PasswordEntry>,
    val conflicts: List<MergeConflict>
)

object MergeManager {

    /**
     * Compares the current local vault entries with an incoming set of entries
     * (e.g., from a CSV import or a Sync staging file).
     *
     * An entry's identity is defined by [PasswordEntry.service] + [PasswordEntry.username].
     */
    fun analyzeMerge(
        localEntries: List<PasswordEntry>,
        incomingEntries: List<PasswordEntry>
    ): MergeReport {
        val additions = mutableListOf<PasswordEntry>()
        val identical = mutableListOf<PasswordEntry>()
        val conflicts = mutableListOf<MergeConflict>()

        // Create a map for fast lookup of local entries by identity
        val localMap = localEntries.associateBy { getIdentity(it) }

        for (incoming in incomingEntries) {
            val identity = getIdentity(incoming)
            val local = localMap[identity]

            if (local == null) {
                // Not found locally -> Addition
                additions.add(incoming)
            } else if (isDataIdentical(local, incoming)) {
                // Identity exists and data matches -> Identical (Skip)
                identical.add(incoming)
            } else {
                // Identity exists but data differs -> Conflict
                conflicts.add(MergeConflict(local, incoming))
            }
        }

        return MergeReport(additions, identical, conflicts)
    }

    private fun getIdentity(entry: PasswordEntry): String {
        return "${entry.service.lowercase()}:${entry.username.lowercase()}"
    }

    private fun isDataIdentical(local: PasswordEntry, incoming: PasswordEntry): Boolean {
        return local.password.contentEquals(incoming.password) &&
               local.totpSecret.contentEquals(incoming.totpSecret) &&
               local.recoveryCodes.contentEquals(incoming.recoveryCodes)
    }
}
