#ifndef DATABASE_H
#define DATABASE_H

#include <sqlite3.h>
#include "sync_protocol.h"

/**
 * @brief Structure representing a password entry.
 */
typedef struct {
    int id;             /**< Unique ID of the entry in the database. */
    char *service;      /**< Name of the service (e.g., "Google", "GitHub"). */
    char *username;     /**< Username for the service. */
    char *password;     /**< Plaintext password (stored encrypted in DB). */
    char *totp_secret;  /**< Base32 TOTP secret. */
    char *recovery_codes; /**< Recovery codes or additional notes. */
    int pwned_count;    /**< Number of times the password was found in breaches. -1 for not checked. */
    long long updated_at; /**< Unix timestamp of the last local modification (sync causality). */
} PasswordEntry;

/**
 * @brief Opens and initializes the database.
 * 
 * @param db_path Path to the SQLite database file.
 * @param password Master password used to derive the encryption key.
 * @param salt_path Path to the salt file used for key derivation.
 * @return 0 on success, -1 on failure.
 */
int database_open(const char *db_path, const char *password, const char *salt_path);

/**
 * @brief Closes the database and wipes the encryption key from memory.
 */
void database_close(void);

/**
 * @brief Retrieves all password entries from the database.
 * 
 * @param count A pointer to an integer that will be filled with the number of entries.
 * @return A dynamically allocated array of PasswordEntry structs. The caller is responsible for freeing this array and its contents using free_password_entries().
 */
PasswordEntry* database_get_all(int *count);

/**
 * @brief Searches for password entries by service or username.
 *
 * @param query The search query string.
 * @param count A pointer to an integer that will be filled with the number of entries.
 * @return A dynamically allocated array of PasswordEntry structs. The caller is responsible for freeing this array and its contents using free_password_entries().
 */
PasswordEntry* database_search(const char *query, int *count);

/**
 * @brief Retrieves a password entry by its identity (Service + Username).
 *
 * @param service The name of the service.
 * @param username The username for the service.
 * @return A dynamically allocated PasswordEntry struct containing full details, or NULL if not found.
 */
PasswordEntry* database_get_entry_by_identity(const char *service, const char *username);

/**
 * @brief Retrieves a single password entry by its ID.
 * 
 * @param id The ID of the entry to retrieve.
 * @return A dynamically allocated PasswordEntry struct, or NULL if not found.
 */
PasswordEntry* database_get_by_id(int id);

/**
 * @brief Adds a new password entry to the database.
 * 
 * @param entry A PasswordEntry struct containing the service, username, password, and optional TOTP/recovery info.
 * @return 0 on success, -1 on failure.
 */
int database_add(PasswordEntry *entry);

/**
 * @brief Updates an existing password entry.
 * 
 * @param entry A PasswordEntry struct with a valid ID and updated fields.
 * @return 0 on success, -1 on failure.
 */
int database_update(PasswordEntry *entry);

/**
 * @brief Updates only the pwned count for an entry.
 *
 * @param id The ID of the entry.
 * @param pwned_count The new pwned count.
 * @return 0 on success, -1 on error.
 */
int database_update_pwned_count(int id, int pwned_count);

/**
 * @brief Deletes a password entry from the database.
 * 
 * @param id The ID of the entry to delete.
 * @return 0 on success, -1 on failure.
 */
int database_delete(int id);

/**
 * @brief Retrieves all deletion tombstones recorded in the database.
 *
 * Tombstones remember which (service, username) pairs were deleted and when,
 * so deletions can propagate during 2-way sync.
 *
 * @param count A pointer to an integer that will be filled with the number of tombstones.
 * @return A dynamically allocated array of sync_tombstone_t structs.
 */
sync_tombstone_t* database_get_tombstones(int *count);

/**
 * @brief Records or refreshes a deletion tombstone (used by the sync engine
 *        when applying a deletion that originated on the peer device).
 *
 * @return 0 on success, -1 on failure.
 */
int database_record_tombstone(const char *service, const char *username, long long deleted_at);

/**
 * @brief OpenPGP key store: armored public/secret keys stored alongside
 *        the passwords. The label is the identity used by 2-way sync;
 *        deletions reuse the deleted_entries tombstone table with
 *        service == "GPG".
 */
typedef struct {
    int id;
    char *label;
    char *email;
    char *key_id;
    char *public_key;   /* ASCII-armored public key */
    char *private_key;  /* ASCII-armored secret key (may be empty) */
    long long updated_at;
} GpgKey;

int database_gpg_add(const GpgKey *key);
int database_gpg_update(const GpgKey *key);
int database_gpg_delete(int id);
GpgKey* database_gpg_get_all(int *count);
void database_gpg_free(GpgKey *keys, int count);

/**
 * @brief Frees the memory allocated for an array of PasswordEntry structs.
 * 
 * @param entries The array of PasswordEntry structs to free.
 * @param count The number of entries in the array.
 */
void free_password_entries(PasswordEntry *entries, int count);

/**
 * @brief Securely wipes and frees a single PasswordEntry struct.
 * 
 * @param entry Pointer to the PasswordEntry struct.
 */
void free_password_entry_secure(PasswordEntry *entry);

/**
 * @brief Changes the master password and re-encrypts the database.
 * 
 * @param old_password Current master password.
 * @param new_password New master password.
 * @param salt_path Path to the salt file.
 * @return 0 on success, -1 on failure.
 */
int database_change_password(const char *old_password, const char *new_password, const char *salt_path);

#endif // DATABASE_H
