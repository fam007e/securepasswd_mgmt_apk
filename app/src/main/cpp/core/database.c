#ifdef _WIN32
#include <windows.h>
#endif
#include "database.h"
#include "key_derivation.h"
#include <sqlite3.h>

// SQLCipher functions are now provided by the linked library

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sodium.h>
#include <stdbool.h>

static sqlite3 *db = NULL;
static char current_db_path[4096] = {0}; // flawfinder: ignore

// Forward declaration for internal function
static int initialize_schema();


int database_open(const char *db_path, const char *password) {
    if (!db_path) {
        return -1;
    }
    strncpy(current_db_path, db_path, sizeof(current_db_path) - 1); // flawfinder: ignore

    uint8_t salt[SALT_LEN];
    uint8_t key[KEY_LEN];

    // Construct salt path
    char salt_path[4128]; // flawfinder: ignore
    snprintf(salt_path, sizeof(salt_path), "%s.salt", db_path); // flawfinder: ignore

    // Load or generate salt
    if (load_or_generate_salt(salt_path, salt) != 0) {
        fputs("Failed to load or generate salt.\n", stderr);
        return -1;
    }

    // Derive key
    if (derive_key(password, salt, key) != 0) {
        fputs("Failed to derive key.\n", stderr);
        return -1;
    }

    if (sqlite3_open(db_path, &db) != SQLITE_OK) {
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db)); // flawfinder: ignore
        sodium_memzero(key, KEY_LEN);
        return -1;
    }

    if (sqlite3_key(db, key, KEY_LEN) != SQLITE_OK) {
        fprintf(stderr, "Failed to set database key: %s\n", sqlite3_errmsg(db)); // flawfinder: ignore
        sqlite3_close(db);
        db = NULL;
        sodium_memzero(key, KEY_LEN);
        return -1;
    }


    // Test if the key is correct by trying to access the database
    if (sqlite3_exec(db, "SELECT count(*) FROM sqlite_master;", NULL, NULL, NULL) != SQLITE_OK) {
        fputs("Invalid key or database file is corrupted.\n", stderr);
        sqlite3_close(db);
        db = NULL;
        sodium_memzero(key, KEY_LEN);
        return -1;
    }

    sodium_memzero(key, KEY_LEN);
    int res = initialize_schema();
    return res;
}

void database_close() {
    if (db) {
        sqlite3_close(db);
        db = NULL;
    }
}

PasswordEntry* database_get_all_entries(int *count) {
    if (!db) return NULL;

    sqlite3_stmt *stmt;
    // First, get the count of entries
    if (sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM passwords", -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db)); // flawfinder: ignore
        return NULL;
    }
    if (sqlite3_step(stmt) != SQLITE_ROW) {
        *count = 0;
        sqlite3_finalize(stmt);
        return NULL;
    }
    *count = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);

    if (*count == 0) {
        return NULL;
    }

    PasswordEntry *entries = malloc(*count * sizeof(PasswordEntry));
    if (!entries) {
        fputs("Failed to allocate memory for entries\n", stderr);
        return NULL;
    }

    // Then, get metadata and password (required for health check in list view)
    // TOTP and recovery codes remain intentionally NOT retrieved here.
    if (sqlite3_prepare_v2(db, "SELECT id, service, username, password, pwned_count FROM passwords", -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db)); // flawfinder: ignore
        free(entries);
        return NULL;
    }

    int i = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        entries[i].id = sqlite3_column_int(stmt, 0);
        const unsigned char *service = sqlite3_column_text(stmt, 1);
        const unsigned char *username = sqlite3_column_text(stmt, 2);
        const unsigned char *password = sqlite3_column_text(stmt, 3);
        entries[i].pwned_count = sqlite3_column_int(stmt, 4);

        entries[i].service = service ? strdup((const char *)service) : strdup("");
        entries[i].username = username ? strdup((const char *)username) : strdup("");
        entries[i].password = password ? strdup((const char *)password) : strdup("");

        // Initialize secrets to NULL/Empty since we didn't fetch them
        entries[i].totp_secret = NULL;
        entries[i].recovery_codes = NULL;
        i++;
    }

    sqlite3_finalize(stmt);
    return entries;
}

void free_password_entry_secure(PasswordEntry *entry) {
    if (!entry) return;
    if (entry->service) {
        sodium_memzero(entry->service, strlen(entry->service));
        free(entry->service);
    }
    if (entry->username) {
        sodium_memzero(entry->username, strlen(entry->username));
        free(entry->username);
    }
    if (entry->password) {
        sodium_memzero(entry->password, strlen(entry->password));
        free(entry->password);
    }
    if (entry->totp_secret) {
        sodium_memzero(entry->totp_secret, strlen(entry->totp_secret));
        free(entry->totp_secret);
    }
    if (entry->recovery_codes) {
        sodium_memzero(entry->recovery_codes, strlen(entry->recovery_codes));
        free(entry->recovery_codes);
    }
}

PasswordEntry* database_get_entry_secure(int id) {
    if (!db) return NULL;

    sqlite3_stmt *stmt;
    const char *sql = "SELECT id, service, username, password, totp_secret, recovery_codes, pwned_count FROM passwords WHERE id = ?";

    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db)); // flawfinder: ignore
        return NULL;
    }

    sqlite3_bind_int(stmt, 1, id);

    if (sqlite3_step(stmt) != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return NULL; // Not found
    }

    PasswordEntry *entry = malloc(sizeof(PasswordEntry));
    if (!entry) {
        sqlite3_finalize(stmt);
        return NULL;
    }

    entry->id = sqlite3_column_int(stmt, 0);
    const unsigned char *service = sqlite3_column_text(stmt, 1);
    const unsigned char *username = sqlite3_column_text(stmt, 2);
    const unsigned char *password = sqlite3_column_text(stmt, 3);
    const unsigned char *totp_secret = sqlite3_column_text(stmt, 4);
    const unsigned char *recovery_codes = sqlite3_column_text(stmt, 5);

    entry->service = service ? strdup((const char *)service) : strdup("");
    entry->username = username ? strdup((const char *)username) : strdup("");
    entry->password = password ? strdup((const char *)password) : strdup("");
    entry->totp_secret = totp_secret ? strdup((const char *)totp_secret) : strdup("");
    entry->recovery_codes = recovery_codes ? strdup((const char *)recovery_codes) : strdup("");
    entry->pwned_count = sqlite3_column_int(stmt, 6);

    sqlite3_finalize(stmt);
    return entry;
}

int database_add_entry(const PasswordEntry *entry) {
    if (!db) return -1;

    sqlite3_stmt *stmt;
    const char *sql = "INSERT INTO passwords (service, username, password, totp_secret, recovery_codes, pwned_count) VALUES (?, ?, ?, ?, ?, ?);";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db)); // flawfinder: ignore
        return -1;
    }

    sqlite3_bind_text(stmt, 1, entry->service, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, entry->username, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, entry->password, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, entry->totp_secret, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 5, entry->recovery_codes, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 6, entry->pwned_count);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        fprintf(stderr, "Failed to execute statement: %s\n", sqlite3_errmsg(db)); // flawfinder: ignore
        sqlite3_finalize(stmt);
        return -1;
    }

    sqlite3_finalize(stmt);
    return sqlite3_last_insert_rowid(db);
}

int database_update_entry(const PasswordEntry *entry) {
    if (!db) return -1;

    sqlite3_stmt *stmt;
    const char *sql = "UPDATE passwords SET service = ?, username = ?, password = ?, totp_secret = ?, recovery_codes = ?, pwned_count = ? WHERE id = ?;";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db)); // flawfinder: ignore
        return -1;
    }

    sqlite3_bind_text(stmt, 1, entry->service, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, entry->username, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, entry->password, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, entry->totp_secret, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 5, entry->recovery_codes, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 6, entry->pwned_count);
    sqlite3_bind_int(stmt, 7, entry->id);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        fprintf(stderr, "Failed to execute statement: %s\n", sqlite3_errmsg(db)); // flawfinder: ignore
        sqlite3_finalize(stmt);
        return -1;
    }

    sqlite3_finalize(stmt);
    return 0;
}

int database_delete_entry(int id) {
    if (!db) return -1;

    sqlite3_stmt *stmt;
    const char *sql = "DELETE FROM passwords WHERE id = ?;";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db)); // flawfinder: ignore
        return -1;
    }

    sqlite3_bind_int(stmt, 1, id);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        fprintf(stderr, "Failed to execute statement: %s\n", sqlite3_errmsg(db)); // flawfinder: ignore
        sqlite3_finalize(stmt);
        return -1;
    }

    // Check if any rows were actually deleted
    int changes = sqlite3_changes(db);
    sqlite3_finalize(stmt);

    if (changes == 0) {
        return -1; // Entry with this ID does not exist
    }

    return 0;
}

void free_password_entries(PasswordEntry *entries, int count) {
    if (!entries) return;
    for (int i = 0; i < count; i++) {
        free_password_entry_secure(&entries[i]);
    }
    free(entries);
}

static int initialize_schema() {
    char *err_msg = 0;
    const char *sql = "CREATE TABLE IF NOT EXISTS passwords ("
                        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
                        "service TEXT NOT NULL, "
                        "username TEXT NOT NULL, "
                        "password TEXT NOT NULL, "
                        "totp_secret TEXT, "
                        "recovery_codes TEXT,"
                        "pwned_count INTEGER DEFAULT -1);";
    if (sqlite3_exec(db, sql, 0, 0, &err_msg) != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", err_msg); // flawfinder: ignore
        sqlite3_free(err_msg);
        return -1;
    }

    // Migration: Check if recovery_codes column exists, if not add it
    sqlite3_stmt *stmt;
    bool has_recovery_codes = false;
    if (sqlite3_prepare_v2(db, "PRAGMA table_info(passwords)", -1, &stmt, NULL) == SQLITE_OK) {
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const unsigned char *name = sqlite3_column_text(stmt, 1);
            if (name && strcmp((const char *)name, "recovery_codes") == 0) {
                has_recovery_codes = true;
                break;
            }
        }
        sqlite3_finalize(stmt);
    }

    if (!has_recovery_codes) {
        const char *alter_sql = "ALTER TABLE passwords ADD COLUMN recovery_codes TEXT;";
        if (sqlite3_exec(db, alter_sql, 0, 0, &err_msg) != SQLITE_OK) {
            fprintf(stderr, "Migration error adding recovery_codes: %s\n", err_msg); // flawfinder: ignore
            sqlite3_free(err_msg);
        }
    }

    // Migration: Check if pwned_count column exists
    bool has_pwned_count = false;
    if (sqlite3_prepare_v2(db, "PRAGMA table_info(passwords)", -1, &stmt, NULL) == SQLITE_OK) {
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const unsigned char *name = sqlite3_column_text(stmt, 1);
            if (name && strcmp((const char *)name, "pwned_count") == 0) {
                has_pwned_count = true;
                break;
            }
        }
        sqlite3_finalize(stmt);
    }

    if (!has_pwned_count) {
        const char *alter_sql = "ALTER TABLE passwords ADD COLUMN pwned_count INTEGER DEFAULT -1;";
        if (sqlite3_exec(db, alter_sql, 0, 0, &err_msg) != SQLITE_OK) {
            fprintf(stderr, "Migration error adding pwned_count: %s\n", err_msg); // flawfinder: ignore
            sqlite3_free(err_msg);
        }
    }

    return 0;
}

int database_rekey(const char *new_password) {
    if (!db || current_db_path[0] == '\0') {
        return -1;
    }

    uint8_t new_salt[SALT_LEN];
    uint8_t new_key[KEY_LEN];

    // Generate new salt
    if (sodium_init() < 0) return -1;
    randombytes_buf(new_salt, SALT_LEN);

    // Derive new key
    if (derive_key(new_password, new_salt, new_key) != 0) {
        return -1;
    }

    // Attempt SQLCipher rekey
    if (sqlite3_rekey(db, new_key, KEY_LEN) != SQLITE_OK) {
        fprintf(stderr, "Failed to rekey database: %s\n", sqlite3_errmsg(db)); // flawfinder: ignore
        sodium_memzero(new_key, KEY_LEN);
        return -1;
    }

    sodium_memzero(new_key, KEY_LEN);

    // SQLCipher rekey succeeded, now update the salt file
    char salt_path[4128]; // flawfinder: ignore
    char salt_path_new[4128]; // flawfinder: ignore
    snprintf(salt_path, sizeof(salt_path), "%s.salt", current_db_path); // flawfinder: ignore
    snprintf(salt_path_new, sizeof(salt_path_new), "%s.salt.new", current_db_path); // flawfinder: ignore

    // Atomic-ish swap: write to .new then rename
    if (save_salt(salt_path_new, new_salt) != 0) {
        fprintf(stderr, "Failed to save new salt to %s\n", salt_path_new); // flawfinder: ignore
        return -1;
    }

#ifdef _WIN32
    if (!MoveFileExA(salt_path_new, salt_path, MOVEFILE_REPLACE_EXISTING)) {
#else
    if (rename(salt_path_new, salt_path) != 0) {
#endif
        fprintf(stderr, "Failed to rename new salt file.\n"); // flawfinder: ignore
        return -1;
    }

    return 0;
}
