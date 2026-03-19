#include "database.h"
#include "key_derivation.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef HAVE_SQLCIPHER_SUBDIR
  #include <sqlcipher/sqlite3.h>
#elif defined(HAVE_SQLCIPHER_HEADER)
  #include <sqlcipher.h>
#else
  #include <sqlite3.h>
#endif
#include <sodium.h>

// Explicitly declare SQLCipher extensions if not picked up from header
#ifndef SQLITE_HAS_CODEC
SQLITE_API int sqlite3_key(sqlite3 *db, const void *pKey, int nKey);
SQLITE_API int sqlite3_rekey(sqlite3 *db, const void *pKey, int nKey);
#endif

static sqlite3 *db = NULL;
static char current_db_path[2048] = {0};

static int initialize_schema(void) {
    char *err_msg = 0;
    const char *sql = "CREATE TABLE IF NOT EXISTS passwords ("
                      "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                      "service TEXT NOT NULL,"
                      "username TEXT NOT NULL,"
                      "password TEXT NOT NULL,"
                      "totp_secret TEXT,"
                      "recovery_codes TEXT,"
                      "pwned_count INTEGER DEFAULT -1"
                      ");";

    int rc = sqlite3_exec(db, sql, 0, 0, &err_msg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", err_msg);
        sqlite3_free(err_msg);
        return -1;
    }

    // Migration for older databases missing pwned_count or recovery_codes
    const char* migrations[] = {
        "ALTER TABLE passwords ADD COLUMN recovery_codes TEXT;",
        "ALTER TABLE passwords ADD COLUMN pwned_count INTEGER DEFAULT -1;"
    };

    for (int i = 0; i < 2; i++) {
        rc = sqlite3_exec(db, migrations[i], 0, 0, &err_msg);
        if (rc != SQLITE_OK) {
            // Ignore "duplicate column name" errors
            sqlite3_free(err_msg);
        }
    }

    return 0;
}

int database_open(const char *db_path, const char *password, const char *salt_path) {
    database_close(); // Ensure any previously open database is closed

    unsigned char salt[SALT_LEN];
    unsigned char key[KEY_LEN];

    if (load_or_generate_salt(salt_path, salt) != 0) {
        return -1;
    }

    if (derive_key(password, salt, key) != 0) {
        return -1;
    }

    int rc = sqlite3_open(db_path, &db);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        database_close();
        sodium_memzero(key, KEY_LEN);
        return -1;
    }

    rc = sqlite3_key(db, key, KEY_LEN);
    sodium_memzero(key, KEY_LEN);

    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to set database key: %s\n", sqlite3_errmsg(db));
        database_close();
        return -1;
    }

    // Handle busy locks from concurrent background operations
    sqlite3_busy_timeout(db, 5000);

    // Test if the key is correct by trying to access the database
    if (sqlite3_exec(db, "SELECT count(*) FROM sqlite_master;", NULL, NULL, NULL) != SQLITE_OK) {
        fputs("Invalid key or database file is corrupted.\n", stderr);
        database_close();
        return -1;
    }

    strncpy(current_db_path, db_path, sizeof(current_db_path) - 1);
    return initialize_schema();
}

void database_close(void) {
    if (db) {
        sqlite3_close(db);
        db = NULL;
    }
    memset(current_db_path, 0, sizeof(current_db_path));
}

PasswordEntry* database_get_all(int *count) {
    if (!db) return NULL;

    sqlite3_stmt *stmt;
    const char *count_sql = "SELECT COUNT(*) FROM passwords";
    if (sqlite3_prepare_v2(db, count_sql, -1, &stmt, NULL) != SQLITE_OK) {
        return NULL;
    }

    if (sqlite3_step(stmt) != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return NULL;
    }

    *count = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);

    if (*count == 0) return NULL;

    PasswordEntry *entries = calloc(*count, sizeof(PasswordEntry));
    if (!entries) return NULL;

    const char *sql = "SELECT id, service, username, password, totp_secret, recovery_codes, pwned_count FROM passwords ORDER BY service COLLATE NOCASE ASC, username COLLATE NOCASE ASC";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        free(entries);
        return NULL;
    }

    int i = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW && i < *count) {
        entries[i].id = sqlite3_column_int(stmt, 0);
        const unsigned char *s = sqlite3_column_text(stmt, 1);
        const unsigned char *u = sqlite3_column_text(stmt, 2);
        const unsigned char *p = sqlite3_column_text(stmt, 3);
        const unsigned char *ts = sqlite3_column_text(stmt, 4);
        const unsigned char *rc = sqlite3_column_text(stmt, 5);

        entries[i].service = s ? strdup((const char *)s) : strdup("");
        entries[i].username = u ? strdup((const char *)u) : strdup("");
        entries[i].password = p ? strdup((const char *)p) : strdup("");
        entries[i].totp_secret = ts ? strdup((const char *)ts) : strdup("");
        entries[i].recovery_codes = rc ? strdup((const char *)rc) : strdup("");
        entries[i].pwned_count = sqlite3_column_int(stmt, 6);
        i++;
    }

    sqlite3_finalize(stmt);
    return entries;
}

PasswordEntry* database_search(const char *query, int *count) {
    if (!db || !query) return NULL;

    sqlite3_stmt *stmt;
    char like_query[1024];
    snprintf(like_query, sizeof(like_query), "%%%s%%", query);

    const char *count_sql = "SELECT COUNT(*) FROM passwords WHERE service LIKE ? OR username LIKE ?";
    if (sqlite3_prepare_v2(db, count_sql, -1, &stmt, NULL) != SQLITE_OK) {
        return NULL;
    }
    sqlite3_bind_text(stmt, 1, like_query, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, like_query, -1, SQLITE_TRANSIENT);

    if (sqlite3_step(stmt) != SQLITE_ROW) {
        *count = 0;
        sqlite3_finalize(stmt);
        return NULL;
    }
    *count = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);

    if (*count == 0) return NULL;

    PasswordEntry *entries = calloc(*count, sizeof(PasswordEntry));
    if (!entries) return NULL;

    const char *search_sql = "SELECT id, service, username FROM passwords WHERE service LIKE ? OR username LIKE ? ORDER BY service COLLATE NOCASE ASC";
    if (sqlite3_prepare_v2(db, search_sql, -1, &stmt, NULL) != SQLITE_OK) {
        free(entries);
        return NULL;
    }
    sqlite3_bind_text(stmt, 1, like_query, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, like_query, -1, SQLITE_TRANSIENT);

    int i = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW && i < *count) {
        entries[i].id = sqlite3_column_int(stmt, 0);
        const unsigned char *s = sqlite3_column_text(stmt, 1);
        const unsigned char *u = sqlite3_column_text(stmt, 2);
        entries[i].service = s ? strdup((const char *)s) : strdup("");
        entries[i].username = u ? strdup((const char *)u) : strdup("");
        entries[i].password = NULL;
        entries[i].totp_secret = NULL;
        entries[i].recovery_codes = NULL;
        entries[i].pwned_count = -1;
        i++;
    }

    sqlite3_finalize(stmt);
    return entries;
}

PasswordEntry* database_get_entry_by_identity(const char *service, const char *username) {
    if (!db || !service || !username) return NULL;

    sqlite3_stmt *stmt;
    const char *sql = "SELECT id, service, username, password, totp_secret, recovery_codes, pwned_count FROM passwords WHERE LOWER(service) = LOWER(?) AND LOWER(username) = LOWER(?)";

    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        return NULL;
    }

    sqlite3_bind_text(stmt, 1, service, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, username, -1, SQLITE_TRANSIENT);

    if (sqlite3_step(stmt) != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return NULL;
    }

    PasswordEntry *entry = calloc(1, sizeof(PasswordEntry));
    if (!entry) {
        sqlite3_finalize(stmt);
        return NULL;
    }

    entry->id = sqlite3_column_int(stmt, 0);
    const unsigned char *s = sqlite3_column_text(stmt, 1);
    const unsigned char *u = sqlite3_column_text(stmt, 2);
    const unsigned char *p = sqlite3_column_text(stmt, 3);
    const unsigned char *ts = sqlite3_column_text(stmt, 4);
    const unsigned char *rc = sqlite3_column_text(stmt, 5);

    entry->service = s ? strdup((const char *)s) : strdup("");
    entry->username = u ? strdup((const char *)u) : strdup("");
    entry->password = p ? strdup((const char *)p) : strdup("");
    entry->totp_secret = ts ? strdup((const char *)ts) : strdup("");
    entry->recovery_codes = rc ? strdup((const char *)rc) : strdup("");
    entry->pwned_count = sqlite3_column_int(stmt, 6);

    sqlite3_finalize(stmt);
    return entry;
}

PasswordEntry* database_get_by_id(int id) {
    if (!db) return NULL;

    sqlite3_stmt *stmt;
    const char *sql = "SELECT id, service, username, password, totp_secret, recovery_codes, pwned_count FROM passwords WHERE id = ?";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        return NULL;
    }

    sqlite3_bind_int(stmt, 1, id);

    if (sqlite3_step(stmt) != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return NULL;
    }

    PasswordEntry *entry = calloc(1, sizeof(PasswordEntry));
    if (!entry) {
        sqlite3_finalize(stmt);
        return NULL;
    }

    entry->id = sqlite3_column_int(stmt, 0);
    const unsigned char *s = sqlite3_column_text(stmt, 1);
    const unsigned char *u = sqlite3_column_text(stmt, 2);
    const unsigned char *p = sqlite3_column_text(stmt, 3);
    const unsigned char *ts = sqlite3_column_text(stmt, 4);
    const unsigned char *rc = sqlite3_column_text(stmt, 5);

    entry->service = s ? strdup((const char *)s) : strdup("");
    entry->username = u ? strdup((const char *)u) : strdup("");
    entry->password = p ? strdup((const char *)p) : strdup("");
    entry->totp_secret = ts ? strdup((const char *)ts) : strdup("");
    entry->recovery_codes = rc ? strdup((const char *)rc) : strdup("");
    entry->pwned_count = sqlite3_column_int(stmt, 6);

    sqlite3_finalize(stmt);
    return entry;
}

int database_add(PasswordEntry *entry) {
    if (!db) return -1;

    sqlite3_stmt *stmt;
    const char *sql = "INSERT INTO passwords (service, username, password, totp_secret, recovery_codes, pwned_count) VALUES (?, ?, ?, ?, ?, ?);";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        return -1;
    }

    sqlite3_bind_text(stmt, 1, entry->service, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, entry->username, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, entry->password, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, entry->totp_secret, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 5, entry->recovery_codes, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 6, entry->pwned_count);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        return -1;
    }

    sqlite3_finalize(stmt);
    return 0;
}

int database_update(PasswordEntry *entry) {
    if (!db) return -1;

    sqlite3_stmt *stmt;
    const char *sql = "UPDATE passwords SET service = ?, username = ?, password = ?, totp_secret = ?, recovery_codes = ?, pwned_count = ? WHERE id = ?;";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        return -1;
    }

    sqlite3_bind_text(stmt, 1, entry->service, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, entry->username, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, entry->password, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, entry->totp_secret, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 5, entry->recovery_codes, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 6, entry->pwned_count);
    sqlite3_bind_int(stmt, 7, entry->id);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        return -1;
    }

    sqlite3_finalize(stmt);
    return 0;
}

int database_update_pwned_count(int id, int pwned_count) {
    if (!db) return -1;

    sqlite3_stmt *stmt;
    const char *sql = "UPDATE passwords SET pwned_count = ? WHERE id = ?;";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        return -1;
    }

    sqlite3_bind_int(stmt, 1, pwned_count);
    sqlite3_bind_int(stmt, 2, id);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        return -1;
    }

    sqlite3_finalize(stmt);
    return 0;
}

int database_delete(int id) {
    if (!db) return -1;

    sqlite3_stmt *stmt;
    const char *sql = "DELETE FROM passwords WHERE id = ?;";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        return -1;
    }

    sqlite3_bind_int(stmt, 1, id);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        return -1;
    }

    sqlite3_finalize(stmt);
    return 0;
}

void free_password_entries(PasswordEntry *entries, int count) {
    if (!entries) return;
    for (int i = 0; i < count; i++) {
        free_password_entry_secure(&entries[i]);
    }
    free(entries);
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

int database_change_password(const char *old_password, const char *new_password, const char *salt_path) {
    if (!db) return -1;

    unsigned char new_key[KEY_LEN];
    char salt_path_new[2048];
    snprintf(salt_path_new, sizeof(salt_path_new), "%s.new", salt_path);

    if (generate_new_salt_and_key(new_password, salt_path_new, new_key) != 0) {
        return -1;
    }

    int rc = sqlite3_rekey(db, new_key, KEY_LEN);
    sodium_memzero(new_key, KEY_LEN);

    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to rekey database: %s\n", sqlite3_errmsg(db));
        remove(salt_path_new);
        return -1;
    }

    if (rename(salt_path_new, salt_path) != 0) {
        fputs("Failed to rename new salt file.\n", stderr);
        return -1;
    }

    return 0;
}
