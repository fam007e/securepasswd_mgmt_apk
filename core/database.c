#include "database.h"
#include "key_derivation.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
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
        "ALTER TABLE passwords ADD COLUMN pwned_count INTEGER DEFAULT -1;",
        "ALTER TABLE passwords ADD COLUMN updated_at INTEGER DEFAULT 0;"
    };

    for (int i = 0; i < 3; i++) {
        rc = sqlite3_exec(db, migrations[i], 0, 0, &err_msg);
        if (rc != SQLITE_OK) {
            // Ignore "duplicate column name" errors
            sqlite3_free(err_msg);
        }
    }

    // Backfill updated_at once when the column is first added so existing
    // entries participate in sync merges.
    rc = sqlite3_exec(db,
        "UPDATE passwords SET updated_at = CAST(strftime('%s', 'now') AS INTEGER) WHERE updated_at = 0;",
        0, 0, &err_msg);
    if (rc != SQLITE_OK) {
        sqlite3_free(err_msg);
    }

    // Deletion tombstones: remember which identities were removed and when,
    // so 2-way sync can propagate deletions instead of resurrecting entries.
    rc = sqlite3_exec(db,
        "CREATE TABLE IF NOT EXISTS deleted_entries ("
        "service TEXT NOT NULL, "
        "username TEXT NOT NULL, "
        "deleted_at INTEGER NOT NULL);",
        0, 0, &err_msg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error (deleted_entries): %s\n", err_msg);
        sqlite3_free(err_msg);
        return -1;
    }

    // OpenPGP key store (labels are unique merge identities).
    rc = sqlite3_exec(db,
        "CREATE TABLE IF NOT EXISTS gpg_keys ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "label TEXT NOT NULL, "
        "email TEXT, "
        "key_id TEXT, "
        "public_key TEXT, "
        "private_key TEXT, "
        "updated_at INTEGER DEFAULT 0);",
        0, 0, &err_msg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error (gpg_keys): %s\n", err_msg);
        sqlite3_free(err_msg);
        return -1;
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

    // Hardening pragmas (must run after sqlite3_key so the codec is active):
    //  - secure_delete: zero freed pages inside the encrypted file so deleted
    //    secrets do not linger; SQLITE_SECURE_DELETE makes this the default,
    //    this re-asserts it per connection.
    //  - cipher_memory_security: SQLCipher wipes its heap buffers after use.
    sqlite3_exec(db, "PRAGMA secure_delete = ON;", NULL, NULL, NULL);
    sqlite3_exec(db, "PRAGMA cipher_memory_security = ON;", NULL, NULL, NULL);

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

    const char *sql = "SELECT id, service, username, password, totp_secret, recovery_codes, pwned_count, updated_at FROM passwords ORDER BY service COLLATE NOCASE ASC, username COLLATE NOCASE ASC";
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
        entries[i].updated_at = (long long)sqlite3_column_int64(stmt, 7);
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
    const char *sql = "SELECT id, service, username, password, totp_secret, recovery_codes, pwned_count, updated_at FROM passwords WHERE LOWER(service) = LOWER(?) AND LOWER(username) = LOWER(?)";

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
    entry->updated_at = (long long)sqlite3_column_int64(stmt, 7);

    sqlite3_finalize(stmt);
    return entry;
}

PasswordEntry* database_get_by_id(int id) {
    if (!db) return NULL;

    sqlite3_stmt *stmt;
    const char *sql = "SELECT id, service, username, password, totp_secret, recovery_codes, pwned_count, updated_at FROM passwords WHERE id = ?";
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
    entry->updated_at = (long long)sqlite3_column_int64(stmt, 7);

    sqlite3_finalize(stmt);
    return entry;
}

int database_add(PasswordEntry *entry) {
    if (!db || !entry) return -1;

    // Re-adding an identity that was previously deleted on this device
    // must clear the tombstone so the entry survives the next sync.
    sqlite3_stmt *tomb_stmt;
    const char *tomb_sql = "DELETE FROM deleted_entries WHERE LOWER(service) = LOWER(?) AND LOWER(username) = LOWER(?);";
    if (sqlite3_prepare_v2(db, tomb_sql, -1, &tomb_stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(tomb_stmt, 1, entry->service ? entry->service : "", -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(tomb_stmt, 2, entry->username ? entry->username : "", -1, SQLITE_TRANSIENT);
        sqlite3_step(tomb_stmt);
        sqlite3_finalize(tomb_stmt);
    }

    long long now = entry->updated_at > 0 ? entry->updated_at : (long long)time(NULL);

    sqlite3_stmt *stmt;
    const char *sql = "INSERT INTO passwords (service, username, password, totp_secret, recovery_codes, pwned_count, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?);";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        return -1;
    }

    sqlite3_bind_text(stmt, 1, entry->service, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, entry->username, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, entry->password, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, entry->totp_secret, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 5, entry->recovery_codes, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 6, entry->pwned_count);
    sqlite3_bind_int64(stmt, 7, (sqlite3_int64)now);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        return -1;
    }

    sqlite3_finalize(stmt);
    return (int)sqlite3_last_insert_rowid(db);
}

int database_update(PasswordEntry *entry) {
    if (!db || !entry) return -1;

    long long now = entry->updated_at > 0 ? entry->updated_at : (long long)time(NULL);

    sqlite3_stmt *stmt;
    const char *sql = "UPDATE passwords SET service = ?, username = ?, password = ?, totp_secret = ?, recovery_codes = ?, pwned_count = ?, updated_at = ? WHERE id = ?;";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        return -1;
    }

    sqlite3_bind_text(stmt, 1, entry->service, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, entry->username, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, entry->password, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, entry->totp_secret, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 5, entry->recovery_codes, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 6, entry->pwned_count);
    sqlite3_bind_int64(stmt, 7, (sqlite3_int64)now);
    sqlite3_bind_int(stmt, 8, entry->id);

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

    // Record a deletion tombstone first so the removal can propagate
    // during 2-way sync instead of looking like a missing entry.
    sqlite3_stmt *stmt;
    const char *identity_sql = "SELECT service, username FROM passwords WHERE id = ?;";
    if (sqlite3_prepare_v2(db, identity_sql, -1, &stmt, NULL) != SQLITE_OK) {
        return -1;
    }
    sqlite3_bind_int(stmt, 1, id);

    char service[512] = {0};
    char username[512] = {0};
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const unsigned char *s = sqlite3_column_text(stmt, 0);
        const unsigned char *u = sqlite3_column_text(stmt, 1);
        if (s) snprintf(service, sizeof(service), "%s", (const char *)s);
        if (u) snprintf(username, sizeof(username), "%s", (const char *)u);
    }
    sqlite3_finalize(stmt);

    if (service[0] == '\0') {
        return -1; // Entry with this ID does not exist
    }

    database_record_tombstone(service, username, (long long)time(NULL));

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

sync_tombstone_t* database_get_tombstones(int *count) {
    if (!db || !count) return NULL;
    *count = 0;

    sqlite3_stmt *stmt;
    const char *sql = "SELECT service, username, deleted_at FROM deleted_entries";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        return NULL;
    }

    int cap = 8, n = 0;
    sync_tombstone_t *tombstones = calloc((size_t)cap, sizeof(sync_tombstone_t));
    if (!tombstones) {
        sqlite3_finalize(stmt);
        return NULL;
    }

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        if (n == cap) {
            cap *= 2;
            sync_tombstone_t *grown = realloc(tombstones, (size_t)cap * sizeof(sync_tombstone_t));
            if (!grown) {
                sync_tombstones_free(tombstones, n);
                sqlite3_finalize(stmt);
                return NULL;
            }
            tombstones = grown;
        }
        const unsigned char *s = sqlite3_column_text(stmt, 0);
        const unsigned char *u = sqlite3_column_text(stmt, 1);
        tombstones[n].service = strdup(s ? (const char *)s : "");
        tombstones[n].username = strdup(u ? (const char *)u : "");
        tombstones[n].deleted_at = (int64_t)sqlite3_column_int64(stmt, 2);
        if (!tombstones[n].service || !tombstones[n].username) {
            sync_tombstones_free(tombstones, n + 1);
            sqlite3_finalize(stmt);
            return NULL;
        }
        n++;
    }

    sqlite3_finalize(stmt);
    *count = n;
    return tombstones;
}

int database_record_tombstone(const char *service, const char *username, long long deleted_at) {
    if (!db || !service || !username) return -1;

    sqlite3_stmt *stmt;
    const char *del_sql = "DELETE FROM deleted_entries WHERE LOWER(service) = LOWER(?) AND LOWER(username) = LOWER(?);";
    if (sqlite3_prepare_v2(db, del_sql, -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, service, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, username, -1, SQLITE_TRANSIENT);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }

    const char *ins_sql = "INSERT INTO deleted_entries (service, username, deleted_at) VALUES (?, ?, ?);";
    if (sqlite3_prepare_v2(db, ins_sql, -1, &stmt, NULL) != SQLITE_OK) {
        return -1;
    }
    sqlite3_bind_text(stmt, 1, service, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, username, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 3, (sqlite3_int64)deleted_at);

    int rc = (sqlite3_step(stmt) == SQLITE_DONE) ? 0 : -1;
    sqlite3_finalize(stmt);
    return rc;
}

/* ---------------------- OpenPGP key store CRUD ---------------------- */

int database_gpg_add(const GpgKey *key) {
    if (!db || !key || !key->label || key->label[0] == '\0') return -1;

    sqlite3_stmt *tomb_stmt;
    const char *tomb_sql = "DELETE FROM deleted_entries WHERE LOWER(service) = 'gpg' AND LOWER(username) = LOWER(?);";
    if (sqlite3_prepare_v2(db, tomb_sql, -1, &tomb_stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(tomb_stmt, 1, key->label, -1, SQLITE_TRANSIENT);
        sqlite3_step(tomb_stmt);
        sqlite3_finalize(tomb_stmt);
    }

    long long now = key->updated_at > 0 ? key->updated_at : (long long)time(NULL);

    sqlite3_stmt *stmt;
    const char *sql = "INSERT INTO gpg_keys (label, email, key_id, public_key, private_key, updated_at) VALUES (?, ?, ?, ?, ?, ?);";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) return -1;
    sqlite3_bind_text(stmt, 1, key->label, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, key->email, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, key->key_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, key->public_key, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 5, key->private_key, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 6, (sqlite3_int64)now);
    int rc = (sqlite3_step(stmt) == SQLITE_DONE) ? (int)sqlite3_last_insert_rowid(db) : -1;
    sqlite3_finalize(stmt);
    return rc;
}

int database_gpg_update(const GpgKey *key) {
    if (!db || !key || key->id <= 0) return -1;

    long long now = key->updated_at > 0 ? key->updated_at : (long long)time(NULL);

    sqlite3_stmt *stmt;
    const char *sql = "UPDATE gpg_keys SET label = ?, email = ?, key_id = ?, public_key = ?, private_key = ?, updated_at = ? WHERE id = ?;";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) return -1;
    sqlite3_bind_text(stmt, 1, key->label, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, key->email, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, key->key_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, key->public_key, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 5, key->private_key, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 6, (sqlite3_int64)now);
    sqlite3_bind_int(stmt, 7, key->id);
    int rc = (sqlite3_step(stmt) == SQLITE_DONE) ? 0 : -1;
    sqlite3_finalize(stmt);
    return rc;
}

int database_gpg_delete(int id) {
    if (!db || id <= 0) return -1;

    sqlite3_stmt *stmt;
    const char *sel = "SELECT label FROM gpg_keys WHERE id = ?;";
    if (sqlite3_prepare_v2(db, sel, -1, &stmt, NULL) != SQLITE_OK) return -1;
    sqlite3_bind_int(stmt, 1, id);
    char label[512] = {0};
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const unsigned char *l = sqlite3_column_text(stmt, 0);
        // sqlite3_column_text always returns a NUL-terminated buffer.
        /* flawfinder: ignore */
        if (l) snprintf(label, sizeof(label), "%s", (const char *)l);
    }
    sqlite3_finalize(stmt);

    if (label[0] == '\0') return -1;

    // Tombstone with service "GPG" so deletions propagate during sync.
    database_record_tombstone("GPG", label, (long long)time(NULL));

    const char *sql = "DELETE FROM gpg_keys WHERE id = ?;";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) return -1;
    sqlite3_bind_int(stmt, 1, id);
    int rc = (sqlite3_step(stmt) == SQLITE_DONE) ? 0 : -1;
    sqlite3_finalize(stmt);
    return rc;
}

GpgKey* database_gpg_get_all(int *count) {
    if (!db || !count) return NULL;
    *count = 0;

    sqlite3_stmt *stmt;
    const char *sql = "SELECT id, label, email, key_id, public_key, private_key, updated_at FROM gpg_keys ORDER BY label COLLATE NOCASE ASC;";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) return NULL;

    int cap = 8, n = 0;
    GpgKey *keys = calloc((size_t)cap, sizeof(GpgKey));
    if (!keys) {
        sqlite3_finalize(stmt);
        return NULL;
    }

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        if (n == cap) {
            cap *= 2;
            GpgKey *grown = realloc(keys, (size_t)cap * sizeof(GpgKey));
            if (!grown) {
                database_gpg_free(keys, n);
                sqlite3_finalize(stmt);
                return NULL;
            }
            keys = grown;
        }
        GpgKey *k = &keys[n];
        k->id = sqlite3_column_int(stmt, 0);
        const unsigned char *label = sqlite3_column_text(stmt, 1);
        const unsigned char *email = sqlite3_column_text(stmt, 2);
        const unsigned char *key_id = sqlite3_column_text(stmt, 3);
        const unsigned char *pub = sqlite3_column_text(stmt, 4);
        const unsigned char *priv = sqlite3_column_text(stmt, 5);
        k->label = strdup(label ? (const char *)label : "");
        k->email = strdup(email ? (const char *)email : "");
        k->key_id = strdup(key_id ? (const char *)key_id : "");
        k->public_key = strdup(pub ? (const char *)pub : "");
        k->private_key = strdup(priv ? (const char *)priv : "");
        k->updated_at = (long long)sqlite3_column_int64(stmt, 6);
        if (!k->label || !k->email || !k->key_id || !k->public_key || !k->private_key) {
            database_gpg_free(keys, n + 1);
            sqlite3_finalize(stmt);
            return NULL;
        }
        n++;
    }

    sqlite3_finalize(stmt);
    *count = n;
    return keys;
}

void database_gpg_free(GpgKey *keys, int count) {
    if (!keys) return;
    for (int i = 0; i < count; i++) {
        sodium_memzero(keys[i].private_key,
                       keys[i].private_key ? strlen(keys[i].private_key) : 0);
        free(keys[i].label);
        free(keys[i].email);
        free(keys[i].key_id);
        free(keys[i].public_key);
        free(keys[i].private_key);
    }
    free(keys);
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
