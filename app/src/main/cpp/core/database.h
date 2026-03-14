#ifndef DATABASE_H
#define DATABASE_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief A struct representing a password entry.
 */
typedef struct {
    int id;             /**< The unique ID of the entry. */
    char *service;      /**< The name of the service. */
    char *username;     /**< The username for the service. */
    char *password;     /**< The password for the service. */
    char *totp_secret;  /**< The TOTP secret for the service. */
    char *recovery_codes; /**< The recovery codes for the service (newline-separated). Used codes are prefixed with '*'. */
    int pwned_count;    /**< Number of times the password was found in breaches. -1 for not checked. */
} PasswordEntry;

/**
 * @brief Opens and initializes the database.
 *
 * @param db_path The path to the database file.
 * @param password The master password for the database.
 * @return 0 on success, -1 on error.
 */
int database_open(const char *db_path, const char *password);

/**
 * @brief Closes the database.
 */
void database_close();

/**
 * @brief Retrieves all password entries from the database.
 *
 * @param count A pointer to an integer that will be filled with the number of entries.
 * @return A dynamically allocated array of PasswordEntry structs. The caller is responsible for freeing this array and its contents using free_password_entries().
 */
PasswordEntry* database_get_all_entries(int *count);

/**
 * @brief Retrieves a single password entry with ALL details (including secrets) by ID.
 *
 * @param id The ID of the entry to retrieve.
 * @return A dynamically allocated PasswordEntry struct containing full details, or NULL if not found/error.
 *         The caller is responsible for freeing this struct using free_password_entry() (to be added) or manual free.
 */
PasswordEntry* database_get_entry_secure(int id);

/**
 * @brief Changes the master password of the database.
 *
 * @param new_password The new master password.
 * @return 0 on success, -1 on error.
 */
int database_rekey(const char *new_password);

/**
 * @brief Adds a new password entry to the database.
 *
 * @param entry A pointer to the PasswordEntry to add.
 * @return The ID of the new entry, or -1 on error.
 */
int database_add_entry(const PasswordEntry *entry);

/**
 * @brief Updates an existing password entry in the database.
 *
 * @param entry A pointer to the PasswordEntry to update.
 * @return 0 on success, -1 on error.
 */
int database_update_entry(const PasswordEntry *entry);

/**
 * @brief Updates only the pwned count for an entry.
 *
 * @param id The ID of the entry.
 * @param pwned_count The new pwned count.
 * @return 0 on success, -1 on error.
 */
int database_update_pwned_count(int id, int pwned_count);

/**
 * @brief Deletes a password entry from the database by its ID.
 *
 * @param id The ID of the entry to delete.
 * @return 0 on success, -1 on error.
 */
int database_delete_entry(int id);

/**
 * @brief Frees a list of PasswordEntry structs.
 *
 * @param entries The array of PasswordEntry structs to free.
 * @param count The number of entries in the array.
 */
void free_password_entries(PasswordEntry *entries, int count);


#ifdef __cplusplus
}
#endif

#endif // DATABASE_H
