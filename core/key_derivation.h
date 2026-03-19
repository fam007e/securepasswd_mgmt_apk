#ifndef KEY_DERIVATION_H
#define KEY_DERIVATION_H

#include <stdint.h>
#include <stddef.h>

#define SALT_LEN 16
#define KEY_LEN 32

/**
 * @brief Derives an encryption key from a password and salt using Argon2id.
 * 
 * @param password The master password.
 * @param salt The 16-byte salt.
 * @param key Pointer to a 32-byte buffer to store the derived key.
 * @return 0 on success, argon2 error code on failure.
 */
int derive_key(const char *password, const uint8_t *salt, uint8_t *key);

/**
 * @brief Loads a salt from a file, or generates and saves a new one if it doesn't exist.
 * 
 * @param path Path to the salt file.
 * @param salt Pointer to a 16-byte buffer to store the salt.
 * @return 0 on success, -1 on failure.
 */
int load_or_generate_salt(const char *path, uint8_t *salt);

/**
 * @brief Saves a salt to a file.
 * 
 * @param path Path to the salt file.
 * @param salt Pointer to the 16-byte salt to save.
 * @return 0 on success, -1 on failure.
 */
int save_salt(const char *path, const uint8_t *salt);

/**
 * @brief Generates a new salt and derives a new key.
 * 
 * @param password The master password.
 * @param salt_path Path to the salt file.
 * @param key Pointer to a 32-byte buffer to store the derived key.
 * @return 0 on success, -1 on failure.
 */
int generate_new_salt_and_key(const char *password, const char *salt_path, uint8_t *key);

#endif // KEY_DERIVATION_H
