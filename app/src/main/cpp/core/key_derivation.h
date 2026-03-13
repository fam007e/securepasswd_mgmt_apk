#ifndef KEY_DERIVATION_H
#define KEY_DERIVATION_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SALT_LEN 16
#define KEY_LEN 32

/**
 * @brief Derives a key from a password and salt using Argon2id.
 *
 * @param password The password to derive the key from.
 * @param salt The salt to use for key derivation.
 * @param key The buffer to store the derived key in. Must be KEY_LEN bytes.
 * @return 0 on success, -1 on error.
 */
int derive_key(const char *password, const uint8_t *salt, uint8_t *key);

/**
 * @brief Loads the salt from the specified path, or generates a new one if it doesn't exist.
 *
 * @param path The path to the salt file.
 * @param salt The buffer to store the loaded or generated salt in. Must be SALT_LEN bytes.
 * @return 0 on success, -1 on error.
 */
int load_or_generate_salt(const char *path, uint8_t *salt);

/**
 * @brief Saves the salt to the specified path.
 *
 * @param path The path to the salt file.
 * @param salt The salt to save. Must be SALT_LEN bytes.
 * @return 0 on success, -1 on error.
 */
int save_salt(const char *path, const uint8_t *salt);

#ifdef __cplusplus
}
#endif

#endif // KEY_DERIVATION_H
