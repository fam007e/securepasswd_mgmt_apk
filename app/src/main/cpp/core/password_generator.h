#ifndef PASSWORD_GENERATOR_H
#define PASSWORD_GENERATOR_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Generates a cryptographically secure random password.
 *
 * Uses libsodium's randombytes_buf for secure entropy and guarantees the
 * inclusion of at least one character from each enabled pool (upper, num, special)
 * using a secured Fisher-Yates shuffle.
 *
 * @param len The desired length of the password.
 * @param upper Whether to include uppercase letters.
 * @param num Whether to include numbers.
 * @param special Whether to include special characters (!@#$%^&*()).
 * @return A dynamically allocated string containing the password. The caller must free it.
 */
char *generate_password(int len, bool upper, bool num, bool special);

#ifdef __cplusplus
}
#endif

#endif // PASSWORD_GENERATOR_H
