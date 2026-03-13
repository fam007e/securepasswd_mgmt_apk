#ifndef TOTP_H
#define TOTP_H

#include <stdint.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Generates a 6-digit TOTP code from a base32-encoded secret for the current time.
 *
 * @param base32_secret The base32-encoded TOTP secret.
 * @return A dynamically allocated string containing the 6-digit TOTP code. The caller is responsible for freeing this string.
 */
char* generate_totp_code(const char *base32_secret);

/**
 * @brief Generates a 6-digit TOTP code from a base32-encoded secret for a specific time.
 *
 * @param base32_secret The base32-encoded TOTP secret.
 * @param current_time The time to generate the TOTP code for.
 * @return A dynamically allocated string containing the 6-digit TOTP code. The caller is responsible for freeing this string.
 */
char* generate_totp_code_at_time(const char *base32_secret, time_t current_time);

#ifdef __cplusplus
}
#endif

#endif // TOTP_H
