#ifndef PWNED_CHECK_H
#define PWNED_CHECK_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Checks if a password has been pwned using the HIBP k-anonymity API.
 *
 * @param password The password to check.
 * @return The number of times the password has been pwned (0 if not found), 
 *         or -1 on network/API error.
 */
int is_password_pwned(const char *password);

#ifdef __cplusplus
}
#endif

#endif // PWNED_CHECK_H
