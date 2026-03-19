#include "password_generator.h"
#include <string.h>
#include <sodium.h>
#include <stdlib.h>

char *generate_password(int len, bool upper, bool num, bool special) {
    if (sodium_init() < 0) {
        return NULL;
    }

    char *pw = malloc(len + 1);
    if (!pw) return NULL;

    const char *lower_set = "abcdefghijklmnopqrstuvwxyz";
    const char *upper_set = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const char *num_set = "0123456789";
    const char *special_set = "!@#$%^&*()";

    char charset[128]; // flawfinder: ignore
    size_t charset_len = 0;

    // Add lower_set
    size_t lower_len = strlen(lower_set); // flawfinder: ignore
    if (charset_len + lower_len < sizeof(charset) - 1) {
        memcpy(charset + charset_len, lower_set, lower_len); // flawfinder: ignore
        charset_len += lower_len;
    }

    int pos = 0;
    // Always include a lowercase
    pw[pos++] = lower_set[randombytes_uniform(lower_len)];

    if (upper) {
        size_t slen = strlen(upper_set); // flawfinder: ignore
        if (charset_len + slen < sizeof(charset) - 1) {
            memcpy(charset + charset_len, upper_set, slen); // flawfinder: ignore
            charset_len += slen;
        }
        if (pos < len) pw[pos++] = upper_set[randombytes_uniform((uint32_t)slen)];
    }
    if (num) {
        size_t slen = strlen(num_set); // flawfinder: ignore
        if (charset_len + slen < sizeof(charset) - 1) {
            memcpy(charset + charset_len, num_set, slen); // flawfinder: ignore
            charset_len += slen;
        }
        if (pos < len) pw[pos++] = num_set[randombytes_uniform((uint32_t)slen)];
    }
    if (special) {
        size_t slen = strlen(special_set); // flawfinder: ignore
        if (charset_len + slen < sizeof(charset) - 1) {
            memcpy(charset + charset_len, special_set, slen); // flawfinder: ignore
            charset_len += slen;
        }
        if (pos < len) pw[pos++] = special_set[randombytes_uniform((uint32_t)slen)];
    }
    charset[charset_len] = '\0';

    // Fill the rest of the password
    for (; pos < len; pos++) {
        pw[pos] = charset[randombytes_uniform(charset_len)];
    }

    // Shuffle the password to avoid predictable positions
    for (int i = len - 1; i > 0; i--) {
        uint32_t j = randombytes_uniform(i + 1);
        char tmp = pw[i];
        pw[i] = pw[j];
        pw[j] = tmp;
    }

    pw[len] = '\0';
    sodium_memzero(charset, sizeof(charset));
    return pw;
}
