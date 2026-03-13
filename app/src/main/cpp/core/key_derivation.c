#include "key_derivation.h"

#include <argon2.h>
#include <sodium.h>
#include <stdio.h>
#include <string.h>

#define MEMORY_COST (1 << 17) // 128MB
#define TIME_COST 3
#define PARALLELISM 1

int derive_key(const char *password, const uint8_t *salt, uint8_t *key) {
    if (sodium_init() < 0)
        return -1;
    size_t pass_len = strlen(password); // flawfinder: ignore
    return argon2id_hash_raw(TIME_COST, MEMORY_COST, PARALLELISM, password,
                             pass_len, salt, SALT_LEN, key, KEY_LEN);
}

int load_or_generate_salt(const char *path, uint8_t *salt) {
    FILE *f = fopen(path, "rb"); // flawfinder: ignore (Path is controlled by app config)
    if (f) {
        // Salt file exists, read it
        size_t n = fread(salt, 1, SALT_LEN, f); // flawfinder: ignore
        fclose(f);
        if (n != SALT_LEN) {
            return -1; // Failed to read salt
        }
        return 0;
    } else {
        // Salt file does not exist, generate a new one
        if (sodium_init() < 0)
            return -1;
        randombytes_buf(salt, SALT_LEN);

        // Save the new salt
        f = fopen(path, "wb"); // flawfinder: ignore (Path is controlled by app config)
        if (!f) {
            return -1; // Failed to open salt file for writing
        }
        size_t n = fwrite(salt, 1, SALT_LEN, f);
        fclose(f);
        if (n != SALT_LEN) {
            return -1; // Failed to write salt
        }
        return 0;
    }
}

int save_salt(const char *path, const uint8_t *salt) {
    FILE *f = fopen(path, "wb"); // flawfinder: ignore
    if (!f) {
        return -1;
    }
    size_t n = fwrite(salt, 1, SALT_LEN, f);
    fclose(f);
    if (n != SALT_LEN) {
        return -1;
    }
    return 0;
}
