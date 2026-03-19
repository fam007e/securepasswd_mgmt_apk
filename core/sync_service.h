#ifndef SYNC_SERVICE_H
#define SYNC_SERVICE_H

#include <stddef.h>

#define SYNC_KEY_LEN 32     // 256 bits
#define SYNC_NONCE_LEN 12   // ChaCha20-Poly1305 nonce
#define SYNC_TAG_LEN 16     // Authentication tag

/**
 * Encrypts a file using OpenSSL ChaCha20-Poly1305 for secure transfer.
 */
int sync_encrypt_vault(const char *db_path, unsigned char *output_buffer, size_t *output_size, const unsigned char key[SYNC_KEY_LEN]);

/**
 * Decrypts a secure transfer package using OpenSSL ChaCha20-Poly1305.
 */
int sync_decrypt_vault(const unsigned char *encrypted_data, size_t data_len, const char *db_path, const unsigned char key[SYNC_KEY_LEN]);

#endif
