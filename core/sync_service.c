#include "sync_service.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#ifdef __ANDROID__
#include <android/log.h>
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, "SyncService", __VA_ARGS__)
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, "SyncService", __VA_ARGS__)
#else
#define LOGE(...) fprintf(stderr, __VA_ARGS__)
#define LOGD(...) printf(__VA_ARGS__)
#endif

int sync_encrypt_vault(const char *db_path, unsigned char *output_buffer, size_t *output_size, const unsigned char key[SYNC_KEY_LEN]) {
    if (!db_path || !output_buffer || !output_size) return -1;
    FILE *f1 = fopen(db_path, "rb");
    if (!f1) return -1;

    char salt_path[2048];
    snprintf(salt_path, sizeof(salt_path), "%s.salt", db_path);
    FILE *f2 = fopen(salt_path, "rb");
    if (!f2) {
        fclose(f1);
        return -1;
    }

    fseek(f1, 0, SEEK_END);
    long db_size = ftell(f1);
    fseek(f1, 0, SEEK_SET);

    fseek(f2, 0, SEEK_END);
    long salt_size = ftell(f2);
    fseek(f2, 0, SEEK_SET);

    if (db_size < 0 || salt_size < 0) {
        fclose(f1);
        fclose(f2);
        return -1;
    }

    size_t total_size = 4 + (size_t)db_size + 4 + (size_t)salt_size;
    unsigned char *file_data = calloc(1, total_size);
    if (!file_data) {
        fclose(f1);
        fclose(f2);
        return -1;
    }

    unsigned int ds = (unsigned int)db_size;
    unsigned int ss = (unsigned int)salt_size;

    memcpy(file_data, &ds, 4);
    if (fread(file_data + 4, 1, (size_t)db_size, f1) != (size_t)db_size) {
        free(file_data); fclose(f1); fclose(f2); return -1;
    }
    memcpy(file_data + 4 + db_size, &ss, 4);
    if (fread(file_data + 4 + db_size + 4, 1, (size_t)salt_size, f2) != (size_t)salt_size) {
        free(file_data); fclose(f1); fclose(f2); return -1;
    }

    fclose(f1);
    fclose(f2);

    // Encryption using OpenSSL (AES-256-GCM)
    unsigned char nonce[SYNC_NONCE_LEN];
    if (RAND_bytes(nonce, SYNC_NONCE_LEN) != 1) {
        free(file_data);
        return -1;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { free(file_data); return -1; }

    memcpy(output_buffer, nonce, SYNC_NONCE_LEN);

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, nonce) != 1) {
        EVP_CIPHER_CTX_free(ctx); free(file_data); return -1;
    }

    int outlen;
    if (EVP_EncryptUpdate(ctx, output_buffer + SYNC_NONCE_LEN, &outlen, file_data, (int)total_size) != 1) {
        EVP_CIPHER_CTX_free(ctx); free(file_data); return -1;
    }

    int final_len;
    if (EVP_EncryptFinal_ex(ctx, output_buffer + SYNC_NONCE_LEN + outlen, &final_len) != 1) {
        EVP_CIPHER_CTX_free(ctx); free(file_data); return -1;
    }

    unsigned char tag[SYNC_TAG_LEN];
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, SYNC_TAG_LEN, tag) != 1) {
        EVP_CIPHER_CTX_free(ctx); free(file_data); return -1;
    }

    memcpy(output_buffer + SYNC_NONCE_LEN + outlen + final_len, tag, SYNC_TAG_LEN);
    
    *output_size = SYNC_NONCE_LEN + (size_t)outlen + (size_t)final_len + SYNC_TAG_LEN;

    EVP_CIPHER_CTX_free(ctx);
    free(file_data);
    return 0;
}

int sync_decrypt_vault(const unsigned char *encrypted_data, size_t data_len, const char *db_path, const unsigned char key[SYNC_KEY_LEN]) {
    if (data_len < SYNC_NONCE_LEN + SYNC_TAG_LEN) return -1;

    const unsigned char *nonce = encrypted_data;
    const unsigned char *ciphertext = encrypted_data + SYNC_NONCE_LEN;
    size_t cipher_len = data_len - SYNC_NONCE_LEN - SYNC_TAG_LEN;
    const unsigned char *tag = encrypted_data + data_len - SYNC_TAG_LEN;

    unsigned char *decrypted = calloc(1, cipher_len);
    if (!decrypted) return -1;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { free(decrypted); return -1; }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, nonce) != 1) {
        EVP_CIPHER_CTX_free(ctx); free(decrypted); return -1;
    }

    int outlen;
    if (EVP_DecryptUpdate(ctx, decrypted, &outlen, ciphertext, (int)cipher_len) != 1) {
        EVP_CIPHER_CTX_free(ctx); free(decrypted); return -1;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, SYNC_TAG_LEN, (void*)tag) != 1) {
        EVP_CIPHER_CTX_free(ctx); free(decrypted); return -1;
    }

    int final_len;
    int res = EVP_DecryptFinal_ex(ctx, decrypted + outlen, &final_len);
    EVP_CIPHER_CTX_free(ctx);

    if (res <= 0) {
        LOGE("Auth failure or padding error in EVP_DecryptFinal_ex\n");
        free(decrypted);
        return -1;
    }

    size_t total_decrypted = (size_t)outlen + (size_t)final_len;
    if (total_decrypted < 8) {
        LOGE("Decrypted payload too small: %zu\n", total_decrypted);
        free(decrypted);
        return -1;
    }

    unsigned int db_size, salt_size;
    memcpy(&db_size, decrypted, 4);

    if (4 + (size_t)db_size + 4 > total_decrypted) {
        LOGE("Invalid format: db_size %u exceeds total %zu\n", db_size, total_decrypted);
        free(decrypted);
        return -1;
    }

    memcpy(&salt_size, decrypted + 4 + db_size, 4);

    if (4 + (size_t)db_size + 4 + (size_t)salt_size != total_decrypted) {
        LOGE("Size mismatch: 4 + %u + 4 + %u != %zu\n", db_size, salt_size, total_decrypted);
        free(decrypted);
        return -1;
    }

    FILE *f1 = fopen(db_path, "wb");
    if (!f1) {
        LOGE("Failed to open vault path for writing: %s\n", db_path);
        free(decrypted);
        return -1;
    }
    fwrite(decrypted + 4, 1, db_size, f1);
    fclose(f1);

    char salt_path[2048];
    snprintf(salt_path, sizeof(salt_path), "%s.salt", db_path);
    FILE *f2 = fopen(salt_path, "wb");
    if (!f2) {
        LOGE("Failed to open salt path for writing: %s\n", salt_path);
        free(decrypted);
        return -1;
    }
    fwrite(decrypted + 4 + db_size + 4, 1, salt_size, f2);
    fclose(f2);

    free(decrypted);
    return 0;
}
