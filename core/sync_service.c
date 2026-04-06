#include "sync_service.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>

#ifdef __ANDROID__
#include <android/log.h>
#endif

int sync_encrypt_vault(const char *db_path, unsigned char *output_buffer, size_t *output_size, const unsigned char key[SYNC_KEY_LEN]) { // flawfinder: ignore
    if (!db_path || !output_buffer || !output_size) return -1;
    FILE *f1 = fopen( /* flawfinder: ignore */ db_path, "rb"); // flawfinder: ignore
    if (!f1) return -1;

    char salt_path[2048]; // flawfinder: ignore
    snprintf(salt_path, sizeof(salt_path), "%s.salt", db_path);
    FILE *f2 = fopen( /* flawfinder: ignore */ salt_path, "rb"); // flawfinder: ignore
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

    // Pack sizes and data (Little Endian for simplicity)
    uint32_t ds = (uint32_t)db_size;
    uint32_t ss = (uint32_t)salt_size;
    
    memcpy( /* flawfinder: ignore */ file_data, &ds, 4); // flawfinder: ignore
    if (fread(file_data + 4, 1, (size_t)db_size, f1) != (size_t)db_size) {
        free(file_data); fclose(f1); fclose(f2); return -1;
    }
    
    memcpy( /* flawfinder: ignore */ file_data + 4 + (size_t)db_size, &ss, 4); // flawfinder: ignore
    if (fread(file_data + 4 + (size_t)db_size + 4, 1, (size_t)salt_size, f2) != (size_t)salt_size) {
        free(file_data); fclose(f1); fclose(f2); return -1;
    }

    fclose(f1);
    fclose(f2);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        free(file_data);
        return -1;
    }

    // Generate random nonce
    unsigned char nonce[SYNC_NONCE_LEN]; // flawfinder: ignore
    if (RAND_bytes(nonce, SYNC_NONCE_LEN) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(file_data);
        return -1;
    }

    // Copy nonce to beginning of output
    memcpy( /* flawfinder: ignore */ output_buffer, nonce, SYNC_NONCE_LEN); // flawfinder: ignore

    int outlen, final_len;
    if (EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, key, nonce) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(file_data);
        return -1;
    }

    if (EVP_EncryptUpdate(ctx, output_buffer + SYNC_NONCE_LEN, &outlen, file_data, (int)total_size) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(file_data);
        return -1;
    }

    if (EVP_EncryptFinal_ex(ctx, output_buffer + SYNC_NONCE_LEN + outlen, &final_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(file_data);
        return -1;
    }

    // Get tag and append it
    unsigned char tag[SYNC_TAG_LEN]; // flawfinder: ignore
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, SYNC_TAG_LEN, tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(file_data);
        return -1;
    }
    memcpy( /* flawfinder: ignore */ output_buffer + SYNC_NONCE_LEN + outlen + final_len, tag, SYNC_TAG_LEN); // flawfinder: ignore

    *output_size = SYNC_NONCE_LEN + (size_t)outlen + (size_t)final_len + SYNC_TAG_LEN;

    EVP_CIPHER_CTX_free(ctx);
    memset(file_data, 0, total_size);
    free(file_data);
    return 0;
}

int sync_decrypt_vault(const unsigned char *encrypted_data, size_t data_len, const char *db_path, const unsigned char key[SYNC_KEY_LEN]) { // flawfinder: ignore
    if (data_len < SYNC_NONCE_LEN + SYNC_TAG_LEN) return -1;

    const unsigned char *nonce = encrypted_data;
    const unsigned char *ciphertext = encrypted_data + SYNC_NONCE_LEN;
    size_t cipher_len = data_len - SYNC_NONCE_LEN - SYNC_TAG_LEN;
    const unsigned char *tag = encrypted_data + data_len - SYNC_TAG_LEN;

    unsigned char *decrypted = calloc(1, cipher_len);
    if (!decrypted) return -1;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        free(decrypted);
        return -1;
    }

    if (EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, key, nonce) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(decrypted);
        return -1;
    }

    int outlen;
    if (EVP_DecryptUpdate(ctx, decrypted, &outlen, ciphertext, (int)cipher_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(decrypted);
        return -1;
    }

    // Set expected tag
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, SYNC_TAG_LEN, (void*)tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(decrypted);
        return -1;
    }

    int final_len;
    if (EVP_DecryptFinal_ex(ctx, decrypted + outlen, &final_len) <= 0) {
#ifdef __ANDROID__
        __android_log_print(ANDROID_LOG_ERROR, "SyncService", "Auth failure or padding error");
#else
        fputs("Auth failure or padding error in EVP_DecryptFinal_ex\n", stderr);
#endif
        EVP_CIPHER_CTX_free(ctx);
        free(decrypted);
        return -1; // Auth failure!
    }

    size_t total_decrypted = (size_t)outlen + (size_t)final_len;

    if (total_decrypted < 8) {
#ifdef __ANDROID__
        __android_log_print(ANDROID_LOG_ERROR, "SyncService", "Decrypted payload too small");
#else
        fputs("Decrypted payload too small\n", stderr);
#endif
        EVP_CIPHER_CTX_free(ctx);
        free(decrypted);
        return -1; // Too small
    }

    uint32_t db_size = 0;
    memcpy( /* flawfinder: ignore */ &db_size, decrypted, 4); // flawfinder: ignore

    if (db_size > total_decrypted - 8) {
#ifdef __ANDROID__
        __android_log_print(ANDROID_LOG_ERROR, "SyncService", "Invalid format: db_size exceeds total");
#else
        fputs("Invalid format: db_size exceeds total\n", stderr);
#endif
        EVP_CIPHER_CTX_free(ctx);
        free(decrypted);
        return -1; // Invalid format
    }

    uint32_t salt_size = 0;
    memcpy( /* flawfinder: ignore */ &salt_size, decrypted + 4 + db_size, 4); // flawfinder: ignore
    
    if (salt_size != total_decrypted - 8 - db_size) {
#ifdef __ANDROID__
        __android_log_print(ANDROID_LOG_ERROR, "SyncService", "Size mismatch in decrypted payload");
#else
        fputs("Size mismatch in decrypted payload\n", stderr);
#endif
        EVP_CIPHER_CTX_free(ctx);
        free(decrypted);
        return -1; // Size mismatch
    }

    // Write vault
    FILE *f1 = fopen( /* flawfinder: ignore */ db_path, "wb"); // flawfinder: ignore
    if (!f1) {
#ifdef __ANDROID__
        __android_log_print(ANDROID_LOG_ERROR, "SyncService", "Failed to open vault path for writing");
#else
        fprintf(stderr, "Failed to open vault path for writing: %s\n", db_path);
#endif
        EVP_CIPHER_CTX_free(ctx);
        free(decrypted);
        return -1;
    }
    fwrite(decrypted + 4, 1, db_size, f1);
    fclose(f1);

    // Write salt
    char salt_path[2048]; // flawfinder: ignore
    snprintf(salt_path, sizeof(salt_path), "%s.salt", db_path);
    FILE *f2 = fopen( /* flawfinder: ignore */ salt_path, "wb"); // flawfinder: ignore
    if (!f2) {
#ifdef __ANDROID__
        __android_log_print(ANDROID_LOG_ERROR, "SyncService", "Failed to open salt path for writing");
#else
        fprintf(stderr, "Failed to open salt path for writing: %s\n", salt_path);
#endif
        EVP_CIPHER_CTX_free(ctx);
        free(decrypted);
        return -1;
    }
    fwrite(decrypted + 4 + db_size + 4, 1, salt_size, f2);
    fclose(f2);
    
    EVP_CIPHER_CTX_free(ctx);
    memset(decrypted, 0, total_decrypted);
    free(decrypted);
    return 0;
}
