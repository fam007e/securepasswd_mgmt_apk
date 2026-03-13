#include "pwned_check.h"
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <curl/curl.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#ifdef _WIN32
#define strtok_r strtok_s
#endif

// Memory struct for libcurl write callback
struct MemoryStruct {
    char *memory;
    size_t size;
};

// libcurl write callback function
static size_t write_callback(const void *contents, size_t size, size_t nmemb, void *userp) {
    if (size == 0 || nmemb == 0) return 0;
    size_t realsize = size * nmemb;
    struct MemoryStruct *mem = (struct MemoryStruct *)userp;

    // Check for overflow before realloc
    if (realsize > (size_t)-1 - mem->size - 1) {
        fprintf(stderr, "%s", "Buffer overflow prevented in write_callback\n"); // flawfinder: ignore
        return 0;
    }

    char *ptr = realloc(mem->memory, mem->size + realsize + 1);
    if (!ptr) {
        // out of memory!
        fprintf(stderr, "%s", "not enough memory (realloc returned NULL)\n"); // flawfinder: ignore
        return 0;
    }
    mem->memory = ptr;
    memcpy(&(mem->memory[mem->size]), contents, realsize); // flawfinder: ignore
    mem->size += realsize;
    mem->memory[mem->size] = 0;
    return realsize;
}

int is_password_pwned(const char *password) {
    if (!password) return -1;
    // 1. Calculate SHA-1 hash of the password using EVP API
    unsigned char hash[EVP_MAX_MD_SIZE]; // flawfinder: ignore
    unsigned int hash_len;

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) {
        return -1;
    }

    if (1 != EVP_DigestInit_ex(mdctx, EVP_sha1(), NULL)) {
        EVP_MD_CTX_free(mdctx);
        return -1;
    }

    size_t pass_len = strlen(password); // flawfinder: ignore
    if (1 != EVP_DigestUpdate(mdctx, password, pass_len)) {
        EVP_MD_CTX_free(mdctx);
        return -1;
    }

    if (1 != EVP_DigestFinal_ex(mdctx, hash, &hash_len)) {
        EVP_MD_CTX_free(mdctx);
        return -1;
    }

    EVP_MD_CTX_free(mdctx);

    if (hash_len > SHA_DIGEST_LENGTH) hash_len = SHA_DIGEST_LENGTH;

    char full_hash[SHA_DIGEST_LENGTH * 2 + 1]; // flawfinder: ignore
    memset(full_hash, 0, sizeof(full_hash));
    for (unsigned int i = 0; i < hash_len; i++) {
        snprintf(full_hash + (i * 2), 3, "%02X", hash[i]); // flawfinder: ignore
    }
    full_hash[hash_len * 2] = 0;

    // 2. Split hash into prefix (5 chars) and suffix
    char prefix[8]; // flawfinder: ignore
    memset(prefix, 0, sizeof(prefix));
    if (hash_len * 2 >= 5) {
        memcpy(prefix, full_hash, 5); // flawfinder: ignore
        prefix[5] = '\0';
    } else {
        return -1;
    }
    const char *suffix = full_hash + 5;

    // 3. Query the HIBP API
    char url[256]; // flawfinder: ignore
    snprintf(url, sizeof(url), "https://api.pwnedpasswords.com/range/%s", prefix); // flawfinder: ignore

    CURL *curl = curl_easy_init();
    if (!curl) return -1;

    struct MemoryStruct chunk;
    chunk.memory = malloc(1);
    if (!chunk.memory) {
        curl_easy_cleanup(curl);
        return -1;
    }
    chunk.size = 0;

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "SecurePasswd-MGMT/1.0");

    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        free(chunk.memory);
        return -1; // Network or other error
    }

    // 4. Check response for the hash suffix
    int pwn_count = 0;
    size_t suffix_len = strlen(suffix); // flawfinder: ignore
    char *saveptr;
    const char *line = strtok_r(chunk.memory, "\r\n", &saveptr);
    while (line) {
        if (strncmp(line, suffix, suffix_len) == 0 && line[suffix_len] == ':') {
            char *endptr;
            long count = strtol(line + suffix_len + 1, &endptr, 10);
            if (*endptr == '\0' || *endptr == '\r' || *endptr == '\n') {
                pwn_count = (int)count;
            }
            break;
        }
        line = strtok_r(NULL, "\r\n", &saveptr);
    }

    free(chunk.memory);
    return pwn_count;
}
