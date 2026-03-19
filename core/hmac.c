#include "hmac.h"
#include "sha1.h"
#include <string.h>

#define SHA1_BLOCK_SIZE 64

void hmac_sha1(const uint8_t *key, size_t key_len,
               const uint8_t *text, size_t text_len,
               uint8_t *digest) {
    SHA1_CTX ctx;
    uint8_t k_ipad[SHA1_BLOCK_SIZE];
    uint8_t k_opad[SHA1_BLOCK_SIZE];
    uint8_t tk[20];
    int i;

    if (key_len > SHA1_BLOCK_SIZE) {
        SHA1Init(&ctx);
        SHA1Update(&ctx, key, key_len);
        SHA1Final(tk, &ctx);
        key = tk;
        key_len = 20;
    }

    memset(k_ipad, 0, sizeof k_ipad);
    memset(k_opad, 0, sizeof k_opad);
    memcpy(k_ipad, key, key_len);
    memcpy(k_opad, key, key_len);

    for (i = 0; i < SHA1_BLOCK_SIZE; i++) {
        k_ipad[i] ^= 0x36;
        k_opad[i] ^= 0x5c;
    }

    SHA1Init(&ctx);
    SHA1Update(&ctx, k_ipad, SHA1_BLOCK_SIZE);
    SHA1Update(&ctx, text, text_len);
    SHA1Final(digest, &ctx);

    SHA1Init(&ctx);
    SHA1Update(&ctx, k_opad, SHA1_BLOCK_SIZE);
    SHA1Update(&ctx, digest, 20);
    SHA1Final(digest, &ctx);
}
