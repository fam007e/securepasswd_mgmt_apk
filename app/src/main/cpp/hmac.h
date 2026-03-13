#ifndef HMAC_H
#define HMAC_H

#include <stdint.h>
#include <stddef.h>

void hmac_sha1(const uint8_t *key, size_t key_len,
               const uint8_t *text, size_t text_len,
               uint8_t *digest);

#endif // HMAC_H
