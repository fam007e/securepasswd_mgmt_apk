#ifndef SODIUM_SHIM_H
#define SODIUM_SHIM_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

int sodium_init(void);
void randombytes_buf(void * const buf, const size_t size);
uint32_t randombytes_uniform(const uint32_t upper_bound);
void sodium_memzero(void * const pnt, const size_t len);

#ifdef __cplusplus
}
#endif

#endif
