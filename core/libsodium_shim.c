#include "sodium.h"
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>

int sodium_init(void) {
    return 0;
}

void randombytes_buf(void * const buf, const size_t size) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd != -1) {
        read(fd, buf, size);
        close(fd);
    }
}

uint32_t randombytes_uniform(const uint32_t upper_bound) {
    uint32_t r;
    randombytes_buf(&r, sizeof r);
    return r % upper_bound;
}

void sodium_memzero(void * const pnt, const size_t len) {
    if (len > 0) {
        memset(pnt, 0, len);
        __asm__ __volatile__("" : : "r"(pnt) : "memory");
    }
}
