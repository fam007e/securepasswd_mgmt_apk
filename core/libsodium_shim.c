#include "sodium.h"
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#if defined(__ANDROID__) || defined(__linux__)
#include <sys/syscall.h>
#endif

/*
 * Minimal libsodium shim backed by the OS CSPRNG.
 *
 * Security requirements handled here:
 *  - randombytes_buf must never return with the buffer only partially
 *    filled (a short read() would leave stale memory in use as "random");
 *    it loops and aborts the process on failure.
 *  - randombytes_uniform must not introduce modulo bias; it uses the
 *    same rejection-sampling algorithm as real libsodium.
 *  - sodium_memzero must not be optimized away; the compiler barrier
 *    plus volatile store loop guarantees the zeroing is emitted.
 */

int sodium_init(void) {
    return 0;
}

static void fill_random(void *buf, size_t size) {
    unsigned char *p = (unsigned char *)buf;
    size_t remaining = size;

    /* Prefer the getrandom(2) syscall (no fd, cannot be chroot-blocked,
     * always the kernel CSPRNG). Fall back to /dev/urandom. */
#if defined(__ANDROID__) || defined(__linux__)
    while (remaining > 0) {
        ssize_t n = syscall(SYS_getrandom, p, remaining, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            break; /* fall back to /dev/urandom */
        }
        if (n == 0) break;
        p += n;
        remaining -= (size_t)n;
    }
    if (remaining == 0) return;
#endif

    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd == -1) abort();
    while (remaining > 0) {
        ssize_t n = read(fd, p, remaining);
        if (n < 0) {
            if (errno == EINTR) continue;
            abort(); /* CSPRNG unavailable: refusing is safer than proceeding */
        }
        if (n == 0) abort();
        p += n;
        remaining -= (size_t)n;
    }
    close(fd);
}

void randombytes_buf(void * const buf, const size_t size) {
    if (size > 0) fill_random(buf, size);
}

uint32_t randombytes_uniform(const uint32_t upper_bound) {
    if (upper_bound < 2) return 0;

    /* Rejection sampling without modulo bias (mirrors libsodium). */
    uint32_t min = (0xFFFFFFFFu - upper_bound + 1u) % upper_bound; /* = 2^32 mod upper_bound */
    uint32_t r;
    for (;;) {
        fill_random(&r, sizeof r);
        if (r >= min) return r % upper_bound;
    }
}

void sodium_memzero(void * const pnt, const size_t len) {
    volatile unsigned char *p = (volatile unsigned char *)pnt;
    size_t i = len;
    while (i--) {
        *p++ = 0;
    }
    /* Compiler barrier: prevents the stores from being elided. */
    __asm__ __volatile__("" : : "r"(pnt) : "memory");
}
