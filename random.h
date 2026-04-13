/**
 * @brief Random number generation for n2n
 *
 * Uses XORSHIFT128+ (same as cnn2n) for platform-independent random numbers.
 * No external crypto library dependency.
 */

#ifndef N2N_RANDOM_H_
#define N2N_RANDOM_H_

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

/* Windows: use BCrypt only for the NULL-ctx path in edge.c (send_register_super) */
#if defined(_WIN32)
#include <windows.h>
#include <bcrypt.h>
#endif

/* ---------- XORSHIFT128+ state (same as cnn2n) ---------- */
typedef struct { uint64_t a, b; } n2n_rng_state_t;

static n2n_rng_state_t _n2n_rng = {
    0x9E3779B97F4A7C15ULL,
    0xBF58476D1CE4E5B9ULL
};

static inline uint64_t n2n_rand(void) {
    uint64_t t = _n2n_rng.a;
    uint64_t s = _n2n_rng.b;
    _n2n_rng.a = s;
    t ^= t << 23;
    t ^= t >> 17;
    t ^= s ^ (s >> 26);
    _n2n_rng.b = t;
    return t + s;
}

static inline void n2n_srand(uint64_t seed) {
    /* splitmix64 to initialise */
    uint64_t z = seed + 0x9E3779B97F4A7C15ULL;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    _n2n_rng.a = z ^ (z >> 31);
    z += 0x9E3779B97F4A7C15ULL;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    _n2n_rng.b = z ^ (z >> 31);
    /* warm up */
    for (int i = 0; i < 32; i++) n2n_rand();
}

/* ---------- random_bytes: fill buffer with random bytes ---------- */
static inline void random_bytes_buf(uint8_t *buf, size_t n) {
#if defined(_WIN32)
    BCryptGenRandom(NULL, buf, (ULONG)n, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
#else
    /* Use n2n_rand() - same approach as cnn2n */
    size_t i = 0;
    while (i + 8 <= n) {
        uint64_t v = n2n_rand();
        memcpy(buf + i, &v, 8);
        i += 8;
    }
    if (i < n) {
        uint64_t v = n2n_rand();
        memcpy(buf + i, &v, n - i);
    }
#endif
}

/* ---------- Compatibility shim for old callers using random_ctx_t ---------- */
struct random_ctx { int _unused; };  /* empty struct, RNG state is global */
typedef struct random_ctx *random_ctx_t;

static inline void random_init(random_ctx_t ctx) {
    (void)ctx;
    n2n_srand((uint64_t)time(NULL) ^ (uint64_t)(uintptr_t)&ctx);
}
static inline void random_free(random_ctx_t ctx) { (void)ctx; }

static inline void random_bytes(random_ctx_t ctx, uint8_t *buf, size_t n) {
    (void)ctx;
    random_bytes_buf(buf, n);
}

#endif /* N2N_RANDOM_H_ */
