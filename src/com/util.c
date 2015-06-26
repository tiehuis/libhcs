/*
 * @file util.c
 */

#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <gmp.h>
#include "util.h"

#ifdef _WIN32
#include "Wincrypt.h"                  // For CryptGenRandom
#pragma comment(lib, "advapi32.lib")
#endif

/* If we are compiling with C11 support, we will have memset_s, otherwise
 * use this simple version instead. */
#if __STDC_VERSION__ < 201112L
static void memset_s(void *v, int c, size_t n)
{
    volatile unsigned char *p = v;
    while (n--) *p++ = c;
}
#endif

/* Zero a single mpz_t variable. mpz_clear does not seem to be required
 * to zero memory before freeing it, so we must do it ourselves. A
 * function mpn_zero exists which performs this. */
inline void mpz_zero(mpz_t op)
{
    mpn_zero(op->_mp_d, op->_mp_alloc);
}

/* Call mpz_zero with a va_list. This follows mpz_clears and mpz_inits
 * in that it is a NULL-terminated va_list */
void mpz_zeros(mpz_t op, ...)
{
    va_list va;
    va_start(va, op);

    /* Use the internal mpz names pre-typedef so we can assign pointers, as
     * mpz_t is defined as __mpz_struct[1] which is non-assignable */
    __mpz_struct *ptr = op;
    do {
        mpz_zero(ptr);
    } while ((ptr = va_arg(va, __mpz_struct*)));
}

/* Attempts to get n bits of seed data from /dev/urandom. The number of
 * bits is always round up to the nearest 8. Asking for 78 bits of seed
 * will gather 80 bits, for example. */
int mpz_seed(mpz_t seed, int bits)
{
#if defined(__unix__) || defined(__linux__) || (defined(__APPLE__) && defined(__MACH__))
    FILE *fd = fopen("/dev/urandom", "rb");
    if (!fd)
        return HCS_EOPEN;

    const int bytes = (bits / 8) + 1;
    unsigned char random_bytes[bytes];
    if (fread(random_bytes, sizeof(random_bytes), 1, fd) != 1)
        return HCS_EREAD;

    mpz_import(seed, bytes, 1, sizeof(random_bytes[0]), 0, 0, random_bytes);
    memset_s(random_bytes, 0, bytes); /* Ensure we zero seed buffer data */
    fclose(fd);

#elif defined(_WIN32)
    const DWORD bytes = (bits / 8) + 1;
    HCRYPTPROV hCryptProv = 0;
    BYTE pbBuffer[bytes];

    if (!CryptAcquireContextW(&hCryptProv, 0, 0, PROV_RSA_FULL,
            CRYPT_VERIFYCONTEXT, CRYPT_SILENT) {
       return HCS_EREAD;
    }

    if (!CryptGenRandom(hCryptProv, bytes, pbBuffer)) {
        CryptReleaseContext(hCryptProv, 0);
        return HCS_EREAD;
    }

    mpz_import(seed, bytes, 1, sizeof(pbBuffer[0]), 0, 0, pbBuffer);
    memset_s(pbBuffer, 0, bytes); /* Ensure we zero seed buffer data */

    if (!CryptReleaseContext(hCryptProv, 0)) {
        return HCS_EREAD;
    }
#else
#   error "No random source known for this OS"
#endif

    return HCS_OK;
}

/* Generate a random value that is in Z_(op)^*. This simply random chooses
 * values until we get one with gcd(rop, op) of n. If one has knowledge about
 * the value of rop, then calling this function may not be neccessary. i.e.
 * if rop is prime, we can just call urandomm directly. */
void mpz_random_in_mult_group(mpz_t rop, gmp_randstate_t rstate, mpz_t op)
{
    mpz_t t1;
    mpz_init(t1);

    do {
        mpz_urandomm(rop, rstate, op);
        mpz_gcd(t1, rop, op);
    } while (mpz_cmp_ui(t1, 1) != 0);

    mpz_clear(t1);
}

/* Generate a random prime of minimum bitcnt number of bits. Currently this
 * doesn't have any other requirements. Strong primes or anything generally
 * are not seen as too useful now, as newer factorization schemes such as the
 * GFNS are not disrupted by this prime choice. */
void mpz_random_prime(mpz_t rop, gmp_randstate_t rstate, mp_bitcnt_t bitcnt)
{
    /* Technically in small cases we could get a prime of n + 1 bits */
    mpz_urandomb(rop, rstate, bitcnt);
    mpz_setbit(rop, bitcnt);
    mpz_nextprime(rop, rop);
}

/* Generate a prime rop1 which is equal to 2 * rop2 + 1 where rop2 is also
 * prime */
void mpz_random_safe_prime(mpz_t rop1, mpz_t rop2, gmp_randstate_t rstate,
                           mp_bitcnt_t bitcnt)
{
    do {
        mpz_random_prime(rop1, rstate, bitcnt);
        mpz_sub_ui(rop2, rop1, 1);
        mpz_divexact_ui(rop2, rop2, 2);
    } while (mpz_probab_prime_p(rop2, 25) == 0);
}

/* Chinese remainder theorem case where k = 2 using Bezout's identity. Unlike
 * other mpz functions rop must not be an aliased with any of the other
 * arguments! This is done to save excessive copying in this function, plus
 * it is usually not beneficial as conX_a and conX_m cannot be the same value
 * anyway */
void mpz_2crt(mpz_t rop, mpz_t con1_a, mpz_t con1_m, mpz_t con2_a, mpz_t con2_m)
{
    mpz_t t;
    mpz_init(t);

    mpz_gcd(t, con1_m, con2_m);
    assert(mpz_cmp_ui(t, 1) == 0);

    mpz_invert(rop, con2_m, con1_m);
    mpz_mul(rop, rop, con2_m);
    mpz_mul(rop, rop, con1_a);
    mpz_invert(t, con1_m, con2_m);
    mpz_mul(t, t, con1_m);
    mpz_mul(t, t, con2_a);
    mpz_add(rop, rop, t);
    mpz_mul(t, con1_m, con2_m);
    mpz_mod(rop, rop, t);

    mpz_clear(t);
}
