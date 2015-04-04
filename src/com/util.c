/*
 * @file util.c
 * @date 15 March 2015
 * @author Marc Tiehuis
 *
 * This file contains common utility functions that are shared amongst
 * cryptographic schemes.
 */

#include <stdarg.h>
#include <stdio.h>
#include <gmp.h>
#include "util.h"

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
void mpz_seed(mpz_t seed, int bits)
{
    FILE *fd = fopen("/dev/urandom", "rb");
    if (!fd)
        err("failed to open /dev/urandom");

    int bytes = (bits / 8) + 1;
    unsigned char random_bytes[bytes];
    if (fread(random_bytes, sizeof(random_bytes), 1, fd) != 1)
        err("failed to read from /dev/urandom");

    mpz_import(seed, bytes, 1, sizeof(random_bytes[0]), 0, 0, random_bytes);
    memset_s(random_bytes, 0, bytes); /* Ensure we zero seed buffer data */
    fclose(fd);
}

/* Generate a random prime of minimum bitcnt number of bits. Currently this doesn't
 * have any other requirements. Strong primes or anything generally are not
 * seen as too useful now, as newer factorization schemes such as the GFNS
 * are not disrupted by this prime choice. */
void mpz_random_prime(mpz_t rop, gmp_randstate_t rstate, mp_bitcnt_t bitcnt)
{
    mpz_urandomb(rop, rstate, bitcnt);  // Techinically in small cases we could get a prime of n + 1 bits
    mpz_nextprime(rop, rop);
}

