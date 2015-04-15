/*
 * @file util.c
 * @date 15 March 2015
 * @author Marc Tiehuis
 *
 * This file contains common utility functions that are shared amongst
 * cryptographic schemes. These are mainly additional functions that work
 * on mpz_t types.
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
    /* Technically in small cases we could get a prime of n + 1 bits */
    mpz_urandomb(rop, rstate, bitcnt);
    mpz_setbit(rop, bitcnt);
    mpz_nextprime(rop, rop);
}

/* Generate a prime rop1 which is equal to 2 * rop2 + 1 where rop2 is also prime */
void mpz_random_safe_prime(mpz_t rop1, mpz_t rop2, gmp_randstate_t rstate, mp_bitcnt_t bitcnt)
{
    do {
        mpz_random_prime(rop1, rstate, bitcnt);
        mpz_sub_ui(rop2, rop1, 1);
        mpz_divexact_ui(rop2, rop2, 2);
    } while (mpz_probab_prime_p(rop2, 25) == 0);
}

#if 0
/* Internal helper function for dsa_prime generation */
static void dsa_g(mpz_t c, gmp_randstate_t rstate, mpz_t alpha)
{
    mpz_t p, t, l, r, temp;
    mpz_init(r);
    mpz_init(temp);
    mpz_init_set_ui(t, 2 * 29);
    mpz_init_set_str(p, "6 649 693 230", 10); // 2 * 3 * 5 * 7 ... * 29
    mpz_set_ui(c, 0);

    size_t seqlen = mpz_sizeinbase(alpha, 2);
    mpz_init_set_ui(l, seqlen);
    mpz_sub(l, l, t);

    for (int i = 0; i < 10; ++i) {
        do {
            mpz_urandomm(r, rstate, l);
            mpz_tdiv_q_2exp(r, r, mpz_get_ui(r));
            mpz_and(r, r, t);
            mpz_mod(temp, r, p);
        } while (mpz_cmp_ui(temp, 0) == 0);

        mpz_add(c, c, r);
        mpz_mod(c, c, p);
    }

    mpz_clears(p, t, l, r, temp, NULL);
}
#endif

/* Generate a random dsa_prime and set rop to the result */
void mpz_random_dsa_prime(mpz_t rop, gmp_randstate_t rstate, mp_bitcnt_t bitcnt)
{
    mpz_random_prime(rop, rstate, bitcnt);
}

/* Chinese remainder theorem case where k = 2 using Bezout's identity. Unlike other
 * mpz functions rop must not be an aliased with any of the other arguments!
 * This is done to save excessive copying in this function, plus it is usually
 * not beneficial as conX_a and conX_m cannot be the same value anyway */
void mpz_2crt(mpz_t rop, mpz_t con1_a, mpz_t con1_m, mpz_t con2_a, mpz_t con2_m)
{
    mpz_t t;
    mpz_init(t);

    mpz_invert(rop, con2_m, con1_m);
    mpz_mul(rop, rop, con2_m);
    mpz_mul(rop, rop, con1_a);
    mpz_invert(t, con1_m, con2_m);
    mpz_mul(t, t, con1_m);
    mpz_mul(t, t, con2_a);
    mpz_add(rop, rop, t);

    mpz_clear(t);
}
