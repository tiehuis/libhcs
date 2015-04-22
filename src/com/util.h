#ifndef UTIL_H
#define UTIL_H

#include <stdio.h>
#include <stdlib.h>
#include <gmp.h>
#include "log.h"

#define HCS_BASE 62

#define err(fmt, ...) fprintf(stderr, fmt "\n", ## __VA_ARGS__ ), abort()

void mpz_zero(mpz_t op);
void mpz_zeros(mpz_t op, ...);
void mpz_random_prime(mpz_t rop, gmp_randstate_t rstate, mp_bitcnt_t bitcnt);
void mpz_random_safe_prime(mpz_t rop1, mpz_t rop2, gmp_randstate_t rstate,
        mp_bitcnt_t bitcnt);
void mpz_seed(mpz_t rop, int bits);
void mpz_2crt(mpz_t rop, mpz_t con1_a, mpz_t con1_m, mpz_t con2_a, mpz_t con2_m);
void mpz_random_dsa_prime(mpz_t rop, gmp_randstate_t rstate, mp_bitcnt_t bitcnt);
void mpz_random_in_mult_group(mpz_t rop, gmp_randstate_t rstate, mpz_t op);

#endif
