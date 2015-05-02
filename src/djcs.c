/*
 * @file djcs.c
 * @brief implements the Damgard-Jurik Cryptosystem
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <gmp.h>
#include "com/util.h"
#include "hcs_rand.h"
#include "djcs.h"

/*
 * Algorithm as seen in the initial paper. Simple optimizations
 * have been added. rop and op can be aliases.
 */
static void dlog_s(djcs_private_key *vk, mpz_t rop, mpz_t op)
{
    mpz_t a, t1, t2, t3, kfact;
    mpz_inits(a, t1, t2, t3, kfact, NULL);

    /* Optimization: L(a mod n^(j+1)) = L(a mod n^(s+1)) mod n^j
     * where j <= s */
    mpz_mod(a, op, vk->n[vk->s]);
    mpz_sub_ui(a, a, 1);
    mpz_divexact(a, a, vk->n[0]);

    mpz_set_ui(rop, 0);
    for (unsigned long j = 1; j <= vk->s; ++j) {
        /* t1 = L(a mod n^j+1) */
        mpz_mod(t1, a, vk->n[j-1]);

        /* t2 = i */
        mpz_set(t2, rop);
        mpz_set_ui(kfact, 1);

        for (unsigned long k = 2; k <= j; ++k) {
            /* i = i - 1 */
            mpz_sub_ui(rop, rop, 1);
            mpz_mul_ui(kfact, kfact, k);

            /* t2 = t2 * i mod n^j */
            mpz_mul(t2, t2, rop);
            mpz_mod(t2, t2, vk->n[j-1]);

            /* t1 = t1 - (t2 * n^(k-1)) * k!^(-1)) mod n^j */
            mpz_invert(t3, kfact, vk->n[j-1]);
            mpz_mul(t3, t3, t2);
            mpz_mod(t3, t3, vk->n[j-1]);
            mpz_mul(t3, t3, vk->n[k-2]);
            mpz_mod(t3, t3, vk->n[j-1]);
            mpz_sub(t1, t1, t3);
            mpz_mod(t1, t1, vk->n[j-1]);
        }

        mpz_set(rop, t1);
    }

    mpz_zeros(a, t1, t2, t3, kfact, NULL);
    mpz_clears(a, t1, t2, t3, kfact, NULL);
}

void djcs_encrypt(djcs_public_key *pk, hcs_rand *hr, mpz_t rop, mpz_t plain1)
{
    mpz_t t1;
    mpz_init(t1);

    mpz_random_in_mult_group(t1, hr->rstate, pk->n[0]);
    mpz_powm(rop, pk->g, plain1, pk->n[pk->s]);
    mpz_powm(t1, t1, pk->n[pk->s-1], pk->n[pk->s]);
    mpz_mul(rop, rop, t1);
    mpz_mod(rop, rop, pk->n[pk->s]);

    mpz_clear(t1);
}

void djcs_decrypt(djcs_private_key *vk, mpz_t rop, mpz_t cipher1)
{
    mpz_powm(rop, cipher1, vk->d, vk->n[vk->s]);
    dlog_s(vk, rop, rop);
    mpz_mul(rop, rop, vk->mu);
    mpz_mod(rop, rop, vk->n[vk->s-1]);
}

void djcs_ep_add(djcs_public_key *pk, mpz_t rop, mpz_t cipher1, mpz_t plain1)
{
    mpz_t t1;
    mpz_init(t1);

    mpz_set(t1, cipher1);
    mpz_powm(rop, pk->g, plain1, pk->n[pk->s]);
    mpz_mul(rop, rop, t1);
    mpz_mod(rop, rop, pk->n[pk->s]);

    mpz_clear(t1);
}

void djcs_ee_add(djcs_public_key *pk, mpz_t rop, mpz_t cipher1, mpz_t cipher2)
{
    mpz_mul(rop, cipher1, cipher2);
    mpz_mod(rop, rop, pk->n[pk->s]);
}

void djcs_ep_mul(djcs_public_key *pk, mpz_t rop, mpz_t cipher1, mpz_t plain1)
{
    mpz_powm(rop, cipher1, plain1, pk->n[pk->s]);
}

int djcs_generate_key_pair(unsigned long s, djcs_public_key *pk,
        djcs_private_key *vk, hcs_rand *hr, unsigned long bits)
{
    mpz_t p, q;

    pk->n = malloc(sizeof(mpz_t) * (s + 1));
    if (pk->n == NULL) return 1;
    vk->n = malloc(sizeof(mpz_t) * (s + 1));
    if (vk->n == NULL) return 1;

    pk->s = s;
    vk->s = s;

    mpz_init(p);
    mpz_init(q);
    mpz_init(pk->n[0]);
    mpz_init(vk->n[0]);

    mpz_random_prime(p, hr->rstate, 1 + (bits-1)/2);
    mpz_random_prime(q, hr->rstate, 1 + (bits-1)/2);
    mpz_mul(pk->n[0], p, q);
    mpz_sub_ui(vk->d, p, 1);
    mpz_sub_ui(q, q, 1);
    mpz_lcm(vk->d, vk->d, q);
    mpz_add_ui(q, q, 1);
    mpz_add_ui(pk->g, pk->n[0], 1);

    mpz_set(vk->n[0], pk->n[0]);
    for (unsigned long i = 1; i <= pk->s; ++i) {
        mpz_init_set(pk->n[i], pk->n[i-1]);
        mpz_mul(pk->n[i], pk->n[i], pk->n[0]);
        mpz_init_set(vk->n[i], pk->n[i]);
    }

    mpz_powm(vk->mu, pk->g, vk->d, vk->n[vk->s]);
    dlog_s(vk, vk->mu, vk->mu);
    mpz_invert(vk->mu, vk->mu, vk->n[vk->s-1]);

    mpz_clear(p);
    mpz_clear(q);

    return 0;
}

djcs_public_key* djcs_init_public_key(void)
{
    djcs_public_key *pk = malloc(sizeof(djcs_public_key));
    if (!pk) return NULL;

    mpz_init(pk->g);
    pk->s = 0;
    pk->n = NULL;
    return pk;
}

djcs_private_key* djcs_init_private_key(void)
{
    djcs_private_key *vk = malloc(sizeof(djcs_private_key));
    if (!vk) return NULL;

    mpz_inits(vk->j, vk->d, vk->mu, NULL);
    vk->s = 0;
    vk->n = NULL;
    return vk;
}

void djcs_free_public_key(djcs_public_key *pk)
{
    for (unsigned long i = 0; i < pk->s; ++i) {
        mpz_zero(pk->n[i]);
        mpz_clear(pk->n[i]);
    }

    if (pk->n) free(pk->n);
    mpz_zero(pk->g);
    mpz_clear(pk->g);
    free(pk);
}

void djcs_free_private_key(djcs_private_key *vk)
{
    for (unsigned long i = 0; i < vk->s; ++i) {
        mpz_zero(vk->n[i]);
        mpz_clear(vk->n[i]);
    }

    if (vk->n) free(vk->n);
    mpz_zeros(vk->j, vk->mu, vk->d, NULL);
    mpz_clears(vk->j, vk->mu, vk->d, NULL);
    free(vk);
}
