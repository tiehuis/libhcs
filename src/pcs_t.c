/*
 * @file pcs_t.c
 * @author Marc Tiehuis
 * @date 15 March 2015
 *
 * Implementation of the Paillier Cryptosystem (pcs_t).
 *
 * This scheme is a threshold variant of the Paillier system. It loosely
 * follows the scheme presented in the paper by damgard-jurik, but with a
 * chosen base of 2, rather than the variable s+1. This scheme was written
 * first for simplicity.
 *
 * POSSIBLE IMPROVEMENTS:
 *
 *  - Rewrite all assertions as checks that return error codes instead. We
 *    don't want to crash and instead want to relay this information to the
 *    caller.
 */

#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <gmp.h>
#include "com/util.h"
#include "pcs_t.h"

/* This is simply L(x) when s = 1 */
static void dlog_s(pcs_t_private_key *vk, mpz_t rop, mpz_t op)
{
    mpz_sub_ui(rop, op, 1);
    mpz_divexact(rop, rop, vk->n);
    mpz_mod(rop, rop, vk->n);
}

void pcs_t_encrypt(pcs_t_public_key *pk, hcs_rand *hr, mpz_t rop, mpz_t plain1)
{
    mpz_t t1;
    mpz_init(t1);

    mpz_random_in_mult_group(t1, hr->rstate, pk->n);
    mpz_powm(rop, t1, pk->n, pk->n2);
    mpz_powm(t1, pk->g, plain1, pk->n2);
    mpz_mul(rop, rop, t1);
    mpz_mod(rop, rop, pk->n2);

    mpz_clear(t1);
}

#if 0
static int dlog_equality(mpz_t u, mpz_t uh, mpz_t v, mpz_t vh)
{
    /* Read up on the Fiat-Shamir heuristic and utilize a hash function
     * H. A hash function is needed anyway for dsa prime generation, so
     * put one in com */
    return 1;
}
#endif

/* Compute a servers share and set rop to the result. rop should usually
 * be part of an array so we can call pcs_t_share_combine with ease. */
void pcs_t_share_decrypt(pcs_t_private_key *vk, pcs_t_auth_server *au,
                         mpz_t rop, mpz_t cipher1)
{
    mpz_t t1;
    mpz_init(t1);

    mpz_mul(t1, au->si, vk->delta);
    mpz_mul_ui(t1, t1, 2);
    mpz_powm(rop, cipher1, t1, vk->n2);

    mpz_clear(t1);
}

/* c is expected to be of length vk->l, the number of servers. If the share
 * is not present, then it is expected to be equal to the value zero. */
void pcs_t_share_combine(pcs_t_private_key *vk, mpz_t rop, mpz_t *c)
{
    mpz_t t1, t2, t3;
    mpz_init(t1);
    mpz_init(t2);
    mpz_init(t3);

    mpz_set_ui(rop, 1);
    for (unsigned long i = 0; i < vk->l; ++i) {

        /* Skip zero shares */
        if (mpz_cmp_ui(c[i], 0) == 0)
            continue;

        /* Compute lagrange coefficients */
        mpz_set(t1, vk->delta);
        for (unsigned long j = 0; j < vk->l; ++j) {
            if ((j == i) || mpz_cmp_ui(c[j], 0) == 0)
                continue; /* i' in S\i and non-zero */

            long v = (long)j - (long)i;
            mpz_tdiv_q_ui(t1, t1, (v < 0 ? v*-1 : v));
            if (v < 0) mpz_neg(t1, t1);
            mpz_mul_ui(t1, t1, j + 1);
        }

        mpz_abs(t2, t1);
        mpz_mul_ui(t2, t2, 2);
        mpz_powm(t2, c[i], t2, vk->n2);
        if (mpz_sgn(t1) < 0) mpz_invert(t2, t2, vk->n2);
        mpz_mul(rop, rop, t2);
        mpz_mod(rop, rop, vk->n2);
    }

    /* rop = c' */
    dlog_s(vk, rop, rop);
    mpz_pow_ui(t1, vk->delta, 2);
    mpz_mul_ui(t1, t1, 4);
    assert(mpz_invert(t1, t1, vk->n));  // This is always true
    mpz_mul(rop, rop, t1);
    mpz_mod(rop, rop, vk->n);

    mpz_clear(t1);
    mpz_clear(t2);
    mpz_clear(t3);
}

void pcs_t_compute_polynomial(pcs_t_private_key *vk, mpz_t *coeff, mpz_t rop,
                              const unsigned long x)
{
    mpz_t t1, t2;
    mpz_init(t1);
    mpz_init(t2);

    mpz_set(rop, coeff[0]);
    for (unsigned long i = 1; i < vk->w; ++i) {
        mpz_ui_pow_ui(t1, x + 1, i);        // Correct for server 0-indexing
        mpz_mul(t1, t1, coeff[i]);
        mpz_add(rop, rop, t1);
        mpz_mod(rop, rop, vk->nm);
    }

    mpz_clear(t1);
    mpz_clear(t2);
}

mpz_t* pcs_t_init_polynomial(pcs_t_private_key *vk, hcs_rand *hr)
{
    mpz_t *coeff = malloc(sizeof(mpz_t) * vk->w);
    if (coeff == NULL) return NULL;

    mpz_init_set(coeff[0], vk->d);
    for (unsigned long i = 1; i < vk->w; ++i) {
        mpz_init(coeff[i]);
        mpz_urandomm(coeff[i], hr->rstate, vk->nm);
    }

    return coeff;
}

void pcs_t_free_polynomial(pcs_t_private_key *vk, mpz_t *coeff)
{
    for (unsigned long i = 0; i < vk->w; ++i)
        mpz_clear(coeff[i]);
    free(coeff);
}

/* Maybe change the arguments passed to this to avoid an individual tampering
 * with the results. One should calculate their verification and send that to
 * the central party, not modify the private key themselves. Keep this as is
 * now though for simplicity in a local example. */
void pcs_t_set_auth_server(pcs_t_auth_server *au, mpz_t si, unsigned long i)
{
    mpz_set(au->si, si);
    au->i = i + 1; // Input is assumed to be 0-indexed (from array)
}

/* Look into methods of using multiparty computation to generate these keys
 * and the data so we don't have to have a trusted party for generation. */
void pcs_t_generate_key_pair(pcs_t_public_key *pk, pcs_t_private_key *vk,
        hcs_rand *hr, const unsigned long bits, const unsigned long w,
        const unsigned long l)
{
    /* The paper does describe some bounds on w, l */
    //assert(l / 2 <= w && w <= l);

    mpz_t t1, t2;
    mpz_init(t1);
    mpz_init(t2);

    do {
        mpz_random_safe_prime(vk->p, vk->qh, hr->rstate, 1 + (bits-1)/2);
        mpz_random_safe_prime(vk->q, vk->ph, hr->rstate, 1 + (bits-1)/2);
    } while (mpz_cmp(vk->p, vk->q) == 0);

    mpz_mul(pk->n, vk->p, vk->q);
    mpz_set(vk->n, pk->n);
    mpz_pow_ui(pk->n2, pk->n, 2);
    mpz_set(vk->n2, pk->n2);
    mpz_add_ui(pk->g, pk->n, 1);
    mpz_mul(vk->m, vk->ph, vk->qh);
    mpz_set_ui(t1, 1);
    mpz_set_ui(t2, 0);
    mpz_2crt(vk->d, t1, vk->n, t2, vk->m);
    mpz_mul(vk->nm, vk->n, vk->m);
    mpz_fac_ui(vk->delta, l);
    mpz_set(vk->v, vk->ph);

    vk->l = l;
    vk->w = w;
    vk->vi = malloc(sizeof(mpz_t) * l);
    for (unsigned long i = 0; i < l; ++i)
        mpz_init(vk->vi[i]);

    mpz_clear(t1);
    mpz_clear(t2);
}

pcs_t_auth_server* pcs_t_init_auth_server(void)
{
    pcs_t_auth_server *au = malloc(sizeof(pcs_t_auth_server));
    if (!au) return NULL;

    mpz_init(au->si);
    return au;
}

pcs_t_public_key* pcs_t_init_public_key(void)
{
    pcs_t_public_key *pk = malloc(sizeof(pcs_t_public_key));
    if (!pk) return NULL;

    mpz_inits(pk->n, pk->n2, pk->g, NULL);
    return pk;
}

pcs_t_private_key* pcs_t_init_private_key(void)
{
    pcs_t_private_key *vk = malloc(sizeof(pcs_t_private_key));
    if (!vk) return NULL;

    vk->w = vk->l = 0;
    mpz_inits(vk->p, vk->ph, vk->q, vk->qh, vk->v, vk->nm, vk->m, vk->n,
              vk->n2, vk->d, vk->delta, NULL);
    return vk;
}

void pcs_t_free_auth_server(pcs_t_auth_server *au)
{
    mpz_clear(au->si);
    free(au);
}

void pcs_t_free_public_key(pcs_t_public_key *pk)
{
    mpz_clears(pk->g, pk->n, pk->n2, NULL);
    free(pk);
}

void pcs_t_free_private_key(pcs_t_private_key *vk)
{
    mpz_clears(vk->p, vk->ph, vk->q, vk->qh, vk->v, vk->nm, vk->m, vk->n,
               vk->n2, vk->d, vk->delta, NULL);

    for (unsigned long i = 0; i < vk->l; ++i)
        mpz_clear(vk->vi[i]);
    free(vk->vi);
    free(vk);
}
