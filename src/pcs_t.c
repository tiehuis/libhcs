/*
 * @file pcs_t.c
 * @author Marc Tiehuis
 * @date 15 March 2015
 *
 * Implementation of the Paillier Cryptosystem (pcs_t).
 *
 * This scheme is a threshold variant of the Paillier system. It loosely follows
 * the scheme presented in the paper by damgard-jurik, but with a chosen base of
 * 2, rather than the variable s+1. This scheme was written first for simplicity.
 *
 * POSSIBLE IMPROVEMENTS:
 *
 *  - Rewrite all assertions as checks that return error codes instead. We don't
 *    want to crash and instead want to relay this information to the caller.
 */

#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <gmp.h>
#include "com/util.h"
#include "pcs_t.h"

/* This is much simpler for the paillier scheme and is simply
 * a computation of L(x) */
static void dlog_s(pcs_t_private_key *vk, mpz_t rop, mpz_t op)
{
    mpz_sub_ui(rop, op, 1);
    mpz_divexact(rop, rop, vk->n);
    mpz_mod(rop, rop, vk->n);
}

void pcs_t_encrypt(pcs_t_public_key *pk, mpz_t rop, mpz_t plain1)
{
    mpz_t t1;
    mpz_init(t1);

    gmp_randstate_t rstate;
    gmp_randinit_default(rstate);
    mpz_seed(t1, PCS_T_SEED_BITS);
    gmp_randseed(rstate, t1);

    mpz_urandomm(t1, rstate, pk->n);
    mpz_powm(rop, t1, pk->n, pk->n2);
    mpz_powm(t1, pk->g, plain1, pk->n2);
    mpz_mul(rop, rop, t1);
    mpz_mod(rop, rop, pk->n2);

    gmp_randclear(rstate);
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
    mpz_powm(rop, cipher1, t1, vk->n2); // Can i powermod here? I do it later??

    mpz_clear(t1);
}

void pcs_t_share_combine(pcs_t_private_key *vk, mpz_t rop, mpz_t *c, unsigned long cl)
{
    /* Take a subset of w shares from c, if we don't have w shares then we can
     * not combine and get a result. Set rop to 0. */
    if (cl < vk->w) mpz_set_ui(rop, 0);

    mpz_t t1, t2;
    mpz_init(t1);
    mpz_init(t2);

    /* Could alter loop to choose a random subset instead of always 0-indexing.
     * Also, note that the first iteration will always be 0, thus we are computing
     * c[0]^0 = 1 and multiplying against rop. Skip this first loop and being
     * from i = 1. */
    mpz_set_ui(rop, 1);
    for (unsigned long i = 1; i < vk->w; ++i) {

        /* Shares must be set to some value. Return with error if not
         * instead of making an assertion. */
        assert(mpz_cmp_ui(c[i], 0) != 0);

        /* Compute lambda_{0,i}^S */
        mpz_set_ui(t1, 1);
        for (unsigned long j = 0; j < vk->w; ++j) {
            if (j == i) continue; /* i' in S\i */
#if 0
            mpz_sub(t2, c[i], c[j]);
            mpz_tdiv_q(t2, c[i], t2);
            mpz_neg(t2, t2);
            mpz_mul(t1, t1, t2);
            mpz_mod(t1, t1, vk->n2);
#else
            /* We are calculating lagrange coefficients */
            mpz_mul_si(t1, t1, -i / (i - j));
#endif
        }
        /* Now we have lambda_{0,i}^S in t1 */
        mpz_mul(t1, t1, vk->delta);
        mpz_mul_ui(t1, t1, 2);
        mpz_powm(t1, c[i], t1, vk->n2);
        mpz_mul(rop, rop, t1);
    }

    /* We now have c', so use algorithm from Theorem 1 to derive the result */
    dlog_s(vk, rop, rop);

    /* Multiply by (4*delta^2)^-1 mod n^2 to get result */
    mpz_pow_ui(t1, vk->delta, 2);
    mpz_mul_ui(t1, t1, 4);
    mpz_invert(t1, t1, vk->n2); // assume this inverse exists for now, add a check
    mpz_mul(rop, rop, t1);
    mpz_mod(rop, rop, vk->n2);

    mpz_clear(t1);
    mpz_clear(t2);
}

static void polynomial_function(pcs_t_private_key *vk, mpz_t rop, const unsigned long v)
{

    mpz_t t1, t2;
    mpz_init(t1);
    mpz_init(t2);

    gmp_randstate_t rstate;
    gmp_randinit_default(rstate);
    mpz_seed(vk->d, PCS_T_SEED_BITS);
    gmp_randseed(rstate, vk->d);

    /* Compute a polynomial with random coefficients in n2m */
    mpz_set(rop, vk->d);
    for (unsigned long i = 1; i < vk->l; ++i) {
        mpz_ui_pow_ui(t1, v, i);
#ifdef PERSIST_POLYNOMIAL
        mpz_mul(t1, t1, vk->mm[i]);
#else
        mpz_urandomm(t2, rstate, vk->n2m);
        mpz_mul(t1, t1, t2);
#endif
        mpz_add(rop, rop, t1);
        mpz_mod(rop, rop, vk->n2m);
    }

    gmp_randclear(rstate);
    mpz_clear(t1);
    mpz_clear(t2);
}

/* Maybe change the arguments passed to this to avoid an individual tampering with
 * the results. One should calculate their verification and send that to the central
 * party, not modify the private key themselves. Keep this as is now though for
 * simplicity in a local example. */
void pcs_t_set_auth_server(pcs_t_private_key *vk, pcs_t_auth_server *au, unsigned long i)
{
    polynomial_function(vk, au->si, i);
    mpz_mul(vk->vi[i], vk->delta, au->si);
    mpz_powm(vk->vi[i], vk->v, vk->vi[i], vk->n2);
}

/* Look into methods of using multiparty computation to generate these keys and
 * the data such that we don't have to have a trusted party for generation. */
void pcs_t_generate_key_pair(pcs_t_public_key *pk, pcs_t_private_key *vk,
        const unsigned long bits, const unsigned long w, const unsigned long l)
{
    /* We can only perform this encryption if we have a w >= l / 2. Unsure
     * if this is the rounded value or not. i.e. is (1,3) system okay?
     * 3 / 2 = 1 by truncation >= 1. Need to confirm if this is allowed, or
     * more traditional rounding should be applied. */
    assert(w >= l / 2);

    mpz_t t1, t2;
    mpz_init(t1);
    mpz_init(t2);

    gmp_randstate_t rstate;
    gmp_randinit_default(rstate);
    mpz_seed(vk->d, PCS_T_SEED_BITS);
    gmp_randseed(rstate, vk->d);

    /* Choose p and q to be safe primes */
    do {
        mpz_random_safe_prime(vk->p, vk->qh, rstate, 1 + (bits-1)/2);
        mpz_random_safe_prime(vk->q, vk->ph, rstate, 1 + (bits-1)/2);
    } while (mpz_cmp(vk->p, vk->q) == 0);

    /* n = p * q */
    mpz_mul(pk->n, vk->p, vk->q);
    mpz_set(vk->n, pk->n);

    /* Lambda = lcm(p-1,q-1) */
    mpz_sub_ui(vk->lambda, vk->p, 1);
    mpz_sub_ui(vk->q, vk->q, 1);
    mpz_lcm(vk->lambda, vk->lambda, vk->q);
    mpz_add_ui(vk->q, vk->q, 1);

    /* n^2 = n * n */
    mpz_pow_ui(pk->n2, pk->n, 2);
    mpz_set(vk->n2, pk->n2);

    /* g = n + 1 */
    mpz_add_ui(pk->g, pk->n, 1);

    /* d == 1 mod n^2 and d == 0 mod lambda */
    mpz_set_ui(t1, 1);
    mpz_set_ui(t2, 0);
    mpz_2crt(vk->d, t1, vk->n2, t2, vk->lambda);

    /* Compute m = ph * qh */
    mpz_mul(vk->m, vk->ph, vk->qh);

    /* Compute n^2 * m */
    mpz_mul(vk->n2m, vk->n2, vk->m);

    /* Set l and w in private key */
    vk->l = l;
    vk->w = w;

    /* Allocate space for verification values */
    vk->vi = malloc(sizeof(mpz_t) * l);
    for (unsigned long i = 0; i < l; ++i)
        mpz_init(vk->vi[i]);

    /* Precompute delta = l! */
    mpz_fac_ui(vk->delta, vk->l);

    /* Compute v being a cyclic generator of squares. This group is
     * always cyclic of order n * p' * q' since n is a safe prime product. */
    mpz_set(vk->v, vk->ph);

#ifdef PERSIST_POLYNOMIAL
    vk->mm = malloc(sizeof(mpz_t) * vk->l);
    mpz_init_set(vk->mm[0], vk->d);
    for (unsigned long i = 1; i < vk->l; ++i) {
        mpz_init(vk->mm[i]);
        mpz_urandomm(vk->mm[i], rstate, vk->n2m);
    }
#endif

    gmp_randclear(rstate);
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
    mpz_inits(vk->p, vk->ph, vk->q, vk->qh,
             vk->v, vk->lambda, vk->n2m, vk->m,
             vk->n, vk->n2, vk->d, vk->delta, NULL);

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
    mpz_clears(vk->p, vk->ph, vk->q, vk->qh,
             vk->v, vk->lambda, vk->n2m, vk->m,
             vk->n, vk->n2, vk->d, vk->delta, NULL);

    for (unsigned long i = 0; i < vk->w; ++i)
        mpz_clear(vk->vi[i]);
    free(vk->vi);
    free(vk);
}
