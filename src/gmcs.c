/*
 *  GMCS (Goldwasser-Micali Cryptosystem)
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <gmp.h>
#include "com/kvec.h"
#include "com/tpl.h"
#include "com/util.h"
#include "gmcs.h"

/* Key encryption functions */
void gmcs_encrypt(gmcs_public_key *pk, mpz_t rop, mpz_t plain1)
{
    /* Use the bits directly from an mpz_t object */

}

void gmcs_decrypt(gmcs_private_key *vk, mpz_t rop, mpz_t cipher1)
{
    mpz_powm(rop, cipher1, vk->lambda, vk->n2);
    mpz_sub_ui(rop, rop, 1);
    mpz_tdiv_q(rop, rop, vk->n);
    mpz_mul(rop, rop, vk->mu);
    mpz_mod(rop, rop, vk->n);
}

void gmcs_ep_add(gmcs_public_key *pk, mpz_t rop, mpz_t cipher1, mpz_t plain1)
{
    mpz_t t1; mpz_init(t1);

    mpz_set(t1, cipher1);
    mpz_powm(rop, pk->g, plain1, pk->n2);
    mpz_mul(rop, rop, t1);
    mpz_mod(rop, rop, pk->n2);

    mpz_clear(t1);
}

void gmcs_ee_add(gmcs_public_key *pk, mpz_t rop, mpz_t cipher1, mpz_t cipher2)
{
    mpz_mul(rop, cipher1, cipher2);
    mpz_mod(rop, rop, pk->n2);
}

void gmcs_ep_mul(gmcs_public_key *pk, mpz_t rop, mpz_t cipher1, mpz_t plain1)
{
    mpz_powm(rop, cipher1, plain1, pk->n2);
}

/* Key generation functions */
/* Add an argument to this for the bits wanted for the private prime */
void gmcs_generate_key_pair(gmcs_public_key *pk, gmcs_private_key *vk, unsigned long bits)
{
    gmp_randstate_t rstate;
    gmp_randinit_default(rstate);
    mpz_seed(vk->p, 256);
    gmp_randseed(rstate, vk->p);

    /* Compute two bits/2 primes. The product is then > 'bits' bits. It can range from
     * [bits + 1, bits] */
    mpz_random_prime(vk->p, rstate, 1 + (bits-1)/2);
    mpz_random_prime(vk->q, rstate, 1 + (bits-1)/2);

    mpz_mul(pk->n, vk->p, vk->q);

    /* If we have a Blum integer, use n - 1 for x */
    if (mpz_fdiv_ui(vk->p, 4) == 3 && mpz_fdiv_ui(vk->q, 4) == 3) {
        mpz_sub_ui(pk->x, pk->n, 1);
    }
    else {
        do {
            mpz_urandomm(pk->x, rstate, pk->n);
        } while (mpz_legendre(pk->x, vk->p) == -1 && mpz_legendre(pk->x, vk->q) == -1);
    }

    /* Private key is (p, q)
     * Public  key is (x, n)
     * */

    gmp_randclear(rstate);
}

gmcs_cipher* gmcs_init_cipher(void)
{
    gmcs_cipher *ct = malloc(sizeof(gmcs_cipher));
    kvec_init(ct->v);
}

void gmcs_free_cipher(gmcs_cipher *c)
{
    kvec_destroy(ct->v);
}

/* Sanity checks for use when importing keys */
int gmcs_verify_public_key(gmcs_public_key *pk)
{
    mpz_t t; mpz_init(t);

    mpz_add_ui(t, pk->n, 1);
    if (mpz_cmp(t, pk->g))
        return 0;

    mpz_pow_ui(t, pk->n, 2);
    if (mpz_cmp(t, pk->n2))
        return 0;

    mpz_clear(t);
    return 1;
}

int gmcs_verify_private_key(gmcs_private_key *vk)
{
    mpz_t t; mpz_init(t);

    mpz_pow_ui(t, vk->n, 2);
    if (mpz_cmp(t, vk->n2))
        return 0;

    mpz_invert(t, vk->lambda, vk->n);
    if (mpz_cmp(t, vk->mu))
        return 0;

    mpz_clear(t);
    return 1;
}

int gmcs_verify_key_pair(gmcs_public_key *pk, gmcs_private_key *vk)
{
    return (!gmcs_verify_public_key(pk) || !gmcs_verify_private_key(vk)) ? 0 : 1;
}

gmcs_public_key* gmcs_init_public_key(void)
{
    gmcs_public_key *pk = malloc(sizeof(gmcs_public_key));
    if (!pk) return NULL;
    mpz_inits(pk->n, pk->g, pk->n2, NULL);
    return pk;
}

gmcs_private_key* gmcs_init_private_key(void)
{
    gmcs_private_key *vk = malloc(sizeof(gmcs_private_key));
    if (!vk) return NULL;
    mpz_inits(vk->lambda, vk->mu, vk->n, vk->n2, NULL);
    return vk;
}

void gmcs_free_public_key(gmcs_public_key *pk)
{
    mpz_zeros(pk->n, pk->g, pk->n2, NULL);
    mpz_clears(pk->n, pk->g, pk->n2, NULL);
    free(pk);
}

void gmcs_free_private_key(gmcs_private_key *vk)
{
    mpz_zeros(vk->lambda, vk->mu, vk->n, vk->n2, NULL);
    mpz_clears(vk->lambda, vk->mu, vk->n, vk->n2, NULL);
    free(vk);
}
