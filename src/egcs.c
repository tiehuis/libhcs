#include <stdio.h>
#include <gmp.h>
#include "com/util.h"
#include "hcs_rand.h"
#include "egcs.h"

void egcs_generate_key_pair(egcs_public_key *pk, egcs_private_key *vk, hcs_rand *hr, int bits)
{
    mpz_t t;
    mpz_init(t);

    /* Generate a prime number which will be the size of our group */
    mpz_random_prime(pk->q, hr->rstate, bits);

    /* Construct h = g ^ x */
    mpz_sub_ui(pk->q, pk->q, 1);
    mpz_urandomm(pk->g, hr->rstate, pk->q); /* g and x are both values in q */
    mpz_urandomm(vk->x, hr->rstate, pk->q); /* Construct a random x */
    mpz_add_ui(pk->q, pk->q, 1);
    mpz_add_ui(pk->g, pk->g, 1);
    mpz_add_ui(vk->x, vk->x, 1);
    mpz_powm(pk->h, pk->g, vk->x, pk->q);
    mpz_set(vk->q, pk->q);  // Problem here

    mpz_clear(t);
}

egcs_public_key* egcs_init_public_key(void)
{
    egcs_public_key *pk = malloc(sizeof(egcs_public_key));
    mpz_inits(pk->g, pk->q, pk->h, NULL);
    return pk;
}

egcs_private_key* egcs_init_private_key(void)
{
    egcs_private_key *vk = malloc(sizeof(egcs_private_key));
    mpz_inits(vk->x, vk->q, NULL);
    return vk;
}

egcs_cipher* egcs_init_cipher(void)
{
    egcs_cipher *ct = malloc(sizeof(egcs_cipher));
    mpz_inits(ct->c1, ct->c2, NULL);
    return ct;
}

void egcs_encrypt(egcs_public_key *pk, hcs_rand *hr, egcs_cipher *rop, mpz_t plain1)
{
    mpz_t t; mpz_init(t);

    /* Get random value for encryption */
    mpz_sub_ui(pk->q, pk->q, 1);
    mpz_urandomm(t, hr->rstate, pk->q);
    mpz_add_ui(t, t, 1);
    mpz_add_ui(pk->q, pk->q, 1);

    mpz_powm(rop->c1, pk->g, t, pk->q);    /* c1 value */

    mpz_powm(rop->c2, pk->h, t, pk->q);    /* c2 value */
    mpz_mul(rop->c2, rop->c2, plain1);
    mpz_mod(rop->c2, rop->c2, pk->q);

    mpz_zero(t); mpz_clear(t);
}

void egcs_decrypt(egcs_private_key *vk, mpz_t rop, egcs_cipher *ct)
{
    mpz_t t; mpz_init(t);

    mpz_sub_ui(t, vk->q, 1);
    mpz_sub(t, t, vk->x);

    mpz_powm(rop, ct->c1, t, vk->q);
    mpz_mul(rop, rop, ct->c2);
    mpz_mod(rop, rop, vk->q);
}

void egcs_clear_cipher(egcs_cipher *ct)
{
    mpz_zeros(ct->c1, ct->c2, NULL);
}

void egcs_free_cipher(egcs_cipher *ct)
{
    mpz_zeros(ct->c1, ct->c2, NULL);
    mpz_clears(ct->c1, ct->c2, NULL);
}

/* Destroy keys */
void egcs_free_public_key(egcs_public_key *pk)
{
    mpz_clears(pk->g, pk->q, pk->h, NULL);
    free(pk);
}

void egcs_free_private_key(egcs_private_key *vk)
{
    mpz_clears(vk->x, NULL);
    free(vk);
}
