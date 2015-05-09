/**
 * @file egcs.c
 *
 * The implemenation of the ElGamal cryptosystem.
 *
 * \todo Confirm that the functions in this scheme work as intended.
 */

#include <stdio.h>
#include <gmp.h>
#include "com/util.h"
#include "hcs_rand.h"
#include "egcs.h"

egcs_public_key* egcs_init_public_key(void)
{
    egcs_public_key *pk = malloc(sizeof(egcs_public_key));
    if (pk == NULL) return NULL;

    mpz_inits(pk->g, pk->q, pk->h, NULL);
    return pk;
}

egcs_private_key* egcs_init_private_key(void)
{
    egcs_private_key *vk = malloc(sizeof(egcs_private_key));
    if (vk == NULL) return NULL;

    mpz_inits(vk->x, vk->q, NULL);
    return vk;
}

void egcs_generate_key_pair(egcs_public_key *pk, egcs_private_key *vk,
        hcs_rand *hr, int bits)
{
    mpz_t t;
    mpz_init(t);

    mpz_random_prime(pk->q, hr->rstate, bits);
    mpz_sub_ui(pk->q, pk->q, 1);
    mpz_urandomm(pk->g, hr->rstate, pk->q);
    mpz_urandomm(vk->x, hr->rstate, pk->q);
    mpz_add_ui(pk->q, pk->q, 1);
    mpz_add_ui(pk->g, pk->g, 1);
    mpz_add_ui(vk->x, vk->x, 1);
    mpz_powm(pk->h, pk->g, vk->x, pk->q);
    mpz_set(vk->q, pk->q);

    mpz_clear(t);
}

egcs_cipher* egcs_init_cipher(void)
{
    egcs_cipher *ct = malloc(sizeof(egcs_cipher));
    if (ct == NULL) return NULL;

    mpz_inits(ct->c1, ct->c2, NULL);
    return ct;
}

void egcs_encrypt(egcs_public_key *pk, hcs_rand *hr, egcs_cipher *rop,
                  mpz_t plain1)
{
    mpz_t t;
    mpz_init(t);

    mpz_sub_ui(pk->q, pk->q, 1);
    mpz_urandomm(t, hr->rstate, pk->q);
    mpz_add_ui(t, t, 1);
    mpz_add_ui(pk->q, pk->q, 1);
    mpz_powm(rop->c1, pk->g, t, pk->q);
    mpz_powm(rop->c2, pk->h, t, pk->q);
    mpz_mul(rop->c2, rop->c2, plain1);
    mpz_mod(rop->c2, rop->c2, pk->q);

    mpz_clear(t);
}

void egcs_ee_mul(egcs_public_key *pk, egcs_cipher *rop, egcs_cipher *ct1,
        egcs_cipher *ct2)
{
    mpz_mul(rop->c1, ct1->c1, ct2->c2);
    mpz_mod(rop->c1, rop->c1, pk->q);
    mpz_mul(rop->c2, ct1->c2, ct2->c2);
    mpz_mod(rop->c2, rop->c2, pk->q);
}

void egcs_decrypt(egcs_private_key *vk, mpz_t rop, egcs_cipher *ct)
{
    mpz_t t;
    mpz_init(t);

    mpz_sub_ui(t, vk->q, 1);
    mpz_sub(t, t, vk->x);
    mpz_powm(rop, ct->c1, t, vk->q);
    mpz_mul(rop, rop, ct->c2);
    mpz_mod(rop, rop, vk->q);

    mpz_clear(t);
}

void egcs_clear_cipher(egcs_cipher *ct)
{
    mpz_zero(ct->c1);
    mpz_zero(ct->c2);
}

void egcs_free_cipher(egcs_cipher *ct)
{
    mpz_clear(ct->c1);
    mpz_clear(ct->c2);
    free(ct);
}

void egcs_clear_public_key(egcs_public_key *pk)
{
    mpz_zero(pk->g);
    mpz_zero(pk->q);
    mpz_zero(pk->h);
}

void egcs_clear_private_key(egcs_private_key *vk)
{
    mpz_zero(vk->x);
    mpz_zero(vk->q);
}

void egcs_free_public_key(egcs_public_key *pk)
{
    mpz_clear(pk->g);
    mpz_clear(pk->q);
    mpz_clear(pk->h);
    free(pk);
}

void egcs_free_private_key(egcs_private_key *vk)
{
    mpz_clear(vk->x);
    mpz_clear(vk->q);
    free(vk);
}

#ifdef MAIN
int main(void)
{
    egcs_private_key *vk = egcs_init_private_key();
    egcs_public_key *pk = egcs_init_public_key();
    hcs_rand *hr = hcs_rand_init(0);

    egcs_generate_key_pair(pk, vk, hr, 128);

    mpz_t a, b;
    egcs_cipher *c = egcs_init_cipher();
    egcs_cipher *d = egcs_init_cipher();
    mpz_init_set_ui(a, 10);
    mpz_init_set_ui(b, 7);

    egcs_encrypt(pk, hr, c, a);
    egcs_encrypt(pk, hr, d, b);
    //egcs_ee_mul(pk, c, c, d);
    egcs_decrypt(vk, a, c);

    gmp_printf("%Zd\n", c);

    mpz_clear(a);
    mpz_clear(b);
    egcs_free_cipher(c);
    egcs_free_cipher(d);

    egcs_free_public_key(pk);
    egcs_free_private_key(vk);
    hcs_rand_free(hr);
}
#endif
