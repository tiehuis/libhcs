/*
 *  GMCS (Goldwasser-Micali Cryptosystem)
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <gmp.h>
#include "com/tpl.h"
#include "com/util.h"
#include "egcs.h"

/* Key encryption functions */
void egcs_encrypt(egcs_public_key *pk, mpz_t rop, mpz_t plain1)
{
    /* Use the bits directly from an mpz_t object */
}

void egcs_decrypt(egcs_private_key *vk, mpz_t rop, mpz_t cipher1)
{
    mpz_powm(rop, cipher1, vk->lambda, vk->n2);
    mpz_sub_ui(rop, rop, 1);
    mpz_tdiv_q(rop, rop, vk->n);
    mpz_mul(rop, rop, vk->mu);
    mpz_mod(rop, rop, vk->n);
}

void egcs_ep_add(egcs_public_key *pk, mpz_t rop, mpz_t cipher1, mpz_t plain1)
{
    mpz_t t1; mpz_init(t1);

    mpz_set(t1, cipher1);
    mpz_powm(rop, pk->g, plain1, pk->n2);
    mpz_mul(rop, rop, t1);
    mpz_mod(rop, rop, pk->n2);

    mpz_clear(t1);
}

void egcs_ee_add(egcs_public_key *pk, mpz_t rop, mpz_t cipher1, mpz_t cipher2)
{
    mpz_mul(rop, cipher1, cipher2);
    mpz_mod(rop, rop, pk->n2);
}

void egcs_ep_mul(egcs_public_key *pk, mpz_t rop, mpz_t cipher1, mpz_t plain1)
{
    mpz_powm(rop, cipher1, plain1, pk->n2);
}

/* Key generation functions */
/* Add an argument to this for the bits wanted for the private prime */
void egcs_generate_key_pair(egcs_public_key *pk, egcs_private_key *vk, unsigned long bits)
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

/* Sanity checks for use when importing keys */
int egcs_verify_public_key(egcs_public_key *pk)
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

int egcs_verify_private_key(egcs_private_key *vk)
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

int egcs_verify_key_pair(egcs_public_key *pk, egcs_private_key *vk)
{
    return (!egcs_verify_public_key(pk) || !egcs_verify_private_key(vk)) ? 0 : 1;
}

egcs_public_key* egcs_init_public_key(void)
{
    egcs_public_key *pk = malloc(sizeof(egcs_public_key));
    if (!pk) return NULL;
    mpz_inits(pk->n, pk->g, pk->n2, NULL);
    return pk;
}

egcs_private_key* egcs_init_private_key(void)
{
    egcs_private_key *vk = malloc(sizeof(egcs_private_key));
    if (!vk) return NULL;
    mpz_inits(vk->lambda, vk->mu, vk->n, vk->n2, NULL);
    return vk;
}

void egcs_free_public_key(egcs_public_key *pk)
{
    mpz_zeros(pk->n, pk->g, pk->n2, NULL);
    mpz_clears(pk->n, pk->g, pk->n2, NULL);
    free(pk);
}

void egcs_free_private_key(egcs_private_key *vk)
{
    mpz_zeros(vk->lambda, vk->mu, vk->n, vk->n2, NULL);
    mpz_clears(vk->lambda, vk->mu, vk->n, vk->n2, NULL);
    free(vk);
}

int egcs_export_public_key(egcs_public_key *pk, char *file)
{
    /* N is largest/only value we need to store */
    const size_t buffer_size = mpz_sizeinbase(pk->n, 62) + 2;
    char *buffer = malloc(buffer_size);
    tpl_node *tn = tpl_map("A(s)", &buffer);

    /* Serialize n, mu, and lambda */
    mpz_get_str(buffer, 62, pk->n);
    tpl_pack(tn, 1);

    if (tpl_dump(tn, TPL_FILE, file) == -1) goto failure;
    tpl_free(tn);
    free(buffer);
    return 0;

failure:
    tpl_free(tn);
    return -1;
}

int egcs_export_private_key(egcs_private_key *vk, char *file)
{
    /* N is largest value we need to store */
    const size_t buffer_size = mpz_sizeinbase(vk->n, 62) + 2;
    char *buffer = malloc(buffer_size);
    tpl_node *tn = tpl_map("A(s)", &buffer);

    /* Serialize n, mu, and lambda */
    mpz_get_str(buffer, 62, vk->lambda);
    tpl_pack(tn, 1);
    mpz_get_str(buffer, 62, vk->mu);
    tpl_pack(tn, 1);
    mpz_get_str(buffer, 62, vk->n);
    tpl_pack(tn, 1);

    if (tpl_dump(tn, TPL_FILE, file) == -1) goto failure;
    tpl_free(tn);
    free(buffer);
    return 0;

failure:
    tpl_free(tn);
    return -1;
}

int egcs_import_public_key(egcs_public_key *pk, char *file)
{
    char *ptr;
    tpl_node *tn = tpl_map("A(s)", &ptr);
    tpl_load(tn, TPL_FILE, file);

    if (tpl_unpack(tn, 1) <= 0) goto failure;
    mpz_set_str(pk->n, ptr, 62);
    free(ptr);

    /* Maybe zero memory used by tpl especially on
     * public key import */
    tpl_free(tn);
    mpz_add_ui(pk->g, pk->n, 1);
    mpz_pow_ui(pk->n2, pk->n, 2);
    return 0;

failure:
    tpl_free(tn);
    return 1;
}

int egcs_import_private_key(egcs_private_key *vk, char *file)
{
    char *ptr;
    tpl_node *tn = tpl_map("A(s)", &ptr);
    tpl_load(tn, TPL_FILE, file);

    if (tpl_unpack(tn, 1) <= 0) goto failure;
    mpz_set_str(vk->lambda, ptr, 62);
    free(ptr);
    if (tpl_unpack(tn, 1) <= 0) goto failure;
    mpz_set_str(vk->mu, ptr, 62);
    free(ptr);
    if (tpl_unpack(tn, 1) <= 0) goto failure;
    mpz_set_str(vk->n, ptr, 62);
    free(ptr);

    tpl_free(tn);
    mpz_pow_ui(vk->n2, vk->n, 2);
    return 1;

failure:
    tpl_free(tn);
    return 0;
}
