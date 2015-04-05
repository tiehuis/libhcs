/*
 * @file pcs.c
 * @author Marc Tiehuis
 * @date 15 March 2015
 *
 * Implementation of the Paillier Cryptosystem (pcs).
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <gmp.h>
#include "com/tpl.h"
#include "com/util.h"
#include "pcs.h"

void pcs_encrypt(pcs_public_key *pk, mpz_t rop, mpz_t plain1)
{
    mpz_t t1, t2;
    mpz_inits(t1, t2, NULL);

    gmp_randstate_t rstate;
    gmp_randinit_default(rstate);
    mpz_seed(t1, 256);
    gmp_randseed(rstate, t1);

    /* Generate a random r in Zn*. This is very likely to pass on the first time
     * as n is comprised of two large prime factors n = p*q, p != q */
    do {
        mpz_urandomm(t2, rstate, pk->n);
        mpz_gcd(t1, t2, pk->n);
    } while (mpz_cmp_ui(t1, 1));

    /* g^m * r^n mod n^2 = (g^m mod n^2) * (r^n mod n^2) mod n^2 */
    mpz_powm(t2, t2, pk->n, pk->n2);
    mpz_powm(rop, pk->g, plain1, pk->n2);
    mpz_mul(rop, rop, t2);
    mpz_mod(rop, rop, pk->n2);

    mpz_clear(t1); mpz_clear(t2);
    gmp_randclear(rstate);
}

void pcs_decrypt(pcs_private_key *vk, mpz_t rop, mpz_t cipher1)
{
    mpz_powm(rop, cipher1, vk->lambda, vk->n2);
    mpz_sub_ui(rop, rop, 1);
    mpz_tdiv_q(rop, rop, vk->n);
    mpz_mul(rop, rop, vk->mu);
    mpz_mod(rop, rop, vk->n);
}

void pcs_reencrypt(pcs_public_key *pk, mpz_t rop, mpz_t op)
{
    mpz_t t1;
    mpz_init(t1);

    gmp_randstate_t rstate;
    gmp_randinit_default(rstate);
    mpz_seed(t1, 256);
    gmp_randseed(rstate, t1);

    mpz_urandomm(t1, rstate, pk->n);
    mpz_powm(t1, t1, pk->n, pk->n2);
    mpz_mul(rop, op, t1);
    mpz_mod(rop, rop, pk->n2);

    mpz_clear(t1);
    gmp_randclear(rstate);
}

void pcs_ep_add(pcs_public_key *pk, mpz_t rop, mpz_t cipher1, mpz_t plain1)
{
    mpz_t t1;
    mpz_init(t1);

    mpz_set(t1, cipher1);
    /* When g = 2, this is effectively a bitwise shift and a modulo. */
    mpz_powm(rop, pk->g, plain1, pk->n2);
    mpz_mul(rop, rop, t1);
    mpz_mod(rop, rop, pk->n2);

    mpz_clear(t1);
}

void pcs_ee_add(pcs_public_key *pk, mpz_t rop, mpz_t cipher1, mpz_t cipher2)
{
    mpz_mul(rop, cipher1, cipher2);
    mpz_mod(rop, rop, pk->n2);
}

void pcs_ep_mul(pcs_public_key *pk, mpz_t rop, mpz_t cipher1, mpz_t plain1)
{
    mpz_powm(rop, cipher1, plain1, pk->n2);
}

void pcs_generate_key_pair(pcs_public_key *pk, pcs_private_key *vk, const unsigned long bits, int option)
{
    mpz_t p, q;
    mpz_inits(p, q, NULL);

    gmp_randstate_t rstate;
    gmp_randinit_default(rstate);
    mpz_seed(p, 256);
    gmp_randseed(rstate, p);

    /* To generate n as 'bits' bits, we generate two primes of length bits/2 and take the
     * product. This ensures that n is in the range [bits, bits+1]. We do not want p and q
     * to be the same prime, so ensure they are not. This is very very unlikely as bits
     * gets large. */
    do {
        mpz_random_prime(p, rstate, 1 + (bits-1)/2);
        mpz_random_prime(q, rstate, 1 + (bits-1)/2);
    } while (mpz_cmp(p, q) == 0);

    /* Calculate private key values under the assumption that our primes are of similar
     * length */
    mpz_mul(vk->n, p, q);
    mpz_sub_ui(vk->lambda, p, 1);
    mpz_sub_ui(q, q, 1);
    mpz_lcm(vk->lambda, vk->lambda, q);
    mpz_add_ui(q, q, 1);
    mpz_pow_ui(vk->n2, vk->n, 2);

    /* Calculate public key fields */
    mpz_set(pk->n, vk->n);
    mpz_set(pk->n2, vk->n2);

//#ifdef PCS_GEQ2  /* A special variant for when g = 2 */
if (option == 1) {
    /* Ensure g is in Z^2* */
    if (mpz_gcd_ui(NULL, pk->n2, 2) != 1) err("gcd is not 1");

    /* Ensure n divides the order of g */
    mpz_set_ui(pk->g, 2);
    mpz_powm(vk->mu, pk->g, vk->lambda, pk->n2);
    mpz_sub_ui(vk->mu, vk->mu, 1);
    mpz_tdiv_q(vk->mu, vk->mu, pk->n);
    mpz_gcd(p, vk->mu, pk->n);

    /* Ensure mu has a multiplicative inverse */
    if (mpz_cmp_ui(p, 1) != 0) err("mu has no inverse");
    mpz_invert(vk->mu, vk->mu, pk->n);
}
//#else
else {
    mpz_invert(vk->mu, vk->lambda, vk->n);
    /* Otherwise g = n + 1 for simplicity */
    mpz_add_ui(pk->g, pk->n, 1);
}
//#endif

    gmp_randclear(rstate);
    mpz_clear(p); mpz_clear(q);
}

/* Sanity checks for use when importing keys */
int pcs_verify_public_key(pcs_public_key *pk)
{
    mpz_t t;
    mpz_init(t);

    mpz_add_ui(t, pk->n, 1);
    if (mpz_cmp(t, pk->g))
        return 0;

    mpz_pow_ui(t, pk->n, 2);
    if (mpz_cmp(t, pk->n2))
        return 0;

    mpz_clear(t);
    return 1;
}

int pcs_verify_private_key(pcs_private_key *vk)
{
    mpz_t t;
    mpz_init(t);

    mpz_pow_ui(t, vk->n, 2);
    if (mpz_cmp(t, vk->n2))
        return 0;

    mpz_invert(t, vk->lambda, vk->n);
    if (mpz_cmp(t, vk->mu))
        return 0;

    mpz_clear(t);
    return 1;
}

int pcs_verify_key_pair(pcs_public_key *pk, pcs_private_key *vk)
{
    return (!pcs_verify_public_key(pk) || !pcs_verify_private_key(vk)) ? 0 : 1;
}

pcs_public_key* pcs_init_public_key(void)
{
    pcs_public_key *pk = malloc(sizeof(pcs_public_key));
    if (!pk) return NULL;
    mpz_inits(pk->n, pk->g, pk->n2, NULL);
    return pk;
}

pcs_private_key* pcs_init_private_key(void)
{
    pcs_private_key *vk = malloc(sizeof(pcs_private_key));
    if (!vk) return NULL;
    mpz_inits(vk->lambda, vk->mu, vk->n, vk->n2, NULL);
    return vk;
}

void pcs_clear_public_key(pcs_public_key *pk)
{
    mpz_zeros(pk->n, pk->g, pk->n2, NULL);
}

void pcs_free_public_key(pcs_public_key *pk)
{
    pcs_clear_public_key(pk);
    mpz_clears(pk->n, pk->g, pk->n2, NULL);
    free(pk);
}

void pcs_clear_private_key(pcs_private_key *vk)
{
    mpz_zeros(vk->lambda, vk->mu, vk->n, vk->n2, NULL);
}

void pcs_free_private_key(pcs_private_key *vk)
{
    pcs_clear_private_key(vk);
    mpz_clears(vk->lambda, vk->mu, vk->n, vk->n2, NULL);
    free(vk);
}

int pcs_export_public_key(pcs_public_key *pk, const char *file)
{
    /* N is largest/only value we need to store */
    const size_t buffer_size = mpz_sizeinbase(pk->n, HCS_BASE) + 2;
    char *buffer = malloc(buffer_size);
    tpl_node *tn = tpl_map("A(s)", &buffer);

    /* Serialize n, mu, and lambda */
    mpz_get_str(buffer, HCS_BASE, pk->n);
    tpl_pack(tn, 1);

    if (tpl_dump(tn, TPL_FILE, file) == -1) goto failure;
    tpl_free(tn);
    free(buffer);
    return 0;

failure:
    tpl_free(tn);
    return -1;
}

int pcs_export_private_key(pcs_private_key *vk, const char *file)
{
    /* N is largest value we need to store */
    const size_t buffer_size = mpz_sizeinbase(vk->n, HCS_BASE) + 2;
    char *buffer = malloc(buffer_size);
    tpl_node *tn = tpl_map("A(s)", &buffer);

    /* Serialize n, mu, and lambda */
    mpz_get_str(buffer, HCS_BASE, vk->lambda);
    tpl_pack(tn, 1);
    mpz_get_str(buffer, HCS_BASE, vk->mu);
    tpl_pack(tn, 1);
    mpz_get_str(buffer, HCS_BASE, vk->n);
    tpl_pack(tn, 1);

    if (tpl_dump(tn, TPL_FILE, file) == -1) goto failure;
    tpl_free(tn);
    free(buffer);
    return 0;

failure:
    tpl_free(tn);
    return -1;
}

int pcs_import_public_key(pcs_public_key *pk, const char *file)
{
    char *ptr;
    tpl_node *tn = tpl_map("A(s)", &ptr);
    tpl_load(tn, TPL_FILE, file);

    if (tpl_unpack(tn, 1) <= 0) goto failure;
    mpz_set_str(pk->n, ptr, HCS_BASE);
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

int pcs_import_private_key(pcs_private_key *vk, const char *file)
{
    char *ptr;
    tpl_node *tn = tpl_map("A(s)", &ptr);
    tpl_load(tn, TPL_FILE, file);

    if (tpl_unpack(tn, 1) <= 0) goto failure;
    mpz_set_str(vk->lambda, ptr, HCS_BASE);
    free(ptr);
    if (tpl_unpack(tn, 1) <= 0) goto failure;
    mpz_set_str(vk->mu, ptr, HCS_BASE);
    free(ptr);
    if (tpl_unpack(tn, 1) <= 0) goto failure;
    mpz_set_str(vk->n, ptr, HCS_BASE);
    free(ptr);

    tpl_free(tn);
    mpz_pow_ui(vk->n2, vk->n, 2);
    return 1;

failure:
    tpl_free(tn);
    return 0;
}
