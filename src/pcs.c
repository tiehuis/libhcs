/*
 * @file pcs.c
 * @author Marc Tiehuis
 * @date 15 March 2015
 *
 * Implementation of the Paillier Cryptosystem (pcs).
 *
 * This variant is the first cryptoscheme described in Paillier's paper, scheme 1.
 * We incorporate a number of optimizations.
 *
 * The chinese remainder theorem is used during the decryption process.
 * The decrypted result is calculated seperately under mod p and mod q, and the
 * two results are then applied with the chinese remainder theorem to get the
 * decrypted result mod n.
 *
 * We also have a preprocessor flag which will allow a g chosen such that it is small.
 * The main improvement in speed here is found in the encryption phase with a modular
 * exponentation now being able to be taken with a smaller base than the usual n + 1.
 *
 * POSSIBLE IMPROVEMENTS:
 *  - Alter the location of the random number generator. This would save reading
 *    from a secure source each time we encrypt and would potentially improve performance
 *    by a noticeable amount. One consideration is where we store the random state, whether
 *    we want to initialise a pcs_state, or refcount a gmp_randstate_t type in a public
 *    and private key.
 *
 *  - Verify the PCS_G_EQ_2 define and resulting code in regards to performance. There may
 *    be an oversight which doesn't allow the improvement expected, otherwise it could likely
 *    be related to the mpz_powm algorithm currently employed and is not worth worrying about
 *    here.
 *
 *  - Add proper abstraction from the gmp library so user does not need to be aware of how
 *    the mpz_t types are interacted with. However, this library works solely on numbers
 *    right now, and to utilize the homomorphic features we are likely going to want to be
 *    aware of this as a caller, so it could potentially be a non-issue. The only thing is
 *    for other cryptosystems we may not have the consistent interface as we may possibly
 *    need to abstract the ciphertext information (e.g. for the Goldwasser-Micalli scheme).
 *
 *  - Potentially drop tpl for a simpler to use serialization interface. Or at least
 *    work on memory and rely on the user to deal with filesystems and everything else.
 *    It is likely this serialization would be used when sending over a network, so
 *    writing to memory is likely the more useful choice.
 *
 *  - Finish the fast variant (pcs3.c) and compare against the performance of this
 *    implementation.
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
    mpz_init(t1);
    mpz_init(t2);

    gmp_randstate_t rstate;
    gmp_randinit_default(rstate);
    mpz_seed(t1, PCS_SEED_BITS);
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

    gmp_randclear(rstate);
    mpz_clear(t1);
    mpz_clear(t2);
}

void pcs_decrypt(pcs_private_key *vk, mpz_t rop, mpz_t cipher1)
{
    mpz_t t1, t2;
    mpz_init(t1);
    mpz_init(t2);

    mpz_sub_ui(t1, vk->p, 1);
    mpz_powm(t1, cipher1, t1, vk->p2);
    mpz_sub_ui(t1, t1, 1);
    mpz_tdiv_q(t1, t1, vk->p);
    mpz_mul(t1, t1, vk->hp);
    mpz_mod(t1, t1, vk->p);

    mpz_sub_ui(t2, vk->q, 1);
    mpz_powm(t2, cipher1, t2, vk->q2);
    mpz_sub_ui(t2, t2, 1);
    mpz_tdiv_q(t2, t2, vk->q);
    mpz_mul(t2, t2, vk->hq);
    mpz_mod(t2, t2, vk->q);

    mpz_2crt(rop, t1, vk->p, t2, vk->q);
    mpz_mod(rop, rop, vk->n);

    mpz_clear(t1);
    mpz_clear(t2);
}

void pcs_reencrypt(pcs_public_key *pk, mpz_t rop, mpz_t op)
{
    mpz_t t1;
    mpz_init(t1);

    gmp_randstate_t rstate;
    gmp_randinit_default(rstate);
    mpz_seed(t1, PCS_SEED_BITS);
    gmp_randseed(rstate, t1);

    mpz_urandomm(t1, rstate, pk->n);
    mpz_powm(t1, t1, pk->n, pk->n2);
    mpz_mul(rop, op, t1);
    mpz_mod(rop, rop, pk->n2);

    gmp_randclear(rstate);
    mpz_clear(t1);
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

void pcs_generate_key_pair(pcs_public_key *pk, pcs_private_key *vk, const unsigned long bits)
{
    gmp_randstate_t rstate;
    gmp_randinit_default(rstate);
    mpz_seed(vk->p, PCS_SEED_BITS);
    gmp_randseed(rstate, vk->p);

    /* To generate n as 'bits' bits, we generate two primes of length bits/2 and take the
     * product. This ensures that n is in the range [bits, bits+1]. We do not want p and q
     * to be the same prime, so ensure they are not. This is very very unlikely as bits
     * gets large. */
    do {
        mpz_random_prime(vk->p, rstate, 1 + (bits-1)/2);
        mpz_random_prime(vk->q, rstate, 1 + (bits-1)/2);
    } while (mpz_cmp(vk->p, vk->q) == 0);

    /* Calculate private key values under the assumption that our primes are of similar
     * length */
    mpz_pow_ui(vk->p2, vk->p, 2);
    mpz_pow_ui(vk->q2, vk->q, 2);

    mpz_mul(vk->n, vk->p, vk->q);
    mpz_sub_ui(vk->lambda, vk->p, 1);
    mpz_sub_ui(vk->q, vk->q, 1);
    mpz_lcm(vk->lambda, vk->lambda, vk->q);
    mpz_add_ui(vk->q, vk->q, 1);
    mpz_pow_ui(vk->n2, vk->n, 2);

    /* Calculate public key fields */
    mpz_set(pk->n, vk->n);
    mpz_set(pk->n2, vk->n2);

#ifdef PCS_G_EQUAL_2  /* A special variant for when g = 2 */
    /* Ensure g is in Z^2* */
    if (mpz_gcd_ui(NULL, pk->n2, 2) != 1)
        err("gcd is not 1");

    /* Ensure n divides the order of g */
    mpz_set_ui(pk->g, 2);
    mpz_powm(vk->mu, pk->g, vk->lambda, pk->n2);
    mpz_sub_ui(vk->mu, vk->mu, 1);
    mpz_tdiv_q(vk->mu, vk->mu, pk->n);
    mpz_gcd(vk->hq, vk->mu, pk->n);

    /* Ensure mu has a multiplicative inverse */
    if (mpz_cmp_ui(vk->hq, 1) != 0)
        err("mu has no inverse");

    mpz_invert(vk->mu, vk->mu, pk->n);
#else
    mpz_invert(vk->mu, vk->lambda, vk->n);
    /* Otherwise g = n + 1 for simplicity */
    mpz_add_ui(pk->g, pk->n, 1);
#endif

    /* Some precomputations for decryption */
    mpz_sub_ui(vk->hp, vk->p, 1);
    mpz_powm(vk->hp, pk->g, vk->hp, vk->p2);
    mpz_sub_ui(vk->hp, vk->hp, 1);
    mpz_tdiv_q(vk->hp, vk->hp, vk->p);
    mpz_invert(vk->hp, vk->hp, vk->p);

    mpz_sub_ui(vk->hq, vk->q, 1);
    mpz_powm(vk->hq, pk->g, vk->hq, vk->q2);
    mpz_sub_ui(vk->hq, vk->hq, 1);
    mpz_tdiv_q(vk->hq, vk->hq, vk->q);
    mpz_invert(vk->hq, vk->hq, vk->q);

    gmp_randclear(rstate);
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

    mpz_inits(pk->g, pk->n, pk->n2, NULL);

    return pk;
}

pcs_private_key* pcs_init_private_key(void)
{
    pcs_private_key *vk = malloc(sizeof(pcs_private_key));
    if (!vk) return NULL;

    mpz_inits(vk->p, vk->p2, vk->q, vk->q2,
             vk->hp, vk->hq, vk->mu, vk->lambda,
             vk->n, vk->n2, NULL);

    return vk;
}

void pcs_clear_public_key(pcs_public_key *pk)
{
    mpz_zeros(pk->g, pk->n, pk->n2, NULL);
}

void pcs_free_public_key(pcs_public_key *pk)
{
    pcs_clear_public_key(pk);
    mpz_clears(pk->g, pk->n, pk->n2, NULL);
    free(pk);
}

void pcs_clear_private_key(pcs_private_key *vk)
{
    mpz_zeros(vk->p, vk->p2, vk->q, vk->q2,
             vk->hp, vk->hq, vk->mu, vk->lambda,
             vk->n, vk->n2, NULL);
}

void pcs_free_private_key(pcs_private_key *vk)
{
    pcs_clear_private_key(vk);
    mpz_clears(vk->p, vk->p2, vk->q, vk->q2,
               vk->hp, vk->hq, vk->mu, vk->lambda,
               vk->n, vk->n2, NULL);
    free(vk);
}

/* Currently obsolete until implementation is more stable */

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
