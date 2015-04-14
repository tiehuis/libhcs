/**
 * @file pcs_t.h
 * @author Marc Tiehuis
 * @date 15 March 2015
 * @brief Header containing function and type definitions for the Paillier cryptosystem.
 *
 * A more detailed look at the internals can be found in pcs_t.c
 */

#ifndef PCS_T_H
#define PCS_T_H

#include <gmp.h>

#ifdef __cplusplus
extern "C" {
#endif

/** The number of bits gathered for seeding the prng */
#define PCS_T_SEED_BITS 256

typedef struct {
    mpz_t si;
} pcs_t_auth_server;

/**
 * @brief The type for a public key, for use with the Paillier system
 */
typedef struct {
    mpz_t n;        /**< Modulus of the key. n = p * q */
    mpz_t g;        /**< Precomputation: n + 1 usually, may be 2*/
    mpz_t n2;       /**< Precomputation: n^2 */

} pcs_t_public_key;

/**
 * @brief The type for a private key, for use with the Paillier system.
 */
typedef struct {
    unsigned long w;
    unsigned long l;
    mpz_t v;    // Cyclic generator of squares in Z*n^2
    mpz_t *vi;
    mpz_t m;
    mpz_t n2m;

    mpz_t delta;


    mpz_t d;
    mpz_t p;        /**< A random prime determined during key generation */
    mpz_t ph;
    mpz_t q;        /**< A random prime determined during key generation */
    mpz_t qh;
    mpz_t lambda;   /**< Precomputation: euler-phi(p, q) */
    mpz_t n;        /**< Modulus of the key: p * q */
    mpz_t n2;       /**< Precomputation: n^2 */
} pcs_t_private_key;

void pcs_t_generate_key_pair(pcs_t_public_key *pk, pcs_t_private_key *vk,
        const unsigned long bits, const unsigned long l, const unsigned long w);

void pcs_t_set_auth_server(pcs_t_private_key *vk, pcs_t_auth_server *au, unsigned long i);

void pcs_t_share_decrypt(pcs_t_private_key *vk, pcs_t_auth_server *au,
        mpz_t rop, mpz_t cipher1);

void pcs_t_share_combine(pcs_t_private_key *vk, mpz_t rop, mpz_t *c, unsigned long cl);

void pcs_t_encrypt(pcs_t_public_key *pk, mpz_t rop, mpz_t plain1);

pcs_t_auth_server* pcs_t_init_auth_server(void);

pcs_t_public_key* pcs_t_init_public_key(void);
pcs_t_private_key* pcs_t_init_private_key(void);
void pcs_t_free_auth_server(pcs_t_auth_server *au);
void pcs_t_free_public_key(pcs_t_public_key *pk);
void pcs_t_free_private_key(pcs_t_private_key *vk);

#endif
