/**
 * @file djcs_t.h
 * @author Marc Tiehuis
 * @date 15 March 2015
 * @brief Header containing function and type definitions for the Paillier
 * cryptosystem.
 *
 * A more detailed look at the internals can be found in djcs_t.c
 */

#ifndef djcs_t_H
#define djcs_t_H

#include <gmp.h>
#include "hcs_rand.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    mpz_t si;
    unsigned long i;
} djcs_t_auth_server;

/**
 * @brief The type for a public key, for use with the Paillier system
 */
typedef struct {
    mpz_t *n;        /**< Modulus of the key. n = p * q */
    mpz_t g;        /**< Precomputation: n + 1 usually, may be 2*/
    unsigned long s;
} djcs_t_public_key;

/**
 * @brief The type for a private key, for use with the Paillier system.
 */
typedef struct {
    unsigned long s;
    unsigned long w;    /**< The number of servers req to decrypt */
    unsigned long l;    /**< The number of decryption servers */
    mpz_t delta;        /**< Precomputation: l! */

    mpz_t *vi;          /**< Verification values for the decrypt servers */
    mpz_t v;            /**< Cyclic generator of squares in Z*n^2 */
    mpz_t d;            /**< d = 0 mod m and d = 1 mod n^2 */
    mpz_t p;            /**< A random prime determined during key generation */
    mpz_t ph;           /**< A random prime such that p = 2*ph + 1 */
    mpz_t q;            /**< A random prime determined during key generation */
    mpz_t qh;           /**< A random prime such that q = 2*qh + 1 */
    mpz_t m;            /**< Precomputation: ph * qh */
    mpz_t *n;           /**< Modulus of the key: p * q */
    mpz_t nsm;          /**< Precomputation: n * m */
} djcs_t_private_key;

void djcs_t_compute_polynomial(djcs_t_private_key *vk, mpz_t *coeff, mpz_t rop,
                               const unsigned long x);

mpz_t* djcs_t_init_polynomial(djcs_t_private_key *vk, hcs_rand *hr);

void djcs_t_free_polynomial(djcs_t_private_key *vk, mpz_t *coeff);

void djcs_t_set_auth_server(djcs_t_auth_server *au, mpz_t si, unsigned long i);

void djcs_t_generate_key_pair(djcs_t_public_key *pk, djcs_t_private_key *vk,
        hcs_rand *hr, const unsigned long s, const unsigned long bits,
        const unsigned long l, const unsigned long w);

void djcs_t_share_decrypt(djcs_t_private_key *vk, djcs_t_auth_server *au,
                          mpz_t rop, mpz_t cipher1);

void djcs_t_share_combine(djcs_t_private_key *vk, mpz_t rop, mpz_t *c);

void djcs_t_encrypt(djcs_t_public_key *pk, hcs_rand *hr, mpz_t rop,
                    mpz_t plain1);

djcs_t_auth_server* djcs_t_init_auth_server(void);

djcs_t_public_key* djcs_t_init_public_key(void);

djcs_t_private_key* djcs_t_init_private_key(void);

void djcs_t_free_auth_server(djcs_t_auth_server *au);

void djcs_t_free_public_key(djcs_t_public_key *pk);

void djcs_t_free_private_key(djcs_t_private_key *vk);

#endif
