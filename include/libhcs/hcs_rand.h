/**
 * @file hcs_rand.h
 *
 * Provides secure random state for use in functions which require random
 * values. This is a wrapper around gmp_randstate_t, and utilizes them
 * internally as a PRNG. Currently, it uses gmp_randinit_default for choice of
 * PRNG.
 *
 * Seed is gathered from the operating systems provided entropy. For example,
 * /dev/urandom is used under Linux. This may be slightly altered, but for now
 * it satisfies the required randomness.
 */

#ifndef HCS_RAND_H
#define HCS_RAND_H

#include <gmp.h>

/**
 * If this define is set, then a static seed of 0 will always be used in any
 * hcs_rand functions. ONLY use this for testing.
 */
//#define HCS_STATIC_SEED

/**
 * The number of bits of seed which is gathered from our entropy source.
 */
#define HCS_RAND_SEED_BITS 256

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Random state used by a number of cryptographic functions. This is just a
 * wrapper around a gmp_randstate_t variable.
 */
typedef struct {
    gmp_randstate_t rstate;
} hcs_rand;

/**
 * Initialise an hcs_rand and return a pointer to the newly created
 * structure.
 *
 * @return A pointer to an hcs_rand type on success, NULL on allocation failure
 */
hcs_rand* hcs_init_rand(void);

/**
 * Reseed the given hcs_rand. If we fail to gather sufficient entropy, we
 * return with an error.
 *
 * \todo Potentially expand error codes so we can explain exactly what went
 * wrong to the caller. For now though, it is better than aborting.
 *
 * @param A pointer to an initialised hcs_rand
 * @return non-zero on successful reseed, zero on failure
 */
int hcs_reseed_rand(hcs_rand *hr);

/**
 * Frees a hcs_rand and all associated memory.
 *
 * @param A pointer to an initliased hcs_rand
 */
void hcs_free_rand(hcs_rand *hr);

#ifdef __cplusplus
}
#endif

#endif
