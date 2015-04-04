/**
 * @file pcs2.h
 * @author Marc Tiehuis
 * @date 15 March 2015
 * @brief Header containing function and type definitions for the Paillier cryptosystem.
 *
 * A more detailed look at the internals can be found in pcs2.c
 */

#ifndef pcs2_H
#define pcs2_H

#include <gmp.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief The type for a public key, for use with the Paillier system
 */
typedef struct {
    mpz_t n;        /**< The modulus size of the key. */
    mpz_t g;        /**< n + 1, cached for speed */
    mpz_t n2;       /**< n^2, cached for speed */
} pcs2_public_key;

/**
 * @brief The type for a private key, for use with the Paillier system.
 */
typedef struct {
    mpz_t lambda;   /**< φ(p, q). p and q being the prime factors of n */
    mpz_t mu;       /**< Inverse of lambda mod n */
    mpz_t n;        /**< A random value composed of two large prime factors, p and q */
    mpz_t n2;       /**< n^2, cached for speed */
} pcs2_private_key;

/**
 * @brief Generate a public and private key pair with a modulus of size bits.
 *
 * Initialise a key pair with modulus size @p bits. It is required that @p pk and
 * @p vk are initialised before calling this function. @p pk and @p vk are also
 * expected to not be NULL.
 *
 * @code
 * pcs2_public_key *pk = pcs2_init_public_key();
 * pcs2_private_key *vk = pcs2_init_private_key();
 * pcs2_generate_key(pk, vk, 2048);
 * @endcode
 *
 * In practice the @p bits value should usually be greater than 2048 to ensure
 * sufficient security.
 *
 * @param pk An initialised pointer to a pcs2_public_key.
 * @param vk An initialised pointer to a pcs2_private_key.
 * @param bits The required number of bits the modulus n will be.
 */
void pcs2_generate_key_pair(pcs2_public_key *pk, pcs2_private_key *vk, const unsigned long bits, int option);

/**
 * @brief Encrypt a plaintext value and set @p rop to the encrypted result.
 *
 * Encrypt a value @p plain1, and set @p rop to the encrypted result. @p rop
 * and @p plain1 can aliases.
 *
 * @param pk A pointer to an initialised pcs2_public_key.
 * @param rop Where the encrypted result is stored.
 * @param plain1 The value which is to be encrypted.
 */
void pcs2_encrypt(pcs2_public_key *pk, mpz_t rop, mpz_t plain1);

/**
 * @brief Decrypt a ciphertext value and set @p rop to the decrypted result.
 *
 * Decrypt a value @p cipher1, and set @p rop to the decrypted result. @p rop
 * and @p cipher1 can aliases.
 *
 * @param vk A pointer to an initialised pcs2_private_key.
 * @param rop Where the decrypted result is stored.
 * @param cipher1 The value which is to be decrypted.
 */
void pcs2_decrypt(pcs2_private_key *vk, mpz_t rop, mpz_t cipher1);

/**
 * @brief Reencrypt an encrypted value directly.
 *
 * Reencrypt an encrypted value with the current public key such
 * that we obtain a new encrypted result, which upon decryption, is still
 * the unchanged.
 *
 * @param pk A pointer to a pcs2_public_key.
 * @param rop The variable to store the encrypted result.
 * @param op The value to reencrypt.
 */
void pcs2_reencrypt(pcs2_public_key *pk, mpz_t rop, mpz_t op);

/**
 * @brief Add a plaintext value to an encrypted value.
 *
 * Add a plaintext value @p plain1 to an encrypted value @p cipher1, storing
 * the result in @p rop. All the parameters can be aliased, however, usually
 * only @p rop and @p cipher1 will be. @p plain1 can be negative.
 *
 * @param pk A pointer to an initialised pcs2_public_key.
 * @param rop Where the new encrypted result is stored.
 * @param cipher1 The encrypted value which is to be added to.
 * @param plain1 The plaintext value which is to be added.
 */
void pcs2_ep_add(pcs2_public_key *pk, mpz_t rop, mpz_t cipher1, mpz_t plain1);

/**
 * @brief Add an encrypted value to an encrypted value.
 *
 * Add a encrypted value @p cipher2 to an encrypted value @p cipher1, storing
 * the result in @p rop. All the parameters can be aliased.
 *
 * @param pk A pointer to an initialised pcs2_public_key.
 * @param rop Where the new encrypted result is stored.
 * @param cipher1 The encrypted value which is to be added to.
 * @param cipher2 The cnrypted value which is to be added.
 */
void pcs2_ee_add(pcs2_public_key *pk, mpz_t rop, mpz_t cipher1, mpz_t cipher2);

/**
 * @brief Multiply a plaintext value with an encrypted value.
 *
 * Multiply a plaintext value @p plain1 with an encrypted value @p cipher1, storing
 * the result in @p rop. All the parameters can be aliased, however, usually
 * only @p rop and @p cipher1 will be.
 *
 * @param pk A pointer to an initialised pcs2_public_key.
 * @param rop Where the new encrypted result is stored.
 * @param cipher1 The encrypted value which is to be multipled to.
 * @param plain1 The plaintext value which is to be multipled.
 */
void pcs2_ep_mul(pcs2_public_key *pk, mpz_t rop, mpz_t cipher1, mpz_t plain1);

/**
 * @brief Verify a private keys values.
 *
 * This can be used as a sanity check to ensure that the pcs2_private_key
 * is valid. Note, that this only checks what it can, and using it with
 * a non-matching private key can still produce unintended results. This
 * will primarily be of use when importing a private key from a file.
 *
 * @code
 * pcs2_private_key *vk = pcs2_init_private_key();
 * pcs2_import_private_key(vk, "key.private");
 * if (!pcs2_verify_public(vk)) exit(0);
 * @endcode
 *
 * @param vk A pointer to an initialised pcs2_private_key.
 * @return non-zero on valid key, 0 on invalid key.
 */
int pcs2_verify_private_key(pcs2_private_key *vk);

/**
 * @brief Verify a public keys values.
 *
 * This can be used as a sanity check to ensure that the pcs2_public_key
 * is valid. Note, that this only checks what it can, and using it with
 * a non-matching public key can still produce unintended results. This
 * will primarily be of use when importing a public key from a file.
 *
 * @param pk A pointer to an initialised pcs2_public_key
 * @return non-zero on valid key, 0 on invalid key.
 */
int pcs2_verify_public_key(pcs2_public_key *pk);

/**
 * @brief Verify a key pair.
 *
 * This essentially performs pcs2_verify_private_key and
 * pcs2_verify_public_key wuth arguments @p pk and @p vk. It also
 * confirms that the keys are indeed matching pairs.
 *
 * @param pk A pointer to an initialised pcs2_public_key.
 * @param vk A pointer to an initialised pcs2_private_key.
 * @return non-zero if the keys both match and are valid, 0 otherwise.
 */
int pcs2_verify_key_pair(pcs2_public_key *pk, pcs2_private_key *vk);

/**
 * @brief Export a pcs2_public_key out to a file.
 *
 * This uses the tpl library to write out a key in an appropriate form
 * to a file.
 *
 * @param pk A pointer to a pcs2_public_key that is to be written to a file.
 * @param file The name of the file to be written to.
 * @return non-zero if and error occured during write.
 */
int pcs2_export_public_key(pcs2_public_key *pk, const char *file);

/**
 * @brief Export a pcs2_private_key out to a file.
 *
 * This uses the tpl library to write out a key in an appropriate form
 * to a file.
 *
 * @param vk A pointer to a pcs2_private_key that is to be written to a file.

 * @param file The name of the file to be written to.
 * @return non-zero if an error occured during write.
 */
int pcs2_export_private_key(pcs2_private_key *vk, const char *file);

/**
 * @brief Import a pcs2_public_key from a file
 *
 * This uses the tpl library to read a key from a file. It is assumed
 * that the file read will have initially been written with a
 * pcs2_export function.
 *
 * @param pk A pointer to an initialised pcs2_public_key in which to set.
 * @param file The name of the file to read from.
 * @return non-zero if an error occured during read.
 */
int pcs2_import_public_key(pcs2_public_key *pk, const char *file);

/**
 * @brief Import a pcs2_private_key from a file
 *
 * This uses the tpl library to read a key from a file. It is assumed
 * that the file read will have initially been written with a
 * pcs2_export function.
 *
 * @param vk A pointer to an initialised pcs2_private_key in which to set.
 * @param file The name of the file to read from.
 * @return non-zero if an error occured during read.
 */
int pcs2_import_private_key(pcs2_private_key *vk, const char *file);

/**
 * @brief Initialise the fields of a public key, returning a pointer to a usable key.
 *
 * @return A pointer to an initialised pcs2_public_key type.
 */
pcs2_public_key*  pcs2_init_public_key(void);

/**
 * @brief Initialise the fields of a private key, returning a pointer to a usable key.
 *
 * @return A pointer to an initialised pcs2_private_key type.
 */
pcs2_private_key* pcs2_init_private_key(void);

/**
 * @brief Zero all fields in a pcs2_public_key.
 *
 * This function zeros all data in @p pk. It is useful to use if we wish
 * to generate or import a new key value and want to safely ensure we
 * have removed the last keys values.
 *
 * @code
 * // ... Initialised a key pk, and done some work with it
 *
 * pcs2_clear_public_key(pk); // All data from old key is now gone
 * pcs2_import_public_key(pk, "public.key"); // Safe to reuse this key, still initialised
 * @endcode
 *
 * @param pk A pointer to an initialised pcs2_public_key.
 */
void pcs2_clear_public_key(pcs2_public_key *pk);

/**
 * @brief Zero all fields in a pcs2_private_key.
 *
 * This function zeros all data in @p vk. It is useful to use if we wisth to
 * generate of import a new key value and want to safely ensure we have removed
 * the last keys values.
 *
 * @param vk A pointer to an initialised pcs2_private_key.
 */
void pcs2_clear_private_key(pcs2_private_key *vk);

/**
 * @brief Free a pcs2_public_key and all associated memory related to it.
 *
 * This function will zero all memory before freeing any data. Therefore
 * one does not need to call pcs2_clear_public_key before using this function.
 *
 * @param pk A pointer to an initialised pcs2_public_key that is to be freed.
 */
void pcs2_free_public_key(pcs2_public_key *pk);

/**
 * @brief Free a pcs2_private_key and all associated memory related to it.
 *
 * This function will zero all memory before freeing any data. Therefore
 * one does not need to call pcs2_clear_private_key before using this function.
 *
 * @param vk v pointer to an initialised pcs2_private_key that is to be freed.
 */
void pcs2_free_private_key(pcs2_private_key *vk);

#ifdef __cplusplus
}
#endif

#endif
