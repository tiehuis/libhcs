#ifndef gmcs_H
#define gmcs_H

#include <gmp.h>
#include "com/kvec.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    mpz_t n;
    mpz_t x;
    mpz_t n2;
} gmcs_public_key;

typedef struct {
    mpz_t p;
    mpz_t q;
} gmcs_private_key;

typedef struct {
    kvec_t(mpz_t) v;
} gmcs_cipher;

/* Construct keys */
gmcs_public_key*  gmcs_init_public_key(void);
gmcs_private_key* gmcs_init_private_key(void);

/* Key generation */
void gmcs_generate_key_pair(gmcs_public_key *pk, gmcs_private_key *vk, unsigned long bits);

/* Encrypt a message */
void gmcs_encrypt(gmcs_public_key *pk, mpz_t rop, mpz_t plain1);
void gmcs_decrypt(gmcs_private_key *vk, mpz_t rop, mpz_t cipher1);

/* Alter an encrypted message */
void gmcs_ep_add(gmcs_public_key *pk, mpz_t rop, mpz_t cipher1, mpz_t plain1);
void gmcs_ee_add(gmcs_public_key *pk, mpz_t rop, mpz_t cipher1, mpz_t cipher2);
void gmcs_ep_mul(gmcs_public_key *pk, mpz_t rop, mpz_t cipher1, mpz_t plain1);

/* Verify imported keys */
int gmcs_verify_private_key(gmcs_private_key *vk);
int gmcs_verify_private_key(gmcs_private_key *vk);
int gmcs_verify_key_pair(gmcs_public_key *pk, gmcs_private_key *vk);

/* Import/Export of keys */
int gmcs_export_public_key(gmcs_public_key *pk, char *file);
int gmcs_export_private_key(gmcs_private_key *vk, char *file);
int gmcs_import_private_key(gmcs_private_key *vk, char *file);
int gmcs_import_public_key(gmcs_public_key *pk, char *file);

/* Destroy keys */
void gmcs_free_public_key(gmcs_public_key *pk);
void gmcs_free_private_key(gmcs_private_key *vk);

#ifdef __cplusplus
}
#endif

#endif
