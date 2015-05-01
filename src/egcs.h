#ifndef EGCS_H
#define EGCS_H

#include <gmp.h>

typedef struct {
    mpz_t c1;
    mpz_t c2;
} egcs_cipher;

/* Group description is given by g ^ q (mod p) */
typedef struct {
    mpz_t g;    // generator for group
    mpz_t q;    // order of group
    mpz_t h;    // g ^ x
} egcs_public_key;

typedef struct {
    mpz_t x;    // random value in group g
    mpz_t q;
} egcs_private_key;

/* Construct keys */
egcs_public_key*  egcs_init_public_key(void);
egcs_private_key* egcs_init_private_key(void);
egcs_cipher* egcs_init_cipher(void);

void egcs_generate_key_pair(egcs_public_key *pk, egcs_private_key *vk, hcs_rand *hr, int bits);

/* Encrypt a message */
void egcs_encrypt(egcs_public_key *pk, hcs_rand *hr, egcs_cipher *rop, mpz_t plain1);
void egcs_decrypt(egcs_private_key *vk, mpz_t rop, egcs_cipher *cipher1);

/* Alter an encrypted message */
void egcs_ep_add(egcs_public_key *pk, mpz_t rop, mpz_t cipher1, mpz_t plain1);
void egcs_ee_add(egcs_public_key *pk, mpz_t rop, mpz_t cipher1, mpz_t cipher2);
void egcs_ep_mul(egcs_public_key *pk, mpz_t rop, mpz_t cipher1, mpz_t plain1);

/* Import/Export of keys */
char* egcs_export_public_key(egcs_public_key *pk);
char* egcs_export_private_key(egcs_private_key *vk);
void egcs_import_private_key(egcs_private_key *vk, char *buffer);
void egcs_import_public_key(egcs_public_key *pk, char *buffer);

/* Destroy keys */
void egcs_free_public_key(egcs_public_key *pk);
void egcs_free_private_key(egcs_private_key *vk);
void egcs_clear_cipher(egcs_cipher *ct);
void egcs_free_cipher(egcs_cipher *ct);

#endif
