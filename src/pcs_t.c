/*
 * @file pcs_t.c
 *
 * Implementation of the Paillier Cryptosystem (pcs_t).
 *
 * This scheme is a threshold variant of the Paillier system. It loosely
 * follows the scheme presented in the paper by damgard-jurik, but with a
 * chosen base of 2, rather than the variable s+1. This scheme was written
 * first for simplicity.
 *
 * @todo Desperately need to move away from naive prime generation here, as
 * it is currently a massive bottleneck and computing large 2048 bit safe
 * primes is taking to long.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <gmp.h>
#include "libhcs/hcs_rand.h"
#include "libhcs/pcs_t.h"
#include "com/parson.h"
#include "com/util.h"

/* This is simply L(x) when s = 1 */
static void dlog_s(mpz_t n, mpz_t rop, mpz_t op)
{
    mpz_sub_ui(rop, op, 1);
    mpz_divexact(rop, rop, n);
    mpz_mod(rop, rop, n);
}

pcs_t_public_key* pcs_t_init_public_key(void)
{
    pcs_t_public_key *pk = malloc(sizeof(pcs_t_public_key));
    if (!pk) return NULL;

    mpz_inits(pk->n, pk->n2, pk->g, pk->delta, NULL);
    return pk;
}

pcs_t_private_key* pcs_t_init_private_key(void)
{
    pcs_t_private_key *vk = malloc(sizeof(pcs_t_private_key));
    if (!vk) return NULL;

    vk->w = vk->l = 0;
    mpz_inits(vk->v, vk->nm, vk->n,
              vk->n2, vk->d, NULL);
    return vk;
}

/* Look into methods of using multiparty computation to generate these keys
 * and the data so we don't have to have a trusted party for generation. */
int pcs_t_generate_key_pair(pcs_t_public_key *pk, pcs_t_private_key *vk,
        hcs_rand *hr, const unsigned long bits, const unsigned long w,
        const unsigned long l)
{
    /* The paper does describe some bounds on w, l */
    //assert(l / 2 <= w && w <= l);

    vk->vi = malloc(sizeof(mpz_t) * l);
    if (vk->vi == NULL) return 0;

    mpz_t t1, t2, t3, t4;
    mpz_init(t1);
    mpz_init(t2);
    mpz_init(t3);
    mpz_init(t4);

    do {
        mpz_random_safe_prime(t1, t2, hr->rstate, 1 + (bits-1)/2);
        mpz_random_safe_prime(t3, t4, hr->rstate, 1 + (bits-1)/2);
    } while (mpz_cmp(t1, t3) == 0);

    mpz_mul(pk->n, t1, t3);
    mpz_set(vk->n, pk->n);
    mpz_pow_ui(pk->n2, pk->n, 2);
    mpz_set(vk->n2, pk->n2);
    mpz_add_ui(pk->g, pk->n, 1);
    mpz_mul(t3, t2, t4);
    mpz_mul(vk->nm, vk->n, t3);
    mpz_set_ui(t1, 1);
    mpz_set_ui(t2, 0);
    mpz_2crt(vk->d, t1, vk->n, t2, t3);
    mpz_fac_ui(pk->delta, l);

    vk->l = l;
    vk->w = w;
    pk->l = l;
    pk->w = w;

    for (unsigned long i = 0; i < l; ++i)
        mpz_init(vk->vi[i]);

    mpz_clear(t1);
    mpz_clear(t2);
    mpz_clear(t3);
    mpz_clear(t4);

    return 1;
}

void pcs_t_r_encrypt(pcs_t_public_key *pk, hcs_rand *hr,
        mpz_t r, mpz_t rop, mpz_t plain1)
{
    mpz_t t1;
    mpz_init(t1);

    mpz_random_in_mult_group(r, hr->rstate, pk->n);
    mpz_powm(rop, r, pk->n, pk->n2);
    mpz_powm(t1, pk->g, plain1, pk->n2);
    mpz_mul(rop, rop, t1);
    mpz_mod(rop, rop, pk->n2);

    mpz_clear(t1);
}

void pcs_t_encrypt_r(pcs_t_public_key *pk, mpz_t rop, mpz_t r, mpz_t plain1)
{
    mpz_t t1;
    mpz_init(t1);

    mpz_powm(t1, pk->g, plain1, pk->n2);
    mpz_powm(rop, r, pk->n, pk->n2);
    mpz_mul(rop, rop, t1);
    mpz_mod(rop, rop, pk->n2);

    mpz_clear(t1);
}

void pcs_t_encrypt(pcs_t_public_key *pk, hcs_rand *hr, mpz_t rop, mpz_t plain1)
{
    mpz_t t1;
    mpz_init(t1);

    mpz_random_in_mult_group(t1, hr->rstate, pk->n);
    mpz_powm(t1, t1, pk->n, pk->n2);
    mpz_powm(rop, pk->g, plain1, pk->n2);
    mpz_mul(rop, rop, t1);
    mpz_mod(rop, rop, pk->n2);

    mpz_clear(t1);
}

void pcs_t_reencrypt(pcs_t_public_key *pk, hcs_rand *hr, mpz_t rop, mpz_t op)
{
    mpz_t t1;
    mpz_init(t1);

    mpz_random_in_mult_group(t1, hr->rstate, pk->n);
    mpz_powm(t1, t1, pk->n, pk->n2);
    mpz_mul(rop, op, t1);
    mpz_mod(rop, rop, pk->n2);

    mpz_clear(t1);
}

void pcs_t_ep_add(pcs_t_public_key *pk, mpz_t rop, mpz_t cipher1, mpz_t plain1)
{
    mpz_t t1;
    mpz_init(t1);

    mpz_set(t1, cipher1);
    mpz_powm(rop, pk->g, plain1, pk->n2);
    mpz_mul(rop, rop, t1);
    mpz_mod(rop, rop, pk->n2);

    mpz_clear(t1);
}

void pcs_t_ee_add(pcs_t_public_key *pk, mpz_t rop, mpz_t cipher1, mpz_t cipher2)
{
    mpz_mul(rop, cipher1, cipher2);
    mpz_mod(rop, rop, pk->n2);
}

void pcs_t_ep_mul(pcs_t_public_key *pk, mpz_t rop, mpz_t cipher1, mpz_t plain1)
{
    mpz_powm(rop, cipher1, plain1, pk->n2);
}

pcs_t_proof* pcs_t_init_proof(void)
{
    pcs_t_proof *pf = malloc(sizeof(pcs_t_proof));
    if (pf == NULL) return NULL;
    mpz_inits(pf->e1, pf->e2, pf->u1, pf->u2, pf->a1, pf->a2, pf->z1, pf->z2, NULL);
    return pf;
}

void pcs_t_set_proof(pcs_t_public_key *pk, pcs_t_proof *pf, unsigned long m1,
        unsigned long m2)
{
    pf->m1 = m1;
    pf->m2 = m2;
}

void pcs_t_compute_ns_protocol(pcs_t_public_key *pk, hcs_rand *hr,
        pcs_t_proof *pf, mpz_t u, mpz_t v, unsigned long id)
{
    mpz_t r, e, _0 ;
    mpz_init(r);
    mpz_init(e);
    mpz_init_set_ui(_0, 0);

    mpz_set(pf->u2, u);

    // Random r in Zn* and a = E(0, r)
    pcs_t_r_encrypt(pk, hr, r, pf->a2, _0);

    /* CHoose a random t-bit hash with a mixture of values */
    //e = hash(pf->a2, pf->S, id);
    mpz_set_ui(e, 0xABCDABCD); // fix e for now

    mpz_powm(pf->z2, v, e, pk->n);
    mpz_mul(pf->z2, pf->z2, r);
    mpz_mod(pf->z2, pf->z2, pk->n);

    mpz_clear(r);
    mpz_clear(e);
    mpz_clear(u);
    mpz_clear(_0);
}

int pcs_t_verify_ns_protocol(pcs_t_public_key *pk, pcs_t_proof *pf,
        unsigned long id)
{
    int retval = 1;

    mpz_t t1, t2, e;
    mpz_init(t1);
    mpz_init(t2);
    mpz_init(e);

    /* Ensure u, a, z are prime to n */
    mpz_gcd(t1, pf->u2, pk->n);
    if (mpz_cmp_ui(t1, 1) != 0) {
        retval = 0; goto end;
    }

    mpz_gcd(t1, pf->a2, pk->n);
    if (mpz_cmp_ui(t1, 1) != 0) {
        retval = 0; goto end;
    }

    mpz_gcd(t1, pf->z2, pk->n);
    if (mpz_cmp_ui(t1, 1) != 0) {
        retval = 0; goto end;
    }

    mpz_set_ui(t1, 0);
    pcs_t_encrypt_r(pk, t1, pf->z2, t1);

    mpz_set_ui(e, 0xABCDABCD);
    mpz_powm(t2, pf->u2, e, pk->n2);
    mpz_mul(t2, t2, pf->a2);
    mpz_mod(t2, t2, pk->n2);

    if (mpz_cmp(t1, t2) != 0) {
        retval = 0;
    }

end:
    mpz_clear(t1);
    mpz_clear(t2);
    mpz_clear(e);
    return retval;
}

void pcs_t_compute_1of2_ns_protocol(pcs_t_public_key *pk, hcs_rand *hr,
        pcs_t_proof *pf, mpz_t c1, mpz_t cr1, unsigned long k, unsigned long id)
{
    mpz_t v1, r1, _0;
    mpz_init(v1);
    mpz_init(r1);
    mpz_init(_0);

    // transform u1 to an encryption of 0
    mpz_t t1, t2;
    mpz_init(t1);
    mpz_init(t2);

    // Compute u1 and u2 based on the input cipher for c1
    mpz_mul_ui(t1, pk->n, pf->m1);
    mpz_powm(t1, pk->g, t1, pk->n2);
    mpz_mul_ui(t2, pk->n, pf->m2);
    mpz_powm(t2, pk->g, t2, pk->n2);
    mpz_invert(t1, t1, pk->n2);
    mpz_invert(t2, t2, pk->n2);

    mpz_mul(pf->u1, c1, t1);
    mpz_mod(pf->u1, pf->u1, pk->n2);
    mpz_mul(pf->u2, c1, t2);
    mpz_mod(pf->u2, pf->u2, pk->n2);

    // We use k from some k*n to determine the new r value
    //    u1 = g^{-m1*n} g^{k*n} r^n mod n^2
    // => u1 = ( (g*r)^{k-m1} ) ^ n mod n^2
    //
    // Which is an encryption of 0, with an r of (g*r)^{k-m1} mod n
    mpz_mul(v1, pk->g, cr1);
    // if k is negative, we need to take the inverse in mod n
    mpz_powm_ui(v1, v1, k - pf->m1, pk->n);

    // ns protocol start : We do this inline as we require the e value
    pcs_t_r_encrypt(pk, hr, r1, pf->a2, _0);
    mpz_set_ui(pf->e2, 0xABCDABCD); // fix e for now
    mpz_powm(pf->z2, r1, pf->e2, pk->n);
    mpz_mul(pf->z2, pf->z2, r1);
    mpz_mod(pf->z2, pf->z2, pk->n);
    // ns protocol end :

    pcs_t_r_encrypt(pk, hr, r1, pf->a1, _0);
    mpz_set_ui(pf->e1, 0xDBCADBCA); // fix e
    mpz_sub(pf->e1, pf->e1, pf->e2);
    mpz_ui_pow_ui(_0, 2, 32); // this should be k2 bits
    mpz_mod(pf->e1, pf->e1, _0);

    mpz_powm(pf->z1, v1, pf->e1, pk->n);
    mpz_mul(pf->z1, pf->z1, r1);
    mpz_mod(pf->z1, pf->z1, pk->n);

    mpz_clear(v1);
    mpz_clear(r1);
    mpz_clear(_0);
}

int pcs_t_verify_1of2_ns_protocol(pcs_t_public_key *pk, pcs_t_proof *pf,
        unsigned long id)
{
    int retval = 1;

    mpz_t t1, t2, e;
    mpz_init(t1);
    mpz_init(t2);
    mpz_init(e);

    /* Ensure u1, u2, a1, a2, z1, z2 are prime to n */
    mpz_gcd(t1, pf->u2, pk->n);
    if (mpz_cmp_ui(t1, 1) != 0) {
        retval = 0; goto end;
    }

    mpz_gcd(t1, pf->a2, pk->n);
    if (mpz_cmp_ui(t1, 1) != 0) {
        retval = 0; goto end;
    }

    mpz_gcd(t1, pf->z2, pk->n);
    if (mpz_cmp_ui(t1, 1) != 0) {
        retval = 0; goto end;
    }

    mpz_gcd(t1, pf->u1, pk->n);
    if (mpz_cmp_ui(t1, 1) != 0) {
        retval = 0; goto end;
    }

    mpz_gcd(t1, pf->a1, pk->n);
    if (mpz_cmp_ui(t1, 1) != 0) {
        retval = 0; goto end;
    }

    mpz_gcd(t1, pf->z1, pk->n);
    if (mpz_cmp_ui(t1, 1) != 0) {
        retval = 0; goto end;
    }

    mpz_set_ui(t1, 0);
    pcs_t_encrypt_r(pk, t1, pf->z1, t1);

    mpz_powm(t2, pf->u2, pf->e2, pk->n2);
    mpz_mul(t2, t2, pf->a2);
    mpz_mod(t2, t2, pk->n2);

    if (mpz_cmp(t1, t2) != 0) {
        retval = 0;
        goto end;
    }

    mpz_powm(t2, pf->u1, pf->e1, pk->n2);
    mpz_mul(t2, t2, pf->a1);
    mpz_mod(t2, t2, pk->n2);

    if (mpz_cmp(t1, t2) != 0) {
        retval = 0;
        goto end;
    }

    // e is fixed as 0xdbcadbca
    mpz_ui_pow_ui(t1, 2, 32); // this should be k2 bits
    mpz_add(t2, pf->e1, pf->e2);
    mpz_mod(t2, t2, t1);
    mpz_set_ui(t1, 0xDBCADBCA);

    if (mpz_cmp(t1, t2) != 0) {
        retval = 0;
        goto end;
    }

end:
    mpz_clear(t1);
    mpz_clear(t2);
    mpz_clear(e);
    return retval;
}

void pcs_t_free_proof(pcs_t_proof *pf)
{
    mpz_clears(pf->e1, pf->e2, pf->u1, pf->u2, pf->a1, pf->a2, pf->z1, pf->z2, NULL);
    free(pf);
}

pcs_t_polynomial* pcs_t_init_polynomial(pcs_t_private_key *vk, hcs_rand *hr)
{
    pcs_t_polynomial *px;

    if ((px = malloc(sizeof(pcs_t_polynomial))) == NULL)
        goto failure;
    if ((px->coeff = malloc(sizeof(mpz_t) * vk->w)) == NULL)
        goto failure;

    px->n = vk->w;
    mpz_init_set(px->coeff[0], vk->d);
    for (unsigned long i = 1; i < px->n; ++i) {
        mpz_init(px->coeff[i]);
        mpz_urandomm(px->coeff[i], hr->rstate, vk->nm);
    }

    return px;

failure:
    if (px->coeff) free(px->coeff);
    if (px) free(px);
    return NULL;
}

void pcs_t_compute_polynomial(pcs_t_private_key *vk, pcs_t_polynomial *px, mpz_t rop,
                              const unsigned long x)
{
    mpz_t t1, t2;
    mpz_init(t1);
    mpz_init(t2);

    mpz_set(rop, px->coeff[0]);
    for (unsigned long i = 1; i < px->n; ++i) {
        mpz_ui_pow_ui(t1, x + 1, i);        // Correct for server 0-indexing
        mpz_mul(t1, t1, px->coeff[i]);
        mpz_add(rop, rop, t1);
        mpz_mod(rop, rop, vk->nm);
    }

    mpz_clear(t1);
    mpz_clear(t2);
}

void pcs_t_free_polynomial(pcs_t_polynomial *px)
{
    for (unsigned long i = 0; i < px->n; ++i)
        mpz_clear(px->coeff[i]);
    free(px->coeff);
    free(px);
}


pcs_t_auth_server* pcs_t_init_auth_server(void)
{
    pcs_t_auth_server *au = malloc(sizeof(pcs_t_auth_server));
    if (!au) return NULL;

    mpz_init(au->si);
    return au;
}

void pcs_t_set_auth_server(pcs_t_auth_server *au, mpz_t si, unsigned long i)
{
    mpz_set(au->si, si);
    au->i = i + 1; // Input is assumed to be 0-indexed (from array)
}

/* Compute a servers share and set rop to the result. rop should usually
 * be part of an array so we can call pcs_t_share_combine with ease. */
void pcs_t_share_decrypt(pcs_t_public_key *pk, pcs_t_auth_server *au,
                         mpz_t rop, mpz_t cipher1)
{
    mpz_t t1;
    mpz_init(t1);

    mpz_mul(t1, au->si, pk->delta);
    mpz_mul_ui(t1, t1, 2);
    mpz_powm(rop, cipher1, t1, pk->n2);

    mpz_clear(t1);
}

/* c is expected to be of length vk->l, the number of servers. If the share
 * is not present, then it is expected to be equal to the value zero. */
int pcs_t_share_combine(pcs_t_public_key *pk, mpz_t rop, mpz_t *c)
{
    mpz_t t1, t2, t3;
    mpz_init(t1);
    mpz_init(t2);
    mpz_init(t3);

    mpz_set_ui(rop, 1);
    for (unsigned long i = 0; i < pk->l; ++i) {

        /* Skip zero shares */
        if (mpz_cmp_ui(c[i], 0) == 0)
            continue;

        /* Compute lagrange coefficients */
        mpz_set(t1, pk->delta);
        for (unsigned long j = 0; j < pk->l; ++j) {
            if ((j == i) || mpz_cmp_ui(c[j], 0) == 0)
                continue; /* i' in S\i and non-zero */

            long v = (long)j - (long)i;
            mpz_tdiv_q_ui(t1, t1, (v < 0 ? v*-1 : v));
            if (v < 0) mpz_neg(t1, t1);
            mpz_mul_ui(t1, t1, j + 1);
        }

        mpz_abs(t2, t1);
        mpz_mul_ui(t2, t2, 2);
        mpz_powm(t2, c[i], t2, pk->n2);

        if (mpz_sgn(t1) < 0 && !mpz_invert(t2, t2, pk->n2))
	        return 0;

        mpz_mul(rop, rop, t2);
        mpz_mod(rop, rop, pk->n2);
    }

    /* rop = c' */
    dlog_s(pk->n, rop, rop);
    mpz_pow_ui(t1, pk->delta, 2);
    mpz_mul_ui(t1, t1, 4);

    if (!mpz_invert(t1, t1, pk->n))
		return 0;

    mpz_mul(rop, rop, t1);
    mpz_mod(rop, rop, pk->n);

    mpz_clear(t1);
    mpz_clear(t2);
    mpz_clear(t3);
    return 1;
}

void pcs_t_free_auth_server(pcs_t_auth_server *au)
{
    mpz_clear(au->si);
    free(au);
}

void pcs_t_clear_public_key(pcs_t_public_key *pk)
{
    mpz_zeros(pk->g, pk->n, pk->n2, pk->delta, NULL);
}

void pcs_t_clear_private_key(pcs_t_private_key *vk)
{
    mpz_zeros(vk->v, vk->nm, vk->n,
              vk->n2, vk->d, NULL);

    if (vk->vi) {
        for (unsigned long i = 0; i < vk->l; ++i)
            mpz_clear(vk->vi[i]);
        free (vk->vi);
    }
}

void pcs_t_free_public_key(pcs_t_public_key *pk)
{
    mpz_clears(pk->g, pk->n, pk->n2, pk->delta, NULL);
    free(pk);
}

void pcs_t_free_private_key(pcs_t_private_key *vk)
{
    mpz_clears(vk->v, vk->nm, vk->n,
               vk->n2, vk->d, NULL);

    if (vk->vi) {
        for (unsigned long i = 0; i < vk->l; ++i)
            mpz_clear(vk->vi[i]);
        free (vk->vi);
    }

    free(vk);
}

int pcs_t_verify_key_pair(pcs_t_public_key *pk, pcs_t_private_key *vk)
{
    return mpz_cmp(vk->n, pk->n) == 0;
}

char *pcs_t_export_public_key(pcs_t_public_key *pk)
{
    char *buffer;
    char *retstr;

    JSON_Value *root = json_value_init_object();
    JSON_Object *obj  = json_value_get_object(root);
    buffer = mpz_get_str(NULL, HCS_INTERNAL_BASE, pk->n);
    json_object_set_string(obj, "n", buffer);
    json_object_set_number(obj, "w", pk->w);
    json_object_set_number(obj, "l", pk->l);
    retstr = json_serialize_to_string(root);

    json_value_free(root);
    free(buffer);
    return retstr;
}

char *pcs_t_export_verify_values(pcs_t_private_key *vk)
{
    return "";
}

char *pcs_t_export_auth_server(pcs_t_auth_server *au)
{
    char *buffer;
    char *retstr;

    JSON_Value *root = json_value_init_object();
    JSON_Object *obj  = json_value_get_object(root);
    buffer = mpz_get_str(NULL, HCS_INTERNAL_BASE, au->si);
    json_object_set_string(obj, "si", buffer);
    json_object_set_number(obj, "i", au->i);
    retstr = json_serialize_to_string(root);

    json_value_free(root);
    free(buffer);
    return retstr;
}

int pcs_t_import_public_key(pcs_t_public_key *pk, const char *json)
{
    JSON_Value *root = json_parse_string(json);
    JSON_Object *obj = json_value_get_object(root);
    mpz_set_str(pk->n, json_object_get_string(obj, "n"), HCS_INTERNAL_BASE);
    pk->l = json_object_get_number(obj, "l");
    pk->w = json_object_get_number(obj, "w");
    json_value_free(root);

    /* Calculate remaining values */
    mpz_add_ui(pk->g, pk->n, 1);
    mpz_pow_ui(pk->n2, pk->n, 2);
    mpz_fac_ui(pk->delta, pk->l);
    return 0;
}

int pcs_t_import_verify_values(pcs_t_private_key *vk, const char *json);

int pcs_t_import_auth_server(pcs_t_auth_server *au, const char *json)
{
    JSON_Value *root = json_parse_string(json);
    JSON_Object *obj = json_value_get_object(root);
    mpz_set_str(au->si, json_object_get_string(obj, "si"), HCS_INTERNAL_BASE);
    au->i = json_object_get_number(obj, "i");
    json_value_free(root);

    /* Calculate remaining values */
    return 0;
}

#ifdef MAIN
int main(void) {
    pcs_t_private_key *vk = pcs_t_init_private_key();
    pcs_t_public_key *pk = pcs_t_init_public_key();
    hcs_rand *hr = hcs_init_rand();

    pcs_t_generate_key_pair(pk, vk, hr, 128, 2, 4);

    mpz_t u, v, _0;
    mpz_inits(u, v, _0, NULL);
    mpz_set_ui(_0, 0); // Any value k * n for integer k will work

    //mpz_mul_ui(_0, _0, 7);  // Altering this value will not make the proof wrong

    // If we have some n^th power, i.e. 1 = n^0, then we can transform the
    // value into an encryption of 0 by multiplying the ciphertext by
    pcs_t_r_encrypt(pk, hr, v, u, _0);

    pcs_t_proof *pf = pcs_t_init_proof();
    pcs_t_set_proof(pk, pf, 0, 1);  // we will accept 0 or 1
    pcs_t_compute_1of2_ns_protocol(pk, hr, pf, u, v, 0, 1); // checking if u
    // is an encryption of 0

    if (pcs_t_verify_1of2_ns_protocol(pk, pf, 1)) {
        gmp_printf("%Zd is an encryption of k*n\n", v);
    }
    else {
        gmp_printf("%Zd is not an encryption of k*n\n", v);
    }
}
#endif
