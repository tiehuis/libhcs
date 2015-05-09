#include <stdlib.h>
#include <stdio.h>
#include <hcs.h>

#define MODULUS_BITS 512
#define AU_COUNT 5
#define AU_REQ 3

int main(void)
{
    hcs_rand *hr = hcs_rand_init();

    /* Initialise our keys as normal */
    pcs_t_public_key *pk = pcs_t_init_public_key();
    pcs_t_private_key *vk = pcs_t_init_private_key();

    /* Initialise each auth server that will aid in the decryption
     * of results. These would usually be different systems. */
    pcs_t_auth_server *au[AU_COUNT];
    for (int i = 0; i < AU_COUNT; ++i)
        au[i] = pcs_t_init_auth_server(); // Want to add index to auth server internally

    mpz_t a, b;
    mpz_init_set_ui(a, 10);
    mpz_init(b);

    pcs_t_generate_key_pair(pk, vk, hr, MODULUS_BITS, AU_REQ, AU_COUNT);
    pcs_t_encrypt(pk, hr, b, a);
    pcs_t_ep_add(pk, b, b, a);
    pcs_t_ep_mul(pk, b, b, a);

    mpz_t *coeff = pcs_t_init_polynomial(vk, hr);

    /* Set up all auth servers with the given vk values. This will
     * generate a secret share for each server and also set the verification
     * value assigned to it in vk. */
    for (int i = 0; i < AU_COUNT; ++i) {
        /* Polynomial is only on one machine. Server must request over network value
         * of polynomial and are sent an index and corresponding value. */
        pcs_t_compute_polynomial(vk, coeff, au[i]->si, i);
        pcs_t_set_auth_server(au[i], au[i]->si, i);
    }

    pcs_t_free_polynomial(vk, coeff);

    /* Intialise a table to store the shares that are decrypted
     * by each individual server. */
    mpz_t fshr[AU_COUNT];
    mpz_t cshr[AU_COUNT];
    /* Share decrypt into the recently created table. */
    for (int i = 0; i < AU_COUNT; ++i) {
        mpz_init(cshr[i]);
        mpz_init(fshr[i]);
        pcs_t_share_decrypt(vk, au[i], fshr[i], b);
    }

    gmp_printf("Input value %Zd\n", a);

    gmp_printf("SHARES\n");
    for (int i = 0; i < AU_COUNT; ++i)
        gmp_printf("%Zd\n\n", fshr[i]);
    printf("\n");

#define CLEAR_TABLE(v)\
    for (int i = 0; i < AU_COUNT; ++i) mpz_set_ui(v[i], 0)

    CLEAR_TABLE(cshr);
    mpz_set(cshr[0], fshr[0]);
    mpz_set(cshr[1], fshr[1]);
    mpz_set(cshr[2], fshr[2]);
    pcs_t_share_combine(vk, b, cshr);
    printf("Using 3 servers: 0, 1, 2\n");
    gmp_printf("Output: %Zd\n\n", b);

    CLEAR_TABLE(cshr);
    mpz_set(cshr[2], fshr[2]);
    mpz_set(cshr[1], fshr[1]);
    mpz_set(cshr[4], fshr[4]);
    pcs_t_share_combine(vk, b, cshr);
    printf("Using 3 servers: 1, 2, 4\n");
    gmp_printf("Output: %Zd\n\n", b);

    CLEAR_TABLE(cshr);
    mpz_set(cshr[1], fshr[1]);
    mpz_set(cshr[2], fshr[2]);
    mpz_set(cshr[3], fshr[3]);
    mpz_set(cshr[4], fshr[4]);
    pcs_t_share_combine(vk, b, cshr);
    printf("Using 4 servers: 1, 2, 3, 4\n");
    gmp_printf("Output: %Zd\n\n", b);

    CLEAR_TABLE(cshr);
    mpz_set(cshr[0], fshr[0]);
    mpz_set(cshr[1], fshr[1]);
    mpz_set(cshr[2], fshr[2]);
    mpz_set(cshr[3], fshr[3]);
    mpz_set(cshr[4], fshr[4]);
    pcs_t_share_combine(vk, b, cshr);
    printf("Using 5 servers: 0, 1, 2, 3, 4\n");
    gmp_printf("Output: %Zd\n\n", b);

    CLEAR_TABLE(cshr);
    mpz_set(cshr[0], fshr[0]);
    mpz_set(cshr[1], fshr[1]);
    pcs_t_share_combine(vk, b, cshr);
    printf("Using 2 servers: 0, 1\n");
    gmp_printf("Output: %Zd\n\n", b);

    CLEAR_TABLE(cshr);
    mpz_set(cshr[1], fshr[1]);
    mpz_set(cshr[3], fshr[3]);
    pcs_t_share_combine(vk, b, cshr);
    printf("Using 2 servers: 1, 3\n");
    gmp_printf("Output: %Zd\n\n", b);

    CLEAR_TABLE(cshr);
    mpz_set(cshr[3], fshr[3]);
    mpz_set(cshr[2], fshr[3]);
    mpz_set(cshr[1], fshr[1]);
    pcs_t_share_combine(vk, b, cshr);
    printf("Using 1 servers: 3\n");
    gmp_printf("Output: %Zd\n\n", b);

    mpz_clear(a);
    mpz_clear(b);

    /* Cleanup */
    for (int i = 0; i < AU_COUNT; ++i) {
        pcs_t_free_auth_server(au[i]);
        mpz_clear(fshr[i]);
        mpz_clear(cshr[i]);
    }

    hcs_rand_free(hr);

    pcs_t_free_public_key(pk);
    pcs_t_free_private_key(vk);
}
