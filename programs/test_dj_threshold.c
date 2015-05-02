#include <stdlib.h>
#include <stdio.h>
#include <hcs.h>

#define MODULUS_BITS 512
#define AU_COUNT 5
#define AU_REQ 2

#define S_ 2

int main(int argc, char *argv[])
{
    if (argc < 2) return 1;
    hcs_rand *hr = hcs_rand_init(atoi(argv[1]));

    /* Initialise our keys as normal */
    djcs_t_public_key *pk = djcs_t_init_public_key();
    djcs_t_private_key *vk = djcs_t_init_private_key();

    /* Initialise each auth server that will aid in the decryption
     * of results. These would usually be different systems. */
    djcs_t_auth_server *au[AU_COUNT];
    for (int i = 0; i < AU_COUNT; ++i)
        au[i] = djcs_t_init_auth_server(); // Want to add index to auth server internally

    mpz_t a, b;
    mpz_init_set_ui(a, 10);
    mpz_init(b);

    djcs_t_generate_key_pair(pk, vk, hr, S_, MODULUS_BITS, AU_REQ, AU_COUNT);
    djcs_t_encrypt(pk, hr, b, a);

    mpz_t *coeff = djcs_t_init_polynomial(vk, hr);

    /* Set up all auth servers with the given vk values. This will
     * generate a secret share for each server and also set the verification
     * value assigned to it in vk. */
    for (int i = 0; i < AU_COUNT; ++i) {
        /* Polynomial is only on one machine. Server must request over network value
         * of polynomial and are sent an index and corresponding value. */
        djcs_t_compute_polynomial(vk, coeff, au[i]->si, i);
        djcs_t_set_auth_server(au[i], au[i]->si, i);
    }

    djcs_t_free_polynomial(vk, coeff);

    /* Intialise a table to store the shares that are decrypted
     * by each individual server. */
    mpz_t fshr[AU_COUNT];
    mpz_t cshr[AU_COUNT];
    /* Share decrypt into the recently created table. */
    for (int i = 0; i < AU_COUNT; ++i) {
        mpz_init(cshr[i]);
        mpz_init(fshr[i]);
        djcs_t_share_decrypt(vk, au[i], fshr[i], b);
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
    djcs_t_share_combine(vk, b, cshr);
    printf("Using 3 servers: 0, 1, 2\n");
    gmp_printf("Output: %Zd\n\n", b);

    CLEAR_TABLE(cshr);
    mpz_set(cshr[2], fshr[2]);
    mpz_set(cshr[1], fshr[1]);
    mpz_set(cshr[4], fshr[4]);
    djcs_t_share_combine(vk, b, cshr);
    printf("Using 3 servers: 1, 2, 4\n");
    gmp_printf("Output: %Zd\n\n", b);

    CLEAR_TABLE(cshr);
    mpz_set(cshr[1], fshr[1]);
    mpz_set(cshr[2], fshr[2]);
    mpz_set(cshr[3], fshr[3]);
    mpz_set(cshr[4], fshr[4]);
    djcs_t_share_combine(vk, b, cshr);
    printf("Using 4 servers: 1, 2, 3, 4\n");
    gmp_printf("Output: %Zd\n\n", b);

    CLEAR_TABLE(cshr);
    mpz_set(cshr[0], fshr[0]);
    mpz_set(cshr[1], fshr[1]);
    mpz_set(cshr[2], fshr[2]);
    mpz_set(cshr[3], fshr[3]);
    mpz_set(cshr[4], fshr[4]);
    djcs_t_share_combine(vk, b, cshr);
    printf("Using 5 servers: 0, 1, 2, 3, 4\n");
    gmp_printf("Output: %Zd\n\n", b);

    CLEAR_TABLE(cshr);
    mpz_set(cshr[0], fshr[0]);
    mpz_set(cshr[1], fshr[1]);
    djcs_t_share_combine(vk, b, cshr);
    printf("Using 2 servers: 0, 1\n");
    gmp_printf("Output: %Zd\n\n", b);

    CLEAR_TABLE(cshr);
    mpz_set(cshr[1], fshr[1]);
    mpz_set(cshr[3], fshr[3]);
    djcs_t_share_combine(vk, b, cshr);
    printf("Using 2 servers: 1, 3\n");
    gmp_printf("Output: %Zd\n\n", b);

    CLEAR_TABLE(cshr);
    mpz_set(cshr[3], fshr[3]);
    mpz_set(cshr[2], fshr[3]);
    mpz_set(cshr[1], fshr[1]);
    djcs_t_share_combine(vk, b, cshr);
    printf("Using 1 servers: 3\n");
    gmp_printf("Output: %Zd\n\n", b);

    mpz_clear(a);
    mpz_clear(b);

    /* Cleanup */
    for (int i = 0; i < AU_COUNT; ++i) {
        djcs_t_free_auth_server(au[i]);
        mpz_clear(fshr[i]);
        mpz_clear(cshr[i]);
    }

    hcs_rand_free(hr);

    djcs_t_free_public_key(pk);
    djcs_t_free_private_key(vk);
}
