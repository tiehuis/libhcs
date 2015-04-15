#include <hcs.h>

#define MODULUS_BITS 16
#define AU_COUNT 3
#define AU_REQ 1

int main(void)
{
    /* Initialise our keys as normal */
    pcs_t_public_key *pk = pcs_t_init_public_key();
    pcs_t_private_key *vk = pcs_t_init_private_key();

    /* Initialise each auth server that will aid in the decryption
     * of results. These would usually be different systems. */
    pcs_t_auth_server *au[AU_COUNT];
    for (int i = 0; i < AU_COUNT; ++i)
        au[i] = pcs_t_init_auth_server();

    mpz_t a, b;
    mpz_init_set_ui(a, 10);
    mpz_init(b);

    pcs_t_generate_key_pair(pk, vk, MODULUS_BITS, AU_REQ, AU_COUNT);
    pcs_t_encrypt(pk, b, a);

    /* Set up all auth servers with the given vk values. This will
     * generate a secret share for each server and also set the verification
     * value assigned to it in vk. */
    for (int i = 0; i < AU_COUNT; ++i)
        pcs_t_set_auth_server(vk, au[i], i);

    /* Intialise a table to store the shares that are decrypted
     * by each individual server. */
    mpz_t au_shares[AU_COUNT];
    /* Share decrypt into the recently created table. */
    for (int i = 0; i < AU_COUNT; ++i) {
        mpz_init(au_shares[i]);
        pcs_t_share_decrypt(vk, au[i], au_shares[i], b);
    }

    /* Combine the shares, producing the decrypted result. */
    pcs_t_share_combine(vk, b, au_shares, AU_COUNT);
    gmp_printf("%Zd\n%Zd\n", a, b);

    mpz_clear(a);
    mpz_clear(b);

    /* Cleanup */
    for (int i = 0; i < AU_COUNT; ++i) {
        pcs_t_free_auth_server(au[i]);
        mpz_clear(au_shares[i]);
    }

    pcs_t_free_public_key(pk);
    pcs_t_free_private_key(vk);
}
