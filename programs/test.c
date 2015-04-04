#include <stdio.h>
#include <stdlib.h>
#include <gmp.h>
#include <pcs.h>

int main(void)
{
    pcs_public_key *pk = pcs_init_public_key();
    pcs_private_key *vk = pcs_init_private_key();

    pcs_generate_key_pair(pk, vk, 2048, 0);

    mpz_t a, b;
    mpz_inits(a, b, NULL);
    mpz_set_ui(a, 1000);

    pcs_encrypt(pk, b, a);
    gmp_printf("%Zd\n", b);
    pcs_reencrypt(pk, b, b);
    gmp_printf("%Zd\n", b);
    /*
    for (unsigned long i = 0; i < 1000; ++i) {
        pcs_ep_add(pk, b, b, a);
    }
    */
    pcs_decrypt(vk, b, b);
    gmp_printf("%Zd\n", b);

    pcs_free_public_key(pk);
    pcs_free_private_key(vk);
}
