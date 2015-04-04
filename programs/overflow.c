#include <gmp.h>
#include "pcs.h"

int main(void)
{
    pcs_public_key *pk = pcs_init_public_key();
    pcs_private_key *vk = pcs_init_private_key();
    pcs_generate_key_pair(pk, vk, 256);

    mpz_t a, b, c, _1000;
    mpz_inits(a, b, c, _1000, NULL);
    mpz_set_ui(_1000, 10);

    mpz_set(a, _1000);
    mpz_set(c, _1000);
    pcs_encrypt(pk, a, a);

    while (1) {
        pcs_decrypt(vk, b, a);
        if (mpz_cmp(b, c) != 0)
            break;

        pcs_ep_mul(pk, a, a, _1000);
        mpz_mul(c, c, _1000);
    }

    gmp_printf("N = %Zd\n\n%u\n", pk->n, mpz_sizeinbase(pk->n, 2));
    gmp_printf("%Zd\n\n%Zd\n\n%u\n", b, c, mpz_sizeinbase(b, 2));

    mpz_clears(a, b, c, _1000, NULL);

    pcs_free_public_key(pk);
    pcs_free_private_key(vk);
}
