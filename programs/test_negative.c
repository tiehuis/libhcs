#include <gmp.h>
#include "pcs.h"

/* ep_add preserves negatives,
 * ee_add and ep_mul do not */

int main(void)
{
    pcs_public_key *pk = pcs_init_public_key();
    pcs_private_key *vk = pcs_init_private_key();
    pcs_generate_key_pair(pk, vk, 256);

    mpz_t a, b, c;
    mpz_inits(a, b, c, NULL);

    mpz_set_ui(a, 1000);
    mpz_set_si(b, -50);
    mpz_set_ui(c, 0);

    pcs_encrypt(pk, a, a);
    pcs_ep_add(pk, a, a, b);
    pcs_decrypt(vk, a, a);
    gmp_printf("%Zd\n", a);

    pcs_encrypt(pk, c, c);
    pcs_ep_add(pk, c, c, b);
    pcs_decrypt(vk, c, c);
    gmp_printf("%Zd\n", c);
    mpz_sub(c, c, pk->n);
    gmp_printf("%Zd\n", c);

    pcs_encrypt(pk, b, b);
    gmp_printf("%Zd\n", b);
    pcs_decrypt(vk, b, b);
    gmp_printf("%Zd\n", b);

    pcs_ee_add(pk, b, b, a);
    gmp_printf("%Zd\n", b);
    pcs_decrypt(vk, b, b);
    gmp_printf("%Zd\n", b);

    mpz_clears(a, b, c, NULL);

    pcs_free_public_key(pk);
    pcs_free_private_key(vk);
}
