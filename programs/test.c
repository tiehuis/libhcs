#include <stdio.h>
#include <stdlib.h>
#include <gmp.h>
#include <hcs.h>
#include "com/timing.h"

#define init_scheme(CRYPTO)\
{\
    printf("Scheme: %s\n", #CRYPTO);\
    CRYPTO##_public_key *pk = CRYPTO##_init_public_key();\
    CRYPTO##_private_key *vk = CRYPTO##_init_private_key();\
    CRYPTO##_generate_key_pair(pk, vk, 2048, 1);\
    mpz_t a, b;\
    mpz_inits(a, b, NULL);\
    mpz_set_ui(a, 1000);\
    CRYPTO##_encrypt(pk, a, a);\
timing_begin()\
    for (int i = 0; i < 100; ++i)\
        CRYPTO##_decrypt(vk, b, a);\
timing_end(\
    gmp_printf("%Zd\n", b);\
    )\
    CRYPTO##_free_public_key(pk);\
    CRYPTO##_free_private_key(vk);\
    mpz_clears(a, b, NULL);\
}

int main(void)
{
    init_scheme(pcs2);
    init_scheme(pcs);
}
