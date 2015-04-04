#include <stdio.h>
#include <pcs.h>
#include "com/timing.h"

int main(int argc, char *argv[])
{
    int quiet = argc < 2 ? 0 : 1;
    (void)*argv;

    const int test_count = 100;

    mpz_t v1, v2, v3;
    mpz_inits(v1, v2, v3, NULL);

    pcs_public_key *pk = pcs_init_public_key();
    pcs_private_key *vk = pcs_init_private_key();

    double time_init, time_curr;

#define RUN_TEST(c)\
do {\
    mpz_set_ui(v1, 15634);\
    mpz_set_ui(v2, 1640);\
    pcs_encrypt(pk, v1, v1);\
\
    time_init = timing_current_cpu_time();\
    for (int i = 0; i < test_count; ++i) {\
        pcs_ep_add(pk, v1, v1, v2);\
        mpz_add_ui(v2, v2, 1);\
    }\
    time_curr = timing_current_cpu_time();\
\
    printf("%d: %fs for %d iterations, %0.3fns per encrypted add\n", c, time_curr - time_init, test_count,\
            (time_curr - time_init) / test_count * 1.0e9);\
    if (!quiet) {\
        pcs_decrypt(vk, v1, v1);\
        gmp_printf("result = %Zd\n", v1);\
    }\
} while (0)

    pcs_generate_key_pair(pk, vk, 2048, 0);
    if (!quiet) gmp_printf("g = %Zd\n", pk->g);
    RUN_TEST(1);

    pcs_clear_public_key(pk);
    pcs_clear_private_key(vk);
    pcs_generate_key_pair(pk, vk, 2048, 1);
    if (!quiet) gmp_printf("g = %Zd\n", pk->g);
    RUN_TEST(2);

    mpz_clears(v1, v2, v3, NULL);
    pcs_free_public_key(pk);
    pcs_free_private_key(vk);
}
