#include <gmp.h>
#define HCS_STATIC_SEED
#include <libhcs/pcs.h>
#include "timing.h"

#define num_runs 1000

int main(void)
{
    pcs_public_key *pk = pcs_init_public_key();
    pcs_private_key *vk = pcs_init_private_key();
    hcs_random *hr = hcs_init_random();
    pcs_generate_key_pair(pk, vk, hr, 256);

    mpz_t a, b, c, d;
    mpz_inits(a, b, c, d, NULL);

    mpz_set_ui(a, 4124124523);
    mpz_set_ui(b, 23423523);
    mpz_set_ui(d, 1);

    printf("%s\n",
#ifdef _OPENMP
                "Parallel"
#else
                "Single-core"
#endif
          );

    for (int i = 0; i < 10; ++i) {
        struct timespec s = MTIME_CODE(
            for (int i = 0; i < num_runs; ++i)
                pcs_encrypt(pk, hr, c, a);
        );

        pcs_ep_add(pk, a, a, d);

        printf("Elapsed:\n\t%lus %juns\n\n", s.tv_sec, s.tv_nsec);\
    }

}
