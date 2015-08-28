#include <gmp.h>
#define HCS_STATIC_SEED
#include <libhcs/pcs.h>
#include "timing.h"

#define num_runs 40

int main(void)
{
    pcs_public_key *pk = pcs_init_public_key();
    pcs_private_key *vk = pcs_init_private_key();
    hcs_random *hr = hcs_init_rand();
    pcs_generate_key_pair(pk, vk, hr, 2048);

    mpz_t a, b, c;
    mpz_inits(a, b, c, NULL);

    mpz_set_ui(a, 4124124523);
    mpz_set_ui(b, 23423523);

    TIME_CODE(
#ifdef _OPENMP
            "Parallel",
#else
            "Single-core",
#endif
        for (int i = 0; i < num_runs; ++i)
            pcs_encrypt(pk, hr, c, a);
    );
}
