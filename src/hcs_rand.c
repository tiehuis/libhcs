#include <gmp.h>
#include "hcs_rand.h"
#include "com/util.h"

/* This provides a wrapper around gmp_randstate_t and provides some seeding
 * functions and such. */

hcs_rand* hcs_rand_init(const unsigned long v)
{
    hcs_rand *hr = malloc(sizeof(hcs_rand));

    mpz_t t1;
    mpz_init_set_ui(t1, v);

    gmp_randinit_default(hr->rstate);
#if 0 // Comment out to zero seed for testing
    mpz_seed(t1, 256);
#endif
    gmp_randseed(hr->rstate, t1);

    mpz_clear(t1);
    return hr;
}

void hcs_rand_free(hcs_rand *hr)
{
    gmp_randclear(hr->rstate);
    free(hr);
}
