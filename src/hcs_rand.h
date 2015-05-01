#ifndef HCS_RAND
#define HCS_RAND

#include <gmp.h>

typedef struct {
    gmp_randstate_t rstate;
} hcs_rand;

hcs_rand* hcs_rand_init(const unsigned long v);
void hcs_rand_free(hcs_rand *hr);

#endif
