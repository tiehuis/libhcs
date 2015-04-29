#ifndef HCS_RAND
#define HCS_RAND

typedef struct {
    gmp_randstate_t rstate;
} hcs_rand;

hcs_rand* hcs_rand_init(const unsigned long v);
void hcs_rand_free(hcs_rand *hr);

#endif
