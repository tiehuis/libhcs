#ifndef HCS_SHARES
#define HCS_SHARES

#include <gmp.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    mpz_t *shares;
    int *flag;
    void **server_id;
    unsigned long size;
} hcs_shares;

hcs_shares* hcs_init_shares(unsigned long size);
void hcs_set_share(hcs_shares *hs, mpz_t share_value, unsigned long share_id);
void hcs_set_flag(hcs_shares *hs, unsigned long share_id);
void hcs_clear_flag(hcs_shares *hs, unsigned long share_id);
void hcs_toggle_flag(hcs_shares *hs, unsigned long share_id);
int hcs_tst_flag(hcs_shares *hs, unsigned long share_id);
void hcs_free_shares(hcs_shares *hs);

#endif

#ifdef __cplusplus
}
#endif
