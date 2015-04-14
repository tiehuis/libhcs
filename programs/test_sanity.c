#include <assert.h>
#include <stdio.h>
#include <hcs.h>
#include <gmp.h>

#define TEST(CRYPTO, ...)\
do {\
    CRYPTO##_public_key *pk = CRYPTO##_init_public_key();\
    CRYPTO##_private_key *vk = CRYPTO##_init_private_key();\
    CRYPTO##_generate_key_pair(__VA_ARGS__);\
    mpz_t a, b, c;\
    mpz_init_set_ui(a, 0x823e42fa);\
    mpz_init(b);\
    mpz_init_set(c, a);\
    CRYPTO##_encrypt(pk, a, a);\
    CRYPTO##_decrypt(vk, b, a);\
    assert(mpz_cmp(b, c) == 0);\
    mpz_clear(a);\
    mpz_clear(b);\
    CRYPTO##_free_public_key(pk);\
    CRYPTO##_free_private_key(vk);\
    printf("%s: All tests passed\n", #CRYPTO);\
} while (0)

int main(void)
{
    TEST(pcs, pk, vk, 512);
    TEST(pcs, pk, vk, 512);
    TEST(djcs, 2, pk, vk, 512);

    /* El gamal */
    do {
        egcs_public_key *pk = egcs_init_public_key();
        egcs_private_key *vk = egcs_init_private_key();
        egcs_generate_key_pair(pk, vk, 512);
        mpz_t a, b;
        egcs_cipher *ct = egcs_init_cipher();
        mpz_init_set_ui(a, 0x823e42fa);
        mpz_init_set(b, a);
        egcs_encrypt(pk, ct, a);
        egcs_decrypt(vk, a, ct);
        assert(mpz_cmp(a, b) == 0);
        mpz_clear(a);
        mpz_clear(b);
        egcs_free_cipher(ct);
        egcs_free_public_key(pk);
        egcs_free_private_key(vk);
        printf("%s: All tests passed\n", "egcs");
    } while (0);
}
