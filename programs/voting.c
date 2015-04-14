#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <gmp.h>
#include <pcs.h>

/***********/
/* Globals */
/***********/

#define key_modulus_size 2048
#define voter_count 10
#define available_votes 5
#define candidate_count 5

/**********/
/* Server */
/**********/

static pcs_public_key *server_pk;
static pcs_private_key *server_vk;
static mpz_t candidates[candidate_count];

void server_init(void)
{
    server_pk = pcs_init_public_key();
    server_vk = pcs_init_private_key();
    pcs_generate_key_pair(server_pk, server_vk, key_modulus_size);

    for (int i = 0; i < candidate_count; ++i) {
        mpz_init(candidates[i]);
        pcs_encrypt(server_pk, candidates[i], candidates[i]);
    }

    srand(time(NULL));
}

void server_cleanup(void)
{
    pcs_free_public_key(server_pk);
    pcs_free_private_key(server_vk);

    for (int i = 0; i < candidate_count; ++i)
        mpz_clear(candidates[i]);
}

void server_request(mpz_t rop, int candidate_number)
{
    assert(candidate_number < candidate_count);
    pcs_ee_add(server_pk, candidates[candidate_number], candidates[candidate_number], rop);
}

void server_verify(void)
{
}

void server_tally(void)
{
    printf("\n--------------\n");
    printf(  "-Vote results-\n");
    printf(  "--------------\n");
    for (int i = 0; i < candidate_count; ++i) {
        pcs_decrypt(server_vk, candidates[i], candidates[i]);
        gmp_printf("Candidate %-3d: %Zd votes\n", i + 1, candidates[i]);
    }
}

/**********/
/* Voting */
/**********/

int main(void)
{
    server_init();

    mpz_t value;
    mpz_init(value);

    /* M^L < n^2 */
    mpz_ui_pow_ui(value, voter_count, candidate_count);
    assert(mpz_cmp(value, server_pk->n2) < 0);

    /* Each voter constructs his vote for each candidate,
     * then encrypts it and sends in to the server to add
     * to the tally */
    for (int i = 0; i < voter_count; ++i) {
        printf("Voter %-3d:\n", i);
        for (int j = 0; j < candidate_count; ++j) {
            mpz_set_ui(value, rand() & 1);
            gmp_printf("\tCandidate %-3d: (%d) encrypting vote %Zd: ", j, i, value);
            pcs_encrypt(server_pk, value, value);
            gmp_printf("%Zd\n", value);

            /* Make a request now we have secured our vote */
            server_request(value, j);
        }
    }

    mpz_clear(value);

    server_verify();
    server_tally();
    server_cleanup();
}
