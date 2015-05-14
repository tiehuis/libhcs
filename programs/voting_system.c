#include <stdio.h>
#include <gmp.h>
#include <hcs.h>

#define V_COUNT 50
#define AS_COUNT 4
#define AS_REQ   2

#define loop_i(high) for (int i = 0; i < (high); ++i)

int main(void)
{
    /* Shared variables used for sending values between users */
    mpz_t svar1, svar2;
    mpz_init(svar1);
    mpz_init(svar2);

    /* Shared for simplicity: Originates from VM */
    hcs_rand *hr = hcs_init_rand();
    pcs_t_public_key *pk = pcs_t_init_public_key();

    /* VM: Initial key setup */
    pcs_t_private_key *vk = pcs_t_init_private_key();
    pcs_t_generate_key_pair(pk, vk, hr, 128, AS_REQ, AS_COUNT);

    /* Seperate AS: AS setup */
    pcs_t_auth_server *ai[AS_COUNT];
    loop_i(AS_COUNT) {
        ai[i] = pcs_t_init_auth_server();
    }

    /* VM: Initialise polynomial */
    pcs_t_poly *px = pcs_t_init_polynomial(vk, hr);

    /* Seperate AS: Each AS sends a request for a polynomial value
     * This is not usually in order. */
    loop_i(AS_COUNT) {

        /* VM: Compute polynomial, storing in shared variable */
        pcs_t_compute_polynomial(vk, px, svar1, i);

        /* AS: Grab return id and value and set */
        pcs_t_set_auth_server(ai[i], svar1, i);
    }

    /* VM: Send a copy of the public key to the Board, discard private key. */
    pcs_t_free_polynomial(px);
    pcs_t_free_private_key(vk);

    /* BOARD: Post public key on board values */

    /* Seperate VOTERS: Each voter initialises their state, and obtains the
     * public key from the board. */
    mpz_t voter[V_COUNT];
    loop_i(V_COUNT) {
        mpz_init(voter[i]);
    }

    /* Seperate VOTERS: Choose their vote and send the value, along with the
     * proof of their value to the server. */
    loop_i(V_COUNT) {
        mpz_set_ui(svar2, 2);
        mpz_urandomm(svar1, hr->rstate, svar2);

        /* Each voter encrypts their value with the public key this cannot
         * be reversed without AS_REQ servers. */
        pcs_t_encrypt(pk, hr, voter[i], svar1);

        /* BOARD: value is sent to board, along with a zero-knowledge proof
         * for the value of the number. The proof can be checked here,
         * although, it is more likely to be checked during tally, and/or
         * during the voting phase. Invalid proof/vote pairs will still be
         * posted, so people can check to see if there are excessive
         * invalid votes posted. */

        // if (!pcs_t_zproof(svar1, proof)) return INVALID;

        /* BOARD: If the value is valid, we add that to the current vote
         * table. In this case, the votes are just stored in voter. */
    }

    /* BOARD: Once the voting stage is done, we prevent any new votes from
     * being added. */

    // voting.cease()

    /* Anyone can tally the votes, as all voters have the private key */
    mpz_set_ui(svar1, 0);
    pcs_t_encrypt(pk, hr, svar1, svar1);
    loop_i(V_COUNT) {
        /* Seperate Voter: Sum the votes and post the result. Every voter
         * can do this for self-verification that the tally is indeed
         * accurate. */
        pcs_t_ee_add(pk, svar1, svar1, voter[i]);
    }

    mpz_t board_shares[AS_COUNT];
    loop_i(AS_COUNT) {
        mpz_init(board_shares[i]);
    }

    /* svar1 stores vote count, now the pcs_t_auth_servers each compute
     * their shares and post their results on the board. */
    loop_i(AS_COUNT) {
        pcs_t_share_decrypt(pk, ai[i], board_shares[i], svar1);
    }

    /* All the shares are contained on the board. Anyone can now sum the
     * results and write the combined values to the board. Multiple share
     * combinations should be taken to ensure that the value we get is
     * indeed correct. */

    /* Confirm we get the same output as others have posted. Confirm that
     * different orderings indeed provide the same results. If not, test
     * more combinations to determine the share that is invalid. */
    pcs_t_share_combine(pk, svar2, board_shares);

    /* Print results */
    printf("Votes\n");
    printf("------\n");
    loop_i(V_COUNT) {
        gmp_printf("(id) %u : %Zd\n", i, voter[i]);
    }
    printf("\nTally\n");
    printf("-----\n");
    gmp_printf("Sum = %Zd\n", svar1);

    printf("\nShares\n");
    printf("------\n");
    loop_i(AS_COUNT) {
        gmp_printf("(id) %u : %Zd\n", i, board_shares[i]);
    }

    printf("\nCombined\n");
    printf("--------\n");
    gmp_printf("%Zd\n", svar2);

    /* We have succesfully completed a vote. Cleanup. */
    loop_i(V_COUNT) mpz_clear(voter[i]);
    loop_i(AS_COUNT) pcs_t_free_auth_server(ai[i]);
    loop_i(AS_COUNT) mpz_clear(board_shares[i]);

    mpz_clear(svar1);
    mpz_clear(svar2);
    pcs_t_free_public_key(pk);
    hcs_free_rand(hr);
}
