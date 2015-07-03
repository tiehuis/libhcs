#define CATCH_CONFIG_MAIN
#include "catch.hpp"

#include <libhcs++/rand.hpp>
#include <gmpxx.h>
#include "../src/com/util.h"

TEST_CASE( "Prime Generation accuracy" ) {
    hcs::rand hr;
    mpz_class a;

    internal_fast_random_prime(a.get_mpz_t(), hr.as_ptr()->rstate, 512);
    REQUIRE(mpz_sizeinbase( a.get_mpz_t(), 2 ) >= 512);
    REQUIRE(mpz_probab_prime_p( a.get_mpz_t(), 25) != 0);

    internal_naive_random_prime(a.get_mpz_t(), hr.as_ptr()->rstate, 512);
    REQUIRE(mpz_sizeinbase( a.get_mpz_t(), 2 ) >= 512);
    REQUIRE(mpz_probab_prime_p( a.get_mpz_t(), 25) != 0);
}
