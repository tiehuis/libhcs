/**
 * @file hcs_random.hpp
 *
 * C++ wrapper class for the hcs_random object.
 */

#ifndef HCS_RAND_HPP
#define HCS_RAND_HPP

#include "../libhcs/hcs_random.h"

namespace hcs {

class rand {

private:
    hcs_random *hr;
    int refcount;   // Counts the number of times this particular instance is counted

public:
    rand() : refcount(0) {
        hr = hcs_init_rand();
    }

    ~rand() {
        hcs_free_rand(hr);
    }

    int reseed() {
        return hcs_reseed_rand(hr);
    }

    void inc_refcount() {
        refcount++;
    }

    bool dec_refcount() {
        return refcount > 0 ? --refcount != 0 : false;
    }

    bool is_referenced() {
        return refcount != 0;
    }

    hcs_random* as_ptr() {
        return hr;
    }
};

} // hcs namespace

#endif
