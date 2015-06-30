/**
 * @file pcsxx.h
 *
 * A C++ wrapper class around pcs.h
 */

#ifndef HCS_PCS_HPP
#define HCS_PCS_HPP

#include <string.h>
#include <gmpxx.h>
#include <libhcs/pcs.h>
#include "rand.hpp"

/*
 * We do not manage the memory associated with an hcs::rand class here, and it
 * is up to the caller to ensure that the hcs::rand associated has the same
 * lifetime as the public/private key.
 */

namespace hcs {
namespace pcs {

class public_key {

private:
    pcs_public_key *pk;
    hcs::rand *hr;

public:
    public_key(hcs::rand &hr_) {
        pk = pcs_init_public_key();
        hr = &hr_;
        hr->inc_refcount();
    }

    ~public_key() {
        pcs_free_public_key(pk);
        hr->dec_refcount();
    }

    pcs_public_key* as_ptr() {
        return pk;
    }

    hcs_rand* get_rand() {
        return hr->as_ptr();
    }

    /* Encryption functions acting on a key */
    void encrypt(mpz_class &rop, mpz_class &op) {
        pcs_encrypt(pk, hr->as_ptr(), rop.get_mpz_t(), op.get_mpz_t());
    }

    void reencrypt(mpz_class &rop, mpz_class &op) {
        pcs_reencrypt(pk, hr->as_ptr(), rop.get_mpz_t(), op.get_mpz_t());
    }

    void ep_add(mpz_class &rop, mpz_class &c1, mpz_class &c2) {
        pcs_ep_add(pk, rop.get_mpz_t(), c1.get_mpz_t(), c2.get_mpz_t());
    }

    void ee_add(mpz_class &rop, mpz_class &c1, mpz_class &c2) {
        pcs_ee_add(pk, rop.get_mpz_t(), c1.get_mpz_t(), c2.get_mpz_t());
    }

    void ep_mul(mpz_class &rop, mpz_class &c1, mpz_class &p1) {
        pcs_ep_mul(pk, rop.get_mpz_t(), c1.get_mpz_t(), p1.get_mpz_t());
    }

    void clear() {
        pcs_clear_public_key(pk);
    }

    std::string export_json() {
        return std::string(pcs_export_public_key(pk));
    }

    int import_json(std::string &json) {
        return pcs_import_public_key(pk, json.c_str());
    }
};

class private_key {

private:
    pcs_private_key *vk;
    hcs::rand *hr;

public:
    private_key(hcs::rand &hr_) {
        vk = pcs_init_private_key();
        hr = &hr_;
        hr->inc_refcount();
    }

    ~private_key() {
        pcs_free_private_key(vk);
        hr->dec_refcount();
    }

    pcs_private_key* as_ptr() {
        return vk;
    }

    hcs_rand* get_rand() {
        return hr->as_ptr();
    }

    void decrypt(mpz_class &rop, mpz_class &c1) {
        pcs_decrypt(vk, rop.get_mpz_t(), c1.get_mpz_t());
    }

    void clear() {
        pcs_clear_private_key(vk);
    }

    std::string export_json() {
        return std::string(pcs_export_private_key(vk));
    }

    int import_json(std::string &json) {
        return pcs_import_private_key(vk, json.c_str());
    }
};

inline void generate_key_pair(public_key &pk, private_key &vk,
        const unsigned long bits)
{
    pcs_generate_key_pair(pk.as_ptr(), vk.as_ptr(), vk.get_rand(), bits);
}

inline int verify_key_pair(public_key &pk, private_key &vk) {
    return pcs_verify_key_pair(pk.as_ptr(), vk.as_ptr());
}

} // pcs namespace
} // hcs namespace
#endif
