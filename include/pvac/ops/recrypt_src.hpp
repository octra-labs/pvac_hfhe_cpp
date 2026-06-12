/*
 * octra labs
 * lambda0xe, denis cmix, J.
 */

#pragma once

#include <array>
#include <stdexcept>

#include "recrypt_ru.hpp"

namespace pvac {

struct RuSrcEval {
    Cipher a;
    Cipher y;
    RSeed seed;
    std::array<uint8_t, 32> digest = {};
    bool key = false;
    bool source = false;
    bool eval = false;
    bool inv = false;
    bool proof = false;
    bool admitted = false;
};

using NatSrcEval = RuSrcEval;

inline Cipher ru_acc(const PubKey& pk, const Rku& rk, const RSeed& seed) {
    if (!rku_safe(pk, rk) || rk.sec.empty())
        throw std::runtime_error("pvac: ru source material rejected");
    auto acc = ru_add_fp(pk, ct_scale(pk, rk.sec[0], fp_from_u64(0)), fp_from_u64(0));
    acc = ru_add_fp(pk, acc, ru_fp(seed, 0, 0, 0));
    for (size_t i = 0; i < rk.prf; ++i) {
        acc = ct_add(pk, acc, ct_scale(pk, rk.sec[i], ru_fp(seed, 1, i, 0)));
    }
    for (size_t i = 0; i < rk.lpn; ++i) {
        acc = ct_add(pk, acc, ct_scale(pk, rk.sec[rk.prf + i], ru_fp(seed, 2, i, 0)));
    }
    return acc;
}

inline Cipher nat_acc(const PubKey& pk, const NatKey& key, const RSeed& seed) {
    return ru_acc(pk, key, seed);
}

inline RuSrcEval eval_ru_src(const PubKey& pk, const Rku& rk, const RSeed& seed) {
    if (!rku_safe(pk, rk))
        throw std::runtime_error("pvac: ru source key rejected");
    RuSrcEval out;
    out.seed = seed;
    out.a = ru_acc(pk, rk, seed);
    auto sq_seed = rku_seed(rk.dom, 3, seed.nonce.lo ^ seed.nonce.hi);
    out.y = ru_add_fp(pk, ct_mul_seeded(pk, out.a, out.a, sq_seed.data(), 4), fp_from_u64(1));
    out.digest = native_runtime_cipher_digest(pk, out.y);
    out.key = true;
    out.source = true;
    out.eval = true;
    out.inv = true;
    out.proof = true;
    out.admitted = true;
    return out;
}

inline NatSrcEval eval_nat_src(const PubKey& pk, const NatKey& key, const RSeed& seed) {
    return eval_ru_src(pk, key, seed);
}

inline bool verify_ru_src(const PubKey& pk, const Rku& rk, const RSeed& seed, const RuSrcEval& eval) {
    try {
        auto expected = eval_ru_src(pk, rk, seed);
        return
            eval.key &&
            eval.source &&
            eval.eval &&
            eval.inv &&
            eval.proof &&
            eval.admitted &&
            native_chosen_digest_eq(eval.digest, expected.digest) &&
            native_chosen_digest_eq(native_runtime_cipher_digest(pk, eval.y), expected.digest);
    } catch (...) {
        return false;
    }
}

inline bool verify_nat_src(const PubKey& pk, const NatKey& key, const RSeed& seed, const NatSrcEval& eval) {
    return verify_ru_src(pk, key, seed, eval);
}

}