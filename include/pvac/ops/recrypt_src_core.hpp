/*
 * octra labs
 * lambda0xe, denis cmix, J.
 */


#pragma once

#include <array>
#include <cstring>
#include <vector>

#include "../core/hash.hpp"
#include "../core/seedable_rng.hpp"
#include "../core/types.hpp"

namespace pvac {

inline Fp ru_fp(const RSeed& seed, uint64_t dom, uint64_t id, uint64_t slot) {
    Sha256 h;
    h.init();
    h.update("pvac.native.ru.fp", std::strlen("pvac.native.ru.fp"));
    sha256_acc_u64(h, seed.ztag);
    sha256_acc_u64(h, seed.nonce.lo);
    sha256_acc_u64(h, seed.nonce.hi);
    sha256_acc_u64(h, dom);
    sha256_acc_u64(h, id);
    sha256_acc_u64(h, slot);
    std::array<uint8_t, 32> d{};
    h.finish(d.data());
    uint64_t lo = 0;
    uint64_t hi = 0;
    std::memcpy(&lo, d.data(), sizeof(lo));
    std::memcpy(&hi, d.data() + sizeof(lo), sizeof(hi));
    auto x = fp_from_words(lo, hi & MASK63);
    return (x.lo || x.hi) ? x : fp_from_u64(1);
}

inline uint64_t ru_ztag(uint64_t canon_tag, const Nonce128& nonce) {
    Sha256 h;
    h.init();
    h.update("pvac.native.ru.ztag", std::strlen("pvac.native.ru.ztag"));
    sha256_acc_u64(h, canon_tag);
    sha256_acc_u64(h, nonce.lo);
    sha256_acc_u64(h, nonce.hi);
    std::array<uint8_t, 32> d{};
    h.finish(d.data());
    uint64_t out = 0;
    std::memcpy(&out, d.data(), sizeof(out));
    return out;
}

inline bool ru_src(const PubKey& pk, const Layer& layer) {
    return layer.rule == RRule::BASE && layer.seed.ztag == ru_ztag(pk.canon_tag, layer.seed.nonce);
}

inline RSeed ru_seed(const PubKey& pk, const uint8_t seed[32]) {
    SeedableRng rng = make_seeded_rng(seed);
    RSeed out;
    out.nonce = rng.nonce128();
    out.ztag = ru_ztag(pk.canon_tag, out.nonce);
    return out;
}

inline Fp ru_affine(const SecKey& sk, const RSeed& seed, size_t slot) {
    Sha256 h;
    h.init();
    h.update("pvac.native.ru.secret", std::strlen("pvac.native.ru.secret"));
    sha256_acc_u64(h, seed.ztag);
    sha256_acc_u64(h, seed.nonce.lo);
    sha256_acc_u64(h, seed.nonce.hi);
    sha256_acc_u64(h, slot);
    for (size_t i = 0; i < sk.prf_k.size(); ++i) {
        sha256_acc_u64(h, i);
        sha256_acc_u64(h, sk.prf_k[i]);
    }
    std::array<uint8_t, 32> d{};
    h.finish(d.data());
    uint64_t lo = 0;
    uint64_t hi = 0;
    std::memcpy(&lo, d.data(), sizeof(lo));
    std::memcpy(&hi, d.data() + sizeof(lo), sizeof(hi));
    auto out = fp_from_words(lo, hi & MASK63);
    return (out.lo || out.hi) ? out : fp_from_u64(1);
}

inline Fp ru_y(const SecKey& sk, const RSeed& seed, size_t slot) {
    auto a = ru_affine(sk, seed, slot);
    return fp_add(fp_mul(a, a), fp_from_u64(1));
}

inline std::vector<Fp> ru_inv_slots(const SecKey& sk, const RSeed& seed, size_t slots) {
    std::vector<Fp> out(slots);
    for (size_t j = 0; j < slots; ++j) {
        out[j] = ru_y(sk, seed, j);
    }
    return out;
}

inline std::vector<Fp> ru_r_slots(const SecKey& sk, const RSeed& seed, size_t slots) {
    auto y = ru_inv_slots(sk, seed, slots);
    for (auto& x : y) {
        x = fp_inv(x);
    }
    return y;
}

}