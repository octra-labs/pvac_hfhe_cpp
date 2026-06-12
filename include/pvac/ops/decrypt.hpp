#pragma once

#include <cstdint>
#include <vector>
#include <stdexcept>

#include "../core/types.hpp"
#include "../crypto/lpn.hpp"
#include "encrypt.hpp"
#include "recrypt_src_core.hpp"

namespace pvac {

enum class DecPolicy : uint8_t {
    STANDARD = 0,
    NATIVE_LOCAL = 1
};

inline bool dec_has_native_src(const PubKey& pk, const Cipher& C) {
    for (const auto& layer : C.L) {
        if (layer.rule == RRule::BASE && ru_src(pk, layer))
            return true;
    }
    return false;
}

inline std::vector<Fp> layer_R_cached(
    const PubKey& pk,
    const SecKey& sk,
    const Cipher& C,
    uint32_t lid,
    std::vector<uint8_t>& st,
    std::vector<std::vector<Fp>>& cache,
    DecPolicy policy = DecPolicy::STANDARD
) {
    if ((size_t)lid >= C.L.size())
        throw std::runtime_error("pvac: layer_R_cached: layer id out of range");
    if (st.size() != C.L.size() || cache.size() != C.L.size())
        throw std::runtime_error("pvac: layer_R_cached: work buffer shape rejected");

    if (st[lid] == 2) return cache[lid];

    if (st[lid] == 1) {
        throw std::runtime_error("pvac: layer_R_cached: cycle in layer dependency graph");
    }

    st[lid] = 1;

    const Layer& L = C.L[lid];

    if (L.rule == RRule::BASE) {
        bool native = ru_src(pk, L);
        if (native && policy != DecPolicy::NATIVE_LOCAL)
            throw std::runtime_error("pvac: native source decrypt rejected");
        cache[lid] = native ? ru_r_slots(sk, L.seed, C.slots) : prf_R_slots(pk, sk, L.seed, C.slots);
    } else {
        auto Ra = layer_R_cached(pk, sk, C, L.pa, st, cache, policy);
        auto Rb = layer_R_cached(pk, sk, C, L.pb, st, cache, policy);
        cache[lid] = field::Op::mul(Ra, Rb);
    }

    st[lid] = 2;
    return cache[lid];
}

inline std::vector<Fp> dec_values(const PubKey& pk, const SecKey& sk, const Cipher& C, DecPolicy policy = DecPolicy::STANDARD) {
    if (!is_cipher_compatible_with_pubkey(pk, C))
        throw std::runtime_error("pvac: cipher/pubkey mismatch");
    if (policy != DecPolicy::NATIVE_LOCAL && dec_has_native_src(pk, C))
        throw std::runtime_error("pvac: native source decrypt rejected");
    size_t L = C.L.size();
    size_t S = C.slots;

    std::vector<std::vector<Fp>> cache(L);
    std::vector<uint8_t> st(L, 0);

    std::vector<std::vector<Fp>> Rinv(L);

    for (size_t lid = 0; lid < L; lid++) {
        auto R = layer_R_cached(pk, sk, C, (uint32_t)lid, st, cache, policy);
        Rinv[lid].resize(S);
        for (size_t j = 0; j < S; ++j)
            Rinv[lid][j] = fp_inv(R[j]);
    }

    auto acc = C.c0.empty() ? field::Op::zeros(S) : C.c0;

    for (const auto& e : C.E) {
        Fp gp = pk.powg_B[e.idx];
        int s = sgn_val(e.ch);

        for (size_t j = 0; j < S; ++j) {
            Fp term = fp_mul(fp_mul(e.w[j], gp), Rinv[e.layer_id][j]);
            acc[j] = s > 0 ? fp_add(acc[j], term) : fp_sub(acc[j], term);
        }
    }

    return acc;
}

inline Fp dec_value(const PubKey& pk, const SecKey& sk, const Cipher& C, DecPolicy policy = DecPolicy::STANDARD) {
    if (C.slots != 1)
        throw std::runtime_error("pvac: dec_value: cipher has multi-slot payload; use dec_values for vector decryption or dec_value_slot0 to explicitly coerce");
    return dec_values(pk, sk, C, policy)[0];
}

inline Fp dec_value_slot0(const PubKey& pk, const SecKey& sk, const Cipher& C, DecPolicy policy = DecPolicy::STANDARD) {
    auto v = dec_values(pk, sk, C, policy);
    if (v.empty())
        throw std::runtime_error("pvac: dec_value_slot0: cipher decrypts to empty value vector");
    return v[0];
}

inline Fp dec_value_native_local(const PubKey& pk, const SecKey& sk, const Cipher& C) {
    return dec_value(pk, sk, C, DecPolicy::NATIVE_LOCAL);
}

}