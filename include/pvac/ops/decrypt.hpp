#pragma once

#include <cstdint>
#include <vector>
#include <iostream>

#include "../core/types.hpp"
#include "../crypto/lpn.hpp"
#include "encrypt.hpp"

namespace pvac {

inline std::vector<Fp> layer_R_cached(
    const PubKey& pk,
    const SecKey& sk,
    const Cipher& C,
    uint32_t lid,
    std::vector<uint8_t>& st,
    std::vector<std::vector<Fp>>& cache
) {
    if ((size_t)lid >= C.L.size()) std::abort();

    if (st[lid] == 2) return cache[lid];

    if (st[lid] == 1) {
        std::cerr << "[R] cycle\n";
        std::abort();
    }

    st[lid] = 1;

    const Layer& L = C.L[lid];

    if (L.rule == RRule::BASE) {
        cache[lid] = prf_R_slots(pk, sk, L.seed, C.slots);
    } else {
        auto Ra = layer_R_cached(pk, sk, C, L.pa, st, cache);
        auto Rb = layer_R_cached(pk, sk, C, L.pb, st, cache);
        cache[lid] = field::Op::mul(Ra, Rb);
    }

    st[lid] = 2;
    return cache[lid];
}

inline std::vector<Fp> dec_values(const PubKey& pk, const SecKey& sk, const Cipher& C) {
    size_t L = C.L.size();
    size_t S = C.slots;

    std::vector<std::vector<Fp>> cache(L);
    std::vector<uint8_t> st(L, 0);

    std::vector<std::vector<Fp>> Rinv(L);

    for (size_t lid = 0; lid < L; lid++) {
        auto R = layer_R_cached(pk, sk, C, (uint32_t)lid, st, cache);
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

inline Fp dec_value(const PubKey& pk, const SecKey& sk, const Cipher& C) {
    return dec_values(pk, sk, C)[0];
}

}