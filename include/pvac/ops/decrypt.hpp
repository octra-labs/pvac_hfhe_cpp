#pragma once

#include <cstdint>
#include <vector>
#include <iostream>

#include "../core/types.hpp"
#include "../crypto/lpn.hpp"

namespace pvac {

inline Fp layer_R_cached(
    const PubKey & pk,
    const SecKey & sk,
    const Cipher & C,
    uint32_t lid,
    std::vector<int> & vis,
    std::vector<Fp> & cache

) {
    if ((size_t)lid >= C.L.size()) {

        std::abort();
    }

    if (cache[lid].lo | cache[lid].hi) 
    
    {
        return cache[lid];
    }

    if (vis[lid]) 
    {
       
        std::cerr << "[R] cycle\n";
        std::abort();
    }

    vis[lid] = 1;

    const Layer & L = C.L[lid];
    Fp R {};

    if (L.rule == RRule::BASE) {
        R = prf_R(pk, sk, L.seed);
    } else {

        Fp Ra = layer_R_cached(pk, sk, C, L.pa, vis, cache);


        // test here later ( rb)
        Fp Rb = layer_R_cached(pk, sk, C, L.pb, vis, cache);
        R = fp_mul(Ra, Rb);
    }

    vis[lid] = 0;
    cache[lid] = R;

    return R;
}

inline Fp dec_value(const PubKey & pk, const SecKey & sk, const Cipher & C) {
    size_t L = C.L.size();

    std::vector<Fp> cache(L, fp_from_u64(0));
    std::vector<int> vis(L, 0);

    std::vector<Fp> Rinv(L, fp_from_u64(0));

    for (size_t lid = 0; lid < L; lid++) {
         Fp R  = layer_R_cached(pk, sk, C, (uint32_t)lid, vis, cache);
        Rinv[lid] = fp_inv(R);
    }

    Fp acc = fp_from_u64(0);

    for (const auto & e : C.E) {
        Fp term = fp_mul(e.w, pk.powg_B[e.idx]);
        term = fp_mul(term, Rinv[e.layer_id]);

        if (e.ch == SGN_P) {
            acc = fp_add(acc, term);
        } else {
            acc = fp_sub(acc, term);
        }
    }

    return acc;
}


}