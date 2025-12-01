#pragma once

#include <cstdint>


// 11/02/2025
// for octra env coomp need to use a different rescript with multi connection sup
    //it won't work otherwise

#include "../core/types.hpp"
#include "../crypto/matrix.hpp"
#include "encrypt.hpp"
#include "arithmetic.hpp"

namespace pvac {



inline EvalKey make_evalkey(
    const PubKey & pk,
    const SecKey & sk,
    size_t         zero_pool,
    int            depth_hint
) {
    EvalKey ek;

    ek.zero_pool.reserve(zero_pool);

    for (size_t i = 0; i < zero_pool; i++) {
        ek.zero_pool.push_back(enc_zero_depth(pk, sk, depth_hint));
    }

    ek.enc_one = enc_value(pk, sk, 1);

    return ek;
}

inline Cipher ct_recrypt(const PubKey & pk, const EvalKey & ek, const Cipher & C) {
    if (ek.zero_pool.empty()) {
        return C;
    }

    Cipher R = C;

    for (int it = 0; it < 4; it++) {
        double d = sigma_density(pk, R);

        if (d >= 0.47 && d <= 0.53) {
            break;
        }

        const Cipher & Z = ek.zero_pool[(size_t)(csprng_u64() % ek.zero_pool.size())];
        R = ct_add(pk, R, Z);

        ubk_apply(pk, R);
        guard_budget(pk, R, "recrypt");
    }

    compact_edges(pk, R);

    return R;
}

}