#pragma once

#include <cstdint>
#include <vector>
#include <iostream>

#include "../core/types.hpp"
#include "matrix.hpp"

namespace pvac {

inline std::vector<int> factor_small(int n) {
    std::vector<int> p;
    int              x = n;

    for (int d = 2; d * (long long)d <= x; ++d) {
        if (x % d == 0) {
            p.push_back(d);

            while (x % d == 0) {
                x /= d;
            }
        }
    }

    if (x > 1) {
        p.push_back(x);
    }

    return p;

}

inline void keygen(const Params & prm, PubKey & pk, SecKey & sk) {
    pk.prm = prm;

    u128 pm1 = (((u128)1) << 127) - 2;

    if ((pm1 % (u128)pk.prm.B) != 0) {
        std::cerr << "[keygen] B|(p-1) fail\n";
        
        std::abort();
    }

    pk.canon_tag = csprng_u64();

    gen_H(pk);

    pk.ubk = gen_ubk_public(pk.canon_tag, pk.prm.m_bits);

    for (int i = 0; i < 4; i++) {
        sk.prf_k[i] = csprng_u64();
    }

    u128 E = pm1 / (u128)pk.prm.B;

    auto rand_fp = [&]() {
        for (;;) {
            Fp x = fp_from_words(csprng_u64(), csprng_u64() & MASK63);

            if (x.lo || x.hi) {
                return x;
            }
        }
    };

    Fp g;

    for (;;) {
        Fp   h    = rand_fp();
        Fp   base = h;
        Fp   acc  = fp_from_u64(1);
        u128 e    = E;

        while (e) {
            if (e & 1) {
                acc = fp_mul(acc, base);
            }

            base = fp_mul(base, base);
            e >>= 1;
        }

        if (!(acc.lo == 1 && acc.hi == 0)) {
            g = acc;
            break;
        }
    }

    pk.powg_B.assign(pk.prm.B, fp_from_u64(0));
    pk.powg_B[0] = fp_from_u64(1);

    for (int i = 1; i < pk.prm.B; i++) {
        pk.powg_B[i] = fp_mul(pk.powg_B[i - 1], g);
    }

    auto primes = factor_small(pk.prm.B);

    for (;;) {
        Fp h = rand_fp();
        Fp w = fp_pow_u64(h, (uint64_t)(pm1 / (u128)pk.prm.B));

        if (w.lo == 1 && w.hi == 0) {
            continue;
        }

        bool ok = true;

        for (int p : primes) {
            Fp t = fp_pow_u64(w, (uint64_t)(pk.prm.B / p));

            if (t.lo == 1 && t.hi == 0) {
                ok = false;
                break;
            }
        }

        if (ok) {
            pk.omega_B = w;
            break;
        }
    }

    size_t s_words = (pk.prm.lpn_n + 63) / 64;
    sk.lpn_s_bits.resize(s_words);

    for (size_t i = 0; i < s_words; i++) {
        sk.lpn_s_bits[i] = csprng_u64();
    }

    if (pk.prm.lpn_n & 63) {
        uint64_t m = (pk.prm.lpn_n & 63);
        uint64_t mask = (m == 64) ? ~0ull : ((1ull << m) - 1ull);
        sk.lpn_s_bits.back() &= mask;
    }
}

}