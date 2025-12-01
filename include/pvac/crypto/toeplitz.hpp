#pragma once

#include <cstdint>
#include <vector>
#include <chrono>
#include <iostream>

#include "../core/config.hpp"
#include "../core/random.hpp"

#if defined(__PCLMUL__)
    #include <wmmintrin.h>
    #include <emmintrin.h>
#endif

#if defined(__aarch64__)
    #include <arm_neon.h>
#endif

namespace pvac {

inline void gf2_conv_scalar(
     const std::vector<uint64_t> & A,
      const std::vector<uint64_t> & B,
    std::vector<uint64_t> & R
) {
    size_t Wa = A.size();
     size_t Wb = B.size();
 
    R.assign(Wa + Wb, 0ull);

    for (size_t i = 0; i < Wa; i++) {
        uint64_t a = A[i];

        while (a) {
            uint64_t bmask = a & -a;
            int      k     = __builtin_ctzll(a);

            for (size_t j = 0; j < Wb; j++) {
                uint64_t b = B[j];

                if (k == 0) {
                    R[i + j] ^= b;
                 } else {
                    R[i + j] ^= (b << k);
                    R[i + j + 1] ^= (b >> (64 - k));
                }
            }

            a ^= bmask;
        }
    }
}

#if defined(__PCLMUL__)

inline void gf2_conv_clmul(
    const std::vector<uint64_t> & A,
    const std::vector<uint64_t> & B,
        std::vector<uint64_t> & R
) {
    size_t Wa = A.size();
    size_t Wb = B.size();

    R.assign(Wa + Wb, 0ull);

    for (size_t i = 0; i < Wa; i++) {
        uint64_t a = A[i];

        if (!a) {
            continue;
        }

        __m128i va = _mm_set_epi64x(0, (long long)a);

        for (size_t j = 0; j < Wb; j++) {
            uint64_t b = B[j];

            if (!b) {
                continue;
            }

            __m128i vb = _mm_set_epi64x(0, (long long)b);
            __m128i p  = _mm_clmulepi64_si128(va, vb, 0x00);

            uint64_t lo = (uint64_t)_mm_cvtsi128_si64(p);
            uint64_t hi = (uint64_t)_mm_cvtsi128_si64(_mm_srli_si128(p, 8));

            R[i + j]     ^= lo;
            R[i + j + 1] ^= hi;
        }
    }
}

#endif

#if defined(__aarch64__) && defined(__ARM_FEATURE_CRYPTO)

inline void gf2_conv_pmull(
    const std::vector<uint64_t> & A,
        const std::vector<uint64_t> & B,
    std::vector<uint64_t> &       R
) {
    size_t Wa = A.size();
    size_t Wb = B.size();

    R.assign(Wa + Wb, 0ull);

      for (size_t i = 0; i < Wa; i++) {
        uint64_t a = A[i];

        if (!a) {
            continue;
        }

        poly64_t pa = (poly64_t)a;

        for (size_t j = 0; j < Wb; j++) {
            uint64_t b = B[j];

            if (!b) {
                continue;
            }

            poly64_t  pb = (poly64_t)b;
            poly128_t p  = vmull_p64(pa, pb);
            uint64x2_t u = vreinterpretq_u64_p128(p);

            uint64_t lo = vgetq_lane_u64(u, 0);
            uint64_t hi = vgetq_lane_u64(u, 1);

            R[i + j]     ^= lo;
            R[i + j + 1] ^= hi;
        }
    }
}

#endif

inline void toep_127_scalar(
    const std::vector<uint64_t> & top,
    const std::vector<uint64_t> & ybits,
    uint64_t & out_lo,
    uint64_t & out_hi
) {
        std::vector<uint64_t> R;
    gf2_conv_scalar(ybits, top, R);

    out_lo = 0;
     out_hi = 0;

    for (int j = 0; j < 127; j++) {
        size_t   wi  = j >> 6;
        int      sh  = j & 63;
        uint64_t bit = (R[wi] >> sh) & 1ull;

        if (j < 64) {
            out_lo |= bit << j;
        } else {
            out_hi |= bit << (j - 64);
        }
    }
}

#if defined(__PCLMUL__)

inline void toep_127_clmul(
    const std::vector<uint64_t> & top,
    const std::vector<uint64_t> & ybits,
    uint64_t & out_lo,
    uint64_t & out_hi
) {
    std::vector<uint64_t> R;
    gf2_conv_clmul(ybits, top, R);

    out_lo = 0;

    out_hi = 0;

    for (int j = 0; j < 127; j++) {
        size_t   wi  = j >> 6;
        int sh  = j & 63;
        uint64_t bit = (R[wi] >> sh) & 1ull;

        if (j < 64) {
            out_lo |= bit << j;
        } else {
            out_hi |= bit << (j - 64);
        }
    }
}


#endif

#if defined(__aarch64__) && defined(__ARM_FEATURE_CRYPTO)

inline void toep_127_pmull(
    const std::vector<uint64_t> & top,
    const std::vector<uint64_t> & ybits,
    uint64_t &               out_lo,
    uint64_t &               out_hi
) {
    std::vector<uint64_t> R;
    gf2_conv_pmull(ybits, top, R);

    out_lo = 0;
    out_hi = 0;

    for (int j = 0; j < 127; j++) {
        size_t wi  = j >> 6;
        int sh  = j & 63;
        uint64_t bit = (R[wi] >> sh) & 1ull;




        // todo 


        if (j < 64) {
            out_lo |= bit << j;
        } else {
            out_hi |= bit << (j - 64);
        }
    }
}

#endif

using toep_fn = void (*)(
    const std::vector<uint64_t> &,
    const std::vector<uint64_t> &,
    uint64_t &,
    uint64_t &
);

inline toep_fn g_toep    = nullptr;
inline int g_toep_id = 0;

inline void select_toeplitz() {
    std::vector<toep_fn> cands;
    std::vector<int> ids;

#if defined(__PCLMUL__)
    cands.push_back(&toep_127_clmul);
    ids.push_back(1);
#endif

#if defined(__aarch64__) && defined(__ARM_FEATURE_CRYPTO)
    cands.push_back(&toep_127_pmull);
    ids.push_back(2);
#endif

    cands.push_back(&toep_127_scalar);
    ids.push_back(3);

    auto bench = [&](toep_fn fn) -> double {
        using namespace std::chrono;

        std::vector<uint64_t> top(4096 / 64 + 4);
        std::vector<uint64_t> y(4096 / 64 + 1);

        for (auto & q : top) {
            q = csprng_u64();
        }

        for (auto & q : y) {
          q = csprng_u64();
        }

        uint64_t lo = 0;
        uint64_t hi = 0;

        auto t0 = high_resolution_clock::now();

        for (int r = 0; r < 64; r++) {
            fn(top, y, lo, hi);
        }

        auto t1 = high_resolution_clock::now();

        return duration<double, std::micro>(t1 - t0).count();
    };

    double  best   = 1e300;
    toep_fn bestfn = nullptr;
    int     bestid = 0;

    for (size_t i = 0; i < cands.size(); ++i) {
        double t = bench(cands[i]);

        if (t < best) {
            best   = t;
            bestfn = cands[i];
            bestid = ids[i];
        }
    }

    g_toep    = bestfn;
    g_toep_id = bestid;

    if (g_dbg) {
        if (g_toep_id == 1) {
            std::cout << "impl = pclmul t_us = " << best << "\n";
        } else if (g_toep_id == 2) {
            std::cout << "impl = pmull t_us = " << best << "\n";
        } else {
            std::cout << "impl = scalar t_us = " << best << "\n";
        }
    }
}

inline void toep_127(
    const std::vector<uint64_t> & top,
    const std::vector<uint64_t> & ybits,
    uint64_t & out_lo,
    uint64_t & out_hi
) {
    if (!g_toep) {
        select_toeplitz();
    }

    g_toep(top, ybits, out_lo, out_hi);
}

}