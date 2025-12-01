#pragma once

#include <cstdint>
#include <fstream>
#include <iomanip>

#include "../core/types.hpp"
#include "../ops/encrypt.hpp"

namespace pvac {

inline void dump_metrics(
    const PubKey & pk,
    const char * tag,
    const Cipher & C,
    const Fp & val
) {
    static bool inited = false;
    static std::ofstream f;

    if (!inited) {
        f.open("pvac_metrics.csv", std::ios::app);

        if (!f) {
            return;
        }

        f << "tag,edges,layers,sigma_density,value_lo,value_hi\n";
        inited = true;
    }

    double dens = sigma_density(pk, C);

    f << tag << ","
      << C.E.size() << ","
      << C.L.size() << ","
      << std::fixed << std::setprecision(6) << dens << ","
      << val.lo << ","
      << val.hi << "\n";
}

inline Fp agg_layer_gsum(const PubKey & pk, const Cipher & X, uint32_t lid) {
    Fp s = fp_from_u64(0);

    for (const auto & e : X.E) {
        if (e.layer_id == lid) {
            Fp term = fp_mul(e.w, pk.powg_B[e.idx]);

            if (e.ch == SGN_P) {
                s = fp_add(s, term);
            } else {
                s = fp_sub(s, term);
            }
        }
    }

    return s;
}

inline bool check_mul_gsum_all(
    const PubKey & pk,
    const Cipher & A,
    const Cipher & B,
    const Cipher & C
) {

    uint32_t base_count = (uint32_t)A.L.size() + (uint32_t)B.L.size();

    for (uint32_t la = 0; la < (uint32_t)A.L.size(); ++la) {
        for (uint32_t lb = 0; lb < (uint32_t)B.L.size(); ++lb) 
        {
            uint32_t lc = base_count + la * (uint32_t)B.L.size() + lb;

            Fp aa = agg_layer_gsum(pk, A, la);
            Fp bb = agg_layer_gsum(pk, B, lb);
            Fp cc = agg_layer_gsum(pk, C, lc);

            if (!fp_eq(cc, fp_mul(aa, bb))) {
                return false;
            }
        }
    }

    return true;
}

}