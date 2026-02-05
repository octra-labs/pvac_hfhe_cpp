#pragma once

#include <cstdint>
#include <fstream>
#include <iomanip>

#include "../core/types.hpp"
#include "../ops/encrypt.hpp"
#include "../core/ct_safe.hpp"

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

inline double sigma_shannon(const Cipher& C) {
    if (C.E.empty()) return 0.0;
    
    std::array<int, 256> freq{};
    int total = 0;
    
    for (const auto& e : C.E) {
        for (auto w : e.s.w) {
            for (int i = 0; i < 8; i++) {
                freq[(w >> (i * 8)) & 0xFF]++;
                total++;
            }
        }
    }
    
    if (total == 0) return 0.0;
    
    double H = 0.0;
    for (int i = 0; i < 256; i++) {
        if (freq[i] > 0) {
            double p = (double)freq[i] / total;
            H -= p * std::log2(p);
        }
    }
    return H; 
}

inline std::vector<Fp> agg_layer_gsum(const PubKey& pk, const Cipher& X, uint32_t lid) {
    auto s = field::Op::zeros(X.slots);

    for (const auto& e : X.E) {
        if (e.layer_id == lid) {
            Fp gp = pk.powg_B[e.idx];
            int sg = sgn_val(e.ch);
            for (size_t j = 0; j < X.slots; ++j) {
                Fp term = fp_mul(e.w[j], gp);
                s[j] = sg > 0 ? fp_add(s[j], term) : fp_sub(s[j], term);
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

            auto aa = agg_layer_gsum(pk, A, la);
            auto bb = agg_layer_gsum(pk, B, lb);
            auto cc = agg_layer_gsum(pk, C, lc);

            for (size_t j = 0; j < aa.size(); ++j) {
                if (!ct::fp_eq(cc[j], fp_mul(aa[j], bb[j])))
                    return false;
            }
        }
    }

    return true;
}

}