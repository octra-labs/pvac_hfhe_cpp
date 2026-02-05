#include <pvac/pvac.hpp>

#include <cstdint>
#include <random>
#include <cassert>
#include <iostream>

using namespace pvac;

static inline bool fp_is_zero(const Fp& x) {
    return x.lo == 0 && x.hi == 0;
}

static bool find_z2_struct(const PubKey& pk, const Cipher& C) {
    const auto& E = C.E;
    size_t n = E.size();

    for (size_t i = 0; i < n; ++i) {
        for (size_t j = i + 1; j < n; ++j) {
            const auto& e1 = E[i];
            const auto& e2 = E[j];

            if (e1.layer_id != e2.layer_id) continue;
            if (e1.idx == e2.idx) continue;

            int s1 = sgn_val(e1.ch);
            int s2 = sgn_val(e2.ch);

            Fp t1 = fp_mul(e1.w[0], pk.powg_B[e1.idx]);
            Fp t2 = fp_mul(e2.w[0], pk.powg_B[e2.idx]);

            if (s1 < 0) t1 = fp_neg(t1);
            if (s2 < 0) t2 = fp_neg(t2);

            Fp sum = fp_add(t1, t2);
            if (fp_is_zero(sum)) {
                return true;
            }
        }
    }
    return false;
}

static bool find_z3_struct(const PubKey& pk, const Cipher& C) {
    const auto& E = C.E;
    size_t n = E.size();

    for (size_t i = 0; i < n; ++i) {
        for (size_t j = i + 1; j < n; ++j) {
            for (size_t k = j + 1; k < n; ++k) {
                const auto& e1 = E[i];
                const auto& e2 = E[j];
                const auto& e3 = E[k];

                if (!(e1.layer_id == e2.layer_id && e2.layer_id == e3.layer_id)) continue;

                int s1 = sgn_val(e1.ch);
                int s2 = sgn_val(e2.ch);
                int s3 = sgn_val(e3.ch);

                Fp t1 = fp_mul(e1.w[0], pk.powg_B[e1.idx]);
                Fp t2 = fp_mul(e2.w[0], pk.powg_B[e2.idx]);
                Fp t3 = fp_mul(e3.w[0], pk.powg_B[e3.idx]);

                if (s1 < 0) t1 = fp_neg(t1);
                if (s2 < 0) t2 = fp_neg(t2);
                if (s3 < 0) t3 = fp_neg(t3);

                Fp sum = fp_add(fp_add(t1, t2), t3);
                if (fp_is_zero(sum)) {
                    return true;
                }
            }
        }
    }
    return false;
}

int main() {
    std::cout << "- noise struct test -\n";

    Params prm;
    PubKey pk;
    SecKey sk;
    keygen(prm, pk, sk);

    std::mt19937_64 rng(0x1234567890abcdefull);

    const int TRIALS = 1;

    for (int t = 0; t < TRIALS; ++t) {
        uint64_t m = (uint64_t)rng();
        Cipher C = enc_value(pk, sk, m);

        bool has_z2 = find_z2_struct(pk, C);
        bool has_z3 = find_z3_struct(pk, C);

        std::cout << "trial " << t
                  << " z2 = " << has_z2
                  << " z3 = " << has_z3 << "\n";

        assert(!has_z2);
        assert(!has_z3);
    }

    std::cout << "noise struct: ok\n";
    std::cout << "PASS\n";
    return 0;
}