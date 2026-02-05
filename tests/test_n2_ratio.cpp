#include <pvac/pvac.hpp>
#include <iostream>
#include <vector>
#include <map>
#include <cstdint>
#include <random>

using namespace pvac;

struct FpKey {
    uint64_t lo, hi;
    bool operator<(const FpKey& o) const {
        return (hi != o.hi) ? (hi < o.hi) : (lo < o.lo);
    }
};

int main() {
    Params prm;
    PubKey pk;
    SecKey sk;
    keygen(prm, pk, sk);

    std::mt19937_64 rng(0xDEADBEEF);
    std::vector<uint64_t> vals(64);
    for (auto& v : vals) v = rng();
    Cipher ct = enc_values(pk, sk, vals);

    int total_max = 0;

    for (uint32_t lid = 0; lid < ct.L.size(); ++lid) {
        if (ct.L[lid].rule != RRule::BASE) continue;

        std::vector<size_t> ei;
        for (size_t i = 0; i < ct.E.size(); ++i)
            if (ct.E[i].layer_id == lid) ei.push_back(i);

        int n = (int)ei.size();
        if (n < 2) continue;

        std::map<FpKey, int> clusters;

        for (int i = 0; i < n; ++i) {
            for (int k = i + 1; k < n; ++k) {
                const Edge& ea = ct.E[ei[i]];
                const Edge& eb = ct.E[ei[k]];

                Fp x0 = fp_add(
                    field::Op::sgn(fp_mul(ea.w[0], pk.powg_B[ea.idx]), ea.ch),
                    field::Op::sgn(fp_mul(eb.w[0], pk.powg_B[eb.idx]), eb.ch)
                );

                if (x0.lo == 0 && x0.hi == 0) continue;

                Fp x1 = fp_add(
                    field::Op::sgn(fp_mul(ea.w[1], pk.powg_B[ea.idx]), ea.ch),
                    field::Op::sgn(fp_mul(eb.w[1], pk.powg_B[eb.idx]), eb.ch)
                );

                Fp rho = fp_mul(x1, fp_inv(x0));
                FpKey key{rho.lo, rho.hi};
                clusters[key]++;
            }
        }

        int mx = 0;
        for (const auto& [k, c] : clusters)
            if (c > mx) mx = c;

        std::cout << "layer " << lid
                  << " edges = " << n
                  << " pairs = " << (n * (n - 1) / 2)
                  << " max_cluster = " << mx << "\n";

        if (
            mx > total_max) total_max = mx;
    }

    std::cout << "total max_cluster = " << total_max << "\n";

    if (total_max > 1) {
        std::cout << "cluster detected\n";
        return 1;
    }

    std::cout << "PASS\n";
    return 0;
}