#include <pvac/pvac.hpp>
#include <iostream>
#include <vector>
#include <cstdint>

using namespace pvac;

Fp sum_signed(const Fp& acc, const Edge& e) {
    return (sgn_val(e.ch) > 0) ? fp_add(acc, e.w[0]) : fp_sub(acc, e.w[0]);
}

bool next_comb(std::vector<int>& c, int n) {
    int k = (int)c.size();
    for (int i = k - 1; i >= 0; --i) {
        if (c[i] != i + n - k) {
            ++c[i];
            for (int j = i + 1; j < k; ++j)
                c[j] = c[j - 1] + 1;
            return true;
        }
    }
    return false;
}

int main() {
    std::cout << "- struct test -\n";

    Params prm;
    PubKey pk;
    SecKey sk;
    keygen(prm, pk, sk);

    Cipher ct = enc_value(pk, sk, 123456789);

    std::vector<Edge> E0;
    for (const auto& e : ct.E)
        if (e.layer_id == 0) E0.push_back(e);

    int n = (int)E0.size();
    std::cout << "layer0 edges = " << n << "\n";

    constexpr int k = 8;
    if (n < k || n > 30) {
        std::cout << "edge count out of range, skip\n";
        return 0;
    }

    std::vector<int> comb(k);
    for (int i = 0; i < k; ++i) comb[i] = i;

    uint64_t total = 0, zeros = 0;

    do {
        Fp acc = fp_from_u64(0);
        for (int t = 0; t < k; ++t)
            acc = sum_signed(acc, E0[comb[t]]);
        ++total;
        if (!ct::fp_is_nonzero(acc)) ++zeros;
    } while (next_comb(comb, n));

    std::cout << "C(" << n << "," << k << ") = " << total
              << ", zero-sum = " << zeros << "\n";

    if (zeros != 0) {
        std::cerr << "FAIL: regression #420\n";
        return 1;
    }

    std::cout << "PASS\n";
    return 0;
}