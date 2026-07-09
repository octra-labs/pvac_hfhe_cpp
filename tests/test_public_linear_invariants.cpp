#include <pvac/pvac.hpp>

#include <iostream>
#include <stdexcept>
#include <vector>

using namespace pvac;

static void must(bool ok, const char * msg) {
    if (!ok)
        throw std::runtime_error(msg);
}

static int parity(const BitVec& v) {
    int out = 0;
    for (uint64_t x : v.w)
        out ^= (__builtin_popcountll(x) & 1);
    return out;
}

static int top_bit(const BitVec& v) {
    for (int i = (int)v.w.size() - 1; i >= 0; --i) {
        uint64_t x = v.w[(size_t)i];
        if (x)
            return i * 64 + 63 - __builtin_clzll(x);
    }
    return -1;
}

static int gf2_rank(const std::vector<BitVec>& cols, size_t bits) {
    std::vector<BitVec> basis(bits);
    std::vector<uint8_t> used(bits, 0);
    int rank = 0;

    for (const auto& col : cols) {
        BitVec x = col;
        for (;;) {
            int p = top_bit(x);
            if (p < 0)
                break;
            if (!used[(size_t)p]) {
                basis[(size_t)p] = x;
                used[(size_t)p] = 1;
                ++rank;
                break;
            }
            x.xor_with(basis[(size_t)p]);
        }
    }

    return rank;
}

int main() {
    try {
        Params prm;
        prm.m_bits = 256;
        prm.n_bits = 512;
        prm.h_col_wt = 32;
        prm.x_col_wt = 32;
        prm.err_wt = 32;

        PubKey pk;
        pk.prm = prm;
        pk.canon_tag = 0x6f637472615f6c69ull;
        gen_H(pk);

        int even_h = 0;
        int odd_h = 0;
        for (const auto& col : pk.H) {
            if (parity(col))
                ++odd_h;
            else
                ++even_h;
        }

        bool even_sigma = false;
        bool odd_sigma = false;
        for (uint64_t i = 0; i < 128; ++i) {
            Nonce128 nonce{0x1000 + i, 0x2000 + i * 17};
            auto s = sigma_from_H(pk, 0x3000 + i, nonce, (uint16_t)i, (uint8_t)(i & 1), i * 257);
            if (parity(s))
                odd_sigma = true;
            else
                even_sigma = true;
        }

        int rank = gf2_rank(pk.H, (size_t)prm.m_bits);

        std::cout << "h_mixed_parity = " << (even_h > 0 && odd_h > 0) << "\n";
        std::cout << "sigma_mixed_parity = " << (even_sigma && odd_sigma) << "\n";
        std::cout << "h_rank_full = " << (rank == prm.m_bits) << "\n";

        must(even_h > 0 && odd_h > 0, "public H parity invariant");
        must(even_sigma && odd_sigma, "public sigma parity invariant");
        must(rank == prm.m_bits, "public H rank deficient");

        return 0;
    } catch (const std::exception& e) {
        std::cerr << "fail = " << e.what() << "\n";
        return 1;
    }
}