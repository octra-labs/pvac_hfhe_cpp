#pragma once

#include <cstdint>
#include <vector>
#include <algorithm>

namespace pvac {

struct BitVec {
    size_t nbits;
    std::vector<uint64_t> w;

    static BitVec make(size_t n) {
        BitVec v;
        v.nbits = n;
        v.w.assign((n + 63) / 64, 0);
        return v;
    }

    void xor_with(const BitVec & b) {
        size_t L = std::min(w.size(), b.w.size());
        for (size_t i = 0; i < L; i++) {
            w[i] ^= b.w[i];
        }
    }

    size_t popcnt() const {
        auto pc = [](uint64_t x) {
            return (uint32_t)__builtin_popcountll(x);
        };

        size_t s = 0;
        for (uint64_t t : w) {
            s += (size_t)pc(t);
        }
        return s;
    }
};

inline int parity64(uint64_t x) {
    return (__builtin_popcountll(x) & 1);
}

}