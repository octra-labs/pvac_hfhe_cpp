#pragma once

#include <cstdint>
#include <cstring>

#include "types.hpp"
#include "../crypto/lpn.hpp"

namespace pvac {

struct SeedableRng {
    AesCtr256 prg;

    void init(const uint8_t seed[32]) {
        prg.init(seed, 0);
    }

    uint64_t u64() { return prg.next_u64(); }

    uint64_t bounded(uint64_t M) { return prg.bounded(M); }

    Fp fp_nonzero() {
        for (;;) {
            uint64_t lo = u64();
            uint64_t hi = u64() & MASK63;
            Fp x = fp_from_words(lo, hi);
            if (x.lo || x.hi) return x;
        }
    }

    Nonce128 nonce128() { return {u64(), u64()}; }
};

inline SeedableRng make_seeded_rng(const uint8_t seed[32]) {
    SeedableRng rng;
    rng.init(seed);
    return rng;
}

}