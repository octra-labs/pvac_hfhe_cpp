#pragma once

#include <cstdint>
#include <vector>
#include <array>

#include "field.hpp"
#include "bitvec.hpp"
#include "random.hpp"

namespace pvac {

// (separations) don't touch it at all 
namespace Dom {
    inline constexpr const char * H_GEN = "pv|h";
    inline constexpr const char * X_SEED = "pv|sx";
    inline constexpr const char * NOISE = "pv|sn";
    
    inline constexpr const char * PRF_LPN = "pv|pr";
    inline constexpr const char * TOEP = "pv|tp";

    inline constexpr const char * ZTAG = "pv|zt";
    inline constexpr const char * COMMIT = "pv|cm";

    inline constexpr const char * PRF_R1 = "pv|r1";
    inline constexpr const char * PRF_R2 = "pv|r2";
    inline constexpr const char * PRF_R3 = "pv|r3";
}


// all safety and dimensions are set, and can only be changed if there is an understanding of why
struct Params {

    // multiplicative group as a carrier of the properties
    // of homo and does not affect security, this is not a dlp
    int B = 337; 
    
    int m_bits = 8192;
    int n_bits = 16384;
    int h_col_wt = 192;
    int x_col_wt = 128;
    int err_wt = 128;

    double noise_entropy_bits = 120.0;
    double tuple2_fraction = 0.55;
    double depth_slope_bits = 16.0;
    size_t edge_budget = 1200000;

    // sec (tau = 1/8):
    // info theor bound: 2226 bits
    // classical: 200+ bits  
    // quantum: 100+ bits

    int lpn_n = 4096;
    int lpn_t = 16384;
    int lpn_tau_num = 1;
    int lpn_tau_den = 8;

    // didn't bother with hypothetical approaches and went 
    // with the absolute maximum in the settings and left it that way, 
    // which is good for security/speed, etc

    double recrypt_lo = 0.48;
    double recrypt_hi = 0.52;
    int recrypt_rounds = 8;
};

struct Nonce128 {
    uint64_t lo;
    uint64_t hi;
};

inline Nonce128 make_nonce128() {
    return Nonce128 { csprng_u64(), csprng_u64() };
}

struct Ubk {
    std::vector<int> perm;
    std::vector<int> inv;
};

struct RSeed {
    uint64_t ztag;
    Nonce128 nonce;
};

enum class RRule : uint8_t {
    BASE = 0,
    PROD = 1
};

struct Layer {
    RRule rule;
    RSeed seed;
    uint32_t pa;
    uint32_t pb;
};

enum EdgeSign : uint8_t {
    SGN_P = 0,
    SGN_M = 1
};

struct Edge {
    uint32_t layer_id;
    uint16_t idx;
    uint8_t ch;
    Fp w;
    BitVec  s;
};

struct Cipher {
    std::vector<Layer> L;
    std::vector<Edge> E;
};

struct PubKey {
    Params prm;
    uint64_t canon_tag;
    std::vector<BitVec> H;
    Ubk ubk;
    std::array<uint8_t, 32> H_digest;
    Fp omega_B;
    std::vector<Fp> powg_B;
};

struct SecKey {
    std::array<uint64_t, 4> prf_k;
    std::vector<uint64_t> lpn_s_bits;
};

struct EvalKey {
    std::vector<Cipher> zero_pool;
    Cipher enc_one;
};

inline int sgn_val(uint8_t ch) {
    return (ch == SGN_P) ? +1 : -1;
}

inline Fp rand_fp_nonzero() {
    for (;;) {
        uint64_t lo = csprng_u64();
        uint64_t hi = csprng_u64() & MASK63;
        Fp x  = fp_from_words(lo, hi);

        if (x.lo || x.hi) {
            return x;
        }
    }
}
}