#pragma once

#include <cstdint>
#include <vector>
#include <array>

#include "field.hpp"
#include "bitvec.hpp"
#include "random.hpp"

namespace pvac {

namespace Dom {

    static constexpr const char * H_GEN    = "hf|h";
    static constexpr const char * X_SEED   = "hf|sx";

    static constexpr const char * NOISE    = "hf|sn";
    static constexpr const char * PRF_LPN  = "hf|pr";
    static constexpr const char * PRF_R1   = "hf|p1";

    static constexpr const char * PRF_R2   = "hf|p2";



    static constexpr const char * PRF_R3   = "hf|p3";
    static constexpr const char * TOEP     = "hf|tp";
    static constexpr const char * ZTAG     = "hf|zt";
    static constexpr const char * COMMIT   = "hf|cm";
}

struct Params {
    int    B                  = 127;
    int    m_bits             = 8192;
    int    n_bits             = 16384;
    
    
    
    
    
    int    h_col_wt           = 192;
    int    x_col_wt           = 128;
    
    int    err_wt             = 128;

    double noise_entropy_bits = 80.0;
    double tuple2_fraction    = 0.55;
    double depth_slope_bits   = 10.0;
    size_t edge_budget        = 800000;
    int    lpn_n              = 2048;

    int    lpn_t              = 4096;
    int    lpn_tau_num        = 1;
    int    lpn_tau_den        = 8;
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
    uint8_t  ch;
    Fp w;
    BitVec  s;
};

struct Cipher {
    std::vector<Layer> L;
    std::vector<Edge>  E;
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
        Fp       x  = fp_from_words(lo, hi);

        if (x.lo || x.hi) {
            return x;
        }
    }
}



}