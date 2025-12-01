#pragma once

#include <cstdint>
#include <vector>
#include <string>

#include "../core/types.hpp"
#include "../core/hash.hpp"
#include "toeplitz.hpp"

namespace pvac {


    // 128 bit to Fp (avoiding 0 and p-1 )
inline Fp hash_to_fp_nonzero(uint64_t lo, uint64_t hi) {
    Fp r = fp_from_words(lo, hi & MASK63);

    if (r.lo == 0 && r.hi == 0) {
        r = fp_from_u64(1);
    }

    if (r.lo == UINT64_MAX && r.hi == MASK63) {
        r = fp_from_u64(1);
    }

    return r;
}

//y[r] <random_row s> xor e noise rate = tau (!!  )
inline void lpn_make_ybits(
    const PubKey & pk,
    const SecKey & sk,
    const RSeed & seed,
    const char * dom,
    std::vector<uint64_t> & ybits
) {
    int  t= pk.prm.lpn_t;
    int n=pk.prm.lpn_n;
    size_t s_words = (n + 63) / 64;

    std::vector<uint64_t> key;
    key.reserve(sk.prf_k.size() + 4);

    for (auto x : sk.prf_k) {
        key.push_back(x);
    }

    key.push_back(pk.canon_tag);
    key.push_back(seed.ztag);
    
    key.push_back(seed.nonce.lo);
    key.push_back(seed.nonce.hi);

    XofShake xof;
    xof.init(std::string(dom), key);

    ybits.assign(((size_t)t + 63) / 64, 0ull);

    int num = pk.prm.lpn_tau_num;
    int den = pk.prm.lpn_tau_den;

    for (int r = 0; r < t; r++) {
        int dot = 0;

        for (size_t wi = 0; wi < s_words; ++wi) {
            uint64_t roww = xof.take_u64();
            dot ^= parity64(roww & sk.lpn_s_bits[wi]);
        }

        int e = (int)(xof.bounded(den) < (uint64_t)num);
        int y = dot ^ e;

        ybits[(size_t)r >> 6] ^= ((uint64_t)y) << (r & 63);
    }
}


//toeplitz compression (Fp)
inline Fp prf_R_core(
    const PubKey & pk,
    const SecKey & sk,
    const RSeed &  seed,
    const char *   dom
) {
    std::vector<uint64_t> ybits;
    lpn_make_ybits(pk, sk, seed, dom, ybits);

    std::vector<uint64_t> seed_words;
    seed_words.reserve(sk.prf_k.size() + 4);

    for (auto x : sk.prf_k) {
        seed_words.push_back(x);
    }

    seed_words.push_back(pk.canon_tag);
    seed_words.push_back(seed.ztag);
    seed_words.push_back(seed.nonce.lo);
    
    seed_words.push_back(seed.nonce.hi);


    XofShake xof;
    xof.init(std::string(Dom::TOEP), seed_words);

    size_t top_words = ((size_t)pk.prm.lpn_t + 127u + 63u) / 64u;

    for (int att = 0; att < 16; att++) {
        std::vector<uint64_t> top(top_words);

        for (size_t i = 0; i < top_words; i++) {
            top[i] = xof.take_u64();
        }

        uint64_t lo = 0;
        uint64_t hi = 0;

        toep_127(top, ybits, lo, hi);

        Fp r = hash_to_fp_nonzero(lo, hi);

        if (!(r.lo == 1 && r.hi == 0)) {
            return r;
        }
    }

    return fp_from_u64(1);
}



// eparated prf R = r1 * r2 * r3 ( aprrox 381 bit entropy) not for prod!
inline Fp prf_R(const PubKey & pk, const SecKey & sk, const RSeed & seed) {
    Fp r1 = prf_R_core(pk, sk, seed, Dom::PRF_R1);
    Fp r2 = prf_R_core(pk, sk, seed, Dom::PRF_R2);
    Fp r3 = prf_R_core(pk, sk, seed, Dom::PRF_R3);
    return fp_mul(fp_mul(r1, r2), r3);
}

}