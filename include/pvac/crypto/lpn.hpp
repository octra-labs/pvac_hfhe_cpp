#pragma once

#include <cstdint>
#include <cstring>
#include <vector>
#include <string>

#include "../core/types.hpp"
#include "../core/hash.hpp"
#include "toeplitz.hpp"
#include "../core/ct_safe.hpp"

#if defined(__AES__) && defined(__SSE2__)
#include <wmmintrin.h>
#include <emmintrin.h>
#define PVAC_USE_AESNI 1
#define PVAC_USE_ARM_AES 0
#elif defined(__aarch64__) && defined(__ARM_FEATURE_CRYPTO)
#include <arm_neon.h>
#define PVAC_USE_AESNI 0
#define PVAC_USE_ARM_AES 1
#elif defined(__aarch64__) && defined(__APPLE__)
#include <arm_neon.h>
#define PVAC_USE_AESNI 0
#define PVAC_USE_ARM_AES 1
#else
#define PVAC_USE_AESNI 0
#define PVAC_USE_ARM_AES 0
#endif

namespace pvac {

inline Fp hash_to_fp_nonzero(uint64_t lo, uint64_t hi) {
    Fp r = fp_from_words(lo, hi & MASK63);
    uint64_t orv = r.lo | r.hi;
    uint64_t mask_zero = ((orv | -orv) >> 63) ^ 1;
    mask_zero = 0u - mask_zero;

    Fp one = fp_from_u64(1);

    Fp out;
    out.lo = (r.lo & ~mask_zero) | (one.lo & mask_zero);
    out.hi = (r.hi & ~mask_zero) | (one.hi & mask_zero);
    return out;
}

#if PVAC_USE_AESNI

struct AesCtr256 {
    __m128i rk[15];
    __m128i ctr;
    alignas(16) uint64_t buf[2] = {0, 0};
    bool has_buf = false;

    static inline __m128i key_expand(__m128i k, __m128i t) {
        t = _mm_shuffle_epi32(t, 0xFF);
        k = _mm_xor_si128(k, _mm_slli_si128(k, 4));
        k = _mm_xor_si128(k, _mm_slli_si128(k, 4));
        k = _mm_xor_si128(k, _mm_slli_si128(k, 4));
        return _mm_xor_si128(k, t);
    }

    static inline __m128i key_expand2(__m128i k1, __m128i k2) {
        __m128i t = _mm_aeskeygenassist_si128(k2, 0);
        t = _mm_shuffle_epi32(t, 0xAA);
        k1 = _mm_xor_si128(k1, _mm_slli_si128(k1, 4));
        k1 = _mm_xor_si128(k1, _mm_slli_si128(k1, 4));
        k1 = _mm_xor_si128(k1, _mm_slli_si128(k1, 4));
        return _mm_xor_si128(k1, t);
    }

    void init(const uint8_t key[32], uint64_t nonce) {
        __m128i k0 = _mm_loadu_si128((const __m128i*)key);
        __m128i k1 = _mm_loadu_si128((const __m128i*)(key + 16));

        rk[0] = k0;
        rk[1] = k1;
        rk[2] = key_expand(k0, _mm_aeskeygenassist_si128(k1, 0x01)); k0 = rk[2];
        rk[3] = key_expand2(k1, k0); k1 = rk[3];
        rk[4] = key_expand(k0, _mm_aeskeygenassist_si128(k1, 0x02)); k0 = rk[4];
        rk[5] = key_expand2(k1, k0); k1 = rk[5];
        rk[6] = key_expand(k0, _mm_aeskeygenassist_si128(k1, 0x04)); k0 = rk[6];
        rk[7] = key_expand2(k1, k0); k1 = rk[7];
        rk[8] = key_expand(k0, _mm_aeskeygenassist_si128(k1, 0x08)); k0 = rk[8];
        rk[9] = key_expand2(k1, k0); k1 = rk[9];
        rk[10] = key_expand(k0, _mm_aeskeygenassist_si128(k1, 0x10)); k0 = rk[10];
        rk[11] = key_expand2(k1, k0); k1 = rk[11];
        rk[12] = key_expand(k0, _mm_aeskeygenassist_si128(k1, 0x20)); k0 = rk[12];
        rk[13] = key_expand2(k1, k0); k1 = rk[13];
        rk[14] = key_expand(k0, _mm_aeskeygenassist_si128(k1, 0x40));

        ctr = _mm_set_epi64x(0, (long long)nonce);
        has_buf = false;
    }

    inline __m128i encrypt_ctr() {
        __m128i t = _mm_xor_si128(ctr, rk[0]);
        t = _mm_aesenc_si128(t, rk[1]);
        t = _mm_aesenc_si128(t, rk[2]);
        t = _mm_aesenc_si128(t, rk[3]);
        t = _mm_aesenc_si128(t, rk[4]);
        t = _mm_aesenc_si128(t, rk[5]);
        t = _mm_aesenc_si128(t, rk[6]);
        t = _mm_aesenc_si128(t, rk[7]);
        t = _mm_aesenc_si128(t, rk[8]);
        t = _mm_aesenc_si128(t, rk[9]);
        t = _mm_aesenc_si128(t, rk[10]);
        t = _mm_aesenc_si128(t, rk[11]);
        t = _mm_aesenc_si128(t, rk[12]);
        t = _mm_aesenc_si128(t, rk[13]);
        t = _mm_aesenclast_si128(t, rk[14]);
        ctr = _mm_add_epi64(ctr, _mm_set_epi64x(0, 1));
        return t;
    }

    inline uint64_t next_u64() {
        if (has_buf) {
            has_buf = false;
            return buf[1];
        }
        __m128i ct = encrypt_ctr();
        _mm_store_si128((__m128i*)buf, ct);
        has_buf = true;
        return buf[0];
    }

    inline void fill_u64(uint64_t* out, size_t n) {
        size_t i = 0;
        if (has_buf && n > 0) {
            out[0] = buf[1];
            has_buf = false;
            i = 1;
        }
        alignas(16) uint64_t tmp[2];
        for (; i + 1 < n; i += 2) {
            __m128i ct = encrypt_ctr();
            _mm_store_si128((__m128i*)tmp, ct);
            out[i] = tmp[0];
            out[i + 1] = tmp[1];
        }
        if (i < n) {
            __m128i ct = encrypt_ctr();
            _mm_store_si128((__m128i*)buf, ct);
            out[i] = buf[0];
            has_buf = true;
        }
    }

    inline uint64_t bounded(uint64_t M) {
        if (M <= 1) return 0;
        uint64_t lim = UINT64_MAX - (UINT64_MAX % M);
        for (;;) {
            uint64_t x = next_u64();
            if (x < lim) return x % M;
        }
    }
};

#elif PVAC_USE_ARM_AES

struct AesCtr256 {
    uint8x16_t rk[15];
    uint64_t ctr_val;
    alignas(16) uint64_t buf[2] = {0, 0};
    bool has_buf = false;

    // Emulate x86 _mm_aesenc_si128 semantics:
    // ShiftRows → SubBytes → MixColumns → AddRoundKey
    // ARM vaeseq_u8(state, zero) = SubBytes → ShiftRows (commutes with ShiftRows→SubBytes)
    // then vaesmcq_u8 = MixColumns, then XOR round key
    static inline uint8x16_t aes_round(uint8x16_t state, uint8x16_t zero, uint8x16_t key) {
        return veorq_u8(vaesmcq_u8(vaeseq_u8(state, zero)), key);
    }

    // Emulate x86 _mm_aesenclast_si128 semantics:
    // ShiftRows → SubBytes → AddRoundKey  (no MixColumns)
    static inline uint8x16_t aes_round_last(uint8x16_t state, uint8x16_t zero, uint8x16_t final_key) {
        return veorq_u8(vaeseq_u8(state, zero), final_key);
    }

    static inline uint32_t sub_word(uint32_t w) {
        uint8x16_t zero = vdupq_n_u8(0);
        uint8x16_t v = vreinterpretq_u8_u32(vdupq_n_u32(w));
        v = vaeseq_u8(v, zero);
        return vgetq_lane_u32(vreinterpretq_u32_u8(v), 0);
    }

    static inline void key_expand_256(const uint8_t key[32], uint8x16_t rk_out[15]) {
        static const uint8_t rcon[] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40};
        uint32_t w[60];
        std::memcpy(w, key, 32);

        for (int i = 8; i < 60; ++i) {
            uint32_t t = w[i - 1];
            if (i % 8 == 0) {
                t = sub_word((t >> 8) | (t << 24)) ^ ((uint32_t)rcon[i / 8 - 1]);
            } else if (i % 8 == 4) {
                t = sub_word(t);
            }
            w[i] = w[i - 8] ^ t;
        }

        for (int i = 0; i < 15; ++i)
            rk_out[i] = vld1q_u8((const uint8_t*)(w + 4 * i));
    }

    void init(const uint8_t key[32], uint64_t nonce) {
        key_expand_256(key, rk);
        ctr_val = nonce;
        has_buf = false;
    }

    inline void encrypt_ctr_block(uint8_t out[16]) {
        alignas(16) uint64_t ctr_block[2] = {ctr_val, 0};
        uint8x16_t state = vld1q_u8((const uint8_t*)ctr_block);
        uint8x16_t zero = vdupq_n_u8(0);

        state = veorq_u8(state, rk[0]);
        state = aes_round(state, zero, rk[1]);
        state = aes_round(state, zero, rk[2]);
        state = aes_round(state, zero, rk[3]);
        state = aes_round(state, zero, rk[4]);
        state = aes_round(state, zero, rk[5]);
        state = aes_round(state, zero, rk[6]);
        state = aes_round(state, zero, rk[7]);
        state = aes_round(state, zero, rk[8]);
        state = aes_round(state, zero, rk[9]);
        state = aes_round(state, zero, rk[10]);
        state = aes_round(state, zero, rk[11]);
        state = aes_round(state, zero, rk[12]);
        state = aes_round(state, zero, rk[13]);
        state = aes_round_last(state, zero, rk[14]);

        vst1q_u8(out, state);
        ++ctr_val;
    }

    inline uint64_t next_u64() {
        if (has_buf) {
            has_buf = false;
            return buf[1];
        }
        alignas(16) uint8_t tmp[16];
        encrypt_ctr_block(tmp);
        std::memcpy(buf, tmp, 16);
        has_buf = true;
        return buf[0];
    }

    inline void fill_u64(uint64_t* out, size_t n) {
        size_t i = 0;
        if (has_buf && n > 0) {
            out[0] = buf[1];
            has_buf = false;
            i = 1;
        }
        alignas(16) uint8_t tmp[16];
        alignas(16) uint64_t pair[2];
        for (; i + 1 < n; i += 2) {
            encrypt_ctr_block(tmp);
            std::memcpy(pair, tmp, 16);
            out[i] = pair[0];
            out[i + 1] = pair[1];
        }
        if (i < n) {
            encrypt_ctr_block(tmp);
            std::memcpy(buf, tmp, 16);
            out[i] = buf[0];
            has_buf = true;
        }
    }

    inline uint64_t bounded(uint64_t M) {
        if (M <= 1) return 0;
        uint64_t lim = UINT64_MAX - (UINT64_MAX % M);
        for (;;) {
            uint64_t x = next_u64();
            if (x < lim) return x % M;
        }
    }
};

#else

#error "hfhe requires hardware AES support (x86_64 with -maes or aarch64 with crypto extensions)"

#endif

inline uint64_t fnv1a_domain(const char* dom) {
    uint64_t h = 0xcbf29ce484222325ull;
    for (const char* p = dom; *p; ++p) {
        h ^= (uint64_t)(uint8_t)*p;
        h *= 0x100000001b3ull;
    }
    return h;
}

inline void derive_aes_key(
    const PubKey& pk,
    const SecKey& sk,
    const RSeed& seed,
    const char* dom,
    uint8_t out_key[32],
    uint64_t& out_nonce
) {
    Sha256 h;
    h.init();

    for (auto x : sk.prf_k) sha256_acc_u64(h, x);
    sha256_acc_u64(h, pk.canon_tag);

    const uint8_t* d = pk.H_digest.data();
    h.update(d, 32);

    sha256_acc_u64(h, seed.ztag);
    sha256_acc_u64(h, seed.nonce.lo);
    sha256_acc_u64(h, seed.nonce.hi);

    uint64_t dom_hash = fnv1a_domain(dom);
    sha256_acc_u64(h, dom_hash);

    h.finish(out_key);
    out_nonce = dom_hash ^ seed.nonce.lo;
}

inline void lpn_make_ybits(
    const PubKey& pk,
    const SecKey& sk,
    const RSeed& seed,
    const char* dom,
    std::vector<uint64_t>& ybits
) {
    int t = pk.prm.lpn_t;
    int n = pk.prm.lpn_n;
    size_t s_words = ((size_t)n + 63) / 64;

    uint8_t aes_key[32];
    uint64_t nonce;
    derive_aes_key(pk, sk, seed, dom, aes_key, nonce);

    AesCtr256 prg;
    prg.init(aes_key, nonce);

    ybits.assign(((size_t)t + 63) / 64, 0ull);

    int num = pk.prm.lpn_tau_num;
    int den = pk.prm.lpn_tau_den;

    std::vector<uint64_t> row_buf(s_words);

    for (int r = 0; r < t; r++) {
        prg.fill_u64(row_buf.data(), s_words);

        uint64_t acc = 0;
        for (size_t wi = 0; wi < s_words; ++wi) {
            acc ^= row_buf[wi] & sk.lpn_s_bits[wi];
        }
        int dot = parity64(acc);

        int e = (prg.bounded((uint64_t)den) < (uint64_t)num) ? 1 : 0;
        int y = dot ^ e;

        ybits[r >> 6] ^= ((uint64_t)y) << (r & 63);
    }
}

inline Fp prf_R_core(
    const PubKey& pk,
    const SecKey& sk,
    const RSeed& seed,
    const char* dom
) {
    std::vector<uint64_t> ybits;
    lpn_make_ybits(pk, sk, seed, dom, ybits);

    uint8_t toep_key[32];
    uint64_t toep_nonce;
    derive_aes_key(pk, sk, seed, Dom::TOEP, toep_key, toep_nonce);
    toep_nonce ^= fnv1a_domain(dom);

    AesCtr256 prg;
    prg.init(toep_key, toep_nonce);

    size_t top_words = ((size_t)pk.prm.lpn_t + 127u + 63u) / 64u;
    std::vector<uint64_t> top(top_words);
    prg.fill_u64(top.data(), top_words);

    uint64_t lo = 0;
    uint64_t hi = 0;
    toep_127(top, ybits, lo, hi);

    return hash_to_fp_nonzero(lo, hi);
}

inline Fp prf_R(const PubKey& pk, const SecKey& sk, const RSeed& seed) {
    Fp r1 = prf_R_core(pk, sk, seed, Dom::PRF_R1);
    Fp r2 = prf_R_core(pk, sk, seed, Dom::PRF_R2);
    Fp r3 = prf_R_core(pk, sk, seed, Dom::PRF_R3);
    return fp_mul(fp_mul(r1, r2), r3);
}

inline Fp prf_R_noise(const PubKey& pk, const SecKey& sk, const RSeed& seed) {
    Fp r1 = prf_R_core(pk, sk, seed, Dom::PRF_NOISE1);
    Fp r2 = prf_R_core(pk, sk, seed, Dom::PRF_NOISE2);
    Fp r3 = prf_R_core(pk, sk, seed, Dom::PRF_NOISE3);
    return fp_mul(fp_mul(r1, r2), r3);
}

}