#pragma once

#include <cstdint>
#include <cstdlib>
#include <algorithm>

#if !defined(__SIZEOF_INT128__) && !(defined(_MSC_VER) && defined(__clang__))
#error "Needs unsigned __int128"
#endif

namespace pvac {

using u128 = unsigned __int128;

static constexpr uint64_t MASK63 = 0x7FFFFFFFFFFFFFFFULL;

struct Fp {
    uint64_t lo;
    uint64_t hi;
};

inline Fp fp_from_u64(uint64_t x) {
    return Fp{x, 0};
}

inline Fp fp_from_words(uint64_t lo, uint64_t hi) {
    uint64_t extra = hi >> 63;
    hi &= MASK63;

    u128 t = (u128)lo + (u128)extra;
    lo = (uint64_t)t;
    hi += (uint64_t)(t >> 64);

    uint64_t lo2 = lo;
    uint64_t hi2 = hi;
    uint64_t old_lo = lo2;

    lo2 -= UINT64_MAX;
    uint64_t br = (old_lo < UINT64_MAX);
    hi2 = hi2 - MASK63 - br;

    bool need_sub = (hi >> 63) || ((hi == MASK63) && (lo == UINT64_MAX));

    if (need_sub) {
        return Fp{lo2, hi2};
    }
    return Fp{lo, hi};
}

inline Fp fp_add(const Fp& a, const Fp& b) {
    u128 t0 = (u128)a.lo + (u128)b.lo;
    uint64_t lo = (uint64_t)t0;
    u128 t1 = (u128)a.hi + (u128)b.hi + (uint64_t)(t0 >> 64);

    return fp_from_words(lo, (uint64_t)t1);
}

inline Fp fp_neg(const Fp& a) {
    u128 Plo = (u128)UINT64_MAX;
    u128 Phi = (u128)MASK63;

    u128 t0 = Plo - a.lo;
    uint64_t lo = (uint64_t)t0;
    u128 t1 = Phi - a.hi - (uint64_t)(t0 >> 64);

    return fp_from_words(lo, (uint64_t)t1);
}

inline Fp fp_sub(const Fp& a, const Fp& b) {
    return fp_add(a, fp_neg(b));
}

#if defined(_MSC_VER) && !defined(__clang__)

inline void mul128x128(uint64_t a0, uint64_t a1, uint64_t b0, uint64_t b1,
                       uint64_t& z0, uint64_t& z1, uint64_t& z2, uint64_t& z3) {
    uint64_t h00, h01, h10, h11;

    z0 = _umul128(a0, b0, &h00);

    uint64_t l01 = _umul128(a0, b1, &h01);
    uint64_t l10 = _umul128(a1, b0, &h10);
    uint64_t l11 = _umul128(a1, b1, &h11);

    uint64_t t1 = h00;
    uint64_t c = 0;
    uint64_t s = t1 + l01;

    c += (s < t1);
    t1 = s;
    s = t1 + l10;
    c += (s < t1);
    z1 = s;

    uint64_t t2 = h01;
    uint64_t c2 = 0;

    s = t2 + h10;
    c2 += (s < t2);
    t2 = s;
    s = t2 + l11;
    c2 += (s < t2);
    t2 = s;
    s = t2 + c;
    c2 += (s < t2);

    z2 = s;
    z3 = h11 + c2;
}

#elif defined(__x86_64__) && defined(__GNUC__) && !defined(_MSC_VER)

inline void mul128x128(uint64_t a0, uint64_t a1, uint64_t b0, uint64_t b1,
                       uint64_t& z0, uint64_t& z1, uint64_t& z2, uint64_t& z3) {
    uint64_t p00_lo, p00_hi;
    uint64_t p01_lo, p01_hi;
    uint64_t p10_lo, p10_hi;
    uint64_t p11_lo, p11_hi;

    __asm__ volatile(
        "movq %[a0], %%rax\n\t"
        "mulq %[b0]\n\t"
        "movq %%rax, %[p00_lo]\n\t"
        "movq %%rdx, %[p00_hi]\n\t"
        "movq %[a0], %%rax\n\t"
        "mulq %[b1]\n\t"
        "movq %%rax, %[p01_lo]\n\t"
        "movq %%rdx, %[p01_hi]\n\t"
        "movq %[a1], %%rax\n\t"
        "mulq %[b0]\n\t"
        "movq %%rax, %[p10_lo]\n\t"
        "movq %%rdx, %[p10_hi]\n\t"
        "movq %[a1], %%rax\n\t"
        "mulq %[b1]\n\t"
        "movq %%rax, %[p11_lo]\n\t"
        "movq %%rdx, %[p11_hi]\n\t"
        : [p00_lo]"=&r"(p00_lo), [p00_hi]"=&r"(p00_hi),
          [p01_lo]"=&r"(p01_lo), [p01_hi]"=&r"(p01_hi),
          [p10_lo]"=&r"(p10_lo), [p10_hi]"=&r"(p10_hi),
          [p11_lo]"=&r"(p11_lo), [p11_hi]"=&r"(p11_hi)
        : [a0]"r"(a0), [a1]"r"(a1), [b0]"r"(b0), [b1]"r"(b1)
        : "rax", "rdx", "cc"
    );

    z0 = p00_lo;

    u128 m1 = (u128)p00_hi + (u128)p01_lo + (u128)p10_lo;
    z1 = (uint64_t)m1;

    u128 m2 = (u128)p01_hi + (u128)p10_hi + (u128)p11_lo + (m1 >> 64);
    z2 = (uint64_t)m2;

    z3 = p11_hi + (uint64_t)(m2 >> 64);
}

#else

inline void mul128x128(uint64_t a0, uint64_t a1, uint64_t b0, uint64_t b1,
                       uint64_t& z0, uint64_t& z1, uint64_t& z2, uint64_t& z3) {
    u128 c0 = (u128)a0 * (u128)b0;
    u128 c1 = (u128)a0 * (u128)b1;
    u128 c2 = (u128)a1 * (u128)b0;
    u128 c3 = (u128)a1 * (u128)b1;

    z0 = (uint64_t)c0;

    u128 t = (c0 >> 64) + (u128)(uint64_t)c1 + (u128)(uint64_t)c2;
    z1 = (uint64_t)t;

    u128 t2 = (c1 >> 64) + (c2 >> 64) + (u128)(uint64_t)c3 + (t >> 64);
    z2 = (uint64_t)t2;

    u128 t3 = (c3 >> 64) + (t2 >> 64);
    z3 = (uint64_t)t3;
}

#endif

inline Fp fp_reduce256(uint64_t z0, uint64_t z1, uint64_t z2, uint64_t z3) {
    uint64_t L0 = z0;
    uint64_t L1 = z1 & MASK63;

    uint64_t H0 = (z1 >> 63) | (z2 << 1);
    uint64_t H1 = (z2 >> 63) | (z3 << 1);
    uint64_t H2 = (z3 >> 63);

    u128 t0 = (u128)L0 + (u128)H0;
    uint64_t x0 = (uint64_t)t0;
    uint64_t c0 = (uint64_t)(t0 >> 64);

    u128 t1 = (u128)L1 + (u128)H1 + (u128)c0;
    uint64_t x1 = (uint64_t)t1;
    uint64_t c1 = (uint64_t)(t1 >> 64);

    uint64_t x2 = H2 + c1;

    uint64_t YL0 = x0;
    uint64_t YL1 = x1 & MASK63;
    uint64_t YH0 = (x1 >> 63) | (x2 << 1);

    u128 s0 = (u128)YL0 + (u128)YH0;
    uint64_t y0 = (uint64_t)s0;
    uint64_t cy = (uint64_t)(s0 >> 64);
    uint64_t y1 = YL1 + cy;

    return fp_from_words(y0, y1);
}

inline Fp fp_mul(const Fp& a, const Fp& b) {
    uint64_t z0, z1, z2, z3;
    mul128x128(a.lo, a.hi, b.lo, b.hi, z0, z1, z2, z3);
    return fp_reduce256(z0, z1, z2, z3);
}

inline Fp fp_pow_u64(Fp a, uint64_t e) {
    Fp r = fp_from_u64(1);

    while (e) {
        if (e & 1) {
            r = fp_mul(r, a);
        }
        a = fp_mul(a, a);
        e >>= 1;
    }

    return r;
}

inline Fp fp_inv_ct(const Fp& a) {
    constexpr int W = 5;
    constexpr int T = 1 << W;

    Fp tbl[T];
    tbl[0] = fp_from_u64(1);
    tbl[1] = a;

    for (int i = 2; i < T; i++) {
        tbl[i] = fp_mul(tbl[i - 1], a);
    }

    u128 e = (((u128)1) << 127) - 3;
    Fp r = fp_from_u64(1);
    int pos = 126;

    while (pos >= 0) {
        if (((e >> pos) & 1) == 0) {
            r = fp_mul(r, r);
            pos--;
            continue;
        }

        int l = std::max(0, pos - W + 1);
        int k = (int)((e >> l) & ((((u128)1) << (pos - l + 1)) - 1));

        while (k >= (1 << W)) {
            k >>= 1;
            l++;
        }

        for (int i = 0; i < pos - l + 1; i++) {
            r = fp_mul(r, r);
        }

        r = fp_mul(r, tbl[k]);
        pos = l - 1;
    }

    return r;
}

inline Fp fp_inv(const Fp& a) {
    return fp_inv_ct(a);
}

}