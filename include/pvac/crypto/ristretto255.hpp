#pragma once

#include <cstdint>
#include <cstring>
#include <array>
#include <stdexcept>
#include "../core/hash.hpp"
#include "../core/field.hpp"

namespace pvac {

struct Fe25519 {
    uint64_t v[5];
};

static constexpr uint64_t FE_MASK51 = (1ULL << 51) - 1;

inline Fe25519 fe_zero() { return {{0,0,0,0,0}}; }
inline Fe25519 fe_one()  { return {{1,0,0,0,0}}; }

inline Fe25519 fe_reduce(Fe25519 h) {
    uint64_t c;
    c = h.v[0] >> 51; h.v[1] += c; h.v[0] &= FE_MASK51;
    c = h.v[1] >> 51; h.v[2] += c; h.v[1] &= FE_MASK51;
    c = h.v[2] >> 51; h.v[3] += c; h.v[2] &= FE_MASK51;
    c = h.v[3] >> 51; h.v[4] += c; h.v[3] &= FE_MASK51;
    c = h.v[4] >> 51; h.v[0] += c * 19; h.v[4] &= FE_MASK51;

    c = h.v[0] >> 51; h.v[1] += c; h.v[0] &= FE_MASK51;
    return h;
}

inline Fe25519 fe_add(const Fe25519& f, const Fe25519& g) {
    Fe25519 h;
    for (int i = 0; i < 5; i++) h.v[i] = f.v[i] + g.v[i];
    return fe_reduce(h);
}

inline Fe25519 fe_sub(const Fe25519& f, const Fe25519& g) {

    Fe25519 h;
    h.v[0] = (f.v[0] + ((1ULL << 52) - 38)) - g.v[0];
    h.v[1] = (f.v[1] + ((1ULL << 52) - 2))  - g.v[1];
    h.v[2] = (f.v[2] + ((1ULL << 52) - 2))  - g.v[2];
    h.v[3] = (f.v[3] + ((1ULL << 52) - 2))  - g.v[3];
    h.v[4] = (f.v[4] + ((1ULL << 52) - 2))  - g.v[4];
    return fe_reduce(h);
}

inline Fe25519 fe_neg(const Fe25519& f) {
    return fe_sub(fe_zero(), f);
}

inline Fe25519 fe_mul(const Fe25519& f, const Fe25519& g) {
    u128 t[5];

    uint64_t g19_1 = 19 * g.v[1];
    uint64_t g19_2 = 19 * g.v[2];
    uint64_t g19_3 = 19 * g.v[3];
    uint64_t g19_4 = 19 * g.v[4];

    t[0] = (u128)f.v[0]*g.v[0] + (u128)f.v[1]*g19_4 + (u128)f.v[2]*g19_3 +
            (u128)f.v[3]*g19_2 + (u128)f.v[4]*g19_1;
    t[1] = (u128)f.v[0]*g.v[1] + (u128)f.v[1]*g.v[0] + (u128)f.v[2]*g19_4 +
            (u128)f.v[3]*g19_3 + (u128)f.v[4]*g19_2;
    t[2] = (u128)f.v[0]*g.v[2] + (u128)f.v[1]*g.v[1] + (u128)f.v[2]*g.v[0] +
            (u128)f.v[3]*g19_4 + (u128)f.v[4]*g19_3;
    t[3] = (u128)f.v[0]*g.v[3] + (u128)f.v[1]*g.v[2] + (u128)f.v[2]*g.v[1] +
            (u128)f.v[3]*g.v[0] + (u128)f.v[4]*g19_4;
    t[4] = (u128)f.v[0]*g.v[4] + (u128)f.v[1]*g.v[3] + (u128)f.v[2]*g.v[2] +
            (u128)f.v[3]*g.v[1] + (u128)f.v[4]*g.v[0];

    Fe25519 h;
    uint64_t c;
    h.v[0] = (uint64_t)t[0] & FE_MASK51; c = (uint64_t)(t[0] >> 51);
    t[1] += c; h.v[1] = (uint64_t)t[1] & FE_MASK51; c = (uint64_t)(t[1] >> 51);
    t[2] += c; h.v[2] = (uint64_t)t[2] & FE_MASK51; c = (uint64_t)(t[2] >> 51);
    t[3] += c; h.v[3] = (uint64_t)t[3] & FE_MASK51; c = (uint64_t)(t[3] >> 51);
    t[4] += c; h.v[4] = (uint64_t)t[4] & FE_MASK51; c = (uint64_t)(t[4] >> 51);
    h.v[0] += c * 19;
    c = h.v[0] >> 51; h.v[1] += c; h.v[0] &= FE_MASK51;
    return h;
}

inline Fe25519 fe_sq(const Fe25519& f) {
    return fe_mul(f, f);
}

inline Fe25519 fe_pow2523(const Fe25519& z) {
    Fe25519 t0, t1, t2;

    t0 = fe_sq(z);
    t1 = fe_sq(t0); t1 = fe_sq(t1);
    t1 = fe_mul(z, t1);
    t0 = fe_mul(t0, t1);
    t0 = fe_sq(t0);
    t0 = fe_mul(t1, t0);
    t1 = fe_sq(t0);
    for (int i = 1; i < 5; i++) t1 = fe_sq(t1);
    t0 = fe_mul(t1, t0);
    t1 = fe_sq(t0);
    for (int i = 1; i < 10; i++) t1 = fe_sq(t1);
    t1 = fe_mul(t1, t0);
    t2 = fe_sq(t1);
    for (int i = 1; i < 20; i++) t2 = fe_sq(t2);
    t1 = fe_mul(t2, t1);
    t1 = fe_sq(t1);
    for (int i = 1; i < 10; i++) t1 = fe_sq(t1);
    t0 = fe_mul(t1, t0);
    t1 = fe_sq(t0);
    for (int i = 1; i < 50; i++) t1 = fe_sq(t1);
    t1 = fe_mul(t1, t0);
    t2 = fe_sq(t1);
    for (int i = 1; i < 100; i++) t2 = fe_sq(t2);
    t1 = fe_mul(t2, t1);
    t1 = fe_sq(t1);
    for (int i = 1; i < 50; i++) t1 = fe_sq(t1);
    t0 = fe_mul(t1, t0);
    t0 = fe_sq(t0); t0 = fe_sq(t0);
    t0 = fe_mul(t0, z);
    return t0;
}

inline Fe25519 fe_inv(const Fe25519& z) {
    Fe25519 t = fe_pow2523(z);

    t = fe_sq(t); t = fe_sq(t); t = fe_sq(t);

    Fe25519 z2 = fe_sq(z);
    Fe25519 z3 = fe_mul(z, z2);
    return fe_mul(t, z3);
}

inline Fe25519 fe_frombytes(const uint8_t s[32]) {
    uint64_t h0 = (uint64_t)s[0]  | ((uint64_t)s[1] <<8) | ((uint64_t)s[2] <<16) |
                  ((uint64_t)s[3] <<24) | ((uint64_t)s[4] <<32) | ((uint64_t)s[5] <<40) |
                  ((uint64_t)s[6] & 0x07) << 48;
    uint64_t h1 = ((uint64_t)s[6] >>3) | ((uint64_t)s[7] <<5) | ((uint64_t)s[8] <<13) |
                  ((uint64_t)s[9] <<21) | ((uint64_t)s[10]<<29) | ((uint64_t)s[11]<<37) |
                  ((uint64_t)s[12] & 0x3f) << 45;
    uint64_t h2 = ((uint64_t)s[12]>>6) | ((uint64_t)s[13]<<2) | ((uint64_t)s[14]<<10) |
                  ((uint64_t)s[15]<<18) | ((uint64_t)s[16]<<26) | ((uint64_t)s[17]<<34) |
                  ((uint64_t)s[18]<<42) | ((uint64_t)s[19] & 0x01) << 50;
    uint64_t h3 = ((uint64_t)s[19]>>1) | ((uint64_t)s[20]<<7) | ((uint64_t)s[21]<<15) |
                  ((uint64_t)s[22]<<23) | ((uint64_t)s[23]<<31) | ((uint64_t)s[24]<<39) |
                  ((uint64_t)s[25] & 0x0f) << 47;
    uint64_t h4 = ((uint64_t)s[25]>>4) | ((uint64_t)s[26]<<4) | ((uint64_t)s[27]<<12) |
                  ((uint64_t)s[28]<<20) | ((uint64_t)s[29]<<28) | ((uint64_t)s[30]<<36) |
                  ((uint64_t)s[31] & 0x7f) << 44;
    return fe_reduce(Fe25519{{h0 & FE_MASK51, h1 & FE_MASK51, h2 & FE_MASK51,
                              h3 & FE_MASK51, h4 & FE_MASK51}});
}

inline void fe_tobytes(uint8_t s[32], Fe25519 h) {
    h = fe_reduce(h);

    uint64_t q = (h.v[0] + 19) >> 51;
    q = (h.v[1] + q) >> 51;
    q = (h.v[2] + q) >> 51;
    q = (h.v[3] + q) >> 51;
    q = (h.v[4] + q) >> 51;

    h.v[0] += 19 * q;
    uint64_t c;
    c = h.v[0] >> 51; h.v[1] += c; h.v[0] &= FE_MASK51;
    c = h.v[1] >> 51; h.v[2] += c; h.v[1] &= FE_MASK51;
    c = h.v[2] >> 51; h.v[3] += c; h.v[2] &= FE_MASK51;
    c = h.v[3] >> 51; h.v[4] += c; h.v[3] &= FE_MASK51;
    h.v[4] &= FE_MASK51;

    uint64_t bits[4];
    bits[0] = h.v[0] | (h.v[1] << 51);
    bits[1] = (h.v[1] >> 13) | (h.v[2] << 38);
    bits[2] = (h.v[2] >> 26) | (h.v[3] << 25);
    bits[3] = (h.v[3] >> 39) | (h.v[4] << 12);

    for (int i = 0; i < 4; i++) {
        s[i*8+0] = (uint8_t)(bits[i]);
        s[i*8+1] = (uint8_t)(bits[i] >> 8);
        s[i*8+2] = (uint8_t)(bits[i] >> 16);
        s[i*8+3] = (uint8_t)(bits[i] >> 24);
        s[i*8+4] = (uint8_t)(bits[i] >> 32);
        s[i*8+5] = (uint8_t)(bits[i] >> 40);
        s[i*8+6] = (uint8_t)(bits[i] >> 48);
        s[i*8+7] = (uint8_t)(bits[i] >> 56);
    }
}

inline bool fe_is_zero(const Fe25519& f) {
    uint8_t s[32];
    fe_tobytes(s, f);
    uint8_t d = 0;
    for (int i = 0; i < 32; i++) d |= s[i];
    return d == 0;
}

inline bool fe_is_negative(const Fe25519& f) {
    uint8_t s[32];
    fe_tobytes(s, f);
    return s[0] & 1;
}

inline Fe25519 fe_cmov(const Fe25519& f, const Fe25519& g, bool b) {
    uint64_t mask = (uint64_t)(-(int64_t)b);
    Fe25519 h;
    for (int i = 0; i < 5; i++) h.v[i] = f.v[i] ^ (mask & (f.v[i] ^ g.v[i]));
    return h;
}

inline Fe25519 fe_cneg(const Fe25519& f, bool b) {
    Fe25519 nf = fe_neg(f);
    return fe_cmov(f, nf, b);
}

inline Fe25519 fe_abs(const Fe25519& f) {
    return fe_cneg(f, fe_is_negative(f));
}

struct Scalar {
    uint64_t v[4];
};

static constexpr uint64_t SC_L[4] = {
    0x5812631a5cf5d3edULL,
    0x14def9dea2f79cd6ULL,
    0x0000000000000000ULL,
    0x1000000000000000ULL
};

inline Scalar sc_zero() { return {{0,0,0,0}}; }

inline Scalar sc_from_bytes(const uint8_t s[32]) {
    Scalar r;
    for (int i = 0; i < 4; i++) {
        r.v[i] = 0;
        for (int j = 0; j < 8; j++)
            r.v[i] |= (uint64_t)s[i*8+j] << (j*8);
    }
    return r;
}

inline bool sc_is_canonical(const Scalar& a) {
    for (int i = 3; i >= 0; --i) {
        if (a.v[i] < SC_L[i]) return true;
        if (a.v[i] > SC_L[i]) return false;
    }
    return false;
}

inline void sc_tobytes(uint8_t s[32], const Scalar& a) {
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 8; j++)
            s[i*8+j] = (uint8_t)(a.v[i] >> (j*8));
    }
}

inline Scalar sc_reduce512(const uint64_t w[8]) {

    uint64_t r[5] = {0, 0, 0, 0, 0};

    for (int i = 7; i >= 0; i--) {

        r[4] = r[3]; r[3] = r[2]; r[2] = r[1]; r[1] = r[0]; r[0] = w[i];

        uint64_t hi = (r[3] >> 60) | (r[4] << 4);

        r[3] &= 0x0FFFFFFFFFFFFFFFULL;
        r[4] = 0;

        if (hi == 0) continue;

        u128 prod0 = (u128)hi * 0x5812631a5cf5d3edULL;
        u128 prod1 = (u128)hi * 0x14def9dea2f79cd6ULL + (prod0 >> 64);
        uint64_t sub[3] = {(uint64_t)prod0, (uint64_t)prod1, (uint64_t)(prod1 >> 64)};

        u128 borrow = 0;
        borrow = (u128)r[0] - (u128)sub[0];
        r[0] = (uint64_t)borrow;
        borrow = (u128)r[1] - (u128)sub[1] - ((borrow >> 64) & 1);
        r[1] = (uint64_t)borrow;
        borrow = (u128)r[2] - (u128)sub[2] - ((borrow >> 64) & 1);
        r[2] = (uint64_t)borrow;
        borrow = (u128)r[3] - 0 - ((borrow >> 64) & 1);
        r[3] = (uint64_t)borrow;

        if ((borrow >> 64) & 1) {
            u128 carry = 0;
            carry = (u128)r[0] + SC_L[0];
            r[0] = (uint64_t)carry;
            carry = (u128)r[1] + SC_L[1] + (carry >> 64);
            r[1] = (uint64_t)carry;
            carry = (u128)r[2] + SC_L[2] + (carry >> 64);
            r[2] = (uint64_t)carry;
            carry = (u128)r[3] + SC_L[3] + (carry >> 64);
            r[3] = (uint64_t)carry;
        }
    }

    for (int iter = 0; iter < 2; iter++) {
        u128 borrow = 0;
        uint64_t diff[4];
        for (int i = 0; i < 4; i++) {
            u128 d = (u128)r[i] - (u128)SC_L[i] - (borrow & 1);
            diff[i] = (uint64_t)d;
            borrow = (d >> 127);
        }
        if (!(borrow & 1)) {
            for (int i = 0; i < 4; i++) r[i] = diff[i];
        }
    }

    return Scalar{{r[0], r[1], r[2], r[3]}};
}

inline Scalar sc_reduce256(const uint8_t s[32]) {
    uint64_t w[8] = {0};
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 8; j++)
            w[i] |= (uint64_t)s[i*8+j] << (j*8);
    }
    return sc_reduce512(w);
}

inline Scalar sc_from_fp(const Fp& x) {
    uint8_t buf[32] = {};

    for (int j = 0; j < 8; j++) buf[j] = (uint8_t)(x.lo >> (j*8));
    for (int j = 0; j < 8; j++) buf[8+j] = (uint8_t)(x.hi >> (j*8));

    return sc_from_bytes(buf);
}

inline Scalar sc_add(const Scalar& a, const Scalar& b) {

    uint64_t w[8] = {0};
    u128 carry = 0;
    for (int i = 0; i < 4; i++) {
        carry += (u128)a.v[i] + (u128)b.v[i];
        w[i] = (uint64_t)carry;
        carry >>= 64;
    }
    w[4] = (uint64_t)carry;
    return sc_reduce512(w);
}

inline Scalar sc_sub(const Scalar& a, const Scalar& b) {

    uint64_t neg_b[4];
    u128 borrow = 0;
    for (int i = 0; i < 4; i++) {
        u128 diff = (u128)SC_L[i] - (u128)b.v[i] - borrow;
        neg_b[i] = (uint64_t)diff;
        borrow = (diff >> 64) & 1;
    }

    uint64_t w[8] = {0};
    u128 carry = 0;
    for (int i = 0; i < 4; i++) {
        carry += (u128)a.v[i] + (u128)neg_b[i];
        w[i] = (uint64_t)carry;
        carry >>= 64;
    }
    w[4] = (uint64_t)carry;
    return sc_reduce512(w);
}

inline Scalar sc_mul(const Scalar& a, const Scalar& b) {

    uint64_t w[8] = {0};
    for (int i = 0; i < 4; i++) {
        u128 carry = 0;
        for (int j = 0; j < 4; j++) {
            carry += (u128)a.v[i] * (u128)b.v[j] + (u128)w[i+j];
            w[i+j] = (uint64_t)carry;
            carry >>= 64;
        }
        w[i+4] = (uint64_t)carry;
    }
    return sc_reduce512(w);
}

inline Scalar sc_neg(const Scalar& a) {
    return sc_sub(sc_zero(), a);
}

inline Scalar sc_from_fp_signed(const Fp& x) {

    if (x.hi & (1ULL << 62)) {
        Fp pos = fp_neg(x);
        return sc_neg(sc_from_fp(pos));
    }
    return sc_from_fp(x);
}

inline Scalar sc_random() {
    uint64_t r[8];
    for (int i = 0; i < 8; i++) r[i] = csprng_u64();
    return sc_reduce512(r);
}

inline Scalar sc_inv(const Scalar& a) {

    uint64_t exp[4] = {
        SC_L[0] - 2, SC_L[1], SC_L[2], SC_L[3]
    };

    Scalar result = Scalar{{1, 0, 0, 0}};
    Scalar base = a;

    for (int i = 0; i < 256; i++) {
        if ((exp[i >> 6] >> (i & 63)) & 1)
            result = sc_mul(result, base);
        base = sc_mul(base, base);
    }
    return result;
}

struct ExtPoint {
    Fe25519 X, Y, Z, T;
};

inline Fe25519 ed_d() {

    static const uint8_t d_bytes[32] = {
        0xa3, 0x78, 0x59, 0x13, 0xca, 0x4d, 0xeb, 0x75,
        0xab, 0xd8, 0x41, 0x41, 0x4d, 0x0a, 0x70, 0x00,
        0x98, 0xe8, 0x79, 0x77, 0x79, 0x40, 0xc7, 0x8c,
        0x73, 0xfe, 0x6f, 0x2b, 0xee, 0x6c, 0x03, 0x52
    };
    return fe_frombytes(d_bytes);
}

inline Fe25519 ed_2d() {
    return fe_add(ed_d(), ed_d());
}

inline ExtPoint ext_identity() {
    return {fe_zero(), fe_one(), fe_one(), fe_zero()};
}

inline ExtPoint ext_double(const ExtPoint& P) {
    Fe25519 A = fe_sq(P.X);
    Fe25519 B = fe_sq(P.Y);
    Fe25519 C = fe_add(fe_sq(P.Z), fe_sq(P.Z));
    Fe25519 D = fe_neg(A);

    Fe25519 E = fe_sub(fe_sq(fe_add(P.X, P.Y)), fe_add(A, B));
    Fe25519 G_ = fe_add(D, B);
    Fe25519 F_ = fe_sub(G_, C);
    Fe25519 H_ = fe_sub(D, B);

    return {
        fe_mul(E, F_),
        fe_mul(G_, H_),
        fe_mul(F_, G_),
        fe_mul(E, H_)
    };
}

inline ExtPoint ext_add(const ExtPoint& P, const ExtPoint& Q) {
    Fe25519 A = fe_mul(fe_sub(P.Y, P.X), fe_sub(Q.Y, Q.X));
    Fe25519 B = fe_mul(fe_add(P.Y, P.X), fe_add(Q.Y, Q.X));
    Fe25519 C = fe_mul(fe_mul(P.T, Q.T), ed_2d());
    Fe25519 D = fe_add(fe_mul(P.Z, Q.Z), fe_mul(P.Z, Q.Z));
    Fe25519 E = fe_sub(B, A);
    Fe25519 F_ = fe_sub(D, C);
    Fe25519 G_ = fe_add(D, C);
    Fe25519 H_ = fe_add(B, A);

    return {
        fe_mul(E, F_),
        fe_mul(G_, H_),
        fe_mul(F_, G_),
        fe_mul(E, H_)
    };
}

inline ExtPoint ext_neg(const ExtPoint& P) {
    return {fe_neg(P.X), P.Y, P.Z, fe_neg(P.T)};
}

inline ExtPoint ext_sub(const ExtPoint& P, const ExtPoint& Q) {
    return ext_add(P, ext_neg(Q));
}

inline ExtPoint ext_scalarmul(const ExtPoint& P, const Scalar& s) {
    uint8_t sb[32];
    sc_tobytes(sb, s);

    ExtPoint R = ext_identity();
    ExtPoint Q = P;

    for (int i = 0; i < 256; i++) {
        if ((sb[i >> 3] >> (i & 7)) & 1) {
            R = ext_add(R, Q);
        }
        Q = ext_double(Q);
    }
    return R;
}

inline ExtPoint ed_basepoint() {

    static const uint8_t by_bytes[32] = {
        0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66
    };
    Fe25519 Y = fe_frombytes(by_bytes);
    Fe25519 Z = fe_one();
    Fe25519 Y2 = fe_sq(Y);
    Fe25519 u = fe_sub(Y2, fe_one());
    Fe25519 v = fe_add(fe_mul(ed_d(), Y2), fe_one());
    Fe25519 v_inv = fe_inv(v);
    Fe25519 X2 = fe_mul(u, v_inv);

    Fe25519 X = fe_mul(fe_pow2523(X2), X2);

    Fe25519 check = fe_sq(X);
    if (!fe_is_zero(fe_sub(check, X2))) {

        static const uint8_t sqrtm1_bytes[32] = {
            0xb0, 0xa0, 0x0e, 0x4a, 0x27, 0x1b, 0xee, 0xc4,
            0x78, 0xe4, 0x2f, 0xad, 0x06, 0x18, 0x43, 0x2f,
            0xa7, 0xd7, 0xfb, 0x3d, 0x99, 0x00, 0x4d, 0x2b,
            0x0b, 0xdf, 0xc1, 0x4f, 0x80, 0x24, 0x83, 0x2b
        };
        Fe25519 sqrtm1 = fe_frombytes(sqrtm1_bytes);
        X = fe_mul(X, sqrtm1);
    }

    if (fe_is_negative(X)) X = fe_neg(X);

    Fe25519 T = fe_mul(X, Y);
    return {X, Y, Z, T};
}

using RistrettoPoint = std::array<uint8_t, 32>;

inline Fe25519 fe_sqrtm1() {
    static const uint8_t sqrtm1_bytes[32] = {
        0xb0, 0xa0, 0x0e, 0x4a, 0x27, 0x1b, 0xee, 0xc4,
        0x78, 0xe4, 0x2f, 0xad, 0x06, 0x18, 0x43, 0x2f,
        0xa7, 0xd7, 0xfb, 0x3d, 0x99, 0x00, 0x4d, 0x2b,
        0x0b, 0xdf, 0xc1, 0x4f, 0x80, 0x24, 0x83, 0x2b
    };
    return fe_frombytes(sqrtm1_bytes);
}

inline Fe25519 rist_invsqrt_a_minus_d() {
    static const uint8_t bytes[32] = {
        0xea, 0x40, 0x5d, 0x80, 0xaa, 0xfd, 0xc8, 0x99,
        0xbe, 0x72, 0x41, 0x5a, 0x17, 0x16, 0x2f, 0x9d,
        0x40, 0xd8, 0x01, 0xfe, 0x91, 0x7b, 0xc2, 0x16,
        0xa2, 0xfc, 0xaf, 0xcf, 0x05, 0x89, 0x6c, 0x78
    };
    return fe_frombytes(bytes);
}

inline Fe25519 rist_sqrt_ad_minus_one() {
    static const uint8_t bytes[32] = {
        0x1b, 0x2e, 0x7b, 0x49, 0xa0, 0xf6, 0x97, 0x7e,
        0xbd, 0x54, 0x78, 0x1b, 0x0c, 0x8e, 0x9d, 0xaf,
        0xfd, 0xd1, 0xf5, 0x31, 0xc9, 0xfc, 0x3c, 0x0f,
        0xac, 0x48, 0x83, 0x2b, 0xbf, 0x31, 0x69, 0x37
    };
    return fe_frombytes(bytes);
}

inline Fe25519 rist_one_minus_d_sq() {
    Fe25519 d = ed_d();
    Fe25519 d2 = fe_sq(d);
    return fe_sub(fe_one(), d2);
}

inline Fe25519 rist_d_minus_one_sq() {
    Fe25519 d = ed_d();
    Fe25519 dm1 = fe_sub(d, fe_one());
    return fe_sq(dm1);
}

inline std::pair<bool, Fe25519> fe_invsqrt(const Fe25519& u, const Fe25519& v) {
    Fe25519 v3 = fe_mul(fe_sq(v), v);
    Fe25519 v7 = fe_mul(fe_sq(v3), v);

    Fe25519 uv7 = fe_mul(u, v7);

    Fe25519 r = fe_mul(fe_mul(u, v3), fe_pow2523(uv7));

    Fe25519 check = fe_mul(v, fe_sq(r));

    Fe25519 u_neg = fe_neg(u);
    Fe25519 sqrtm1 = fe_sqrtm1();
    Fe25519 u_neg_sqrtm1 = fe_mul(u_neg, sqrtm1);

    bool correct = fe_is_zero(fe_sub(check, u));
    bool flipped = fe_is_zero(fe_sub(check, u_neg));
    bool flipped_sqrtm1 = fe_is_zero(fe_sub(check, u_neg_sqrtm1));

    Fe25519 r_prime = fe_mul(r, sqrtm1);
    r = fe_cmov(r, r_prime, flipped || flipped_sqrtm1);
    r = fe_abs(r);

    bool was_square = correct || flipped;
    return {was_square, r};
}

inline RistrettoPoint rist_encode(const ExtPoint& P) {
    Fe25519 u1 = fe_mul(fe_add(P.Z, P.Y), fe_sub(P.Z, P.Y));
    Fe25519 u2 = fe_mul(P.X, P.Y);

    auto [_, inv] = fe_invsqrt(fe_one(), fe_mul(u1, fe_sq(u2)));
    (void)_;

    Fe25519 den1 = fe_mul(inv, u1);
    Fe25519 den2 = fe_mul(inv, u2);
    Fe25519 z_inv = fe_mul(fe_mul(den1, den2), P.T);

    Fe25519 ix = fe_mul(P.X, fe_sqrtm1());
    Fe25519 iy = fe_mul(P.Y, fe_sqrtm1());
    Fe25519 enchanted_denominator = fe_mul(den1, rist_invsqrt_a_minus_d());

    bool rotate = fe_is_negative(fe_mul(P.T, z_inv));

    Fe25519 X = fe_cmov(P.X, iy, rotate);
    Fe25519 Y = fe_cmov(P.Y, ix, rotate);
    Fe25519 den_inv = fe_cmov(den2, enchanted_denominator, rotate);

    Y = fe_cneg(Y, fe_is_negative(fe_mul(X, z_inv)));

    Fe25519 s = fe_abs(fe_mul(den_inv, fe_sub(P.Z, Y)));

    RistrettoPoint out;
    fe_tobytes(out.data(), s);
    return out;
}

inline bool rist_decode(ExtPoint& P, const RistrettoPoint& bytes) {
    Fe25519 s = fe_frombytes(bytes.data());

    if (fe_is_negative(s)) return false;

    Fe25519 ss = fe_sq(s);
    Fe25519 u1 = fe_sub(fe_one(), ss);
    Fe25519 u2 = fe_add(fe_one(), ss);
    Fe25519 u2_sq = fe_sq(u2);

    Fe25519 v = fe_sub(fe_neg(fe_mul(ed_d(), fe_sq(u1))), u2_sq);

    auto [was_square, I] = fe_invsqrt(fe_one(), fe_mul(v, u2_sq));
    if (!was_square) return false;

    Fe25519 den_x = fe_mul(I, u2);
    Fe25519 den_y = fe_mul(fe_mul(I, den_x), v);

    Fe25519 x = fe_abs(fe_mul(fe_add(s, s), den_x));
    Fe25519 y = fe_mul(u1, den_y);
    Fe25519 t = fe_mul(x, y);

    if (fe_is_negative(t) || fe_is_zero(y)) return false;

    P = {x, y, fe_one(), t};
    return true;
}

inline ExtPoint rist_decode_or_throw(const RistrettoPoint& bytes) {
    ExtPoint P;
    if (!rist_decode(P, bytes))
        throw std::runtime_error("pvac: invalid Ristretto point encoding");
    return P;
}

inline RistrettoPoint rist_add(const RistrettoPoint& a, const RistrettoPoint& b) {
    ExtPoint P = rist_decode_or_throw(a);
    ExtPoint Q = rist_decode_or_throw(b);
    return rist_encode(ext_add(P, Q));
}

inline RistrettoPoint rist_sub(const RistrettoPoint& a, const RistrettoPoint& b) {
    ExtPoint P = rist_decode_or_throw(a);
    ExtPoint Q = rist_decode_or_throw(b);
    return rist_encode(ext_sub(P, Q));
}

inline RistrettoPoint rist_scalarmul(const RistrettoPoint& pt, const Scalar& s) {
    ExtPoint P = rist_decode_or_throw(pt);
    return rist_encode(ext_scalarmul(P, s));
}

inline RistrettoPoint rist_basemul(const Scalar& s) {
    return rist_encode(ext_scalarmul(ed_basepoint(), s));
}

inline RistrettoPoint rist_identity() {
    return rist_encode(ext_identity());
}

inline RistrettoPoint rist_G() {
    return rist_basemul(Scalar{{1,0,0,0}});
}

inline RistrettoPoint rist_H() {

    const char* domain = "pvac.rist.pedersen.H";
    uint8_t hash[32];
    sha256_bytes(domain, strlen(domain), hash);

    Fe25519 r0 = fe_frombytes(hash);

    hash[31] &= 0x7f;
    r0 = fe_frombytes(hash);

    Fe25519 r = fe_mul(fe_sqrtm1(), fe_sq(r0));
    Fe25519 ns = fe_sub(fe_add(r, fe_one()), fe_one());
    ns = r;
    Fe25519 u = fe_sub(fe_neg(fe_one()), fe_mul(ns, fe_add(ns, fe_one())));

    Fe25519 d = ed_d();
    Fe25519 sqrtm1 = fe_sqrtm1();
    Fe25519 one_minus_d_sq = rist_one_minus_d_sq();
    Fe25519 d_minus_one_sq = rist_d_minus_one_sq();
    Fe25519 sqrt_ad_minus_one = rist_sqrt_ad_minus_one();

    r = fe_mul(sqrtm1, fe_sq(r0));
    u = fe_mul(fe_add(r, fe_one()), one_minus_d_sq);
    Fe25519 v = fe_mul(fe_sub(fe_neg(fe_one()), fe_mul(r, d)), fe_add(r, d));

    auto [was_square, s] = fe_invsqrt(u, v);

    Fe25519 s_result = fe_abs(fe_mul(u, s));

    s_result = s;

    Fe25519 s_prime = fe_neg(fe_abs(fe_mul(s_result, r0)));
    s_result = fe_cmov(s_prime, s_result, was_square);
    Fe25519 c = fe_cmov(r, fe_neg(fe_one()), was_square);

    Fe25519 N = fe_sub(fe_mul(fe_mul(c, fe_sub(r, fe_one())), d_minus_one_sq), v);
    Fe25519 w0 = fe_mul(fe_add(s_result, s_result), v);
    Fe25519 w1 = fe_mul(N, sqrt_ad_minus_one);
    Fe25519 w2 = fe_sub(fe_one(), fe_sq(s_result));
    Fe25519 w3 = fe_add(fe_one(), fe_sq(s_result));

    ExtPoint P = {
        fe_mul(w0, w3),
        fe_mul(w2, w1),
        fe_mul(w1, w3),
        fe_mul(w0, w2)
    };
    return rist_encode(P);
}

inline RistrettoPoint pedersen_commit(const Scalar& value, const Scalar& blinding) {

    ExtPoint G_pt, H_pt;
    RistrettoPoint G_enc = rist_G();
    RistrettoPoint H_enc = rist_H();
    if (!rist_decode(G_pt, G_enc))
        throw std::runtime_error("pvac: invalid Pedersen G generator");
    if (!rist_decode(H_pt, H_enc))
        throw std::runtime_error("pvac: invalid Pedersen H generator");

    ExtPoint vG = ext_scalarmul(G_pt, value);
    ExtPoint bH = ext_scalarmul(H_pt, blinding);

    return rist_encode(ext_add(vG, bH));
}

inline RistrettoPoint pedersen_commit_fp(const Fp& value, const Scalar& blinding) {
    return pedersen_commit(sc_from_fp(value), blinding);
}

}