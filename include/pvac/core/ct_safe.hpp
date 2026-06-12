#pragma once

#include <cstdint>
#include <cstddef>
#include <type_traits>
#include <array>
#include <algorithm>

#include "field.hpp"
#include "bitvec.hpp"

namespace pvac {
namespace ct {

using u64 = std::uint64_t;
using u32 = std::uint32_t;
using u16 = std::uint16_t;
using u8 = std::uint8_t;

template<typename T>
struct word_traits : std::false_type {};

template<> struct word_traits<u64> : std::true_type {
    static constexpr std::size_t bits = 64;
    static constexpr std::size_t msb = 63;
    static constexpr u64 one = 1;
    static constexpr u64 zero = 0;
    static constexpr u64 all = ~u64{0};
};

template<> struct word_traits<u32> : std::true_type {
    static constexpr std::size_t bits = 32;
    static constexpr std::size_t msb = 31;
    static constexpr u32 one = 1;
    static constexpr u32 zero = 0;
    static constexpr u32 all = ~u32{0};
};

template<> struct word_traits<u16> : std::true_type {
    static constexpr std::size_t bits = 16;
    static constexpr std::size_t msb = 15;
    static constexpr u16 one = 1;
    static constexpr u16 zero = 0;
    static constexpr u16 all = ~u16{0};
};

template<> struct word_traits<u8> : std::true_type {
    static constexpr std::size_t bits = 8;
    static constexpr std::size_t msb = 7;
    static constexpr u8 one = 1;
    static constexpr u8 zero = 0;
    static constexpr u8 all = ~u8{0};
};

template<typename T>
inline constexpr bool is_word_v = word_traits<T>::value;

template<typename W, typename = std::enable_if_t<is_word_v<W>>>
inline constexpr W is_zero(W x) noexcept {
    constexpr auto msb = word_traits<W>::msb;
    W y = x | (W{0} - x);
    return (y >> msb) ^ W{1};
}

template<typename W, typename = std::enable_if_t<is_word_v<W>>>
inline constexpr W is_nonzero(W x) noexcept {
    return is_zero(x) ^ W{1};
}

template<typename W, typename = std::enable_if_t<is_word_v<W>>>
inline constexpr W eq(W a, W b) noexcept {
    return is_zero(a ^ b);
}

template<typename W, typename = std::enable_if_t<is_word_v<W>>>
inline constexpr W neq(W a, W b) noexcept {
    return is_nonzero(a ^ b);
}

template<typename W, typename = std::enable_if_t<is_word_v<W>>>
inline constexpr W lt(W a, W b) noexcept {
    return a < b ? W{1} : W{0};
}

template<typename W, typename = std::enable_if_t<is_word_v<W>>>
inline constexpr W gt(W a, W b) noexcept {
    return a > b ? W{1} : W{0};
}

template<typename W, typename = std::enable_if_t<is_word_v<W>>>
inline constexpr W le(W a, W b) noexcept {
    return a <= b ? W{1} : W{0};
}

template<typename W, typename = std::enable_if_t<is_word_v<W>>>
inline constexpr W ge(W a, W b) noexcept {
    return a >= b ? W{1} : W{0};
}

template<typename W, typename = std::enable_if_t<is_word_v<W>>>
inline constexpr W mask_from_bit(W bit) noexcept {
    return W{0} - (bit & W{1});
}

template<typename W, typename = std::enable_if_t<is_word_v<W>>>
inline constexpr W zero_mask(W a) noexcept {
    return mask_from_bit(is_zero(a));
}

template<typename W, typename = std::enable_if_t<is_word_v<W>>>
inline constexpr W nonzero_mask(W a) noexcept {
    return mask_from_bit(is_nonzero(a));
}

template<typename W, typename = std::enable_if_t<is_word_v<W>>>
inline constexpr W eq_mask(W a, W b) noexcept {
    return mask_from_bit(eq(a, b));
}

template<typename W, typename = std::enable_if_t<is_word_v<W>>>
inline constexpr W neq_mask(W a, W b) noexcept {
    return mask_from_bit(neq(a, b));
}

template<typename W, typename = std::enable_if_t<is_word_v<W>>>
inline constexpr W lt_mask(W a, W b) noexcept {
    return mask_from_bit(lt(a, b));
}

template<typename W, typename = std::enable_if_t<is_word_v<W>>>
inline constexpr W gt_mask(W a, W b) noexcept {
    return mask_from_bit(gt(a, b));
}

template<typename W, typename = std::enable_if_t<is_word_v<W>>>
inline constexpr W le_mask(W a, W b) noexcept {
    return mask_from_bit(le(a, b));
}

template<typename W, typename = std::enable_if_t<is_word_v<W>>>
inline constexpr W ge_mask(W a, W b) noexcept {
    return mask_from_bit(ge(a, b));
}

template<typename W, typename = std::enable_if_t<is_word_v<W>>>
inline constexpr W select(W mask, W a, W b) noexcept {
    return (a & mask) | (b & ~mask);
}

template<typename W, typename = std::enable_if_t<is_word_v<W>>>
inline constexpr W select_bit(W cond, W a, W b) noexcept {
    return select(mask_from_bit(cond), a, b);
}

template<typename W, typename = std::enable_if_t<is_word_v<W>>>
inline constexpr void cswap(W mask, W& a, W& b) noexcept {
    W t = mask & (a ^ b);
    a ^= t;
    b ^= t;
}

template<typename W, typename = std::enable_if_t<is_word_v<W>>>
inline constexpr void cswap_bit(W cond, W& a, W& b) noexcept {
    cswap(mask_from_bit(cond), a, b);
}

template<typename W, typename = std::enable_if_t<is_word_v<W>>>
inline constexpr W min(W a, W b) noexcept {
    return select(lt_mask(a, b), a, b);
}

template<typename W, typename = std::enable_if_t<is_word_v<W>>>
inline constexpr W max(W a, W b) noexcept {
    return select(gt_mask(a, b), a, b);
}

template<typename W, typename = std::enable_if_t<is_word_v<W>>>
inline constexpr W abs_diff(W a, W b) noexcept {
    return select(lt_mask(a, b), b - a, a - b);
}

template<typename W, typename = std::enable_if_t<is_word_v<W>>>
inline constexpr W clamp(W x, W lo, W hi) noexcept {
    return min(max(x, lo), hi);
}

template<typename W, typename = std::enable_if_t<is_word_v<W>>>
inline constexpr W saturating_add(W a, W b) noexcept {
    W sum = a + b;
    W overflow = lt(sum, a);
    return select(mask_from_bit(overflow), word_traits<W>::all, sum);
}

template<typename W, typename = std::enable_if_t<is_word_v<W>>>
inline constexpr W saturating_sub(W a, W b) noexcept {
    W diff = a - b;
    W underflow = gt(b, a);
    return select(mask_from_bit(underflow), W{0}, diff);
}

template<typename W, typename = std::enable_if_t<is_word_v<W>>>
inline constexpr W rotate_left(W x, unsigned n) noexcept {
    constexpr auto bits = word_traits<W>::bits;
    n &= (bits - 1);
    return (x << n) | (x >> (bits - n));
}

template<typename W, typename = std::enable_if_t<is_word_v<W>>>
inline constexpr W rotate_right(W x, unsigned n) noexcept {
    constexpr auto bits = word_traits<W>::bits;
    n &= (bits - 1);
    return (x >> n) | (x << (bits - n));
}

inline u64 fp_is_zero(const Fp& x) noexcept {
    return is_zero(x.lo | x.hi);
}

inline u64 fp_is_nonzero(const Fp& x) noexcept {
    return is_nonzero(x.lo | x.hi);
}

inline u64 fp_eq(const Fp& a, const Fp& b) noexcept {
    return eq(a.lo, b.lo) & eq(a.hi, b.hi);
}

inline u64 fp_neq(const Fp& a, const Fp& b) noexcept {
    return fp_eq(a, b) ^ u64{1};
}

inline u64 fp_is_one(const Fp& x) noexcept {
    return eq(x.lo, u64{1}) & eq(x.hi, u64{0});
}

inline u64 fp_zero_mask(const Fp& x) noexcept {
    return mask_from_bit(fp_is_zero(x));
}

inline u64 fp_nonzero_mask(const Fp& x) noexcept {
    return mask_from_bit(fp_is_nonzero(x));
}

inline u64 fp_eq_mask(const Fp& a, const Fp& b) noexcept {
    return mask_from_bit(fp_eq(a, b));
}

inline Fp fp_select(u64 mask, const Fp& a, const Fp& b) noexcept {
    return Fp{select(mask, a.lo, b.lo), select(mask, a.hi, b.hi)};
}

inline Fp fp_select_bit(u64 cond, const Fp& a, const Fp& b) noexcept {
    return fp_select(mask_from_bit(cond), a, b);
}

inline void fp_cswap(u64 mask, Fp& a, Fp& b) noexcept {
    cswap(mask, a.lo, b.lo);
    cswap(mask, a.hi, b.hi);
}

inline void fp_cswap_bit(u64 cond, Fp& a, Fp& b) noexcept {
    fp_cswap(mask_from_bit(cond), a, b);
}

inline void bv_cswap(u64 mask, BitVec& a, BitVec& b) noexcept {
    std::size_t n = std::min(a.w.size(), b.w.size());
    for (std::size_t i = 0; i < n; ++i) {
        cswap(mask, a.w[i], b.w[i]);
    }
}

inline BitVec bv_select(u64 mask, const BitVec& a, const BitVec& b) {
    BitVec r;
    r.nbits = a.nbits;
    std::size_t n = a.w.size();
    r.w.resize(n);
    for (std::size_t i = 0; i < n; ++i) {
        u64 av = i < a.w.size() ? a.w[i] : u64{0};
        u64 bv = i < b.w.size() ? b.w[i] : u64{0};
        r.w[i] = select(mask, av, bv);
    }
    return r;
}

template<std::size_t N>
inline u64 lookup(const u64 (&arr)[N], std::size_t idx) noexcept {
    u64 res = arr[0];
    for (std::size_t i = 1; i < N; ++i) {
        res = select(eq_mask(u64{i}, u64(idx)), arr[i], res);
    }
    return res;
}

template<std::size_t N>
inline void store(u64 (&arr)[N], std::size_t idx, u64 val) noexcept {
    for (std::size_t i = 0; i < N; ++i) {
        arr[i] = select(eq_mask(u64{i}, u64(idx)), val, arr[i]);
    }
}

template<std::size_t N>
inline u64 lookup(const std::array<u64, N>& arr, std::size_t idx) noexcept {
    u64 res = arr[0];
    for (std::size_t i = 1; i < N; ++i) {
        res = select(eq_mask(u64{i}, u64(idx)), arr[i], res);
    }
    return res;
}

template<std::size_t N>
inline void store(std::array<u64, N>& arr, std::size_t idx, u64 val) noexcept {
    for (std::size_t i = 0; i < N; ++i) {
        arr[i] = select(eq_mask(u64{i}, u64(idx)), val, arr[i]);
    }
}

inline u64 memeq(const u8* a, const u8* b, std::size_t n) noexcept {
    u64 diff = 0;
    for (std::size_t i = 0; i < n; ++i) {
        diff |= u64(a[i] ^ b[i]);
    }
    return is_zero(diff);
}

inline void memcpy_if(u64 cond, u8* dst, const u8* src, std::size_t n) noexcept {
    u8 m8 = u8(mask_from_bit(cond) & 0xFFu);
    for (std::size_t i = 0; i < n; ++i) {
        dst[i] = u8((src[i] & m8) | (dst[i] & ~m8));
    }
}

inline void memset_if(u64 cond, u8* dst, u8 val, std::size_t n) noexcept {
    u8 m8 = u8(mask_from_bit(cond) & 0xFFu);
    for (std::size_t i = 0; i < n; ++i) {
        dst[i] = u8((val & m8) | (dst[i] & ~m8));
    }
}

inline void memzero_if(u64 cond, u8* dst, std::size_t n) noexcept {
    memset_if(cond, dst, 0, n);
}

}
}