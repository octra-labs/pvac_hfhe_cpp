/*
 * octra labs
 * lambda0xe, denis cmix, J.
 */





#pragma once

#include <array>
#include <cstring>
#include <cstdint>
#include <vector>

#include "../core/field.hpp"
#include "sha256_trace.hpp"

namespace pvac {

struct Sha256HiddenBit {
    std::array<Fp, 3> v = {};
};

struct Sha256HiddenGate {
    Sha256HiddenBit x;
    Sha256HiddenBit y;
    Sha256HiddenBit z;
};

struct Sha256HiddenGateOpen {
    size_t branch = 0;
    Fp x = {};
    Fp y = {};
    Fp z = {};
    Fp xn = {};
    Fp yn = {};
    Fp zn = {};
    Fp residual = {};
};

struct Sha256HiddenWord {
    std::array<Sha256HiddenBit, 32> bit = {};
};

struct Sha256HiddenAddBit {
    Sha256HiddenBit sum;
    Sha256HiddenBit carry;
};

struct Sha256HiddenAddBitTrace {
    Sha256HiddenGate x_y;
    Sha256HiddenGate x_and_y;
    Sha256HiddenGate x_and_c;
    Sha256HiddenGate y_and_c;
    Sha256HiddenGate sum;
    Sha256HiddenGate carry_left;
    Sha256HiddenGate carry;
};

struct Sha256HiddenAddWordTrace {
    Sha256HiddenWord left;
    Sha256HiddenWord right;
    Sha256HiddenWord out;
    std::array<Sha256HiddenBit, 33> carry = {};
    std::array<Sha256HiddenAddBitTrace, 32> step = {};
};

struct Sha256HiddenXorWordTrace {
    Sha256HiddenWord left;
    Sha256HiddenWord right;
    Sha256HiddenWord out;
    std::array<Sha256HiddenGate, 32> gate = {};
};

struct Sha256HiddenChWordTrace {
    Sha256HiddenWord x;
    Sha256HiddenWord y;
    Sha256HiddenWord z;
    Sha256HiddenWord out;
    std::array<Sha256HiddenGate, 32> nx = {};
    std::array<Sha256HiddenGate, 32> xy = {};
    std::array<Sha256HiddenGate, 32> nz = {};
    std::array<Sha256HiddenGate, 32> bit = {};
};

struct Sha256HiddenMajWordTrace {
    Sha256HiddenWord x;
    Sha256HiddenWord y;
    Sha256HiddenWord z;
    Sha256HiddenWord out;
    std::array<Sha256HiddenGate, 32> xy = {};
    std::array<Sha256HiddenGate, 32> xz = {};
    std::array<Sha256HiddenGate, 32> yz = {};
    std::array<Sha256HiddenGate, 32> left = {};
    std::array<Sha256HiddenGate, 32> bit = {};
};

struct Sha256HiddenSigmaTrace {
    Sha256HiddenWord input;
    Sha256HiddenWord a;
    Sha256HiddenWord b;
    Sha256HiddenWord c;
    Sha256HiddenXorWordTrace left;
    Sha256HiddenXorWordTrace out;
};

struct Sha256HiddenAdd4Trace {
    Sha256HiddenAddWordTrace ab;
    Sha256HiddenAddWordTrace cd;
    Sha256HiddenAddWordTrace out;
};

struct Sha256HiddenAdd5Trace {
    Sha256HiddenAddWordTrace ab;
    Sha256HiddenAddWordTrace cd;
    Sha256HiddenAddWordTrace abcd;
    Sha256HiddenAddWordTrace out;
};

struct Sha256HiddenScheduleTrace {
    Sha256HiddenSigmaTrace s1;
    Sha256HiddenSigmaTrace s0;
    Sha256HiddenAdd4Trace sum;
};

struct Sha256HiddenRoundTrace {
    Sha256HiddenSigmaTrace s1;
    Sha256HiddenChWordTrace ch;
    Sha256HiddenAdd5Trace t1;
    Sha256HiddenSigmaTrace s0;
    Sha256HiddenMajWordTrace maj;
    Sha256HiddenAddWordTrace t2;
    Sha256HiddenAddWordTrace e;
    Sha256HiddenAddWordTrace a;
};

struct Sha256HiddenState {
    std::array<Sha256HiddenWord, 8> word = {};
};

struct Sha256HiddenBlockProof {
    Sha256TraceBlock public_block;
    Sha256HiddenState pre;
    Sha256HiddenState post;
    std::array<Sha256HiddenWord, 64> words = {};
    std::array<Sha256HiddenState, 65> states = {};
    std::vector<Sha256HiddenScheduleTrace> schedule;
    std::vector<Sha256HiddenRoundTrace> rounds;
    std::vector<Sha256HiddenAddWordTrace> post_sum;
};

struct Sha256HiddenTraceProof {
    Sha256Trace public_trace;
    std::vector<Sha256HiddenBlockProof> blocks;
};

struct Sha256HiddenWordShare {
    std::array<Fp, 32> bit = {};
};

struct Sha256HiddenStateShare {
    std::array<Sha256HiddenWordShare, 8> word = {};
};

constexpr uint8_t SHA256_HIDDEN_GATE_XOR = 1;
constexpr uint8_t SHA256_HIDDEN_GATE_AND = 2;
constexpr uint8_t SHA256_HIDDEN_GATE_NOT = 3;

struct Sha256HiddenGateShare {
    uint8_t kind = 0;
    Fp x = {};
    Fp y = {};
    Fp z = {};
};

struct Sha256HiddenBlockBranch {
    size_t branch = 0;
    Sha256HiddenStateShare pre;
    Sha256HiddenStateShare post;
    std::array<Sha256HiddenWordShare, 64> words = {};
    std::array<Sha256HiddenStateShare, 65> states = {};
    std::vector<Sha256HiddenGateShare> gates;
    std::array<uint8_t, 32> commit = {};
};

struct Sha256HiddenTraceBranchProof {
    uint64_t byte_len = 0;
    size_t blocks = 0;
    std::array<uint8_t, 32> digest = {};
    std::array<uint8_t, 32> challenge = {};
    std::array<uint8_t, 32> response_digest = {};
    std::array<std::array<uint8_t, 32>, 3> commits = {};
    std::array<Sha256HiddenStateShare, 3> final_post = {};
    std::vector<Sha256HiddenBlockBranch> openings;
    bool message_hidden = false;
    bool schedule_trace = false;
    bool compression_trace = false;
    bool digest_bound = false;
    bool native_backend = false;
    bool has_raw_message = false;
};

inline bool sha256_hidden_fp_eq(const Fp& a, const Fp& b) {
    uint64_t diff = (a.lo ^ b.lo) | ((a.hi ^ b.hi) & MASK63);
    return diff == 0;
}

inline bool sha256_hidden_bit_eq(const Sha256HiddenBit& a, const Sha256HiddenBit& b) {
    for (size_t i = 0; i < 3; ++i) {
        if (!sha256_hidden_fp_eq(a.v[i], b.v[i]))
            return false;
    }
    return true;
}

inline bool sha256_hidden_word_eq(const Sha256HiddenWord& a, const Sha256HiddenWord& b) {
    for (size_t i = 0; i < 32; ++i) {
        if (!sha256_hidden_bit_eq(a.bit[i], b.bit[i]))
            return false;
    }
    return true;
}

inline bool sha256_hidden_state_eq(const Sha256HiddenState& a, const Sha256HiddenState& b) {
    for (size_t i = 0; i < 8; ++i) {
        if (!sha256_hidden_word_eq(a.word[i], b.word[i]))
            return false;
    }
    return true;
}

inline void sha256_hidden_acc_fp(Sha256& h, const Fp& x) {
    sha256_acc_u64(h, x.lo);
    sha256_acc_u64(h, x.hi & MASK63);
}

inline void sha256_hidden_acc_word_share(Sha256& h, const Sha256HiddenWordShare& word) {
    for (const auto& bit : word.bit) {
        sha256_hidden_acc_fp(h, bit);
    }
}

inline void sha256_hidden_acc_state_share(Sha256& h, const Sha256HiddenStateShare& state) {
    for (const auto& word : state.word) {
        sha256_hidden_acc_word_share(h, word);
    }
}

inline void sha256_hidden_acc_gate_share(Sha256& h, const Sha256HiddenGateShare& gate) {
    sha256_acc_u64(h, gate.kind);
    sha256_hidden_acc_fp(h, gate.x);
    sha256_hidden_acc_fp(h, gate.y);
    sha256_hidden_acc_fp(h, gate.z);
}

inline void sha256_hidden_acc_domain(Sha256& h, const char* domain) {
    h.update(domain, std::strlen(domain));
}

inline Sha256HiddenBit sha256_hidden_bit(uint8_t bit, Fp a, Fp b) {
    Sha256HiddenBit out;
    out.v[0] = a;
    out.v[1] = b;
    out.v[2] = fp_sub(fp_sub(fp_from_u64(bit & 1), a), b);
    return out;
}

inline Fp sha256_hidden_bit_value(const Sha256HiddenBit& x) {
    return fp_add(fp_add(x.v[0], x.v[1]), x.v[2]);
}

inline bool sha256_hidden_bit_is_binary(const Sha256HiddenBit& x) {
    auto v = sha256_hidden_bit_value(x);
    return sha256_hidden_fp_eq(fp_mul(v, fp_sub(v, fp_from_u64(1))), fp_from_u64(0));
}

inline Fp sha256_hidden_mul_branch(Fp x, Fp y, Fp xn, Fp yn) {
    return fp_add(fp_add(fp_mul(x, y), fp_mul(x, yn)), fp_mul(xn, y));
}

inline Fp sha256_hidden_local_mul(const Sha256HiddenBit& x, const Sha256HiddenBit& y, size_t branch) {
    return sha256_hidden_mul_branch(x.v[branch], y.v[branch], x.v[(branch + 1) % 3], y.v[(branch + 1) % 3]);
}

inline Fp sha256_hidden_and_residual(const Sha256HiddenGateOpen& open) {
    return fp_sub(open.z, sha256_hidden_mul_branch(open.x, open.y, open.xn, open.yn));
}

inline Fp sha256_hidden_xor_residual(const Sha256HiddenGateOpen& open) {
    auto xy = sha256_hidden_mul_branch(open.x, open.y, open.xn, open.yn);
    auto rhs = fp_sub(fp_add(open.x, open.y), fp_mul(fp_from_u64(2), xy));
    return fp_sub(open.z, rhs);
}

inline Fp sha256_hidden_not_residual(const Sha256HiddenGateOpen& open) {
    auto base = open.branch == 0 ? fp_from_u64(1) : fp_from_u64(0);
    return fp_sub(fp_add(open.z, open.x), base);
}

inline Fp sha256_hidden_bit_residual(Fp x, Fp xn) {
    auto xx = fp_add(fp_mul(x, x), fp_mul(fp_mul(fp_from_u64(2), x), xn));
    return fp_sub(xx, x);
}

inline Sha256HiddenGateOpen sha256_hidden_gate_open(const Sha256HiddenGate& gate, size_t branch) {
    Sha256HiddenGateOpen out;
    out.branch = branch;
    out.x = gate.x.v[branch];
    out.y = gate.y.v[branch];
    out.z = gate.z.v[branch];
    out.xn = gate.x.v[(branch + 1) % 3];
    out.yn = gate.y.v[(branch + 1) % 3];
    out.zn = gate.z.v[(branch + 1) % 3];
    return out;
}

inline Fp sha256_hidden_residual_sum(const std::array<Fp, 3>& residuals) {
    return fp_add(fp_add(residuals[0], residuals[1]), residuals[2]);
}

inline bool sha256_hidden_gate_residuals_zero(const std::array<Fp, 3>& residuals) {
    return sha256_hidden_fp_eq(sha256_hidden_residual_sum(residuals), fp_from_u64(0));
}

inline Sha256HiddenGate sha256_hidden_and_gate(const Sha256HiddenBit& x, const Sha256HiddenBit& y, Fp a, Fp b) {
    (void)a;
    (void)b;
    Sha256HiddenGate out;
    out.x = x;
    out.y = y;
    for (size_t branch = 0; branch < 3; ++branch) {
        out.z.v[branch] = sha256_hidden_local_mul(x, y, branch);
    }
    return out;
}

inline Sha256HiddenGate sha256_hidden_xor_gate(const Sha256HiddenBit& x, const Sha256HiddenBit& y, Fp a, Fp b) {
    (void)a;
    (void)b;
    Sha256HiddenGate out;
    out.x = x;
    out.y = y;
    for (size_t branch = 0; branch < 3; ++branch) {
        auto xy = sha256_hidden_local_mul(x, y, branch);
        out.z.v[branch] = fp_sub(fp_add(x.v[branch], y.v[branch]), fp_mul(fp_from_u64(2), xy));
    }
    return out;
}

inline Sha256HiddenGate sha256_hidden_not_gate(const Sha256HiddenBit& x, Fp a, Fp b) {
    (void)a;
    (void)b;
    Sha256HiddenGate out;
    out.x = x;
    out.z.v[0] = fp_sub(fp_from_u64(1), x.v[0]);
    out.z.v[1] = fp_sub(fp_from_u64(0), x.v[1]);
    out.z.v[2] = fp_sub(fp_from_u64(0), x.v[2]);
    return out;
}

inline std::array<Fp, 3> sha256_hidden_and_residuals(const Sha256HiddenGate& gate) {
    std::array<Fp, 3> out{};
    for (size_t branch = 0; branch < 3; ++branch) {
        auto open = sha256_hidden_gate_open(gate, branch);
        out[branch] = sha256_hidden_and_residual(open);
    }
    return out;
}

inline std::array<Fp, 3> sha256_hidden_xor_residuals(const Sha256HiddenGate& gate) {
    std::array<Fp, 3> out{};
    for (size_t branch = 0; branch < 3; ++branch) {
        auto open = sha256_hidden_gate_open(gate, branch);
        out[branch] = sha256_hidden_xor_residual(open);
    }
    return out;
}

inline std::array<Fp, 3> sha256_hidden_not_residuals(const Sha256HiddenGate& gate) {
    std::array<Fp, 3> out{};
    for (size_t branch = 0; branch < 3; ++branch) {
        auto open = sha256_hidden_gate_open(gate, branch);
        out[branch] = sha256_hidden_not_residual(open);
    }
    return out;
}

inline Sha256HiddenBit sha256_hidden_ch_bit(const Sha256HiddenBit& x, const Sha256HiddenBit& y, const Sha256HiddenBit& z, Fp a, Fp b) {
    auto xy = fp_mul(sha256_hidden_bit_value(x), sha256_hidden_bit_value(y));
    auto nx = fp_sub(fp_from_u64(1), sha256_hidden_bit_value(x));
    auto nz = fp_mul(nx, sha256_hidden_bit_value(z));
    auto out = fp_sub(fp_add(xy, nz), fp_mul(fp_from_u64(2), fp_mul(xy, nz)));
    return sha256_hidden_bit(sha256_hidden_fp_eq(out, fp_from_u64(0)) ? 0 : 1, a, b);
}

inline Sha256HiddenBit sha256_hidden_maj_bit(const Sha256HiddenBit& x, const Sha256HiddenBit& y, const Sha256HiddenBit& z, Fp a, Fp b) {
    auto xy = fp_mul(sha256_hidden_bit_value(x), sha256_hidden_bit_value(y));
    auto xz = fp_mul(sha256_hidden_bit_value(x), sha256_hidden_bit_value(z));
    auto yz = fp_mul(sha256_hidden_bit_value(y), sha256_hidden_bit_value(z));
    auto out = fp_add(fp_add(xy, xz), yz);
    return sha256_hidden_bit(sha256_hidden_fp_eq(out, fp_from_u64(0)) ? 0 : 1, a, b);
}

inline Sha256HiddenWord sha256_hidden_word(uint32_t value, Fp a, Fp b) {
    Sha256HiddenWord out;
    for (size_t i = 0; i < 32; ++i) {
        auto ai = fp_add(a, fp_from_u64(i + 1));
        auto bi = fp_add(b, fp_from_u64((i + 1) * 3));
        out.bit[i] = sha256_hidden_bit(static_cast<uint8_t>((value >> i) & 1), ai, bi);
    }
    return out;
}

inline uint32_t sha256_hidden_word_value(const Sha256HiddenWord& word) {
    uint32_t out = 0;
    for (size_t i = 0; i < 32; ++i) {
        if (!sha256_hidden_fp_eq(sha256_hidden_bit_value(word.bit[i]), fp_from_u64(0))) {
            out |= static_cast<uint32_t>(1) << i;
        }
    }
    return out;
}

inline bool sha256_hidden_word_bits_ok(const Sha256HiddenWord& word) {
    for (const auto& bit : word.bit) {
        if (!sha256_hidden_bit_is_binary(bit))
            return false;
    }
    return true;
}

inline Sha256HiddenWord sha256_hidden_word_rotr(const Sha256HiddenWord& word, size_t n) {
    Sha256HiddenWord out;
    for (size_t i = 0; i < 32; ++i) {
        out.bit[i] = word.bit[(i + n) % 32];
    }
    return out;
}

inline Sha256HiddenWord sha256_hidden_word_shr(const Sha256HiddenWord& word, size_t n) {
    Sha256HiddenWord out;
    for (size_t i = 0; i < 32; ++i) {
        if (i + n < 32) {
            out.bit[i] = word.bit[i + n];
        } else {
            out.bit[i] = sha256_hidden_bit(0, fp_from_u64(i + 5), fp_from_u64(i + 11));
        }
    }
    return out;
}

inline Sha256HiddenWord sha256_hidden_word_xor(const Sha256HiddenWord& left, const Sha256HiddenWord& right, Fp a, Fp b) {
    Sha256HiddenWord out;
    for (size_t i = 0; i < 32; ++i) {
        auto ai = fp_add(a, fp_from_u64(i + 1));
        auto bi = fp_add(b, fp_from_u64((i + 1) * 5));
        out.bit[i] = sha256_hidden_xor_gate(left.bit[i], right.bit[i], ai, bi).z;
    }
    return out;
}

inline Sha256HiddenWord sha256_hidden_word_ch(const Sha256HiddenWord& x, const Sha256HiddenWord& y, const Sha256HiddenWord& z, Fp a, Fp b) {
    Sha256HiddenWord out;
    for (size_t i = 0; i < 32; ++i) {
        auto ai = fp_add(a, fp_from_u64(i + 1));
        auto bi = fp_add(b, fp_from_u64((i + 1) * 7));
        out.bit[i] = sha256_hidden_ch_bit(x.bit[i], y.bit[i], z.bit[i], ai, bi);
    }
    return out;
}

inline Sha256HiddenWord sha256_hidden_word_maj(const Sha256HiddenWord& x, const Sha256HiddenWord& y, const Sha256HiddenWord& z, Fp a, Fp b) {
    Sha256HiddenWord out;
    for (size_t i = 0; i < 32; ++i) {
        auto ai = fp_add(a, fp_from_u64(i + 1));
        auto bi = fp_add(b, fp_from_u64((i + 1) * 11));
        out.bit[i] = sha256_hidden_maj_bit(x.bit[i], y.bit[i], z.bit[i], ai, bi);
    }
    return out;
}

inline Sha256HiddenAddBit sha256_hidden_add_bit(const Sha256HiddenBit& x, const Sha256HiddenBit& y, const Sha256HiddenBit& carry, Fp a, Fp b) {
    auto t = sha256_hidden_xor_gate(x, y, fp_add(a, fp_from_u64(1)), fp_add(b, fp_from_u64(1)));
    Sha256HiddenAddBit out;
    out.sum = sha256_hidden_xor_gate(t.z, carry, fp_add(a, fp_from_u64(3)), fp_add(b, fp_from_u64(3))).z;
    out.carry = sha256_hidden_maj_bit(x, y, carry, fp_add(a, fp_from_u64(5)), fp_add(b, fp_from_u64(5)));
    return out;
}

inline bool sha256_hidden_xor_gate_ok(const Sha256HiddenGate& gate) {
    return
        sha256_hidden_bit_is_binary(gate.x) &&
        sha256_hidden_bit_is_binary(gate.y) &&
        sha256_hidden_bit_is_binary(gate.z) &&
        sha256_hidden_gate_residuals_zero(sha256_hidden_xor_residuals(gate));
}

inline bool sha256_hidden_and_gate_ok(const Sha256HiddenGate& gate) {
    return
        sha256_hidden_bit_is_binary(gate.x) &&
        sha256_hidden_bit_is_binary(gate.y) &&
        sha256_hidden_bit_is_binary(gate.z) &&
        sha256_hidden_gate_residuals_zero(sha256_hidden_and_residuals(gate));
}

inline bool sha256_hidden_not_gate_ok(const Sha256HiddenGate& gate) {
    return
        sha256_hidden_bit_is_binary(gate.x) &&
        sha256_hidden_bit_is_binary(gate.z) &&
        sha256_hidden_gate_residuals_zero(sha256_hidden_not_residuals(gate));
}

inline Sha256HiddenAddBitTrace sha256_hidden_add_bit_trace(const Sha256HiddenBit& x, const Sha256HiddenBit& y, const Sha256HiddenBit& carry, Fp a, Fp b) {
    Sha256HiddenAddBitTrace out;
    out.x_y = sha256_hidden_xor_gate(x, y, fp_add(a, fp_from_u64(1)), fp_add(b, fp_from_u64(1)));
    out.x_and_y = sha256_hidden_and_gate(x, y, fp_add(a, fp_from_u64(3)), fp_add(b, fp_from_u64(3)));
    out.x_and_c = sha256_hidden_and_gate(x, carry, fp_add(a, fp_from_u64(5)), fp_add(b, fp_from_u64(5)));
    out.y_and_c = sha256_hidden_and_gate(y, carry, fp_add(a, fp_from_u64(7)), fp_add(b, fp_from_u64(7)));
    out.sum = sha256_hidden_xor_gate(out.x_y.z, carry, fp_add(a, fp_from_u64(11)), fp_add(b, fp_from_u64(11)));
    out.carry_left = sha256_hidden_xor_gate(out.x_and_y.z, out.x_and_c.z, fp_add(a, fp_from_u64(13)), fp_add(b, fp_from_u64(13)));
    out.carry = sha256_hidden_xor_gate(out.carry_left.z, out.y_and_c.z, fp_add(a, fp_from_u64(17)), fp_add(b, fp_from_u64(17)));
    return out;
}

inline bool sha256_hidden_add_bit_trace_ok(const Sha256HiddenAddBitTrace& trace) {
    return
        sha256_hidden_xor_gate_ok(trace.x_y) &&
        sha256_hidden_and_gate_ok(trace.x_and_y) &&
        sha256_hidden_and_gate_ok(trace.x_and_c) &&
        sha256_hidden_and_gate_ok(trace.y_and_c) &&
        sha256_hidden_xor_gate_ok(trace.sum) &&
        sha256_hidden_xor_gate_ok(trace.carry_left) &&
        sha256_hidden_xor_gate_ok(trace.carry);
}

inline Sha256HiddenAddWordTrace sha256_hidden_word_add2_trace(const Sha256HiddenWord& left, const Sha256HiddenWord& right, Fp a, Fp b) {
    Sha256HiddenAddWordTrace trace;
    trace.left = left;
    trace.right = right;
    trace.carry[0] = sha256_hidden_bit(0, fp_add(a, fp_from_u64(1)), fp_add(b, fp_from_u64(1)));
    for (size_t i = 0; i < 32; ++i) {
        trace.step[i] = sha256_hidden_add_bit_trace(left.bit[i], right.bit[i], trace.carry[i], fp_add(a, fp_from_u64(i * 17 + 3)), fp_add(b, fp_from_u64(i * 19 + 3)));
        trace.out.bit[i] = trace.step[i].sum.z;
        trace.carry[i + 1] = trace.step[i].carry.z;
    }
    return trace;
}

inline bool sha256_hidden_word_add2_trace_ok(const Sha256HiddenAddWordTrace& trace) {
    if (!sha256_hidden_word_bits_ok(trace.left))
        return false;
    if (!sha256_hidden_word_bits_ok(trace.right))
        return false;
    if (!sha256_hidden_word_bits_ok(trace.out))
        return false;
    for (const auto& carry : trace.carry) {
        if (!sha256_hidden_bit_is_binary(carry))
            return false;
    }
    for (size_t i = 0; i < 32; ++i) {
        if (!sha256_hidden_add_bit_trace_ok(trace.step[i]))
            return false;
        if (!sha256_hidden_bit_eq(trace.step[i].x_y.x, trace.left.bit[i]))
            return false;
        if (!sha256_hidden_bit_eq(trace.step[i].x_y.y, trace.right.bit[i]))
            return false;
        if (!sha256_hidden_bit_eq(trace.step[i].x_and_y.x, trace.left.bit[i]))
            return false;
        if (!sha256_hidden_bit_eq(trace.step[i].x_and_y.y, trace.right.bit[i]))
            return false;
        if (!sha256_hidden_bit_eq(trace.step[i].x_and_c.x, trace.left.bit[i]))
            return false;
        if (!sha256_hidden_bit_eq(trace.step[i].x_and_c.y, trace.carry[i]))
            return false;
        if (!sha256_hidden_bit_eq(trace.step[i].y_and_c.x, trace.right.bit[i]))
            return false;
        if (!sha256_hidden_bit_eq(trace.step[i].y_and_c.y, trace.carry[i]))
            return false;
        if (!sha256_hidden_bit_eq(trace.step[i].sum.x, trace.step[i].x_y.z))
            return false;
        if (!sha256_hidden_bit_eq(trace.step[i].sum.y, trace.carry[i]))
            return false;
        if (!sha256_hidden_bit_eq(trace.step[i].carry_left.x, trace.step[i].x_and_y.z))
            return false;
        if (!sha256_hidden_bit_eq(trace.step[i].carry_left.y, trace.step[i].x_and_c.z))
            return false;
        if (!sha256_hidden_bit_eq(trace.step[i].carry.x, trace.step[i].carry_left.z))
            return false;
        if (!sha256_hidden_bit_eq(trace.step[i].carry.y, trace.step[i].y_and_c.z))
            return false;
        if (!sha256_hidden_bit_eq(trace.step[i].sum.z, trace.out.bit[i]))
            return false;
        if (!sha256_hidden_bit_eq(trace.step[i].carry.z, trace.carry[i + 1]))
            return false;
    }
    return true;
}

inline Sha256HiddenWord sha256_hidden_word_add2(const Sha256HiddenWord& left, const Sha256HiddenWord& right, Fp a, Fp b) {
    return sha256_hidden_word_add2_trace(left, right, a, b).out;
}

inline Sha256HiddenXorWordTrace sha256_hidden_word_xor_trace(const Sha256HiddenWord& left, const Sha256HiddenWord& right, Fp a, Fp b) {
    Sha256HiddenXorWordTrace trace;
    trace.left = left;
    trace.right = right;
    for (size_t i = 0; i < 32; ++i) {
        auto ai = fp_add(a, fp_from_u64(i + 1));
        auto bi = fp_add(b, fp_from_u64((i + 1) * 5));
        trace.gate[i] = sha256_hidden_xor_gate(left.bit[i], right.bit[i], ai, bi);
        trace.out.bit[i] = trace.gate[i].z;
    }
    return trace;
}

inline bool sha256_hidden_word_xor_trace_ok(const Sha256HiddenXorWordTrace& trace) {
    if (!sha256_hidden_word_bits_ok(trace.left))
        return false;
    if (!sha256_hidden_word_bits_ok(trace.right))
        return false;
    if (!sha256_hidden_word_bits_ok(trace.out))
        return false;
    for (size_t i = 0; i < 32; ++i) {
        if (!sha256_hidden_xor_gate_ok(trace.gate[i]))
            return false;
        if (!sha256_hidden_bit_eq(trace.gate[i].x, trace.left.bit[i]))
            return false;
        if (!sha256_hidden_bit_eq(trace.gate[i].y, trace.right.bit[i]))
            return false;
        if (!sha256_hidden_bit_eq(trace.gate[i].z, trace.out.bit[i]))
            return false;
    }
    return true;
}

inline Sha256HiddenChWordTrace sha256_hidden_word_ch_trace(const Sha256HiddenWord& x, const Sha256HiddenWord& y, const Sha256HiddenWord& z, Fp a, Fp b) {
    Sha256HiddenChWordTrace trace;
    trace.x = x;
    trace.y = y;
    trace.z = z;
    for (size_t i = 0; i < 32; ++i) {
        auto ai = fp_add(a, fp_from_u64(i * 23 + 1));
        auto bi = fp_add(b, fp_from_u64(i * 29 + 1));
        trace.nx[i] = sha256_hidden_not_gate(x.bit[i], ai, bi);
        trace.xy[i] = sha256_hidden_and_gate(x.bit[i], y.bit[i], fp_add(ai, fp_from_u64(3)), fp_add(bi, fp_from_u64(3)));
        trace.nz[i] = sha256_hidden_and_gate(trace.nx[i].z, z.bit[i], fp_add(ai, fp_from_u64(5)), fp_add(bi, fp_from_u64(5)));
        trace.bit[i] = sha256_hidden_xor_gate(trace.xy[i].z, trace.nz[i].z, fp_add(ai, fp_from_u64(7)), fp_add(bi, fp_from_u64(7)));
        trace.out.bit[i] = trace.bit[i].z;
    }
    return trace;
}

inline bool sha256_hidden_word_ch_trace_ok(const Sha256HiddenChWordTrace& trace) {
    if (!sha256_hidden_word_bits_ok(trace.x))
        return false;
    if (!sha256_hidden_word_bits_ok(trace.y))
        return false;
    if (!sha256_hidden_word_bits_ok(trace.z))
        return false;
    if (!sha256_hidden_word_bits_ok(trace.out))
        return false;
    for (size_t i = 0; i < 32; ++i) {
        if (!sha256_hidden_not_gate_ok(trace.nx[i]))
            return false;
        if (!sha256_hidden_and_gate_ok(trace.xy[i]))
            return false;
        if (!sha256_hidden_and_gate_ok(trace.nz[i]))
            return false;
        if (!sha256_hidden_xor_gate_ok(trace.bit[i]))
            return false;
        if (!sha256_hidden_bit_eq(trace.nx[i].x, trace.x.bit[i]))
            return false;
        if (!sha256_hidden_bit_eq(trace.xy[i].x, trace.x.bit[i]))
            return false;
        if (!sha256_hidden_bit_eq(trace.xy[i].y, trace.y.bit[i]))
            return false;
        if (!sha256_hidden_bit_eq(trace.nz[i].x, trace.nx[i].z))
            return false;
        if (!sha256_hidden_bit_eq(trace.nz[i].y, trace.z.bit[i]))
            return false;
        if (!sha256_hidden_bit_eq(trace.bit[i].x, trace.xy[i].z))
            return false;
        if (!sha256_hidden_bit_eq(trace.bit[i].y, trace.nz[i].z))
            return false;
        if (!sha256_hidden_bit_eq(trace.bit[i].z, trace.out.bit[i]))
            return false;
    }
    return true;
}

inline Sha256HiddenMajWordTrace sha256_hidden_word_maj_trace(const Sha256HiddenWord& x, const Sha256HiddenWord& y, const Sha256HiddenWord& z, Fp a, Fp b) {
    Sha256HiddenMajWordTrace trace;
    trace.x = x;
    trace.y = y;
    trace.z = z;
    for (size_t i = 0; i < 32; ++i) {
        auto ai = fp_add(a, fp_from_u64(i * 31 + 1));
        auto bi = fp_add(b, fp_from_u64(i * 37 + 1));
        trace.xy[i] = sha256_hidden_and_gate(x.bit[i], y.bit[i], ai, bi);
        trace.xz[i] = sha256_hidden_and_gate(x.bit[i], z.bit[i], fp_add(ai, fp_from_u64(3)), fp_add(bi, fp_from_u64(3)));
        trace.yz[i] = sha256_hidden_and_gate(y.bit[i], z.bit[i], fp_add(ai, fp_from_u64(5)), fp_add(bi, fp_from_u64(5)));
        trace.left[i] = sha256_hidden_xor_gate(trace.xy[i].z, trace.xz[i].z, fp_add(ai, fp_from_u64(7)), fp_add(bi, fp_from_u64(7)));
        trace.bit[i] = sha256_hidden_xor_gate(trace.left[i].z, trace.yz[i].z, fp_add(ai, fp_from_u64(11)), fp_add(bi, fp_from_u64(11)));
        trace.out.bit[i] = trace.bit[i].z;
    }
    return trace;
}

inline bool sha256_hidden_word_maj_trace_ok(const Sha256HiddenMajWordTrace& trace) {
    if (!sha256_hidden_word_bits_ok(trace.x))
        return false;
    if (!sha256_hidden_word_bits_ok(trace.y))
        return false;
    if (!sha256_hidden_word_bits_ok(trace.z))
        return false;
    if (!sha256_hidden_word_bits_ok(trace.out))
        return false;
    for (size_t i = 0; i < 32; ++i) {
        if (!sha256_hidden_and_gate_ok(trace.xy[i]))
            return false;
        if (!sha256_hidden_and_gate_ok(trace.xz[i]))
            return false;
        if (!sha256_hidden_and_gate_ok(trace.yz[i]))
            return false;
        if (!sha256_hidden_xor_gate_ok(trace.left[i]))
            return false;
        if (!sha256_hidden_xor_gate_ok(trace.bit[i]))
            return false;
        if (!sha256_hidden_bit_eq(trace.xy[i].x, trace.x.bit[i]))
            return false;
        if (!sha256_hidden_bit_eq(trace.xy[i].y, trace.y.bit[i]))
            return false;
        if (!sha256_hidden_bit_eq(trace.xz[i].x, trace.x.bit[i]))
            return false;
        if (!sha256_hidden_bit_eq(trace.xz[i].y, trace.z.bit[i]))
            return false;
        if (!sha256_hidden_bit_eq(trace.yz[i].x, trace.y.bit[i]))
            return false;
        if (!sha256_hidden_bit_eq(trace.yz[i].y, trace.z.bit[i]))
            return false;
        if (!sha256_hidden_bit_eq(trace.left[i].x, trace.xy[i].z))
            return false;
        if (!sha256_hidden_bit_eq(trace.left[i].y, trace.xz[i].z))
            return false;
        if (!sha256_hidden_bit_eq(trace.bit[i].x, trace.left[i].z))
            return false;
        if (!sha256_hidden_bit_eq(trace.bit[i].y, trace.yz[i].z))
            return false;
        if (!sha256_hidden_bit_eq(trace.bit[i].z, trace.out.bit[i]))
            return false;
    }
    return true;
}

inline Sha256HiddenWord sha256_hidden_word_add3(const Sha256HiddenWord& a, const Sha256HiddenWord& b, const Sha256HiddenWord& c, Fp x, Fp y) {
    auto ab = sha256_hidden_word_add2(a, b, x, y);
    return sha256_hidden_word_add2(ab, c, fp_add(x, fp_from_u64(97)), fp_add(y, fp_from_u64(101)));
}

inline Sha256HiddenAdd4Trace sha256_hidden_word_add4_trace(const Sha256HiddenWord& a, const Sha256HiddenWord& b, const Sha256HiddenWord& c, const Sha256HiddenWord& d, Fp x, Fp y) {
    Sha256HiddenAdd4Trace trace;
    trace.ab = sha256_hidden_word_add2_trace(a, b, x, y);
    trace.cd = sha256_hidden_word_add2_trace(c, d, fp_add(x, fp_from_u64(103)), fp_add(y, fp_from_u64(107)));
    trace.out = sha256_hidden_word_add2_trace(trace.ab.out, trace.cd.out, fp_add(x, fp_from_u64(109)), fp_add(y, fp_from_u64(113)));
    return trace;
}

inline bool sha256_hidden_word_add4_trace_ok(const Sha256HiddenAdd4Trace& trace) {
    return
        sha256_hidden_word_add2_trace_ok(trace.ab) &&
        sha256_hidden_word_add2_trace_ok(trace.cd) &&
        sha256_hidden_word_add2_trace_ok(trace.out) &&
        sha256_hidden_word_eq(trace.out.left, trace.ab.out) &&
        sha256_hidden_word_eq(trace.out.right, trace.cd.out);
}

inline Sha256HiddenWord sha256_hidden_word_add4(const Sha256HiddenWord& a, const Sha256HiddenWord& b, const Sha256HiddenWord& c, const Sha256HiddenWord& d, Fp x, Fp y) {
    return sha256_hidden_word_add4_trace(a, b, c, d, x, y).out.out;
}

inline Sha256HiddenAdd5Trace sha256_hidden_word_add5_trace(const Sha256HiddenWord& a, const Sha256HiddenWord& b, const Sha256HiddenWord& c, const Sha256HiddenWord& d, const Sha256HiddenWord& e, Fp x, Fp y) {
    Sha256HiddenAdd5Trace trace;
    trace.ab = sha256_hidden_word_add2_trace(a, b, x, y);
    trace.cd = sha256_hidden_word_add2_trace(c, d, fp_add(x, fp_from_u64(127)), fp_add(y, fp_from_u64(131)));
    trace.abcd = sha256_hidden_word_add2_trace(trace.ab.out, trace.cd.out, fp_add(x, fp_from_u64(137)), fp_add(y, fp_from_u64(139)));
    trace.out = sha256_hidden_word_add2_trace(trace.abcd.out, e, fp_add(x, fp_from_u64(149)), fp_add(y, fp_from_u64(151)));
    return trace;
}

inline bool sha256_hidden_word_add5_trace_ok(const Sha256HiddenAdd5Trace& trace) {
    return
        sha256_hidden_word_add2_trace_ok(trace.ab) &&
        sha256_hidden_word_add2_trace_ok(trace.cd) &&
        sha256_hidden_word_add2_trace_ok(trace.abcd) &&
        sha256_hidden_word_add2_trace_ok(trace.out) &&
        sha256_hidden_word_eq(trace.abcd.left, trace.ab.out) &&
        sha256_hidden_word_eq(trace.abcd.right, trace.cd.out) &&
        sha256_hidden_word_eq(trace.out.left, trace.abcd.out);
}

inline Sha256HiddenWord sha256_hidden_word_add5(const Sha256HiddenWord& a, const Sha256HiddenWord& b, const Sha256HiddenWord& c, const Sha256HiddenWord& d, const Sha256HiddenWord& e, Fp x, Fp y) {
    return sha256_hidden_word_add5_trace(a, b, c, d, e, x, y).out.out;
}

inline Sha256HiddenSigmaTrace sha256_hidden_word_sigma_trace(const Sha256HiddenWord& x, const Sha256HiddenWord& a, const Sha256HiddenWord& b, const Sha256HiddenWord& c, Fp u, Fp v) {
    Sha256HiddenSigmaTrace trace;
    trace.input = x;
    trace.a = a;
    trace.b = b;
    trace.c = c;
    trace.left = sha256_hidden_word_xor_trace(a, b, u, v);
    trace.out = sha256_hidden_word_xor_trace(trace.left.out, c, fp_add(u, fp_from_u64(157)), fp_add(v, fp_from_u64(163)));
    return trace;
}

inline bool sha256_hidden_word_sigma_trace_ok(const Sha256HiddenSigmaTrace& trace, const Sha256HiddenWord& expected_a, const Sha256HiddenWord& expected_b, const Sha256HiddenWord& expected_c) {
    return
        sha256_hidden_word_eq(trace.a, expected_a) &&
        sha256_hidden_word_eq(trace.b, expected_b) &&
        sha256_hidden_word_eq(trace.c, expected_c) &&
        sha256_hidden_word_xor_trace_ok(trace.left) &&
        sha256_hidden_word_xor_trace_ok(trace.out) &&
        sha256_hidden_word_eq(trace.left.left, trace.a) &&
        sha256_hidden_word_eq(trace.left.right, trace.b) &&
        sha256_hidden_word_eq(trace.out.left, trace.left.out) &&
        sha256_hidden_word_eq(trace.out.right, trace.c);
}

inline Sha256HiddenWord sha256_hidden_sigma_trace_out(const Sha256HiddenSigmaTrace& trace) {
    return trace.out.out;
}

inline Sha256HiddenSigmaTrace sha256_hidden_word_s0_trace(const Sha256HiddenWord& x, Fp a, Fp b) {
    return sha256_hidden_word_sigma_trace(x, sha256_hidden_word_rotr(x, 7), sha256_hidden_word_rotr(x, 18), sha256_hidden_word_shr(x, 3), a, b);
}

inline bool sha256_hidden_word_s0_trace_ok(const Sha256HiddenSigmaTrace& trace) {
    return sha256_hidden_word_sigma_trace_ok(trace, sha256_hidden_word_rotr(trace.input, 7), sha256_hidden_word_rotr(trace.input, 18), sha256_hidden_word_shr(trace.input, 3));
}

inline Sha256HiddenSigmaTrace sha256_hidden_word_s1_trace(const Sha256HiddenWord& x, Fp a, Fp b) {
    return sha256_hidden_word_sigma_trace(x, sha256_hidden_word_rotr(x, 17), sha256_hidden_word_rotr(x, 19), sha256_hidden_word_shr(x, 10), a, b);
}

inline bool sha256_hidden_word_s1_trace_ok(const Sha256HiddenSigmaTrace& trace) {
    return sha256_hidden_word_sigma_trace_ok(trace, sha256_hidden_word_rotr(trace.input, 17), sha256_hidden_word_rotr(trace.input, 19), sha256_hidden_word_shr(trace.input, 10));
}

inline Sha256HiddenSigmaTrace sha256_hidden_word_s2_trace(const Sha256HiddenWord& x, Fp a, Fp b) {
    return sha256_hidden_word_sigma_trace(x, sha256_hidden_word_rotr(x, 2), sha256_hidden_word_rotr(x, 13), sha256_hidden_word_rotr(x, 22), a, b);
}

inline bool sha256_hidden_word_s2_trace_ok(const Sha256HiddenSigmaTrace& trace) {
    return sha256_hidden_word_sigma_trace_ok(trace, sha256_hidden_word_rotr(trace.input, 2), sha256_hidden_word_rotr(trace.input, 13), sha256_hidden_word_rotr(trace.input, 22));
}

inline Sha256HiddenSigmaTrace sha256_hidden_word_s3_trace(const Sha256HiddenWord& x, Fp a, Fp b) {
    return sha256_hidden_word_sigma_trace(x, sha256_hidden_word_rotr(x, 6), sha256_hidden_word_rotr(x, 11), sha256_hidden_word_rotr(x, 25), a, b);
}

inline bool sha256_hidden_word_s3_trace_ok(const Sha256HiddenSigmaTrace& trace) {
    return sha256_hidden_word_sigma_trace_ok(trace, sha256_hidden_word_rotr(trace.input, 6), sha256_hidden_word_rotr(trace.input, 11), sha256_hidden_word_rotr(trace.input, 25));
}

inline Sha256HiddenWord sha256_hidden_word_s0(const Sha256HiddenWord& x, Fp a, Fp b) {
    return sha256_hidden_sigma_trace_out(sha256_hidden_word_s0_trace(x, a, b));
}

inline Sha256HiddenWord sha256_hidden_word_s1(const Sha256HiddenWord& x, Fp a, Fp b) {
    return sha256_hidden_sigma_trace_out(sha256_hidden_word_s1_trace(x, a, b));
}

inline Sha256HiddenWord sha256_hidden_word_s2(const Sha256HiddenWord& x, Fp a, Fp b) {
    return sha256_hidden_sigma_trace_out(sha256_hidden_word_s2_trace(x, a, b));
}

inline Sha256HiddenWord sha256_hidden_word_s3(const Sha256HiddenWord& x, Fp a, Fp b) {
    return sha256_hidden_sigma_trace_out(sha256_hidden_word_s3_trace(x, a, b));
}

inline Sha256HiddenState sha256_hidden_state(const std::array<uint32_t, 8>& state, Fp a, Fp b) {
    Sha256HiddenState out;
    for (size_t i = 0; i < 8; ++i) {
        out.word[i] = sha256_hidden_word(state[i], fp_add(a, fp_from_u64(i * 17 + 1)), fp_add(b, fp_from_u64(i * 19 + 1)));
    }
    return out;
}

inline std::array<uint32_t, 8> sha256_hidden_state_value(const Sha256HiddenState& state) {
    std::array<uint32_t, 8> out{};
    for (size_t i = 0; i < 8; ++i) {
        out[i] = sha256_hidden_word_value(state.word[i]);
    }
    return out;
}

inline bool sha256_hidden_state_bits_ok(const Sha256HiddenState& state) {
    for (const auto& word : state.word) {
        if (!sha256_hidden_word_bits_ok(word))
            return false;
    }
    return true;
}

inline Sha256HiddenScheduleTrace sha256_hidden_schedule_trace(const Sha256HiddenWord& w2, const Sha256HiddenWord& w7, const Sha256HiddenWord& w15, const Sha256HiddenWord& w16, Fp a, Fp b) {
    Sha256HiddenScheduleTrace trace;
    trace.s1 = sha256_hidden_word_s1_trace(w2, fp_add(a, fp_from_u64(1)), fp_add(b, fp_from_u64(1)));
    trace.s0 = sha256_hidden_word_s0_trace(w15, fp_add(a, fp_from_u64(3)), fp_add(b, fp_from_u64(3)));
    trace.sum = sha256_hidden_word_add4_trace(sha256_hidden_sigma_trace_out(trace.s1), w7, sha256_hidden_sigma_trace_out(trace.s0), w16, fp_add(a, fp_from_u64(5)), fp_add(b, fp_from_u64(5)));
    return trace;
}

inline Sha256HiddenWord sha256_hidden_schedule_trace_out(const Sha256HiddenScheduleTrace& trace) {
    return trace.sum.out.out;
}

inline bool sha256_hidden_schedule_trace_ok(const Sha256HiddenScheduleTrace& trace, const Sha256HiddenWord& w2, const Sha256HiddenWord& w7, const Sha256HiddenWord& w15, const Sha256HiddenWord& w16, const Sha256HiddenWord& out) {
    return
        sha256_hidden_word_s1_trace_ok(trace.s1) &&
        sha256_hidden_word_s0_trace_ok(trace.s0) &&
        sha256_hidden_word_add4_trace_ok(trace.sum) &&
        sha256_hidden_word_eq(trace.s1.input, w2) &&
        sha256_hidden_word_eq(trace.s0.input, w15) &&
        sha256_hidden_word_eq(trace.sum.ab.left, sha256_hidden_sigma_trace_out(trace.s1)) &&
        sha256_hidden_word_eq(trace.sum.ab.right, w7) &&
        sha256_hidden_word_eq(trace.sum.cd.left, sha256_hidden_sigma_trace_out(trace.s0)) &&
        sha256_hidden_word_eq(trace.sum.cd.right, w16) &&
        sha256_hidden_word_eq(sha256_hidden_schedule_trace_out(trace), out);
}

inline Sha256HiddenRoundTrace sha256_hidden_round_trace(const Sha256HiddenState& state, const Sha256HiddenWord& w, uint32_t k, Fp a, Fp b) {
    Sha256HiddenRoundTrace trace;
    auto kw = sha256_hidden_word(k, fp_add(a, fp_from_u64(211)), fp_add(b, fp_from_u64(211)));
    trace.s1 = sha256_hidden_word_s3_trace(state.word[4], fp_add(a, fp_from_u64(223)), fp_add(b, fp_from_u64(227)));
    trace.ch = sha256_hidden_word_ch_trace(state.word[4], state.word[5], state.word[6], fp_add(a, fp_from_u64(229)), fp_add(b, fp_from_u64(233)));
    trace.t1 = sha256_hidden_word_add5_trace(state.word[7], sha256_hidden_sigma_trace_out(trace.s1), trace.ch.out, kw, w, fp_add(a, fp_from_u64(239)), fp_add(b, fp_from_u64(241)));
    trace.s0 = sha256_hidden_word_s2_trace(state.word[0], fp_add(a, fp_from_u64(251)), fp_add(b, fp_from_u64(257)));
    trace.maj = sha256_hidden_word_maj_trace(state.word[0], state.word[1], state.word[2], fp_add(a, fp_from_u64(263)), fp_add(b, fp_from_u64(269)));
    trace.t2 = sha256_hidden_word_add2_trace(sha256_hidden_sigma_trace_out(trace.s0), trace.maj.out, fp_add(a, fp_from_u64(271)), fp_add(b, fp_from_u64(277)));
    trace.e = sha256_hidden_word_add2_trace(state.word[3], trace.t1.out.out, fp_add(a, fp_from_u64(281)), fp_add(b, fp_from_u64(283)));
    trace.a = sha256_hidden_word_add2_trace(trace.t1.out.out, trace.t2.out, fp_add(a, fp_from_u64(293)), fp_add(b, fp_from_u64(307)));
    return trace;
}

inline Sha256HiddenState sha256_hidden_round_trace_state(const Sha256HiddenState& state, const Sha256HiddenRoundTrace& trace) {
    Sha256HiddenState out;
    out.word[7] = state.word[6];
    out.word[6] = state.word[5];
    out.word[5] = state.word[4];
    out.word[4] = trace.e.out;
    out.word[3] = state.word[2];
    out.word[2] = state.word[1];
    out.word[1] = state.word[0];
    out.word[0] = trace.a.out;
    return out;
}

inline bool sha256_hidden_round_trace_ok(const Sha256HiddenRoundTrace& trace, const Sha256HiddenState& state, const Sha256HiddenWord& w, uint32_t k, const Sha256HiddenState& out) {
    auto kw = sha256_hidden_word(k, fp_from_u64(1), fp_from_u64(1));
    auto expected = sha256_hidden_round_trace_state(state, trace);
    return
        sha256_hidden_word_s3_trace_ok(trace.s1) &&
        sha256_hidden_word_ch_trace_ok(trace.ch) &&
        sha256_hidden_word_add5_trace_ok(trace.t1) &&
        sha256_hidden_word_s2_trace_ok(trace.s0) &&
        sha256_hidden_word_maj_trace_ok(trace.maj) &&
        sha256_hidden_word_add2_trace_ok(trace.t2) &&
        sha256_hidden_word_add2_trace_ok(trace.e) &&
        sha256_hidden_word_add2_trace_ok(trace.a) &&
        sha256_hidden_word_eq(trace.s1.input, state.word[4]) &&
        sha256_hidden_word_eq(trace.ch.x, state.word[4]) &&
        sha256_hidden_word_eq(trace.ch.y, state.word[5]) &&
        sha256_hidden_word_eq(trace.ch.z, state.word[6]) &&
        sha256_hidden_word_eq(trace.t1.ab.left, state.word[7]) &&
        sha256_hidden_word_eq(trace.t1.ab.right, sha256_hidden_sigma_trace_out(trace.s1)) &&
        sha256_hidden_word_eq(trace.t1.cd.left, trace.ch.out) &&
        sha256_hidden_word_value(trace.t1.cd.right) == k &&
        sha256_hidden_word_eq(trace.t1.out.right, w) &&
        sha256_hidden_word_eq(trace.s0.input, state.word[0]) &&
        sha256_hidden_word_eq(trace.maj.x, state.word[0]) &&
        sha256_hidden_word_eq(trace.maj.y, state.word[1]) &&
        sha256_hidden_word_eq(trace.maj.z, state.word[2]) &&
        sha256_hidden_word_eq(trace.t2.left, sha256_hidden_sigma_trace_out(trace.s0)) &&
        sha256_hidden_word_eq(trace.t2.right, trace.maj.out) &&
        sha256_hidden_word_eq(trace.e.left, state.word[3]) &&
        sha256_hidden_word_eq(trace.e.right, trace.t1.out.out) &&
        sha256_hidden_word_eq(trace.a.left, trace.t1.out.out) &&
        sha256_hidden_word_eq(trace.a.right, trace.t2.out) &&
        sha256_hidden_word_eq(expected.word[7], out.word[7]) &&
        sha256_hidden_word_eq(expected.word[6], out.word[6]) &&
        sha256_hidden_word_eq(expected.word[5], out.word[5]) &&
        sha256_hidden_word_eq(expected.word[4], out.word[4]) &&
        sha256_hidden_word_eq(expected.word[3], out.word[3]) &&
        sha256_hidden_word_eq(expected.word[2], out.word[2]) &&
        sha256_hidden_word_eq(expected.word[1], out.word[1]) &&
        sha256_hidden_word_eq(expected.word[0], out.word[0]) &&
        sha256_hidden_word_bits_ok(kw);
}

inline Sha256HiddenState sha256_hidden_round(const Sha256HiddenState& state, const Sha256HiddenWord& w, uint32_t k, Fp a, Fp b) {
    auto trace = sha256_hidden_round_trace(state, w, k, a, b);
    return sha256_hidden_round_trace_state(state, trace);
}

inline Sha256HiddenGateShare sha256_hidden_gate_share(const Sha256HiddenGate& gate, size_t branch, uint8_t kind) {
    Sha256HiddenGateShare out;
    out.kind = kind;
    out.x = gate.x.v[branch];
    out.y = gate.y.v[branch];
    out.z = gate.z.v[branch];
    return out;
}

inline void sha256_hidden_push_gate_share(std::vector<Sha256HiddenGateShare>& out, const Sha256HiddenGate& gate, size_t branch, uint8_t kind) {
    out.push_back(sha256_hidden_gate_share(gate, branch, kind));
}

inline void sha256_hidden_push_add_bit_shares(std::vector<Sha256HiddenGateShare>& out, const Sha256HiddenAddBitTrace& trace, size_t branch) {
    sha256_hidden_push_gate_share(out, trace.x_y, branch, SHA256_HIDDEN_GATE_XOR);
    sha256_hidden_push_gate_share(out, trace.x_and_y, branch, SHA256_HIDDEN_GATE_AND);
    sha256_hidden_push_gate_share(out, trace.x_and_c, branch, SHA256_HIDDEN_GATE_AND);
    sha256_hidden_push_gate_share(out, trace.y_and_c, branch, SHA256_HIDDEN_GATE_AND);
    sha256_hidden_push_gate_share(out, trace.sum, branch, SHA256_HIDDEN_GATE_XOR);
    sha256_hidden_push_gate_share(out, trace.carry_left, branch, SHA256_HIDDEN_GATE_XOR);
    sha256_hidden_push_gate_share(out, trace.carry, branch, SHA256_HIDDEN_GATE_XOR);
}

inline void sha256_hidden_push_add_word_shares(std::vector<Sha256HiddenGateShare>& out, const Sha256HiddenAddWordTrace& trace, size_t branch) {
    for (const auto& step : trace.step) {
        sha256_hidden_push_add_bit_shares(out, step, branch);
    }
}

inline void sha256_hidden_push_xor_word_shares(std::vector<Sha256HiddenGateShare>& out, const Sha256HiddenXorWordTrace& trace, size_t branch) {
    for (const auto& gate : trace.gate) {
        sha256_hidden_push_gate_share(out, gate, branch, SHA256_HIDDEN_GATE_XOR);
    }
}

inline void sha256_hidden_push_ch_word_shares(std::vector<Sha256HiddenGateShare>& out, const Sha256HiddenChWordTrace& trace, size_t branch) {
    for (size_t i = 0; i < 32; ++i) {
        sha256_hidden_push_gate_share(out, trace.nx[i], branch, SHA256_HIDDEN_GATE_NOT);
        sha256_hidden_push_gate_share(out, trace.xy[i], branch, SHA256_HIDDEN_GATE_AND);
        sha256_hidden_push_gate_share(out, trace.nz[i], branch, SHA256_HIDDEN_GATE_AND);
        sha256_hidden_push_gate_share(out, trace.bit[i], branch, SHA256_HIDDEN_GATE_XOR);
    }
}

inline void sha256_hidden_push_maj_word_shares(std::vector<Sha256HiddenGateShare>& out, const Sha256HiddenMajWordTrace& trace, size_t branch) {
    for (size_t i = 0; i < 32; ++i) {
        sha256_hidden_push_gate_share(out, trace.xy[i], branch, SHA256_HIDDEN_GATE_AND);
        sha256_hidden_push_gate_share(out, trace.xz[i], branch, SHA256_HIDDEN_GATE_AND);
        sha256_hidden_push_gate_share(out, trace.yz[i], branch, SHA256_HIDDEN_GATE_AND);
        sha256_hidden_push_gate_share(out, trace.left[i], branch, SHA256_HIDDEN_GATE_XOR);
        sha256_hidden_push_gate_share(out, trace.bit[i], branch, SHA256_HIDDEN_GATE_XOR);
    }
}

inline void sha256_hidden_push_sigma_shares(std::vector<Sha256HiddenGateShare>& out, const Sha256HiddenSigmaTrace& trace, size_t branch) {
    sha256_hidden_push_xor_word_shares(out, trace.left, branch);
    sha256_hidden_push_xor_word_shares(out, trace.out, branch);
}

inline void sha256_hidden_push_add4_shares(std::vector<Sha256HiddenGateShare>& out, const Sha256HiddenAdd4Trace& trace, size_t branch) {
    sha256_hidden_push_add_word_shares(out, trace.ab, branch);
    sha256_hidden_push_add_word_shares(out, trace.cd, branch);
    sha256_hidden_push_add_word_shares(out, trace.out, branch);
}

inline void sha256_hidden_push_add5_shares(std::vector<Sha256HiddenGateShare>& out, const Sha256HiddenAdd5Trace& trace, size_t branch) {
    sha256_hidden_push_add_word_shares(out, trace.ab, branch);
    sha256_hidden_push_add_word_shares(out, trace.cd, branch);
    sha256_hidden_push_add_word_shares(out, trace.abcd, branch);
    sha256_hidden_push_add_word_shares(out, trace.out, branch);
}

inline void sha256_hidden_push_schedule_shares(std::vector<Sha256HiddenGateShare>& out, const Sha256HiddenScheduleTrace& trace, size_t branch) {
    sha256_hidden_push_sigma_shares(out, trace.s1, branch);
    sha256_hidden_push_sigma_shares(out, trace.s0, branch);
    sha256_hidden_push_add4_shares(out, trace.sum, branch);
}

inline void sha256_hidden_push_round_shares(std::vector<Sha256HiddenGateShare>& out, const Sha256HiddenRoundTrace& trace, size_t branch) {
    sha256_hidden_push_sigma_shares(out, trace.s1, branch);
    sha256_hidden_push_ch_word_shares(out, trace.ch, branch);
    sha256_hidden_push_add5_shares(out, trace.t1, branch);
    sha256_hidden_push_sigma_shares(out, trace.s0, branch);
    sha256_hidden_push_maj_word_shares(out, trace.maj, branch);
    sha256_hidden_push_add_word_shares(out, trace.t2, branch);
    sha256_hidden_push_add_word_shares(out, trace.e, branch);
    sha256_hidden_push_add_word_shares(out, trace.a, branch);
}

inline std::vector<Sha256HiddenGateShare> sha256_hidden_block_gate_shares(const Sha256HiddenBlockProof& block, size_t branch) {
    std::vector<Sha256HiddenGateShare> out;
    out.reserve(162000);
    for (const auto& trace : block.schedule) {
        sha256_hidden_push_schedule_shares(out, trace, branch);
    }
    for (const auto& trace : block.rounds) {
        sha256_hidden_push_round_shares(out, trace, branch);
    }
    for (const auto& trace : block.post_sum) {
        sha256_hidden_push_add_word_shares(out, trace, branch);
    }
    return out;
}

inline Sha256HiddenBlockProof make_sha256_hidden_block_proof(const Sha256TraceBlock& block, Fp a, Fp b) {
    Sha256HiddenBlockProof proof;
    proof.public_block = block;
    proof.schedule.resize(48);
    proof.rounds.resize(64);
    proof.post_sum.resize(8);
    proof.pre = sha256_hidden_state(block.pre, a, b);
    proof.states[0] = proof.pre;
    for (size_t i = 0; i < 16; ++i) {
        proof.words[i] = sha256_hidden_word(block.words[i], fp_add(a, fp_from_u64(i * 17 + 1)), fp_add(b, fp_from_u64(i * 19 + 1)));
    }
    for (size_t i = 16; i < 64; ++i) {
        proof.schedule[i - 16] = sha256_hidden_schedule_trace(proof.words[i - 2], proof.words[i - 7], proof.words[i - 15], proof.words[i - 16], fp_add(a, fp_from_u64(i * 41 + 1)), fp_add(b, fp_from_u64(i * 43 + 1)));
        proof.words[i] = sha256_hidden_schedule_trace_out(proof.schedule[i - 16]);
    }
    for (size_t i = 0; i < 64; ++i) {
        proof.rounds[i] = sha256_hidden_round_trace(proof.states[i], proof.words[i], Sha256::K[i], fp_add(a, fp_from_u64(i * 47 + 1)), fp_add(b, fp_from_u64(i * 53 + 1)));
        proof.states[i + 1] = sha256_hidden_round_trace_state(proof.states[i], proof.rounds[i]);
    }
    for (size_t i = 0; i < 8; ++i) {
        proof.post_sum[i] = sha256_hidden_word_add2_trace(proof.pre.word[i], proof.states[64].word[i], fp_add(a, fp_from_u64(i * 307 + 1)), fp_add(b, fp_from_u64(i * 311 + 1)));
        proof.post.word[i] = proof.post_sum[i].out;
    }
    return proof;
}

inline bool verify_sha256_hidden_block_proof(const Sha256HiddenBlockProof& proof) {
    if (proof.schedule.size() != 48)
        return false;
    if (proof.rounds.size() != 64)
        return false;
    if (proof.post_sum.size() != 8)
        return false;
    if (!sha256_hidden_state_bits_ok(proof.pre))
        return false;
    if (!sha256_hidden_state_bits_ok(proof.post))
        return false;
    for (const auto& word : proof.words) {
        if (!sha256_hidden_word_bits_ok(word))
            return false;
    }
    for (const auto& state : proof.states) {
        if (!sha256_hidden_state_bits_ok(state))
            return false;
    }
    if (sha256_hidden_state_value(proof.pre) != proof.public_block.pre)
        return false;
    if (sha256_hidden_state_value(proof.post) != proof.public_block.post)
        return false;
    if (sha256_hidden_state_value(proof.states[0]) != proof.public_block.pre)
        return false;
    for (size_t i = 0; i < 16; ++i) {
        if (sha256_hidden_word_value(proof.words[i]) != proof.public_block.words[i])
            return false;
    }
    for (size_t i = 16; i < 64; ++i) {
        const auto& trace = proof.schedule[i - 16];
        if (!sha256_hidden_schedule_trace_ok(trace, proof.words[i - 2], proof.words[i - 7], proof.words[i - 15], proof.words[i - 16], proof.words[i]))
            return false;
    }
    for (size_t i = 0; i < 64; ++i) {
        if (!sha256_hidden_round_trace_ok(proof.rounds[i], proof.states[i], proof.words[i], Sha256::K[i], proof.states[i + 1]))
            return false;
    }
    for (size_t i = 0; i < 8; ++i) {
        if (!sha256_hidden_word_add2_trace_ok(proof.post_sum[i]))
            return false;
        if (!sha256_hidden_word_eq(proof.post_sum[i].left, proof.pre.word[i]))
            return false;
        if (!sha256_hidden_word_eq(proof.post_sum[i].right, proof.states[64].word[i]))
            return false;
        if (!sha256_hidden_word_eq(proof.post_sum[i].out, proof.post.word[i]))
            return false;
    }
    return true;
}

inline Sha256HiddenTraceProof make_sha256_hidden_trace_proof(const Sha256Trace& trace, Fp a, Fp b) {
    Sha256HiddenTraceProof proof;
    proof.public_trace = trace;
    proof.blocks.reserve(trace.blocks.size());
    for (size_t i = 0; i < trace.blocks.size(); ++i) {
        proof.blocks.push_back(make_sha256_hidden_block_proof(trace.blocks[i], fp_add(a, fp_from_u64(i * 313 + 1)), fp_add(b, fp_from_u64(i * 317 + 1))));
    }
    return proof;
}

inline bool verify_sha256_hidden_trace_proof(const Sha256HiddenTraceProof& proof) {
    if (!verify_sha256_trace(proof.public_trace))
        return false;
    if (proof.blocks.size() != proof.public_trace.blocks.size())
        return false;
    for (size_t i = 0; i < proof.blocks.size(); ++i) {
        if (!verify_sha256_hidden_block_proof(proof.blocks[i]))
            return false;
        if (proof.blocks[i].public_block.pre != proof.public_trace.blocks[i].pre)
            return false;
        if (proof.blocks[i].public_block.words != proof.public_trace.blocks[i].words)
            return false;
        if (proof.blocks[i].public_block.post != proof.public_trace.blocks[i].post)
            return false;
    }
    if (proof.blocks.empty())
        return false;
    return proof.public_trace.digest == sha256_trace_digest_from_state(proof.blocks.back().public_block.post);
}

inline Sha256HiddenWordShare sha256_hidden_word_share(const Sha256HiddenWord& word, size_t branch) {
    Sha256HiddenWordShare out;
    for (size_t i = 0; i < 32; ++i) {
        out.bit[i] = word.bit[i].v[branch];
    }
    return out;
}

inline Sha256HiddenStateShare sha256_hidden_state_share(const Sha256HiddenState& state, size_t branch) {
    Sha256HiddenStateShare out;
    for (size_t i = 0; i < 8; ++i) {
        out.word[i] = sha256_hidden_word_share(state.word[i], branch);
    }
    return out;
}

inline Sha256HiddenBlockBranch sha256_hidden_block_branch(const Sha256HiddenBlockProof& block, size_t branch) {
    Sha256HiddenBlockBranch out;
    out.branch = branch;
    out.pre = sha256_hidden_state_share(block.pre, branch);
    out.post = sha256_hidden_state_share(block.post, branch);
    for (size_t i = 0; i < 64; ++i) {
        out.words[i] = sha256_hidden_word_share(block.words[i], branch);
    }
    for (size_t i = 0; i < 65; ++i) {
        out.states[i] = sha256_hidden_state_share(block.states[i], branch);
    }
    out.gates = sha256_hidden_block_gate_shares(block, branch);
    return out;
}

inline void sha256_hidden_acc_block_branch(Sha256& h, const Sha256HiddenBlockBranch& branch) {
    sha256_acc_u64(h, branch.branch);
    sha256_hidden_acc_state_share(h, branch.pre);
    sha256_hidden_acc_state_share(h, branch.post);
    for (const auto& word : branch.words) {
        sha256_hidden_acc_word_share(h, word);
    }
    for (const auto& state : branch.states) {
        sha256_hidden_acc_state_share(h, state);
    }
    sha256_acc_u64(h, branch.gates.size());
    for (const auto& gate : branch.gates) {
        sha256_hidden_acc_gate_share(h, gate);
    }
}

inline bool sha256_hidden_gate_share_shape_ok(const Sha256HiddenGateShare& left, const Sha256HiddenGateShare& right) {
    return left.kind == right.kind && left.kind >= SHA256_HIDDEN_GATE_XOR && left.kind <= SHA256_HIDDEN_GATE_NOT;
}

inline bool sha256_hidden_block_branch_shape_ok(const Sha256HiddenBlockBranch& left, const Sha256HiddenBlockBranch& right) {
    if (left.gates.empty())
        return false;
    if (left.gates.size() != right.gates.size())
        return false;
    for (size_t i = 0; i < left.gates.size(); ++i) {
        if (!sha256_hidden_gate_share_shape_ok(left.gates[i], right.gates[i]))
            return false;
    }
    return true;
}

inline Fp sha256_hidden_gate_share_residual(const Sha256HiddenGateShare& self, const Sha256HiddenGateShare& next, size_t branch) {
    Sha256HiddenGateOpen open;
    open.branch = branch;
    open.x = self.x;
    open.y = self.y;
    open.z = self.z;
    open.xn = next.x;
    open.yn = next.y;
    open.zn = next.z;
    if (self.kind == SHA256_HIDDEN_GATE_XOR)
        return sha256_hidden_xor_residual(open);
    if (self.kind == SHA256_HIDDEN_GATE_AND)
        return sha256_hidden_and_residual(open);
    if (self.kind == SHA256_HIDDEN_GATE_NOT)
        return sha256_hidden_not_residual(open);
    return fp_from_u64(1);
}

inline bool sha256_hidden_block_branch_residuals_ok(const Sha256HiddenBlockBranch& self, const Sha256HiddenBlockBranch& next) {
    if ((self.branch + 1) % 3 != next.branch)
        return false;
    if (!sha256_hidden_block_branch_shape_ok(self, next))
        return false;
    for (size_t i = 0; i < self.gates.size(); ++i) {
        auto residual = sha256_hidden_gate_share_residual(self.gates[i], next.gates[i], self.branch);
        if (!sha256_hidden_fp_eq(residual, fp_from_u64(0)))
            return false;
    }
    return true;
}

inline std::array<uint8_t, 32> sha256_hidden_block_branch_commit(const Sha256HiddenBlockBranch& branch) {
    Sha256 h;
    h.init();
    sha256_hidden_acc_domain(h, "pvac.native.sha256.branch");
    sha256_hidden_acc_block_branch(h, branch);
    std::array<uint8_t, 32> out{};
    h.finish(out.data());
    return out;
}

inline std::array<uint8_t, 32> sha256_hidden_trace_branch_challenge(const Sha256HiddenTraceBranchProof& proof) {
    Sha256 h;
    h.init();
    sha256_hidden_acc_domain(h, "pvac.native.sha256.challenge");
    sha256_acc_u64(h, proof.byte_len);
    sha256_acc_u64(h, proof.blocks);
    h.update(proof.digest.data(), proof.digest.size());
    for (const auto& commit : proof.commits) {
        h.update(commit.data(), commit.size());
    }
    // Bind the revealed per-branch output shares into the Fiat-Shamir challenge so the
    // prover cannot pick them after seeing which branch stays closed.
    for (const auto& share : proof.final_post) {
        sha256_hidden_acc_state_share(h, share);
    }
    std::array<uint8_t, 32> out{};
    h.finish(out.data());
    return out;
}

// Reconstruct the SHA-256 output words from the three branch shares of the final state.
inline std::array<uint32_t, 8> sha256_hidden_reconstruct_state(const std::array<Sha256HiddenStateShare, 3>& shares) {
    std::array<uint32_t, 8> out{};
    for (size_t i = 0; i < 8; ++i) {
        for (size_t j = 0; j < 32; ++j) {
            Fp v = fp_add(fp_add(shares[0].word[i].bit[j], shares[1].word[i].bit[j]), shares[2].word[i].bit[j]);
            if (!sha256_hidden_fp_eq(v, fp_from_u64(0))) {
                out[i] |= static_cast<uint32_t>(1) << j;
            }
        }
    }
    return out;
}

inline bool sha256_hidden_state_share_eq(const Sha256HiddenStateShare& a, const Sha256HiddenStateShare& b) {
    for (size_t i = 0; i < 8; ++i) {
        for (size_t j = 0; j < 32; ++j) {
            if (!sha256_hidden_fp_eq(a.word[i].bit[j], b.word[i].bit[j])) {
                return false;
            }
        }
    }
    return true;
}

inline std::array<uint8_t, 32> sha256_hidden_trace_branch_response(const Sha256HiddenTraceBranchProof& proof) {
    Sha256 h;
    h.init();
    sha256_hidden_acc_domain(h, "pvac.native.sha256.response");
    h.update(proof.challenge.data(), proof.challenge.size());
    sha256_acc_u64(h, proof.openings.size());
    for (const auto& opening : proof.openings) {
        sha256_hidden_acc_block_branch(h, opening);
        h.update(opening.commit.data(), opening.commit.size());
    }
    std::array<uint8_t, 32> out{};
    h.finish(out.data());
    return out;
}

inline std::array<uint8_t, 32> sha256_hidden_trace_branch_proof_digest(const Sha256HiddenTraceBranchProof& proof) {
    Sha256 h;
    h.init();
    sha256_hidden_acc_domain(h, "pvac.native.sha256.branch_proof");
    sha256_acc_u64(h, proof.byte_len);
    sha256_acc_u64(h, proof.blocks);
    h.update(proof.digest.data(), proof.digest.size());
    h.update(proof.challenge.data(), proof.challenge.size());
    h.update(proof.response_digest.data(), proof.response_digest.size());
    for (const auto& commit : proof.commits) {
        h.update(commit.data(), commit.size());
    }
    sha256_acc_u64(h, proof.openings.size());
    for (const auto& opening : proof.openings) {
        h.update(opening.commit.data(), opening.commit.size());
    }
    sha256_acc_u64(h, proof.message_hidden ? 1 : 0);
    sha256_acc_u64(h, proof.schedule_trace ? 1 : 0);
    sha256_acc_u64(h, proof.compression_trace ? 1 : 0);
    sha256_acc_u64(h, proof.digest_bound ? 1 : 0);
    sha256_acc_u64(h, proof.native_backend ? 1 : 0);
    sha256_acc_u64(h, proof.has_raw_message ? 1 : 0);
    std::array<uint8_t, 32> out{};
    h.finish(out.data());
    return out;
}

inline Sha256HiddenTraceBranchProof make_sha256_hidden_trace_branch_proof(const Sha256HiddenTraceProof& trace) {
    Sha256HiddenTraceBranchProof proof;
    proof.byte_len = trace.public_trace.byte_len;
    proof.blocks = trace.blocks.size();
    proof.digest = trace.public_trace.digest;
    proof.message_hidden = true;
    proof.schedule_trace = true;
    proof.compression_trace = true;
    proof.digest_bound = true;
    proof.native_backend = true;
    std::array<std::vector<Sha256HiddenBlockBranch>, 3> by_branch;
    for (const auto& block : trace.blocks) {
        for (size_t branch = 0; branch < 3; ++branch) {
            auto view = sha256_hidden_block_branch(block, branch);
            view.commit = sha256_hidden_block_branch_commit(view);
            by_branch[branch].push_back(view);
        }
    }
    // Reveal each branch's final output-state share so the verifier can reconstruct the
    // digest and bind it. Revealing all three shares only reveals the public output.
    for (size_t branch = 0; branch < 3; ++branch) {
        proof.final_post[branch] = by_branch[branch].back().post;
    }
    for (size_t branch = 0; branch < 3; ++branch) {
        Sha256 h;
        h.init();
        sha256_hidden_acc_domain(h, "pvac.native.sha256.trace_branch");
        sha256_acc_u64(h, branch);
        for (const auto& view : by_branch[branch]) {
            h.update(view.commit.data(), view.commit.size());
        }
        h.finish(proof.commits[branch].data());
    }
    proof.challenge = sha256_hidden_trace_branch_challenge(proof);
    size_t closed = static_cast<size_t>(proof.challenge[0]) % 3;
    for (size_t branch = 0; branch < 3; ++branch) {
        if (branch == closed)
            continue;
        for (const auto& view : by_branch[branch]) {
            proof.openings.push_back(view);
        }
    }
    proof.response_digest = sha256_hidden_trace_branch_response(proof);
    return proof;
}

inline bool verify_sha256_hidden_trace_branch_proof(const Sha256HiddenTraceBranchProof& proof) {
    if (proof.has_raw_message)
        return false;
    if (!proof.message_hidden || !proof.schedule_trace || !proof.compression_trace || !proof.digest_bound || !proof.native_backend)
        return false;
    if (proof.blocks == 0)
        return false;
    if (proof.openings.size() != proof.blocks * 2)
        return false;
    if (proof.challenge != sha256_hidden_trace_branch_challenge(proof))
        return false;
    size_t closed = static_cast<size_t>(proof.challenge[0]) % 3;
    std::array<std::vector<Sha256HiddenBlockBranch>, 3> opened;
    size_t pos = 0;
    for (size_t branch = 0; branch < 3; ++branch) {
        if (branch == closed)
            continue;
        for (size_t block = 0; block < proof.blocks; ++block) {
            const auto& view = proof.openings[pos++];
            if (view.branch != branch)
                return false;
            auto commit = sha256_hidden_block_branch_commit(view);
            if (commit != view.commit)
                return false;
            opened[branch].push_back(view);
        }
    }
    auto left = (closed + 1) % 3;
    auto right = (closed + 2) % 3;
    if (opened[left].size() != proof.blocks || opened[right].size() != proof.blocks)
        return false;
    for (size_t block = 0; block < proof.blocks; ++block) {
        if (!sha256_hidden_block_branch_shape_ok(opened[left][block], opened[right][block]))
            return false;
        if (!sha256_hidden_block_branch_residuals_ok(opened[left][block], opened[right][block]))
            return false;
    }
    for (size_t branch = 0; branch < 3; ++branch) {
        if (branch == closed)
            continue;
        Sha256 h;
        h.init();
        sha256_hidden_acc_domain(h, "pvac.native.sha256.trace_branch");
        sha256_acc_u64(h, branch);
        for (const auto& view : opened[branch]) {
            h.update(view.commit.data(), view.commit.size());
        }
        std::array<uint8_t, 32> out{};
        h.finish(out.data());
        if (out != proof.commits[branch])
            return false;
    }
    // Bind proof.digest to the traced computation: reconstruct the output from the three
    // revealed final-state shares and require it to equal the claimed digest. Require each
    // opened branch's revealed share to match its verified view, so the two opened shares
    // are the real computation's output shares (only the closed share is unchecked, which
    // is what the per-repetition soundness of the outer certificate must cover).
    auto out_state = sha256_hidden_reconstruct_state(proof.final_post);
    if (sha256_trace_digest_from_state(out_state) != proof.digest)
        return false;
    if (!sha256_hidden_state_share_eq(proof.final_post[left], opened[left].back().post))
        return false;
    if (!sha256_hidden_state_share_eq(proof.final_post[right], opened[right].back().post))
        return false;
    return proof.response_digest == sha256_hidden_trace_branch_response(proof);
}

}