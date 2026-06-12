/*
 * octra labs
 * lambda0xe, denis cmix, J.
 */




#pragma once

#include <array>
#include <cstdint>
#include <vector>

#include "../core/hash.hpp"

namespace pvac {

struct Sha256TraceBlock {
    std::array<uint32_t, 8> pre = {};
    std::array<uint32_t, 64> words = {};
    std::array<uint32_t, 8> post = {};
};

struct Sha256Trace {
    uint64_t byte_len = 0;
    std::vector<uint8_t> message;
    std::vector<Sha256TraceBlock> blocks;
    std::array<uint8_t, 32> digest = {};
};

inline uint32_t sha256_trace_load_be32(const uint8_t* p) {
    return
        (static_cast<uint32_t>(p[0]) << 24) |
        (static_cast<uint32_t>(p[1]) << 16) |
        (static_cast<uint32_t>(p[2]) << 8) |
        static_cast<uint32_t>(p[3]);
}

inline void sha256_trace_store_be64(std::vector<uint8_t>& out, uint64_t x) {
    for (int i = 7; i >= 0; --i) {
        out.push_back(static_cast<uint8_t>((x >> (i * 8)) & 0xff));
    }
}

inline void sha256_trace_store_le64(std::vector<uint8_t>& out, uint64_t x) {
    for (int i = 0; i < 8; ++i) {
        out.push_back(static_cast<uint8_t>((x >> (i * 8)) & 0xff));
    }
}

inline uint32_t sha256_trace_rotr(uint32_t x, uint32_t n) {
    return (x >> n) | (x << (32 - n));
}

inline uint32_t sha256_trace_ch(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (~x & z);
}

inline uint32_t sha256_trace_maj(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

inline uint32_t sha256_trace_s0(uint32_t x) {
    return sha256_trace_rotr(x, 2) ^ sha256_trace_rotr(x, 13) ^ sha256_trace_rotr(x, 22);
}

inline uint32_t sha256_trace_s1(uint32_t x) {
    return sha256_trace_rotr(x, 6) ^ sha256_trace_rotr(x, 11) ^ sha256_trace_rotr(x, 25);
}

inline uint32_t sha256_trace_w0(uint32_t x) {
    return sha256_trace_rotr(x, 7) ^ sha256_trace_rotr(x, 18) ^ (x >> 3);
}

inline uint32_t sha256_trace_w1(uint32_t x) {
    return sha256_trace_rotr(x, 17) ^ sha256_trace_rotr(x, 19) ^ (x >> 10);
}

inline std::vector<uint8_t> sha256_trace_pad(const std::vector<uint8_t>& message) {
    auto out = message;
    uint64_t bit_len = static_cast<uint64_t>(message.size()) * 8;
    out.push_back(0x80);
    while ((out.size() % 64) != 56) {
        out.push_back(0);
    }
    sha256_trace_store_be64(out, bit_len);
    return out;
}

inline std::array<uint8_t, 32> sha256_trace_digest_from_state(const std::array<uint32_t, 8>& state) {
    std::array<uint8_t, 32> out{};
    for (size_t i = 0; i < state.size(); ++i) {
        out[4 * i + 0] = static_cast<uint8_t>((state[i] >> 24) & 0xff);
        out[4 * i + 1] = static_cast<uint8_t>((state[i] >> 16) & 0xff);
        out[4 * i + 2] = static_cast<uint8_t>((state[i] >> 8) & 0xff);
        out[4 * i + 3] = static_cast<uint8_t>(state[i] & 0xff);
    }
    return out;
}

inline Sha256TraceBlock sha256_trace_block(const uint8_t* block, const std::array<uint32_t, 8>& pre) {
    Sha256TraceBlock out;
    out.pre = pre;
    for (size_t i = 0; i < 16; ++i) {
        out.words[i] = sha256_trace_load_be32(block + 4 * i);
    }
    for (size_t i = 16; i < 64; ++i) {
        out.words[i] =
            sha256_trace_w1(out.words[i - 2]) +
            out.words[i - 7] +
            sha256_trace_w0(out.words[i - 15]) +
            out.words[i - 16];
    }
    uint32_t a = pre[0];
    uint32_t b = pre[1];
    uint32_t c = pre[2];
    uint32_t d = pre[3];
    uint32_t e = pre[4];
    uint32_t f = pre[5];
    uint32_t g = pre[6];
    uint32_t h = pre[7];
    for (size_t i = 0; i < 64; ++i) {
        uint32_t t1 = h + sha256_trace_s1(e) + sha256_trace_ch(e, f, g) + Sha256::K[i] + out.words[i];
        uint32_t t2 = sha256_trace_s0(a) + sha256_trace_maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }
    out.post[0] = pre[0] + a;
    out.post[1] = pre[1] + b;
    out.post[2] = pre[2] + c;
    out.post[3] = pre[3] + d;
    out.post[4] = pre[4] + e;
    out.post[5] = pre[5] + f;
    out.post[6] = pre[6] + g;
    out.post[7] = pre[7] + h;
    return out;
}

inline Sha256Trace make_sha256_trace(const std::vector<uint8_t>& message) {
    Sha256Trace trace;
    trace.byte_len = message.size();
    trace.message = message;
    std::array<uint32_t, 8> state = {
        0x6a09e667,
        0xbb67ae85,
        0x3c6ef372,
        0xa54ff53a,
        0x510e527f,
        0x9b05688c,
        0x1f83d9ab,
        0x5be0cd19
    };
    auto padded = sha256_trace_pad(message);
    trace.blocks.reserve(padded.size() / 64);
    for (size_t off = 0; off < padded.size(); off += 64) {
        auto block = sha256_trace_block(padded.data() + off, state);
        state = block.post;
        trace.blocks.push_back(block);
    }
    trace.digest = sha256_trace_digest_from_state(state);
    return trace;
}

inline bool verify_sha256_trace(const Sha256Trace& trace) {
    if (trace.byte_len != trace.message.size())
        return false;
    std::array<uint32_t, 8> state = {
        0x6a09e667,
        0xbb67ae85,
        0x3c6ef372,
        0xa54ff53a,
        0x510e527f,
        0x9b05688c,
        0x1f83d9ab,
        0x5be0cd19
    };
    auto padded = sha256_trace_pad(trace.message);
    if (trace.blocks.size() != padded.size() / 64)
        return false;
    for (size_t off = 0, id = 0; off < padded.size(); off += 64, ++id) {
        auto block = sha256_trace_block(padded.data() + off, state);
        if (trace.blocks[id].pre != block.pre)
            return false;
        if (trace.blocks[id].words != block.words)
            return false;
        if (trace.blocks[id].post != block.post)
            return false;
        state = block.post;
    }
    return trace.digest == sha256_trace_digest_from_state(state);
}

inline std::vector<uint8_t> sha256_trace_r_com_base_message(uint64_t canon_tag, uint64_t ztag, uint64_t nonce_lo, uint64_t nonce_hi, const std::vector<Fp>& r_slots) {
    std::vector<uint8_t> out;
    const char* domain = "pvac.dom.r_com";
    out.insert(out.end(), domain, domain + 14);
    sha256_trace_store_le64(out, canon_tag);
    sha256_trace_store_le64(out, ztag);
    sha256_trace_store_le64(out, nonce_lo);
    sha256_trace_store_le64(out, nonce_hi);
    sha256_trace_store_le64(out, r_slots.size());
    for (const auto& r : r_slots) {
        sha256_trace_store_le64(out, r.lo);
        sha256_trace_store_le64(out, r.hi & MASK63);
    }
    return out;
}

inline std::vector<uint8_t> sha256_trace_r_com_prod_message(const std::array<uint8_t, 32>& left, const std::array<uint8_t, 32>& right) {
    std::vector<uint8_t> out;
    const char* domain = "pvac.dom.r_com";
    out.insert(out.end(), domain, domain + 14);
    out.insert(out.end(), left.begin(), left.end());
    out.insert(out.end(), right.begin(), right.end());
    return out;
}

inline Sha256Trace make_r_com_base_sha256_trace(uint64_t canon_tag, uint64_t ztag, uint64_t nonce_lo, uint64_t nonce_hi, const std::vector<Fp>& r_slots) {
    return make_sha256_trace(sha256_trace_r_com_base_message(canon_tag, ztag, nonce_lo, nonce_hi, r_slots));
}

inline Sha256Trace make_r_com_prod_sha256_trace(const std::array<uint8_t, 32>& left, const std::array<uint8_t, 32>& right) {
    return make_sha256_trace(sha256_trace_r_com_prod_message(left, right));
}

inline bool verify_r_com_base_sha256_trace(const Sha256Trace& trace, uint64_t canon_tag, uint64_t ztag, uint64_t nonce_lo, uint64_t nonce_hi, const std::vector<Fp>& r_slots, const std::array<uint8_t, 32>& digest) {
    return
        trace.message == sha256_trace_r_com_base_message(canon_tag, ztag, nonce_lo, nonce_hi, r_slots) &&
        trace.digest == digest &&
        verify_sha256_trace(trace);
}

inline bool verify_r_com_prod_sha256_trace(const Sha256Trace& trace, const std::array<uint8_t, 32>& left, const std::array<uint8_t, 32>& right, const std::array<uint8_t, 32>& digest) {
    return
        trace.message == sha256_trace_r_com_prod_message(left, right) &&
        trace.digest == digest &&
        verify_sha256_trace(trace);
}

}