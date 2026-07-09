#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <algorithm>
#include <stdexcept>

#include "../core/types.hpp"
#include "../ops/encrypt.hpp"
#include "../ops/decrypt.hpp"

namespace pvac {

inline Fp pack_15_bytes_to_fp(const uint8_t* p, size_t len) {
    uint64_t lo = 0, hi = 0;

    for (size_t i = 0; i < len && i < 15; i++) {
        uint64_t b = p[i];
        size_t sh = i * 8;
        if (sh < 64) lo |= b << sh;
        else hi |= b << (sh - 64);
    }

    return fp_from_words(lo, hi);
}

inline void unpack_fp_to_15_bytes(const Fp& x, uint8_t* out) {
    uint64_t lo = x.lo, hi = x.hi;

    for (size_t i = 0; i < 15; i++) {
        size_t sh = i * 8;
        out[i] = (sh < 64)
            ? (uint8_t)((lo >> sh) & 0xFF)
            : (uint8_t)((hi >> (sh - 64)) & 0xFF);
    }
}

inline std::vector<Cipher> enc_text(
    const PubKey& pk,
    const SecKey& sk,
    const std::string& msg
) {
    std::vector<Cipher> out;
    out.push_back(enc_value(pk, sk, (uint64_t)msg.size()));

    const uint8_t* p = (const uint8_t*)msg.data();
    size_t n = msg.size();
    size_t pos = 0;
    int depth_hint = 2;

    while (pos < n) {
        size_t take = std::min((size_t)15, n - pos);
        Fp x = pack_15_bytes_to_fp(p + pos, take);
        out.push_back(enc_fp_wrapped_depth(pk, sk, x, depth_hint));
        pos += take;
        depth_hint++;
    }

    return out;
}

inline std::string dec_text(
    const PubKey& pk,
    const SecKey& sk,
    const std::vector<Cipher>& cts
) {
    if (cts.empty()) return {};

    Fp flen = dec_value(pk, sk, cts[0]);
    if (flen.hi != 0) throw std::runtime_error("pvac: text length rejected");

    uint64_t len = flen.lo;
    uint64_t max_len = static_cast<uint64_t>(cts.size() - 1) * 15;
    if (len > max_len) throw std::runtime_error("pvac: text length exceeds block count");
    std::vector<uint8_t> buf;
    buf.reserve((size_t)len + 16);

    for (size_t i = 1; i < cts.size(); ++i) {
        Fp fx = dec_value(pk, sk, cts[i]);
        uint8_t block[15];
        unpack_fp_to_15_bytes(fx, block);
        for (int j = 0; j < 15; j++) buf.push_back(block[j]);
    }

    return std::string((const char*)buf.data(), (size_t)len);
}

}