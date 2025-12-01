#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <iostream>
#include <algorithm>

#include "../core/types.hpp"
#include "../ops/encrypt.hpp"
#include "../ops/decrypt.hpp"

namespace pvac {


inline Fp pack_15_bytes_to_fp(const uint8_t * p, size_t len) 
{
    uint64_t lo = 0;
    uint64_t hi = 0;

    for (size_t i = 0; i < len && i < 15; i++) {
        uint64_t b  = p[i];
        size_t   sh = i * 8;

        if (sh < 64) {
            lo |= b << sh;
        } else {
            hi |= b << (sh - 64);
        }
    }

    return fp_from_words(lo, hi);
}

inline void unpack_fp_to_15_bytes(const Fp & x, uint8_t * out) {
    uint64_t lo = x.lo;
    uint64_t hi = x.hi;

    for (size_t i = 0; i < 15; i++) {
        size_t  sh = i * 8;
        uint8_t b;

        if (sh < 64) {
            b = (uint8_t)((lo >> sh) & 0xFF);
        } else {
            b = (uint8_t)((hi >> (sh - 64)) & 0xFF);
        }

        out[i] = b;
    }
}

inline std::vector<Cipher> enc_text(
    const PubKey &      pk,
    const SecKey &      sk,
    const std::string & msg
) {
    std::vector<Cipher> out;

    uint64_t len = (uint64_t)msg.size();
    out.push_back(enc_value(pk, sk, len));

    const uint8_t * p   = (const uint8_t *)msg.data();
    size_t          n   = msg.size();
    size_t          pos = 0;
    int             depth_hint = 2;

    while (pos < n) {
        size_t take = std::min((size_t)15, n - pos);
        Fp     x    = pack_15_bytes_to_fp(p + pos, take);
        Cipher C    = enc_fp_depth(pk, sk, x, depth_hint);

        out.push_back(std::move(C));

        pos += take;
        depth_hint++;
    }

    return out;
}

inline std::string dec_text(
    const PubKey &               pk,
    const SecKey &               sk,
    const std::vector<Cipher> &  cts
) {
    if (cts.empty()) {
        return {};
    }

    Fp flen = dec_value(pk, sk, cts[0]);

    if (flen.hi != 0) {
        std::cerr << "text length hi! = 0 clipping\n";
    }

    uint64_t len = flen.lo;

    std::vector<uint8_t> buf;
    buf.reserve((size_t)len + 16);

    for (size_t i = 1; i < cts.size(); ++i) {
        Fp      fx = dec_value(pk, sk, cts[i]);
        uint8_t block[15];


        unpack_fp_to_15_bytes(fx, block);

        for (int j = 0; j < 15; j++) {
            buf.push_back(block[j]);
        }
    }

    if (buf.size() < len) {
        len = (uint64_t)buf.size();
    }

    return std::string((const char *)buf.data(), (size_t)len);
}

}
