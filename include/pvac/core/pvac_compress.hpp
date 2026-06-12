#pragma once

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <stdexcept>

namespace pvac {
namespace compress {

static constexpr uint8_t PVAC_COMPRESSED_TAG = 0xEC;

namespace detail {

struct AdaptiveState {
    const int n_states;
    int prev;
    uint32_t* ctx;
    static int rate_table[256];
    static bool rate_init;

    AdaptiveState(int n = 256) : n_states(n), prev(0) {
        ctx = (uint32_t*)calloc(n_states, sizeof(uint32_t));
        if (!ctx) throw std::runtime_error("pvac_compress: alloc failed");
        for (int i = 0; i < n_states; ++i) {
            uint32_t w = (i & 1) * 2 + (i & 2) + (i >> 2 & 1) + (i >> 3 & 1)
                       + (i >> 4 & 1) + (i >> 5 & 1) + (i >> 6 & 1) + (i >> 7 & 1) + 3;
            ctx[i] = w << 28 | 6;
        }
        if (!rate_init) {
            for (int i = 0; i < 256; ++i)
                rate_table[i] = 32768 / (i + i + 3);
            rate_init = true;
        }
    }

    ~AdaptiveState() { free(ctx); }

    int predict(int s) {
        prev = s;
        return ctx[s] >> 16;
    }

    void update(int bit, int limit = 255) {
        int cnt = ctx[prev] & 255;
        int p = ctx[prev] >> 14;
        if (cnt < limit) {
            ++ctx[prev];
            ctx[prev] += ((bit << 18) - p) * rate_table[cnt] & 0xffffff00;
        }
    }
};

bool AdaptiveState::rate_init = false;
int AdaptiveState::rate_table[256] = {0};

struct Predictor {
    int prev;
    AdaptiveState matrix;
    int order[256];

    Predictor() : prev(0), matrix(0x10000) {
        for (int i = 0; i < 256; ++i) order[i] = 0x66;
    }

    int predict() {
        return matrix.predict(prev << 8 | order[prev]);
    }

    void update(int bit) {
        matrix.update(bit, 90);
        int& s = order[prev];
        (s += s + bit) &= 255;
        if ((prev += prev + bit) >= 256) prev = 0;
    }
};

struct RangeEncoder {
    Predictor pred;
    std::vector<uint8_t>& out;
    uint32_t lo, hi;

    RangeEncoder(std::vector<uint8_t>& dst)
        : out(dst), lo(0), hi(0xffffffff) {}

    void encode_bit(int bit) {
        uint32_t p = pred.predict();
        uint32_t mid = lo + ((hi - lo) >> 16) * p
                     + (((hi - lo) & 0xffff) * p >> 16);
        if (bit)
            hi = mid;
        else
            lo = mid + 1;
        pred.update(bit);
        while (((lo ^ hi) & 0xff000000) == 0) {
            out.push_back(hi >> 24);
            lo <<= 8;
            hi = (hi << 8) + 255;
        }
    }

    void flush() {
        while (((lo ^ hi) & 0xff000000) == 0) {
            out.push_back(hi >> 24);
            lo <<= 8;
            hi = (hi << 8) + 255;
        }
        out.push_back(hi >> 24);
    }

    void encode_byte(uint8_t b) {
        encode_bit(1);
        for (int i = 7; i >= 0; --i)
            encode_bit((b >> i) & 1);
    }

    void encode_eof() {
        encode_bit(0);
    }
};

struct RangeDecoder {
    Predictor pred;
    const uint8_t* src;
    size_t src_len;
    size_t pos;
    uint32_t lo, hi, code;

    RangeDecoder(const uint8_t* data, size_t len)
        : src(data), src_len(len), pos(0), lo(0), hi(0xffffffff), code(0) {
        for (int i = 0; i < 4; ++i)
            code = (code << 8) + next_byte();
    }

    uint8_t next_byte() {
        return pos < src_len ? src[pos++] : 0;
    }

    int decode_bit() {
        uint32_t p = pred.predict();
        uint32_t mid = lo + ((hi - lo) >> 16) * p
                     + (((hi - lo) & 0xffff) * p >> 16);
        int bit = 0;
        if (code <= mid) {
            bit = 1;
            hi = mid;
        } else {
            lo = mid + 1;
        }
        pred.update(bit);
        while (((lo ^ hi) & 0xff000000) == 0) {
            lo <<= 8;
            hi = (hi << 8) + 255;
            code = (code << 8) + next_byte();
        }
        return bit;
    }

    int decode_byte_or_eof() {
        if (!decode_bit()) return -1;
        int b = 1;
        while (b < 256)
            b += b + decode_bit();
        return b - 256;
    }
};

}

inline std::vector<uint8_t> pack(const uint8_t* raw, size_t raw_len) {
    std::vector<uint8_t> out;
    out.reserve(raw_len / 4);
    out.push_back(PVAC_COMPRESSED_TAG);
    uint32_t sz = (uint32_t)raw_len;
    out.push_back(sz >> 24);
    out.push_back(sz >> 16);
    out.push_back(sz >> 8);
    out.push_back(sz & 0xff);

    detail::RangeEncoder enc(out);
    for (size_t i = 0; i < raw_len; ++i)
        enc.encode_byte(raw[i]);
    enc.encode_eof();
    enc.flush();
    return out;
}

inline std::vector<uint8_t> pack(const std::vector<uint8_t>& raw) {
    return pack(raw.data(), raw.size());
}

inline std::vector<uint8_t> unpack(const uint8_t* data, size_t len) {
    if (len < 5 || data[0] != PVAC_COMPRESSED_TAG)
        throw std::runtime_error("pvac_compress: bad header");
    uint32_t orig_sz = (uint32_t)data[1] << 24
                     | (uint32_t)data[2] << 16
                     | (uint32_t)data[3] << 8
                     | (uint32_t)data[4];
    if (orig_sz > 64 * 1024 * 1024)
        throw std::runtime_error("pvac_compress: size exceeds 64MB limit");

    detail::RangeDecoder dec(data + 5, len - 5);
    std::vector<uint8_t> out;
    out.reserve(orig_sz);
    int b;
    while ((b = dec.decode_byte_or_eof()) >= 0) {
        if (out.size() >= orig_sz)
            throw std::runtime_error("pvac_compress: output exceeds declared size");
        out.push_back((uint8_t)b);
    }
    if (out.size() != orig_sz)
        throw std::runtime_error("pvac_compress: size mismatch");
    return out;
}

inline std::vector<uint8_t> unpack(const std::vector<uint8_t>& data) {
    return unpack(data.data(), data.size());
}

inline bool is_packed(const uint8_t* data, size_t len) {
    return len >= 1 && data[0] == PVAC_COMPRESSED_TAG;
}

}
}