#pragma once

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <algorithm>
#include <sstream>
#include <iomanip>

#include "random.hpp"

namespace pvac {

inline std::string hex8(const uint8_t* d, size_t n) {
    std::ostringstream os;
    os << std::hex << std::setfill('0');
    for (size_t i = 0; i < n; i++) {
        os << std::setw(2) << (unsigned)d[i];
    }
    return os.str();
}

struct Sha256 {
    uint32_t h[8];
    uint64_t len;
    uint8_t buf[64];
    size_t ptr;

    static constexpr uint32_t K[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

    static uint32_t rotr(uint32_t x, uint32_t n) {
        return (x >> n) | (x << (32 - n));
    }

    static uint32_t Ch(uint32_t x, uint32_t y, uint32_t z) {
        return (x & y) ^ (~x & z);
    }

    static uint32_t Maj(uint32_t x, uint32_t y, uint32_t z) {
        return (x & y) ^ (x & z) ^ (y & z);
    }

    static uint32_t S0(uint32_t x) {
        return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
    }

    static uint32_t S1(uint32_t x) {
        return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
    }

    static uint32_t s0(uint32_t x) {
        return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
    }

    static uint32_t s1(uint32_t x) {
        return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
    }

    void init() {
        h[0] = 0x6a09e667;
        h[1] = 0xbb67ae85;
        h[2] = 0x3c6ef372;
        h[3] = 0xa54ff53a;
        h[4] = 0x510e527f;
        h[5] = 0x9b05688c;
        h[6] = 0x1f83d9ab;
        h[7] = 0x5be0cd19;
        len = 0;
        ptr = 0;
    }

    void process(const uint8_t* p) {
        uint32_t w[64];

        for (int i = 0; i < 16; i++) {
            w[i] = ((uint32_t)p[4 * i + 0] << 24) |
                   ((uint32_t)p[4 * i + 1] << 16) |
                   ((uint32_t)p[4 * i + 2] << 8) |
                   ((uint32_t)p[4 * i + 3]);
        }

        for (int i = 16; i < 64; i++) {
            w[i] = s1(w[i - 2]) + w[i - 7] + s0(w[i - 15]) + w[i - 16];
        }

        uint32_t a = h[0];
        uint32_t b = h[1];
        uint32_t c = h[2];
        uint32_t d = h[3];
        uint32_t e = h[4];
        uint32_t f = h[5];
        uint32_t g = h[6];
        uint32_t hh = h[7];

        for (int i = 0; i < 64; i++) {
            uint32_t T1 = hh + S1(e) + Ch(e, f, g) + K[i] + w[i];
            uint32_t T2 = S0(a) + Maj(a, b, c);
            hh = g;
            g = f;
            f = e;
            e = d + T1;
            d = c;
            c = b;
            b = a;
            a = T1 + T2;
        }

        h[0] += a;
        h[1] += b;
        h[2] += c;
        h[3] += d;
        h[4] += e;
        h[5] += f;
        h[6] += g;
        h[7] += hh;
    }

    void update(const void* data, size_t n) {
        const uint8_t* p = (const uint8_t*)data;
        len += n;

        while (n) {
            size_t take = std::min((size_t)64 - ptr, n);
            std::memcpy(buf + ptr, p, take);
            ptr += take;
            p += take;
            n -= take;

            if (ptr == 64) {
                process(buf);
                ptr = 0;
            }
        }
    }

    void finish(uint8_t out[32]) {
        uint64_t bitlen = len * 8;

        uint8_t b0 = 0x80;
        update(&b0, 1);

        uint8_t z = 0;
        while (ptr != 56) {
            update(&z, 1);
        }

        uint8_t be[8];
        for (int i = 0; i < 8; i++) {
            be[7 - i] = (uint8_t)(bitlen >> (i * 8));
        }
        update(be, 8);

        for (int i = 0; i < 8; i++) {
            out[4 * i + 0] = (h[i] >> 24) & 0xFF;
            out[4 * i + 1] = (h[i] >> 16) & 0xFF;
            out[4 * i + 2] = (h[i] >> 8) & 0xFF;
            out[4 * i + 3] = (h[i]) & 0xFF;
        }
    }
};

inline void sha256_bytes(const void* data, size_t n, uint8_t out[32]) {
    Sha256 s;
    s.init();
    s.update(data, n);
    s.finish(out);
}

inline void sha256_acc_u64(Sha256& s, uint64_t x) {
    uint8_t b[8];
    store_le64(b, x);
    s.update(b, 8);
}

struct Shake256 {
    uint64_t st[25];
    size_t rate;
    size_t pos;
    bool squeezing;

    static constexpr uint64_t RC[24] = {
        0x0000000000000001ULL, 0x0000000000008082ULL,
        0x800000000000808aULL, 0x8000000080008000ULL,
        0x000000000000808bULL, 0x0000000080000001ULL,
        0x8000000080008081ULL, 0x8000000000008009ULL,
        0x000000000000008aULL, 0x0000000000000088ULL,
        0x0000000080008009ULL, 0x000000008000000aULL,
        0x000000008000808bULL, 0x800000000000008bULL,
        0x8000000000008089ULL, 0x8000000000008003ULL,
        0x8000000000008002ULL, 0x8000000000000080ULL,
        0x000000000000800aULL, 0x800000008000000aULL,
        0x8000000080008081ULL, 0x8000000000008080ULL,
        0x0000000080000001ULL, 0x8000000080008008ULL
    };

    static constexpr int ROT[5][5] = {
        {  0, 36,  3, 41, 18 },
        {  1, 44, 10, 45,  2 },
        { 62,  6, 43, 15, 61 },
        { 28, 55, 25, 21, 56 },
        { 27, 20, 39,  8, 14 }
    };

    static uint64_t rotl(uint64_t x, int r) {
        return (x << r) | (x >> (64 - r));
    }

    void keccakf() {
        for (int round = 0; round < 24; ++round) {
            uint64_t C[5];
            for (int x = 0; x < 5; x++) {
                C[x] = st[x] ^ st[x + 5] ^ st[x + 10] ^ st[x + 15] ^ st[x + 20];
            }

            uint64_t D[5];
            for (int x = 0; x < 5; x++) {
                D[x] = C[(x + 4) % 5] ^ rotl(C[(x + 1) % 5], 1);
            }

            for (int x = 0; x < 5; x++) {
                for (int y = 0; y < 5; y++) {
                    st[x + 5 * y] ^= D[x];
                }
            }

            uint64_t B[25];
            for (int x = 0; x < 5; x++) {
                for (int y = 0; y < 5; y++) {
                    int X = y;
                    int Y = (2 * x + 3 * y) % 5;
                    B[X + 5 * Y] = rotl(st[x + 5 * y], ROT[x][y]);
                }
            }

            for (int x = 0; x < 5; x++) {
                for (int y = 0; y < 5; y++) {
                    st[x + 5 * y] = B[x + 5 * y] ^ ((~B[(x + 1) % 5 + 5 * y]) & B[(x + 2) % 5 + 5 * y]);
                }
            }

            st[0] ^= RC[round];
        }
    }

    void init() {
        std::fill(std::begin(st), std::end(st), 0);
        rate = 136;
        pos = 0;
        squeezing = false;
    }

    void absorb(const uint8_t* data, size_t len) {
        if (squeezing) {
            std::abort();
        }

        size_t i = 0;

        while (i < len) {
            if (pos == rate) {
                keccakf();
                pos = 0;
            }

            size_t take = std::min(rate - pos, len - i);

            for (size_t j = 0; j < take; j++) {
                size_t idx = pos + j;
                size_t w = idx / 8;
                size_t sh = (idx % 8) * 8;
                st[w] ^= (uint64_t)data[i + j] << sh;
            }

            pos += take;
            i += take;
        }
    }

    void pad() {
        size_t idx = pos;
        size_t w = idx / 8;
        size_t sh = (idx % 8) * 8;

        st[w] ^= (uint64_t)0x1F << sh;

        idx = rate - 1;
        w = idx / 8;
        sh = (idx % 8) * 8;

        st[w] ^= (uint64_t)0x80 << sh;

        keccakf();

        pos = 0;
        squeezing = true;
    }

    void squeeze(uint8_t* out, size_t len) {
        if (!squeezing) {
            pad();
        }

        size_t i = 0;

        while (i < len) {
            if (pos == rate) {
                keccakf();
                pos = 0;
            }

            size_t take = std::min(rate - pos, len - i);

            for (size_t j = 0; j < take; j++) {
                size_t idx = pos + j;
                size_t w = idx / 8;
                size_t sh = (idx % 8) * 8;
                out[i + j] = (uint8_t)((st[w] >> sh) & 0xFF);
            }

            pos += take;
            i += take;
        }
    }

    uint64_t next_u64() {
        uint8_t b[8];
        squeeze(b, 8);
        return load_le64(b);
    }
};

struct XofShake {
    Shake256 sh;

    void init(const std::string& label, const std::vector<uint64_t>& seed) {
        sh.init();
        sh.absorb((const uint8_t*)label.data(), label.size());

        for (uint64_t w : seed) {
            uint8_t b[8];
            store_le64(b, w);
            sh.absorb(b, 8);
        }

        sh.pad();
    }

    uint64_t take_u64() {
        return sh.next_u64();
    }

    uint64_t bounded(uint64_t M) {
        if (M <= 1) {
            return 0;
        }

        uint64_t lim = UINT64_MAX - (UINT64_MAX % M);

        for (;;) {
            uint64_t x = take_u64();
            if (x <= lim) {
                return x % M;
            }
        }
    }
};

}