#pragma once

#include <cstdint>
#include <cstring>
#include <array>
#include <vector>
#include <unordered_set>
#include <numeric>
#include <stdexcept>

#include "../core/types.hpp"
#include "../core/hash.hpp"

namespace pvac {

inline std::vector<int> prg_choose_k(
    int k,
    int N,
    const char * label,
    const std::vector<uint64_t> & words
) {
    if (k < 0 || N < 0)
        throw std::runtime_error("pvac: unique sample negative domain rejected");
    if (k > N)
        throw std::runtime_error("pvac: unique sample exceeds domain");

    struct Ctr {
        const char * L;
        std::vector<uint64_t>   w;
        uint64_t ctr;
        uint8_t buf[32];
        int idx;

        Ctr(const char * lab, const std::vector<uint64_t> & ww)
            : L(lab), w(ww), ctr(0), idx(32) {}

        void refill() {
            uint8_t out[32];
            Sha256 s;

            s.init();
            s.update(L, std::strlen(L));

            for (uint64_t x : w) {
                uint8_t b[8];
                store_le64(b, x);
                s.update(b, 8);
            }

            uint8_t cb[8];
            store_le64(cb, ctr++);
            s.update(cb, 8);
            s.finish(out);

            std::memcpy(buf, out, 32);
            idx = 0;
        }

        uint64_t rnd() {
            if (idx >= 32) {
                refill();
            }
            uint64_t x = load_le64(buf + idx);
            idx += 8;
            return x;
        }

        uint64_t bounded(uint64_t M) {
            if (M <= 1) {
                return 0;
            }

            uint64_t lim = UINT64_MAX - (UINT64_MAX % M);

            for (;;) {
                uint64_t x = rnd();
                if (x <= lim) {
                    return x % M;
                }
            }
        }
    } rng(label, words);

    std::unordered_set<int> used;
    used.reserve((size_t)k * 2 + 1);

    std::vector<int> out;
    out.reserve(k);

    while ((int)out.size() < k) {
        int x = (int)rng.bounded((uint64_t)N);
        if (used.insert(x).second) {
            out.push_back(x);
        }
    }

    return out;
}

inline uint64_t prg_u64(
    const char * label,
    const std::vector<uint64_t> & words
) {
    Sha256 s;

    s.init();
    s.update(label, std::strlen(label));

    for (uint64_t x : words) {
        uint8_t b[8];
        store_le64(b, x);
        s.update(b, 8);
    }

    std::array<uint8_t, 32> out{};
    s.finish(out.data());
    return load_le64(out.data());
}

inline int mixed_weight(
    int base,
    int limit,
    const char * label,
    const std::vector<uint64_t> & words
) {
    if (base < limit && (prg_u64(label, words) & 1ull))
        return base + 1;
    return base;
}

inline Ubk gen_ubk_public(uint64_t canon_tag, int m_bits) {
    std::vector<int> perm(m_bits);
    std::iota(perm.begin(), perm.end(), 0);

    struct Ctr {
        uint64_t tag;
        uint64_t c;
        uint8_t b[32];
        int idx;

        Ctr(uint64_t t) : tag(t), c(0), idx(32) {}

        uint64_t r() {
            if (idx >= 32) {
                uint8_t out[32];
                Sha256 s;

                s.init();
                s.update("UBK", 3);

                uint8_t tb[8];
                store_le64(tb, tag);
                s.update(tb, 8);

                uint8_t cb[8];
                store_le64(cb, c++);
                s.update(cb, 8);
                s.finish(out);

                std::memcpy(b, out, 32);
                idx = 0;
            }

            uint64_t x = load_le64(b + idx);
            idx += 8;
            return x;
        }

        uint64_t bounded(uint64_t M) {
            if (M <= 1) {
                return 0;
            }

            uint64_t lim = UINT64_MAX - (UINT64_MAX % M);

            for (;;) {
                uint64_t x = r();
                if (x <= lim) {
                    return x % M;
                }
            }
        }
    } rr(canon_tag);

    for (int i = m_bits - 1; i > 0; --i) {
        int j = (int)rr.bounded((uint64_t)i + 1);
        std::swap(perm[i], perm[j]);
    }

    std::vector<int> inv(m_bits);
    for (int i = 0; i < m_bits; i++) {
        inv[perm[i]] = i;
    }

    Ubk u;
    u.perm = std::move(perm);
    u.inv = std::move(inv);

    return u;
}

inline BitVec apply_perm_sigma(const BitVec & v, const std::vector<int> & inv) {
    BitVec o = BitVec::make(v.nbits);

    for (size_t wi = 0; wi < v.w.size(); ++wi) {
        uint64_t x = v.w[wi];

        while (x) {
            uint64_t b = x & -x;
            unsigned bit = __builtin_ctzll(x);
            size_t src = (wi << 6) + bit;

            if (src < v.nbits) {
                int j = inv[src];
                o.w[(size_t)j >> 6] |= (1ull << (j & 63));
            }

            x ^= b;
        }
    }

    return o;
}

inline void gen_H(PubKey & pk) {
    int m = pk.prm.m_bits;
    int n = pk.prm.n_bits;

    pk.H.resize(n, BitVec::make(m));

    for (int c = 0; c < n; c++) {
        BitVec col = BitVec::make(m);

        std::vector<uint64_t> words {
            (uint64_t)m,
            (uint64_t)n,
            (uint64_t)pk.prm.h_col_wt,
            (uint64_t)c,
            pk.canon_tag
        };

        int wt = mixed_weight(pk.prm.h_col_wt, m, "pvac.H.weight", words);
        auto rows = prg_choose_k(wt, m, Dom::H_GEN, words);

        for (int r : rows) {
            col.w[(size_t)r >> 6] |= (1ull << (r & 63));
        }

        pk.H[c] = std::move(col);
    }

    Sha256 s;

    s.init();
    s.update("H|v2", 4);
    sha256_acc_u64(s, pk.prm.m_bits);
    sha256_acc_u64(s, pk.prm.n_bits);
    sha256_acc_u64(s, pk.prm.h_col_wt);

    for (const auto & col : pk.H) {
        size_t bytes = (col.nbits + 7) / 8;
        size_t full = bytes / 8;
        size_t rem = bytes % 8;

        for (size_t i = 0; i < full; i++) {
            uint8_t b[8];
            store_le64(b, col.w[i]);
            s.update(b, 8);
        }

        if (rem) {
            uint8_t b[8];
            uint64_t x = col.w[full];

            for (size_t j = 0; j < rem; j++) {
                b[j] = (uint8_t)((x >> (8 * j)) & 0xFF);
            }

            s.update(b, rem);
        }
    }

    s.finish(pk.H_digest.data());
}

inline uint64_t prg_layer_ztag(uint64_t canon_tag, Nonce128 n) {
    Sha256 s;
    s.init();
    s.update(Dom::ZTAG, std::strlen(Dom::ZTAG));
    sha256_acc_u64(s, canon_tag);
    sha256_acc_u64(s, n.lo);
    sha256_acc_u64(s, n.hi);
    uint8_t out[32];
    s.finish(out);
    return load_le64(out);
}

inline BitVec sigma_from_H(
    const PubKey & pk,
    uint64_t ztag,
    Nonce128 nonce,
    uint16_t idx,
    uint8_t ch,
    uint64_t salt
) {
    int m = pk.prm.m_bits;
    int n = pk.prm.n_bits;

    BitVec s = BitVec::make(m);

    std::vector<uint64_t> words {
        pk.canon_tag,
        ztag,
        nonce.lo,
        nonce.hi,
        (uint64_t)idx,
        (uint64_t)ch,
        salt
    };

    auto cols = prg_choose_k(pk.prm.x_col_wt, n, Dom::X_SEED, words);

    for (int c : cols) {
        s.xor_with(pk.H[c]);
    }

    int noise_wt = mixed_weight(pk.prm.err_wt, m, "pvac.noise.weight", words);
    auto noise = prg_choose_k(noise_wt, m, Dom::NOISE, words);

    for (int r : noise) {
        s.w[(size_t)r >> 6] ^= (1ull << (r & 63));
    }

    return s;
}

inline void ubk_apply(const PubKey & pk, Cipher & C) {
    for (auto & e : C.E) {
        e.s = apply_perm_sigma(e.s, pk.ubk.inv);
    }
}

}