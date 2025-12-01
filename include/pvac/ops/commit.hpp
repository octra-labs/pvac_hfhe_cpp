#pragma once

#include <cstdint>
#include <cstring>
#include <array>

#include "../core/types.hpp"
#include "../core/hash.hpp"

namespace pvac {

inline std::array<uint8_t, 32> commit_ct(const PubKey & pk, const Cipher & C) 
{
    Sha256 s;
    s.init();
    s.update(Dom::COMMIT, std::strlen(Dom::COMMIT));



    s.update(pk.H_digest.data(), 32);

    sha256_acc_u64(s, pk.canon_tag);

    for (const auto & L : C.L) {
        uint8_t r[1] = { (uint8_t)L.rule };

        s.update(r, 1);

        if (L.rule == RRule::BASE) {

            sha256_acc_u64(s, L.seed.ztag);
            sha256_acc_u64(s, L.seed.nonce.lo);
            sha256_acc_u64(s, L.seed.nonce.hi);
        } else {
            sha256_acc_u64(s, L.pa);
            sha256_acc_u64(s, L.pb);
        }
    }

    for (const auto & e : C.E) {
        sha256_acc_u64(s, e.layer_id);
        sha256_acc_u64(s, e.idx);

        uint8_t ch[1] = { e.ch };
        s.update(ch, 1);

        uint8_t w16[16];

        for (int i = 0; i < 8; i++) 
        {
            w16[i] = (uint8_t)((e.w.lo >> (8 * i)) & 0xFF);
        }

        for (int i = 0; i < 8; i++) {
            w16[8 + i] = (uint8_t)(((e.w.hi & MASK63) >> (8 * i)) & 0xFF);
        }

        s.update(w16, 16);

        size_t bytes = (e.s.nbits + 7) / 8;
        size_t full  = bytes / 8;
        size_t rem   = bytes % 8;

        for (size_t i = 0; i < full; i++) {
            uint8_t b[8];
            store_le64(b, e.s.w[i]);
            s.update(b, 8);
        }

        if (rem) {
            uint8_t b[8];

            uint64_t x = e.s.w[full];

            for (size_t j = 0; j < rem; j++) {
                b[j] = (uint8_t)((x >> (8 * j)) & 0xFF);
            }

            s.update(b, rem);
        }
    }

    std::array<uint8_t, 32> out {};
    s.finish(out.data());

    return out;
}



}