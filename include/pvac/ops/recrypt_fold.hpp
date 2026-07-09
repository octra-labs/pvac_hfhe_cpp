/*
 * Octra Labs
 * Internal use only
 * December 2025
 */

#pragma once

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <vector>

#include "../core/hash.hpp"
#include "../core/types.hpp"
#include "encrypt.hpp"

namespace pvac {

inline bool fold_seed_eq(const RSeed& a, const RSeed& b) {
    return a.ztag == b.ztag && a.nonce.lo == b.nonce.lo && a.nonce.hi == b.nonce.hi;
}

inline bool fold_bytes_eq(const std::array<uint8_t, 32>& a, const std::array<uint8_t, 32>& b) {
    return std::equal(a.begin(), a.end(), b.begin());
}

inline bool fold_bytes_less(const std::array<uint8_t, 32>& a, const std::array<uint8_t, 32>& b) {
    return std::lexicographical_compare(a.begin(), a.end(), b.begin(), b.end());
}

inline bool fold_sig_eq(const std::vector<std::array<uint8_t, 32>>& a, const std::vector<std::array<uint8_t, 32>>& b) {
    return a == b;
}

inline void fold_prod_norm(Layer& layer) {
    if (layer.rule == RRule::PROD && layer.pb < layer.pa) {
        std::swap(layer.pa, layer.pb);
    }
}

inline std::array<uint8_t, 32> fold_sig_digest(const char* tag, const Layer& layer) {
    Sha256 h;
    h.init();
    h.update(tag, std::strlen(tag));
    uint8_t rule[1] = {static_cast<uint8_t>(layer.rule)};
    h.update(rule, 1);
    sha256_acc_u64(h, layer.seed.ztag);
    sha256_acc_u64(h, layer.seed.nonce.lo);
    sha256_acc_u64(h, layer.seed.nonce.hi);
    sha256_acc_u64(h, layer.pa);
    sha256_acc_u64(h, layer.pb);
    sha256_acc_u64(h, static_cast<uint64_t>(layer.PC.size()));
    for (const auto& pc : layer.PC) {
        h.update(pc.data(), pc.size());
    }
    std::array<uint8_t, 32> out{};
    h.finish(out.data());
    return out;
}

inline std::vector<std::array<uint8_t, 32>> fold_sig_base(const Layer& layer) {
    return {fold_sig_digest("pvac.fold.base", layer)};
}

inline std::vector<std::array<uint8_t, 32>> fold_sig_prod(const std::vector<std::array<uint8_t, 32>>& a, const std::vector<std::array<uint8_t, 32>>& b) {
    std::vector<std::array<uint8_t, 32>> out;
    out.reserve(a.size() + b.size());
    out.insert(out.end(), a.begin(), a.end());
    out.insert(out.end(), b.begin(), b.end());
    std::sort(out.begin(), out.end(), fold_bytes_less);
    return out;
}

inline bool fold_once(Cipher& ct) {
    if (ct.L.empty())
        return false;
    std::vector<uint32_t> map(ct.L.size(), UINT32_MAX);
    std::vector<Layer> layers;
    std::vector<std::vector<std::array<uint8_t, 32>>> sigs;
    layers.reserve(ct.L.size());
    sigs.reserve(ct.L.size());
    for (size_t i = 0; i < ct.L.size(); ++i) {
        auto layer = ct.L[i];
        std::vector<std::array<uint8_t, 32>> sig;
        if (layer.rule == RRule::PROD) {
            layer.pa = map[layer.pa];
            layer.pb = map[layer.pb];
            fold_prod_norm(layer);
            sig = fold_sig_prod(sigs[layer.pa], sigs[layer.pb]);
        } else {
            sig = fold_sig_base(layer);
        }
        uint32_t seen = UINT32_MAX;
        for (uint32_t j = 0; j < layers.size(); ++j) {
            if (fold_sig_eq(sig, sigs[j])) {
                seen = j;
                break;
            }
        }
        if (seen == UINT32_MAX) {
            seen = static_cast<uint32_t>(layers.size());
            layers.push_back(layer);
            sigs.push_back(std::move(sig));
        }
        map[i] = seen;
    }
    if (layers.size() == ct.L.size())
        return false;
    for (auto& edge : ct.E) {
        edge.layer_id = map[edge.layer_id];
    }
    ct.L.swap(layers);
    return true;
}

inline void fold_cipher(const PubKey& pk, Cipher& ct) {
    for (size_t i = 0; i < 8; ++i) {
        compact_layers(ct);
        auto changed = fold_once(ct);
        compact_edges(pk, ct);
        compact_layers(ct);
        if (!changed)
            break;
    }
}

}