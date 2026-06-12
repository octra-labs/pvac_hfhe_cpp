/*
 * Octra Labs
 * Internal use only
 * December 2025
 */

#pragma once

#include <cstdint>
#include <stdexcept>
#include <vector>

#include "../core/types.hpp"

namespace pvac {

inline std::vector<std::vector<Fp>> compute_layer_coeffs(const PubKey& pk, const Cipher& ct) {
    size_t slots = ct.slots;
    size_t layers = ct.L.size();
    std::vector<std::vector<Fp>> out(layers, std::vector<Fp>(slots, Fp{0, 0}));
    for (const auto& edge : ct.E) {
        if (edge.layer_id >= layers)
            throw std::runtime_error("pvac: edge layer out of range");
        if (edge.idx >= pk.powg_B.size())
            throw std::runtime_error("pvac: edge public-key index out of range");
        if (edge.w.size() != slots)
            throw std::runtime_error("pvac: edge weight/slots size mismatch");
        Fp gp = pk.powg_B[edge.idx];
        int sign = sgn_val(edge.ch);
        for (size_t j = 0; j < slots; ++j) {
            Fp term = fp_mul(edge.w[j], gp);
            out[edge.layer_id][j] = sign > 0 ?
                fp_add(out[edge.layer_id][j], term) :
                fp_sub(out[edge.layer_id][j], term);
        }
    }
    return out;
}

}