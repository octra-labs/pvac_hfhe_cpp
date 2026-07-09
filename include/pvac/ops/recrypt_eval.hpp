/*
 * Octra Labs
 * Internal use only
 * December 2025
 */

#pragma once

#include <limits>

#include "recrypt_fold.hpp"
#include "recrypt_src.hpp"

namespace pvac {

enum class RuSrc : uint8_t {
    NONE = 0,
    AES_LPN = 1,
    FIELD_NATIVE = 2
};

using NatSrc = RuSrc;

struct RuPlan {
    RuSrc src = RuSrc::AES_LPN;
    size_t in_layers = 0;
    size_t out_layers = 0;
    size_t edges = 0;
    size_t slots = 0;
    size_t eval_terms = 0;
    bool material = false;
    bool native = false;
    bool prf = false;
    bool inv = false;
    bool proof = false;
};

using NatPlan = RuPlan;

struct RuGate {
    bool admitted = false;
    bool key = false;
    bool input = false;
    bool budget = false;
    bool material = false;
    bool native = false;
    bool prf = false;
    bool inv = false;
    bool proof = false;
    bool rejects_aes_lpn = false;
    bool rejects_no_prf = false;
    bool rejects_no_inv = false;
    bool rejects_no_proof = false;
    bool rejects_source = false;
    bool rejects_budget = false;
};

using NatGate = RuGate;

inline size_t ru_terms(size_t layers, size_t slots) {
    if (layers == 0 || slots == 0)
        return 0;
    if (layers > std::numeric_limits<size_t>::max() / slots)
        return std::numeric_limits<size_t>::max();
    return layers * slots;
}

inline size_t ru_trace_cap(const Rku& rk) {
    auto cap = rk.budget.max_trace_units / 8;
    return cap ? cap : 1;
}

inline RuPlan plan_ru_eval(const PubKey& pk, const Rku& rk, const Cipher& ct, size_t out_layers, size_t edges, RuSrc src = RuSrc::AES_LPN) {
    RuPlan plan;
    plan.src = src;
    plan.in_layers = ct.L.size();
    plan.out_layers = out_layers;
    plan.edges = edges;
    plan.slots = ct.slots;
    plan.eval_terms = ru_terms(ct.L.size(), ct.slots);
    plan.material = rku_safe(pk, rk);
    plan.native = src == RuSrc::FIELD_NATIVE && ru_cipher(pk, ct);
    plan.prf = plan.native && plan.material;
    plan.inv = plan.prf;
    plan.proof = plan.inv && plan.eval_terms != 0 && plan.eval_terms <= rk.budget.max_output_tags;
    return plan;
}

inline RuGate decide_ru_eval(const PubKey& pk, const Rku& rk, const Cipher& ct, const RuPlan& plan) {
    RuGate gate;
    gate.key = rku_safe(pk, rk);
    gate.input = is_cipher_compatible_with_pubkey(pk, ct) && plan.in_layers == ct.L.size() && plan.slots == ct.slots && plan.out_layers > 0 && plan.edges > 0;
    gate.material = plan.material;
    gate.native = plan.native;
    gate.prf = plan.prf;
    gate.inv = plan.inv;
    gate.proof = plan.proof;
    gate.rejects_aes_lpn = plan.src == RuSrc::AES_LPN;
    gate.rejects_no_prf = !plan.prf;
    gate.rejects_no_inv = !plan.inv;
    gate.rejects_no_proof = !plan.proof;
    gate.rejects_source = !plan.native;
    gate.rejects_budget =
        plan.eval_terms == 0 ||
        plan.eval_terms > rk.budget.max_output_tags ||
        plan.in_layers > ru_trace_cap(rk) ||
        plan.edges > rk.budget.max_output_tags;
    gate.budget = !gate.rejects_budget;
    gate.admitted =
        gate.key &&
        gate.input &&
        gate.material &&
        gate.native &&
        gate.prf &&
        gate.inv &&
        gate.proof &&
        gate.budget &&
        !gate.rejects_source &&
        !gate.rejects_aes_lpn;
    return gate;
}

inline bool eval_ru_layers(const PubKey& pk, const Rku& rk, const Cipher& ct) {
    if (!ru_cipher(pk, ct))
        return false;
    for (const auto& layer : ct.L) {
        if (layer.rule == RRule::BASE && !verify_ru_src(pk, rk, layer.seed, eval_ru_src(pk, rk, layer.seed)))
            return false;
    }
    return true;
}

inline Cipher ru_const_ct(size_t slots, const std::vector<Fp>& c) {
    if (slots == 0 || (!c.empty() && c.size() != slots))
        throw std::runtime_error("pvac: ru const shape rejected");
    Cipher out;
    out.slots = slots;
    out.c0 = c.empty() ? field::Op::zeros(slots) : c;
    return out;
}

inline Cipher ru_scale_vec(const PubKey&, Cipher ct, const std::vector<Fp>& scale) {
    if (ct.slots == 0 || scale.size() != ct.slots)
        throw std::runtime_error("pvac: ru vector scale shape rejected");
    for (auto& edge : ct.E) {
        edge.w = field::Op::mul(edge.w, scale);
    }
    if (!ct.c0.empty()) {
        ct.c0 = field::Op::mul(ct.c0, scale);
    }
    return ct;
}

inline std::array<uint8_t, 32> ru_eval_seed(const PubKey& pk, const Rku& rk, const Cipher& ct, uint64_t dom, uint64_t id) {
    Sha256 h;
    h.init();
    h.update("pvac.native.ru.eval", std::strlen("pvac.native.ru.eval"));
    h.update(rk.view.data(), rk.view.size());
    auto digest = native_runtime_cipher_digest(pk, ct);
    h.update(digest.data(), digest.size());
    sha256_acc_u64(h, dom);
    sha256_acc_u64(h, id);
    std::array<uint8_t, 32> out{};
    h.finish(out.data());
    return out;
}

inline Cipher ru_layer_inv_eval(const PubKey& pk, const Rku& rk, const Cipher& ct, size_t lid, std::vector<uint8_t>& state, std::vector<Cipher>& cache) {
    if (lid >= ct.L.size())
        throw std::runtime_error("pvac: ru layer eval index rejected");
    if (state.size() != ct.L.size() || cache.size() != ct.L.size())
        throw std::runtime_error("pvac: ru layer eval work buffer rejected");
    if (state[lid] == 2)
        return cache[lid];
    if (state[lid] == 1)
        throw std::runtime_error("pvac: ru layer eval cycle rejected");
    state[lid] = 1;
    const auto& layer = ct.L[lid];
    Cipher out;
    if (layer.rule == RRule::BASE) {
        out = eval_ru_src(pk, rk, layer.seed).y;
    } else {
        auto left = ru_layer_inv_eval(pk, rk, ct, layer.pa, state, cache);
        auto right = ru_layer_inv_eval(pk, rk, ct, layer.pb, state, cache);
        auto seed = ru_eval_seed(pk, rk, ct, 4, lid);
        out = ct_mul_seeded(pk, left, right, seed.data(), 1);
    }
    if (!ru_cipher(pk, out))
        throw std::runtime_error("pvac: ru layer eval output rejected");
    cache[lid] = std::move(out);
    state[lid] = 2;
    return cache[lid];
}

inline Cipher ru_repack(const PubKey& pk, const Cipher& ct, const std::array<uint8_t, 32>& seed, size_t edges) {
    if (!ru_cipher(pk, ct))
        throw std::runtime_error("pvac: ru repack input rejected");
    SeedableRng rng = make_seeded_rng(seed.data());
    auto alpha = compute_layer_coeffs(pk, ct);
    Cipher out;
    out.slots = ct.slots;
    out.c0 = ct.c0;
    out.L = ct.L;
    for (size_t i = 0; i < alpha.size(); ++i) {
        if (!field::Op::nz(alpha[i]))
            continue;
        auto rows = detail::emit_repack_edges(pk, static_cast<uint32_t>(i), out.L[i], alpha[i], edges ? edges : 1, rng);
        std::move(rows.begin(), rows.end(), std::back_inserter(out.E));
    }
    compact_edges(pk, out);
    compact_layers(out);
    return out;
}

inline Cipher ru_refresh(const PubKey& pk, const Rku& rk, const Cipher& ct) {
    auto plan = plan_ru_eval(pk, rk, ct, ct.L.size(), ct.E.size(), RuSrc::FIELD_NATIVE);
    auto gate = decide_ru_eval(pk, rk, ct, plan);
    if (!gate.admitted)
        throw std::runtime_error("pvac: reusable refresh gate rejected");
    auto alpha = compute_layer_coeffs(pk, ct);
    auto acc = ru_const_ct(ct.slots, ct.c0);
    std::vector<Cipher> cache(ct.L.size());
    std::vector<uint8_t> state(ct.L.size(), 0);
    for (size_t i = 0; i < alpha.size(); ++i) {
        if (!field::Op::nz(alpha[i]))
            continue;
        auto y = ru_layer_inv_eval(pk, rk, ct, i, state, cache);
        acc = ct_add(pk, acc, ru_scale_vec(pk, y, alpha[i]));
    }
    guard_budget(pk, acc, "ru refresh");
    compact_edges(pk, acc);
    compact_layers(acc);
    fold_cipher(pk, acc);
    auto seed = ru_eval_seed(pk, rk, ct, 5, acc.L.size());
    acc = ru_repack(pk, acc, seed, 2);
    fold_cipher(pk, acc);
    if (!ru_cipher(pk, acc))
        throw std::runtime_error("pvac: reusable refresh output rejected");
    if (acc.L.empty() || ru_terms(acc.L.size(), acc.slots) > rk.budget.max_output_tags || acc.E.size() > pk.prm.edge_budget)
        throw std::runtime_error("pvac: reusable refresh output budget rejected");
    return acc;
}

inline NativeRuntimeHiddenCarrier recrypt_hidden(const PubKey& pk, const Rku& rk, const Cipher& ct, const std::vector<NativeResetStageRequest>& requests) {
    auto plan = plan_ru_eval(pk, rk, ct, requests.empty() ? 0 : requests.back().next_terms, 1, RuSrc::FIELD_NATIVE);
    auto gate = decide_ru_eval(pk, rk, ct, plan);
    if (!gate.key || !gate.input || !gate.material || !gate.native || !gate.prf || !gate.inv || !gate.budget || gate.rejects_source)
        throw std::runtime_error("pvac: reusable hidden recrypt source rejected");
    if (!eval_ru_layers(pk, rk, ct))
        throw std::runtime_error("pvac: reusable hidden recrypt source eval rejected");
    auto source = make_native_runtime_source_carrier(pk, ct);
    return rku_recrypt_unsafe(pk, rk, source, requests);
}

inline bool recrypt_hidden_verify(const PubKey& pk, const Rku& rk, const Cipher& ct, const std::vector<NativeResetStageRequest>& requests, const NativeRuntimeHiddenCarrier& clean) {
    try {
        auto expected = recrypt_hidden(pk, rk, ct, requests);
        return native_recrypt_carrier_eq(expected, clean);
    } catch (...) {
        return false;
    }
}

inline Cipher recrypt(const PubKey& pk, const Rku& rk, const Cipher& ct) {
    (void)pk;
    (void)rk;
    (void)ct;
    throw std::runtime_error("pvac: recrypt mode rejected");
}

inline Cipher recrypt(const PubKey& pk, const Rku& rk, const Cipher& ct, const uint8_t seed[32], size_t out_layers, size_t edges = 8) {
    (void)seed;
    (void)out_layers;
    (void)edges;
    return recrypt(pk, rk, ct);
}

inline bool recrypt_verify(const PubKey& pk, const Rku& rk, const Cipher& ct, const Cipher& clean) {
    try {
        auto expected = recrypt(pk, rk, ct);
        return native_chosen_digest_eq(native_runtime_cipher_digest(pk, expected), native_runtime_cipher_digest(pk, clean));
    } catch (...) {
        return false;
    }
}

inline size_t nat_eval_terms(size_t layers, size_t slots) {
    return ru_terms(layers, slots);
}

inline size_t nat_trace_cap(const NatKey& key) {
    return ru_trace_cap(key);
}

inline NatPlan nat_plan(const PubKey& pk, const NatKey& key, const Cipher& ct, size_t out_layers, size_t edges, NatSrc src = NatSrc::AES_LPN) {
    return plan_ru_eval(pk, key, ct, out_layers, edges, src);
}

inline NatGate nat_gate(const PubKey& pk, const NatKey& key, const Cipher& ct, const NatPlan& plan) {
    return decide_ru_eval(pk, key, ct, plan);
}

inline bool eval_nat_layers(const PubKey& pk, const NatKey& key, const Cipher& ct) {
    return eval_ru_layers(pk, key, ct);
}

inline std::array<uint8_t, 32> nat_eval_seed(const PubKey& pk, const NatKey& key, const Cipher& ct, uint64_t dom, uint64_t id) {
    return ru_eval_seed(pk, key, ct, dom, id);
}

inline Cipher nat_refresh(const PubKey& pk, const NatKey& key, const Cipher& ct) {
    return ru_refresh(pk, key, ct);
}

}