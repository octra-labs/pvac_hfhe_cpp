/*
 * octra labs
 * lambda0xe, denis cmix, J.
 */

#pragma once

#include <utility>

#include "arithmetic.hpp"
#include "recrypt_runtime_eval.hpp"
#include "recrypt_src_core.hpp"

namespace pvac {

inline Cipher ru_add_fp(const PubKey&, Cipher ct, const Fp& x) {
    if (ct.c0.empty()) {
        ct.c0 = field::Op::zeros(ct.slots);
    }
    for (auto& c : ct.c0) {
        c = fp_add(c, x);
    }
    return ct;
}

inline Cipher nat_add_fp(const PubKey& pk, Cipher ct, const Fp& x) {
    return ru_add_fp(pk, std::move(ct), x);
}

inline Layer ru_layer(const PubKey& pk, const SecKey& sk, const RSeed& seed, size_t slots) {
    Layer layer;
    layer.rule = RRule::BASE;
    layer.seed = seed;
    auto r = ru_r_slots(sk, seed, slots);
    layer.R_com = compute_R_com_base(pk.canon_tag, seed.ztag, seed.nonce.lo, seed.nonce.hi, r);
    return layer;
}

inline Layer nat_layer(const PubKey& pk, const SecKey& sk, const RSeed& seed, size_t slots) {
    return ru_layer(pk, sk, seed, slots);
}

inline Cipher enc_ru_fp_seeded(const PubKey& pk, const SecKey& sk, const std::vector<Fp>& v, const uint8_t seed[32], size_t edges = 8) {
    if (v.empty())
        throw std::runtime_error("pvac: ru encrypt value rejected");
    SeedableRng rng = make_seeded_rng(seed);
    auto rseed = ru_seed(pk, seed);
    auto layer = ru_layer(pk, sk, rseed, v.size());
    auto r = ru_r_slots(sk, rseed, v.size());
    auto target = field::Op::mul(v, r);
    Cipher out;
    out.slots = v.size();
    out.c0 = field::Op::zeros(v.size());
    out.L.push_back(layer);
    out.E = detail::emit_repack_edges(pk, 0, out.L[0], target, edges ? edges : 1, rng);
    guard_budget(pk, out, "ru encrypt");
    compact_edges(pk, out);
    compact_layers(out);
    return out;
}

inline Cipher enc_nat_fp_seeded(const PubKey& pk, const SecKey& sk, const std::vector<Fp>& v, const uint8_t seed[32], size_t edges = 8) {
    return enc_ru_fp_seeded(pk, sk, v, seed, edges);
}

inline Cipher enc_ru_value_seeded(const PubKey& pk, const SecKey& sk, uint64_t v, const uint8_t seed[32], size_t edges = 8) {
    return enc_ru_fp_seeded(pk, sk, {fp_from_u64(v)}, seed, edges);
}

inline Cipher enc_nat_value_seeded(const PubKey& pk, const SecKey& sk, uint64_t v, const uint8_t seed[32], size_t edges = 8) {
    return enc_ru_value_seeded(pk, sk, v, seed, edges);
}

inline bool ru_cipher(const PubKey& pk, const Cipher& ct) {
    if (!is_cipher_compatible_with_pubkey(pk, ct))
        return false;
    for (size_t i = 0; i < ct.L.size(); ++i) {
        const auto& layer = ct.L[i];
        if (layer.rule == RRule::BASE && !ru_src(pk, layer))
            return false;
        if (layer.rule == RRule::PROD && (layer.pa >= i || layer.pb >= i))
            return false;
    }
    return !ct.L.empty();
}

inline bool nat_cipher(const PubKey& pk, const Cipher& ct) {
    return ru_cipher(pk, ct);
}

struct Rku {
    std::array<uint8_t, 32> key = {};
    std::array<uint8_t, 32> dom = {};
    std::array<uint8_t, 32> view = {};
    std::vector<Cipher> sec;
    NativeResetChosenPolicy policy;
    NativeRuntimeReusableBudget budget;
    size_t prf = 0;
    size_t lpn = 0;
    bool safe = false;
};

using NatKey = Rku;

struct NatAdm {
    size_t max_terms = 16;
    size_t out_terms = 2;
    size_t max_slots = 1;
    size_t max_query = 64;
    size_t alpha_bits = 8;
    size_t row_bits = 8;
};

struct NatProdGate {
    bool admitted = false;
    bool key = false;
    bool profile = false;
    bool budget = false;
    bool rejects_key = false;
    bool rejects_profile = false;
    bool rejects_budget = false;
    bool rejects_sha_compat = false;
    bool rejects_underbudget = false;
    bool rejects_trace_wide = false;
    bool rejects_output_wide = false;
    bool rejects_proof_wide = false;
};

class NatStep {
    NativeRuntimeHiddenCarrier h_;
    size_t q_ = 0;
    std::array<uint8_t, 32> profile_ = {};

public:
    NatStep() = default;

    NatStep(NativeRuntimeHiddenCarrier h, size_t q, std::array<uint8_t, 32> profile)
        : h_(std::move(h)), q_(q), profile_(profile) {}

    const NativeRuntimeHiddenCarrier& carrier() const {
        return h_;
    }

    size_t query() const {
        return q_;
    }

    const std::array<uint8_t, 32>& profile() const {
        return profile_;
    }
};

inline NativeResetChosenPolicy rk_policy(size_t queries) {
    NativeResetChosenPolicy policy;
    policy.reusable = true;
    policy.hidden_output = true;
    policy.statement_bound = true;
    policy.transcript_bound = true;
    policy.material_bound = true;
    policy.no_basis_oracle = true;
    policy.native_backend = true;
    policy.max_queries = queries;
    policy.cert = HiddenCoeffCertKind::PVAC_NATIVE;
    return policy;
}

inline NatAdm nat_adm() {
    return NatAdm{};
}

inline NatAdm nat_lin() {
    NatAdm adm;
    adm.max_terms = 8;
    adm.max_query = 32;
    return adm;
}

inline NatAdm nat_quad() {
    return NatAdm{};
}

inline NatAdm nat_chain() {
    NatAdm adm;
    adm.max_terms = 16;
    adm.out_terms = 2;
    adm.max_query = 64;
    return adm;
}

inline NatAdm nat_wide() {
    NatAdm adm;
    adm.max_terms = 32;
    adm.out_terms = 4;
    adm.max_query = 32;
    return adm;
}

inline NatAdm nat_vec4() {
    NatAdm adm;
    adm.max_terms = 16;
    adm.out_terms = 2;
    adm.max_slots = 4;
    adm.max_query = 32;
    return adm;
}

inline NatAdm nat_vec8() {
    NatAdm adm;
    adm.max_terms = 16;
    adm.out_terms = 2;
    adm.max_slots = 8;
    adm.max_query = 32;
    return adm;
}

inline NatAdm nat_prod_adm() {
    NatAdm adm;
    adm.max_terms = 32;
    adm.out_terms = 4;
    adm.max_slots = 8;
    adm.max_query = 64;
    adm.alpha_bits = 8;
    adm.row_bits = 8;
    return adm;
}

inline NativeRuntimeReusableBudget nat_prod_budget() {
    NativeRuntimeReusableBudget budget;
    budget.proof = NativeResetProofProfileKind::FIELD_NATIVE;
    budget.target_bits = 128;
    budget.max_trace_units = 1024;
    budget.max_output_tags = 64;
    budget.max_proof_bytes = 1 << 20;
    return budget;
}

inline bool nat_prod_profile_ok(const NatAdm& adm) {
    auto prod = nat_prod_adm();
    return
        adm.max_terms != 0 &&
        adm.out_terms != 0 &&
        adm.max_slots != 0 &&
        adm.max_query != 0 &&
        adm.out_terms <= adm.max_terms &&
        adm.max_terms <= prod.max_terms &&
        adm.out_terms <= prod.out_terms &&
        adm.max_slots <= prod.max_slots &&
        adm.max_query <= prod.max_query &&
        adm.alpha_bits <= prod.alpha_bits &&
        adm.row_bits <= prod.row_bits;
}

inline std::array<uint8_t, 32> nat_profile_digest(const NatAdm& adm) {
    Sha256 h;
    h.init();
    h.update("pvac.native.nat.profile", std::strlen("pvac.native.nat.profile"));
    sha256_acc_u64(h, adm.max_terms);
    sha256_acc_u64(h, adm.out_terms);
    sha256_acc_u64(h, adm.max_slots);
    sha256_acc_u64(h, adm.max_query);
    sha256_acc_u64(h, adm.alpha_bits);
    sha256_acc_u64(h, adm.row_bits);
    std::array<uint8_t, 32> out{};
    h.finish(out.data());
    return out;
}

inline bool nat_admit(const NatAdm& adm, const NativeRuntimeHiddenCarrier& h) {
    return
        native_runtime_carrier_ok(h) &&
        h.out.target_terms != 0 &&
        h.out.target_terms <= adm.max_terms &&
        h.out.slots != 0 &&
        h.out.slots <= adm.max_slots &&
        !h.materialized_cipher &&
        h.hidden_coeffs &&
        h.no_basis_oracle &&
        h.native_backend &&
        h.out.hidden_coeffs &&
        !h.out.visible_beta;
}

inline void nat_need(const NatAdm& adm, const NativeRuntimeHiddenCarrier& h) {
    if (!nat_admit(adm, h))
        throw std::runtime_error("pvac: reusable evaluator profile rejected");
}

inline const NativeRuntimeHiddenCarrier& nat_carrier(const NatStep& s) {
    return s.carrier();
}

inline size_t nat_query(const NatStep& s) {
    return s.query();
}

inline size_t nat_terms(const NatStep& s) {
    return s.carrier().out.target_terms;
}

inline void nat_need_step(const NatAdm& adm, const NatStep& s) {
    if (!native_chosen_digest_eq(s.profile(), nat_profile_digest(adm)))
        throw std::runtime_error("pvac: reusable evaluator profile mismatch");
    nat_need(adm, s.carrier());
    if (s.query() >= adm.max_query)
        throw std::runtime_error("pvac: reusable evaluator query rejected");
}

inline std::array<uint8_t, 32> rku_dom(const PubKey& pk, const SecKey& sk) {
    auto key = native_runtime_pubkey_digest(pk);
    auto sec = native_runtime_seckey_digest(pk, sk);
    return native_runtime_digest2("pvac.native.rku.dom", key, sec);
}

inline std::array<uint8_t, 32> rku_seed(const std::array<uint8_t, 32>& dom, uint64_t kind, uint64_t id) {
    Sha256 h;
    h.init();
    h.update("pvac.native.rku.seed", std::strlen("pvac.native.rku.seed"));
    h.update(dom.data(), dom.size());
    sha256_acc_u64(h, kind);
    sha256_acc_u64(h, id);
    std::array<uint8_t, 32> out{};
    h.finish(out.data());
    return out;
}

inline std::array<uint8_t, 32> rku_view(const PubKey& pk, const Rku& rk) {
    Sha256 h;
    h.init();
    h.update("pvac.native.rku.view", std::strlen("pvac.native.rku.view"));
    h.update(rk.key.data(), rk.key.size());
    h.update(rk.dom.data(), rk.dom.size());
    sha256_acc_u64(h, rk.prf);
    sha256_acc_u64(h, rk.lpn);
    sha256_acc_u64(h, rk.policy.max_queries);
    sha256_acc_u64(h, rk.policy.reusable ? 1 : 0);
    sha256_acc_u64(h, rk.policy.hidden_output ? 1 : 0);
    sha256_acc_u64(h, rk.policy.statement_bound ? 1 : 0);
    sha256_acc_u64(h, rk.policy.transcript_bound ? 1 : 0);
    sha256_acc_u64(h, rk.policy.material_bound ? 1 : 0);
    sha256_acc_u64(h, rk.policy.no_basis_oracle ? 1 : 0);
    sha256_acc_u64(h, rk.policy.native_backend ? 1 : 0);
    sha256_acc_u64(h, static_cast<uint8_t>(rk.policy.cert));
    sha256_acc_u64(h, static_cast<uint8_t>(rk.budget.proof));
    sha256_acc_u64(h, rk.budget.target_bits);
    sha256_acc_u64(h, rk.budget.max_trace_units);
    sha256_acc_u64(h, rk.budget.max_output_tags);
    sha256_acc_u64(h, rk.budget.max_proof_bytes);
    sha256_acc_u64(h, rk.sec.size());
    for (const auto& ct : rk.sec) {
        auto d = native_runtime_cipher_digest(pk, ct);
        h.update(d.data(), d.size());
    }
    std::array<uint8_t, 32> out{};
    h.finish(out.data());
    return out;
}

inline bool rku_safe(const PubKey& pk, const Rku& rk) {
    if (!native_chosen_digest_eq(rk.key, native_runtime_pubkey_digest(pk)))
        return false;
    if (!rk.safe || !native_reset_chosen_policy_ok(rk.policy))
        return false;
    if (rk.prf != 4 || rk.lpn != 0 || rk.sec.size() != rk.prf)
        return false;
    for (const auto& ct : rk.sec) {
        if (!ru_cipher(pk, ct))
            return false;
    }
    return native_chosen_digest_eq(rk.view, rku_view(pk, rk));
}

inline bool nat_key_safe(const PubKey& pk, const NatKey& key) {
    return rku_safe(pk, key);
}

inline bool nat_prod_budget_ok(const NativeRuntimeReusableBudget& budget) {
    auto prod = nat_prod_budget();
    return
        budget.proof == NativeResetProofProfileKind::FIELD_NATIVE &&
        budget.target_bits >= prod.target_bits &&
        budget.max_trace_units <= prod.max_trace_units &&
        budget.max_output_tags <= prod.max_output_tags &&
        budget.max_proof_bytes <= prod.max_proof_bytes;
}

inline NatProdGate nat_prod_gate(const PubKey& pk, const NatKey& key, const NatAdm& adm) {
    NatProdGate gate;
    auto prod = nat_prod_budget();
    gate.key = nat_key_safe(pk, key) && key.policy.max_queries <= nat_prod_adm().max_query;
    gate.profile = nat_prod_profile_ok(adm);
    gate.budget = nat_prod_budget_ok(key.budget);
    gate.rejects_key = !gate.key;
    gate.rejects_profile = !gate.profile;
    gate.rejects_budget = !gate.budget;
    gate.rejects_sha_compat = key.budget.proof != NativeResetProofProfileKind::FIELD_NATIVE;
    gate.rejects_underbudget = key.budget.target_bits < prod.target_bits;
    gate.rejects_trace_wide = key.budget.max_trace_units > prod.max_trace_units;
    gate.rejects_output_wide = key.budget.max_output_tags > prod.max_output_tags;
    gate.rejects_proof_wide = key.budget.max_proof_bytes > prod.max_proof_bytes;
    gate.admitted = gate.key && gate.profile && gate.budget;
    return gate;
}

inline std::vector<Fp> rku_alpha(const PubKey& pk, const Rku& rk, const NativeRuntimeHiddenCarrier& ct, const NatAdm& adm, size_t query) {
    if (!rku_safe(pk, rk) || !native_runtime_carrier_ok(ct))
        throw std::runtime_error("pvac: reusable stage alpha rejected");
    auto profile = nat_profile_digest(adm);
    std::vector<Fp> out;
    out.reserve(ct.out.target_terms);
    for (size_t i = 0; i < ct.out.target_terms; ++i) {
        Sha256 h;
        h.init();
        h.update("pvac.native.rku.alpha", std::strlen("pvac.native.rku.alpha"));
        h.update(rk.view.data(), rk.view.size());
        h.update(profile.data(), profile.size());
        h.update(ct.out.output_digest.data(), ct.out.output_digest.size());
        sha256_acc_u64(h, query);
        sha256_acc_u64(h, i);
        std::array<uint8_t, 32> d{};
        h.finish(d.data());
        out.push_back(fp_from_u64(1 + (d[0] & 127)));
    }
    return out;
}

inline NativeResetStageRequest rku_req(const PubKey& pk, const Rku& rk, const NativeRuntimeHiddenCarrier& ct, const NatAdm& adm, size_t next_terms, size_t query) {
    if (next_terms == 0 || next_terms != adm.out_terms || next_terms > adm.max_terms || query >= adm.max_query)
        throw std::runtime_error("pvac: reusable stage request profile rejected");
    NativeResetStageRequest req;
    req.alpha = rku_alpha(pk, rk, ct, adm, query);
    req.next_terms = next_terms;
    req.alpha_bits = adm.alpha_bits;
    req.row_bits = adm.row_bits;
    req.query = query;
    return req;
}

inline NatStep nat_step(const NatAdm& adm, NativeRuntimeHiddenCarrier h, size_t query) {
    nat_need(adm, h);
    if (query >= adm.max_query)
        throw std::runtime_error("pvac: reusable evaluator query rejected");
    return NatStep(std::move(h), query, nat_profile_digest(adm));
}

inline NatStep nat_in(const PubKey& pk, const Cipher& ct, const NatAdm& adm = NatAdm{}) {
    return nat_step(adm, make_native_runtime_source_carrier(pk, ct), 0);
}

inline NatStep nat_add(const NatAdm& adm, const NatStep& a, const NatStep& b) {
    nat_need_step(adm, a);
    nat_need_step(adm, b);
    auto q = a.query() > b.query() ? a.query() : b.query();
    return nat_step(adm, make_native_runtime_add_carrier(a.carrier(), b.carrier()), q);
}

inline NatStep nat_sub(const NatAdm& adm, const NatStep& a, const NatStep& b) {
    nat_need_step(adm, a);
    nat_need_step(adm, b);
    auto q = a.query() > b.query() ? a.query() : b.query();
    return nat_step(adm, make_native_runtime_sub_carrier(a.carrier(), b.carrier()), q);
}

inline NatStep nat_mul(const NatAdm& adm, const NatStep& a, const NatStep& b) {
    nat_need_step(adm, a);
    nat_need_step(adm, b);
    auto q = a.query() > b.query() ? a.query() : b.query();
    return nat_step(adm, make_native_runtime_product_carrier(a.carrier(), b.carrier()), q);
}

inline NatStep nat_scale(const NatAdm& adm, const NatStep& x, const Fp& c) {
    nat_need_step(adm, x);
    return nat_step(adm, make_native_runtime_scale_carrier(x.carrier(), c), x.query());
}

inline NatStep nat_add_const(const NatAdm& adm, const NatStep& x, const Fp& c) {
    nat_need_step(adm, x);
    return nat_step(adm, make_native_runtime_add_const_carrier(x.carrier(), c), x.query());
}

inline Rku make_rku(const PubKey& pk, const SecKey& sk, size_t queries = 64, const NativeRuntimeReusableBudget& budget = NativeRuntimeReusableBudget{}) {
    Rku rk;
    rk.key = native_runtime_pubkey_digest(pk);
    rk.dom = rku_dom(pk, sk);
    rk.policy = rk_policy(queries);
    rk.budget = budget;
    rk.prf = sk.prf_k.size();
    rk.lpn = 0;
    rk.sec.reserve(rk.prf + rk.lpn);
    for (size_t i = 0; i < rk.prf; ++i) {
        auto seed = rku_seed(rk.dom, 1, i);
        rk.sec.push_back(enc_ru_value_seeded(pk, sk, sk.prf_k[i], seed.data(), 4));
    }
    rk.view = rku_view(pk, rk);
    rk.safe = native_reset_chosen_policy_ok(rk.policy);
    if (!rku_safe(pk, rk))
        throw std::runtime_error("pvac: reusable recrypt key rejected");
    return rk;
}

inline NatKey make_nat_key(const PubKey& pk, const SecKey& sk, size_t queries = 64, const NativeRuntimeReusableBudget& budget = NativeRuntimeReusableBudget{}) {
    return make_rku(pk, sk, queries, budget);
}

inline NativeRuntimeHiddenCarrier rku_bind(const Rku& rk, NativeRuntimeHiddenCarrier carrier) {
    carrier.source_digest = native_runtime_digest2("pvac.native.rku.source", carrier.source_digest, rk.dom);
    carrier.left_digest = native_runtime_digest2("pvac.native.rku.left", carrier.left_digest, rk.dom);
    carrier.right_digest = native_runtime_digest2("pvac.native.rku.right", carrier.right_digest, rk.dom);
    carrier.out.material_digest = native_runtime_digest2("pvac.native.rku.material", carrier.out.material_digest, rk.dom);
    carrier.out.statement_digest = native_runtime_digest2("pvac.native.rku.statement", carrier.out.statement_digest, rk.key);
    for (auto& tag : carrier.out.coeff_tags) {
        tag = native_runtime_digest2("pvac.native.rku.coeff", tag, rk.dom);
    }
    carrier.out.output_digest = native_chosen_output_digest(carrier.out);
    return carrier;
}

inline NativeRuntimeHiddenCarrier rku_recrypt_unsafe(const PubKey& pk, const Rku& rk, const NativeRuntimeHiddenCarrier& ct, const std::vector<NativeResetStageRequest>& requests) {
    if (!rku_safe(pk, rk))
        throw std::runtime_error("pvac: reusable recrypt key mismatch");
    if (!rk.safe || !native_runtime_carrier_ok(ct))
        throw std::runtime_error("pvac: reusable recrypt input rejected");
    auto chain = eval_native_runtime_hidden_reset_chain(rk.policy, ct, requests);
    auto decision = decide_native_runtime_hidden_reset_chain(rk.policy, chain);
    if (!decision.admitted)
        throw std::runtime_error("pvac: reusable recrypt chain rejected");
    auto reusable = decide_native_runtime_reusable(chain.output, rk.budget);
    if (!reusable.admitted)
        throw std::runtime_error("pvac: reusable recrypt budget rejected");
    auto out = rku_bind(rk, chain.output);
    auto bound = decide_native_runtime_reusable(out, rk.budget);
    if (!bound.admitted)
        throw std::runtime_error("pvac: reusable recrypt bound output rejected");
    return out;
}

inline NativeRuntimeHiddenCarrier nat_recrypt_unsafe(const PubKey& pk, const NatKey& key, const NativeRuntimeHiddenCarrier& ct, const std::vector<NativeResetStageRequest>& requests) {
    return rku_recrypt_unsafe(pk, key, ct, requests);
}

inline NativeRuntimeHiddenCarrier recrypt(const PubKey& pk, const Rku& rk, const NativeRuntimeHiddenCarrier& ct, const NatAdm& adm, size_t next_terms, size_t query) {
    std::vector<NativeResetStageRequest> requests = {
        rku_req(pk, rk, ct, adm, next_terms, query)
    };
    return rku_recrypt_unsafe(pk, rk, ct, requests);
}

inline NatStep nat_recrypt(const PubKey& pk, const Rku& rk, const NatAdm& adm, const NatStep& x) {
    nat_need_step(adm, x);
    if (adm.max_query == 0 || x.query() >= adm.max_query - 1)
        throw std::runtime_error("pvac: reusable evaluator reset query rejected");
    auto q = x.query() + 1;
    auto h = recrypt(pk, rk, x.carrier(), adm, adm.out_terms, q);
    return nat_step(adm, h, q);
}

inline NatStep nat_prod_recrypt(const PubKey& pk, const NatKey& key, const NatAdm& adm, const NatStep& x) {
    auto gate = nat_prod_gate(pk, key, adm);
    if (!gate.admitted)
        throw std::runtime_error("pvac: native production recrypt gate rejected");
    return nat_recrypt(pk, key, adm, x);
}

inline bool rku_recrypt_verify_unsafe(const PubKey& pk, const Rku& rk, const NativeRuntimeHiddenCarrier& ct, const std::vector<NativeResetStageRequest>& requests, const NativeRuntimeHiddenCarrier& clean) {
    try {
        auto expected = rku_recrypt_unsafe(pk, rk, ct, requests);
        return native_recrypt_carrier_eq(expected, clean);
    } catch (...) {
        return false;
    }
}

inline bool nat_recrypt_verify_unsafe(const PubKey& pk, const NatKey& key, const NativeRuntimeHiddenCarrier& ct, const std::vector<NativeResetStageRequest>& requests, const NativeRuntimeHiddenCarrier& clean) {
    return rku_recrypt_verify_unsafe(pk, key, ct, requests, clean);
}

inline bool recrypt_verify(const PubKey& pk, const Rku& rk, const NativeRuntimeHiddenCarrier& ct, const NatAdm& adm, size_t next_terms, size_t query, const NativeRuntimeHiddenCarrier& clean) {
    try {
        auto expected = recrypt(pk, rk, ct, adm, next_terms, query);
        return native_recrypt_carrier_eq(expected, clean);
    } catch (...) {
        return false;
    }
}

inline bool nat_prod_verify(const PubKey& pk, const NatKey& key, const NatAdm& adm, const NatStep& src, const NatStep& clean) {
    try {
        auto gate = nat_prod_gate(pk, key, adm);
        if (!gate.admitted)
            return false;
        auto expected = nat_prod_recrypt(pk, key, adm, src);
        return native_recrypt_carrier_eq(nat_carrier(expected), nat_carrier(clean));
    } catch (...) {
        return false;
    }
}

}