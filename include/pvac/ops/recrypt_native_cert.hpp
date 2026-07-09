/*
 * octra labs
 * lambda0xe, denis cmix, J.
 */

#pragma once

#include <array>
#include <cstring>
#include <limits>
#include <stdexcept>
#include <vector>

#include "../core/field.hpp"
#include "../core/hash.hpp"
#include "../core/types.hpp"
#include "recrypt_arith_proof.hpp"
#include "recrypt_hidden_coeff.hpp"
#include "recrypt_layer_proof.hpp"
#include "recrypt_proof_profile.hpp"

namespace pvac {

struct NativeResetStmt {
    std::vector<Fp> c;
    std::vector<std::vector<Fp>> alpha;
    size_t target_terms = 0;
    HiddenCoeffBound bound;
};

struct NativeResetRows {
    std::vector<std::vector<Fp>> bias;
    std::vector<std::vector<std::vector<Fp>>> mix;
};

struct NativeResetSecrets {
    std::vector<std::vector<Fp>> old_x;
    std::vector<std::vector<Fp>> new_y;
};

struct NativeResetOutput {
    std::vector<Fp> c;
    std::vector<std::vector<Fp>> beta;
};

struct NativeResetCheck {
    bool shape = false;
    bool aggregation = false;
    bool witness = false;
    bool value = false;
    bool support = false;
    bool admitted = false;
};

enum class NativeResetCertKind : uint8_t {
    NONE = 0,
    WITNESS_LOCAL = 1,
    HIDDEN_PUBLIC = 2
};

enum class NativeResetBindKind : uint8_t {
    NONE = 0,
    R_COM_HASH = 1,
    LEGACY_PC = 2,
    FIELD_NATIVE = 3
};

struct NativeResetPublicSpec {
    NativeResetBindKind bind = NativeResetBindKind::NONE;
    bool stmt_bound = false;
    bool output_bound = false;
    bool material_bound = false;
    bool relation_bound = false;
    bool no_basis_oracle = false;
    bool native_backend = false;
};

struct NativeResetPublicDecision {
    bool admitted = false;
    bool rejects_hash_only = false;
    bool rejects_legacy_pc = false;
    bool needs_layer_inverse_binding = true;
    bool needs_relation_backend = true;
    bool needs_wide_decomposition = false;
};

struct NativeResetLimbPlan {
    size_t limb_bits = 0;
    size_t alpha_limbs = 0;
    size_t row_limbs = 0;
    size_t chunk_terms = 0;
    size_t chunks = 0;
    size_t partial_bits = 0;
    bool needs_p_correction = false;
    bool needs_wide_correction = true;
    bool admitted = false;
};

struct NativeResetProofCircuit {
    size_t slots = 0;
    size_t old_terms = 0;
    size_t target_terms = 0;
    size_t relation_mul = 0;
    size_t inverse_mul = 0;
    size_t hash_openings = 0;
    size_t field_checks = 0;
    bool admitted = false;
};

struct NativeResetTraceOpening {
    size_t round = 0;
    size_t branch = 0;
    std::array<uint8_t, 32> branch_digest = {};
    std::array<uint8_t, 32> commit = {};
    bool mul_trace = false;
    bool layer_trace = false;
    bool inverse_trace = false;
};

struct NativeResetProofPayload {
    NativeResetProofParams params;
    NativeResetLimbPlan limb;
    NativeResetProofCircuit circuit;
    NativeResetArithProof arith;
    NativeResetLayerProof layer;
    std::vector<std::array<uint8_t, 32>> trace_commits;
    std::vector<NativeResetTraceOpening> trace_openings;
    std::array<uint8_t, 32> challenge = {};
    std::array<uint8_t, 32> response_digest = {};
    bool has_mul_trace = false;
    bool has_layer_trace = false;
    bool has_inverse_trace = false;
};

struct NativeResetProofDecision {
    bool admitted = false;
    bool ready = false;
    bool params = false;
    bool spec = false;
    bool circuit = false;
    bool transcript = false;
    bool traces = false;
    bool response = false;
    bool arithmetic = false;
    bool layer_binding = false;
};

enum class NativeResetPublicEvalKind : uint8_t {
    NONE = 0,
    RAW_ROWS = 1,
    STATEMENT_TRACE = 2,
    HIDDEN_CARRIER = 3
};

enum class NativeResetReuseKind : uint8_t {
    NONE = 0,
    STATEMENT_REPLAY = 1,
    CHOSEN_STATEMENT = 2,
    RAW_ROW_API = 3
};

struct NativeResetPublicEvalMaterial {
    NativeResetPublicEvalKind kind = NativeResetPublicEvalKind::NONE;
    NativeResetReuseKind reuse = NativeResetReuseKind::NONE;
    std::array<uint8_t, 32> stmt_digest = {};
    std::array<uint8_t, 32> output_digest = {};
    std::array<uint8_t, 32> relation_digest = {};
    std::array<uint8_t, 32> trace_digest = {};
    std::array<uint8_t, 32> material_digest = {};
    NativeResetLimbPlan limb;
    NativeResetProofCircuit circuit;
    bool reusable = false;
    bool statement_bound = false;
    bool output_bound = false;
    bool relation_bound = false;
    bool trace_bound = false;
    bool material_bound = false;
    bool has_raw_rows = false;
    bool hides_rows = false;
    bool no_basis_oracle = false;
    bool native_backend = false;
};

struct NativeResetPublicEvalDecision {
    bool admitted = false;
    bool publish_safe = false;
    bool material = false;
    bool privacy = false;
    bool reusable_safe = false;
    bool spec = false;
    bool payload = false;
    bool trace = false;
    bool rejects_raw = false;
    bool rejects_reusable = false;
    bool rejects_unbound = false;
    bool rejects_basis_oracle = false;
};

struct NativeResetPublicEvalPrivacy {
    bool admitted = false;
    bool publish_safe = false;
    bool reusable_safe = false;
    bool statement_replay = false;
    bool rejects_raw = false;
    bool rejects_oracle = false;
    bool rejects_unbound = false;
    bool rejects_unadmitted_payload = false;
};

struct NativeResetCert {
    NativeResetCertKind kind = NativeResetCertKind::NONE;
    std::array<uint8_t, 32> stmt_digest = {};
    std::array<uint8_t, 32> rows_digest = {};
    std::array<uint8_t, 32> output_digest = {};
    std::array<uint8_t, 32> relation_digest = {};
    HiddenCoeffPlan plan;
    NativeResetCheck check;
};

inline NativeResetPublicDecision decide_native_reset_public_spec(const NativeResetPublicSpec& spec, const HiddenCoeffPlan& plan) {
    NativeResetPublicDecision decision;
    decision.rejects_hash_only = spec.bind == NativeResetBindKind::R_COM_HASH;
    decision.rejects_legacy_pc = spec.bind == NativeResetBindKind::LEGACY_PC;
    decision.needs_layer_inverse_binding = spec.bind != NativeResetBindKind::FIELD_NATIVE;
    decision.needs_relation_backend = !spec.native_backend;
    decision.needs_wide_decomposition = plan.needs_wide_correction;
    decision.admitted =
        spec.bind == NativeResetBindKind::FIELD_NATIVE &&
        spec.stmt_bound &&
        spec.output_bound &&
        spec.material_bound &&
        spec.relation_bound &&
        spec.no_basis_oracle &&
        spec.native_backend &&
        plan.admitted &&
        !plan.needs_wide_correction;
    return decision;
}

inline size_t native_div_ceil(size_t a, size_t b) {
    if (b == 0)
        return 0;
    return (a + b - 1) / b;
}

inline NativeResetLimbPlan plan_native_reset_limbs(const HiddenCoeffBound& bound, size_t limb_bits = 63, size_t max_partial_bits = 251) {
    NativeResetLimbPlan plan;
    if (bound.terms == 0 || limb_bits == 0 || limb_bits > 63)
        return plan;
    if (bound.alpha_bits > 127 || bound.row_bits > 127)
        return plan;
    plan.limb_bits = limb_bits;
    plan.alpha_limbs = native_div_ceil(bound.alpha_bits, limb_bits);
    plan.row_limbs = native_div_ceil(bound.row_bits, limb_bits);
    plan.chunk_terms = bound.terms;
    plan.chunks = 1;
    plan.partial_bits = limb_bits + limb_bits + hidden_coeff_ceil_log2(plan.chunk_terms);
    if (plan.partial_bits > max_partial_bits) {
        size_t headroom = max_partial_bits > limb_bits + limb_bits ? max_partial_bits - limb_bits - limb_bits : 0;
        if (headroom == 0)
            return plan;
        size_t max_terms = headroom >= sizeof(size_t) * 8 - 1 ?
            std::numeric_limits<size_t>::max() :
            static_cast<size_t>(1) << headroom;
        if (max_terms == 0)
            return plan;
        plan.chunk_terms = bound.terms < max_terms ? bound.terms : max_terms;
        plan.chunks = native_div_ceil(bound.terms, plan.chunk_terms);
        plan.partial_bits = limb_bits + limb_bits + hidden_coeff_ceil_log2(plan.chunk_terms);
    }
    plan.needs_p_correction = plan.partial_bits >= 127;
    plan.needs_wide_correction = plan.partial_bits >= 252;
    plan.admitted =
        plan.alpha_limbs != 0 &&
        plan.row_limbs != 0 &&
        plan.chunk_terms != 0 &&
        !plan.needs_wide_correction;
    return plan;
}

inline NativeResetPublicDecision decide_native_reset_public_limb_spec(const NativeResetPublicSpec& spec, const HiddenCoeffBound& bound) {
    auto direct = plan_hidden_coeff(bound);
    auto limb = plan_native_reset_limbs(bound);
    auto decision = decide_native_reset_public_spec(spec, direct);
    decision.needs_wide_decomposition = direct.needs_wide_correction && !limb.admitted;
    decision.admitted =
        spec.bind == NativeResetBindKind::FIELD_NATIVE &&
        spec.stmt_bound &&
        spec.output_bound &&
        spec.material_bound &&
        spec.relation_bound &&
        spec.no_basis_oracle &&
        spec.native_backend &&
        direct.admitted &&
        (!direct.needs_wide_correction || limb.admitted);
    return decision;
}

inline bool native_reset_stmt_shape(const NativeResetStmt& stmt);
inline bool native_reset_output_shape(const NativeResetStmt& stmt, const NativeResetOutput& out);
inline bool native_digest_eq(const std::array<uint8_t, 32>& a, const std::array<uint8_t, 32>& b);
inline void native_hash_domain(Sha256& h, const char* domain);
inline std::array<uint8_t, 32> native_reset_stmt_digest(const NativeResetStmt& stmt);
inline std::array<uint8_t, 32> native_reset_output_digest(const NativeResetOutput& out);
inline std::array<uint8_t, 32> native_reset_arith_digest(const NativeResetArithProof& proof);
inline std::array<uint8_t, 32> native_reset_field_proof_digest(const NativeResetFieldProof& proof);
inline std::array<uint8_t, 32> native_reset_layer_trace_digest(const NativeResetLayerTraceProof& proof);
inline std::array<uint8_t, 32> native_reset_layer_digest(const NativeResetLayerProof& proof);
inline std::array<uint8_t, 32> native_reset_proof_trace_digest(const NativeResetProofPayload& payload);
inline std::array<uint8_t, 32> native_reset_trace_commit(const NativeResetTraceOpening& opening);
inline std::array<uint8_t, 32> native_reset_proof_response_digest(const NativeResetProofPayload& payload);
inline std::array<uint8_t, 32> native_reset_public_eval_label(const NativeResetStmt& stmt, const NativeResetOutput& out, const NativeResetCert& cert, const NativeResetProofPayload& payload, NativeResetPublicEvalKind kind = NativeResetPublicEvalKind::STATEMENT_TRACE, bool reusable = false, NativeResetReuseKind reuse = NativeResetReuseKind::NONE);
inline NativeResetArithDecision decide_native_reset_arith_proof(const NativeResetStmt& stmt, const NativeResetOutput& out, const NativeResetCert& cert, const NativeResetArithProof& proof);
inline NativeResetArithParams native_reset_arith_params_from_proof(const NativeResetProofParams& params);
inline bool native_reset_arith_params_ok(const NativeResetArithParams& params);
inline size_t native_reset_arith_opened_branch(const NativeResetArithParams& params, const std::array<uint8_t, 32>& challenge, size_t round, size_t slot);
inline void native_hash_arith_params(Sha256& h, const NativeResetArithParams& params);
inline Fp native_reset_arith_seed_fp(const std::array<uint8_t, 32>& seed, const char* domain, size_t round, size_t branch, size_t a, size_t b, size_t c);
inline std::array<uint8_t, 32> native_reset_layer_stack_digest(const std::vector<Layer>& layers);
inline NativeResetLayerTraceDecision decide_native_reset_layer_trace(const NativeResetLayerTraceProof& proof, const std::array<uint8_t, 32>& old_layer_digest, const std::array<uint8_t, 32>& new_layer_digest);
inline NativeResetFieldDecision decide_native_reset_field_proof(const NativeResetFieldProof& proof, const std::array<uint8_t, 32>& old_layer_digest, const std::array<uint8_t, 32>& new_layer_digest);
inline NativeResetLayerDecision decide_native_reset_layer_proof(const NativeResetStmt& stmt, const NativeResetOutput& out, const NativeResetLayerProof& proof);
inline bool verify_native_reset_witness_cert(const NativeResetStmt& stmt, const NativeResetRows& rows, const NativeResetSecrets& sec, const NativeResetOutput& out, const NativeResetCert& cert);

inline void native_hash_layer_trace_opening(Sha256& h, const NativeResetLayerTraceOpening& opening) {
    sha256_acc_u64(h, opening.round);
    sha256_acc_u64(h, opening.branch);
    h.update(opening.branch_digest.data(), opening.branch_digest.size());
    sha256_acc_u64(h, opening.message_trace ? 1 : 0);
    sha256_acc_u64(h, opening.schedule_trace ? 1 : 0);
    sha256_acc_u64(h, opening.compression_trace ? 1 : 0);
    sha256_acc_u64(h, opening.digest_trace ? 1 : 0);
}

inline std::array<uint8_t, 32> native_reset_layer_trace_opening_commit(const NativeResetLayerTraceOpening& opening) {
    Sha256 h;
    h.init();
    native_hash_domain(h, "pvac.native.reset.layer.trace.branch");
    native_hash_layer_trace_opening(h, opening);
    std::array<uint8_t, 32> out{};
    h.finish(out.data());
    return out;
}

inline void native_hash_layer_trace_layer(Sha256& h, const Layer& layer) {
    sha256_acc_u64(h, static_cast<uint8_t>(layer.rule));
    sha256_acc_u64(h, layer.seed.ztag);
    sha256_acc_u64(h, layer.seed.nonce.lo);
    sha256_acc_u64(h, layer.seed.nonce.hi);
    sha256_acc_u64(h, layer.pa);
    sha256_acc_u64(h, layer.pb);
    h.update(layer.R_com.data(), layer.R_com.size());
    sha256_acc_u64(h, layer.PC.size());
    for (const auto& pc : layer.PC) {
        h.update(pc.data(), pc.size());
    }
}

inline void native_hash_layer_trace_layers(Sha256& h, const std::vector<Layer>& layers) {
    sha256_acc_u64(h, layers.size());
    for (const auto& layer : layers) {
        native_hash_layer_trace_layer(h, layer);
    }
}

inline std::array<uint8_t, 32> native_reset_layer_trace_digest(const NativeResetLayerTraceProof& proof) {
    Sha256 h;
    h.init();
    native_hash_domain(h, "pvac.native.reset.layer.trace.proof");
    sha256_acc_u64(h, static_cast<uint8_t>(proof.kind));
    native_hash_arith_params(h, proof.params);
    native_hash_layer_trace_layers(h, proof.old_layers);
    native_hash_layer_trace_layers(h, proof.new_layers);
    sha256_acc_u64(h, proof.sha_proofs.size());
    for (const auto& branch_proof : proof.sha_proofs) {
        auto digest = sha256_hidden_trace_branch_proof_digest(branch_proof);
        h.update(digest.data(), digest.size());
    }
    auto field_digest = native_reset_field_proof_digest(proof.field_proof);
    h.update(field_digest.data(), field_digest.size());
    h.update(proof.old_layer_digest.data(), proof.old_layer_digest.size());
    h.update(proof.new_layer_digest.data(), proof.new_layer_digest.size());
    h.update(proof.challenge.data(), proof.challenge.size());
    h.update(proof.response_digest.data(), proof.response_digest.size());
    sha256_acc_u64(h, proof.trace_commits.size());
    for (const auto& commit : proof.trace_commits) {
        h.update(commit.data(), commit.size());
    }
    sha256_acc_u64(h, proof.openings.size());
    for (const auto& opening : proof.openings) {
        native_hash_layer_trace_opening(h, opening);
        h.update(opening.commit.data(), opening.commit.size());
    }
    sha256_acc_u64(h, proof.sha_repetitions);
    sha256_acc_u64(h, proof.sha_soundness_bits);
    sha256_acc_u64(h, proof.sha_target_bits);
    sha256_acc_u64(h, proof.sha_slots);
    sha256_acc_u64(h, proof.base_binding_relation ? 1 : 0);
    sha256_acc_u64(h, proof.product_binding_relation ? 1 : 0);
    sha256_acc_u64(h, proof.message_bound ? 1 : 0);
    sha256_acc_u64(h, proof.digest_bound ? 1 : 0);
    sha256_acc_u64(h, proof.sha_transition ? 1 : 0);
    sha256_acc_u64(h, proof.field_transition ? 1 : 0);
    sha256_acc_u64(h, proof.hides_witness ? 1 : 0);
    sha256_acc_u64(h, proof.no_basis_oracle ? 1 : 0);
    sha256_acc_u64(h, proof.native_backend ? 1 : 0);
    sha256_acc_u64(h, proof.has_raw_witness ? 1 : 0);
    std::array<uint8_t, 32> out{};
    h.finish(out.data());
    return out;
}

inline std::array<uint8_t, 32> native_reset_layer_trace_challenge(const NativeResetLayerTraceProof& proof, const std::array<uint8_t, 32>& old_layer_digest, const std::array<uint8_t, 32>& new_layer_digest) {
    Sha256 h;
    h.init();
    native_hash_domain(h, "pvac.native.reset.layer.trace.challenge");
    h.update(old_layer_digest.data(), old_layer_digest.size());
    h.update(new_layer_digest.data(), new_layer_digest.size());
    native_hash_arith_params(h, proof.params);
    native_hash_layer_trace_layers(h, proof.old_layers);
    native_hash_layer_trace_layers(h, proof.new_layers);
    sha256_acc_u64(h, proof.sha_proofs.size());
    for (const auto& branch_proof : proof.sha_proofs) {
        auto digest = sha256_hidden_trace_branch_proof_digest(branch_proof);
        h.update(digest.data(), digest.size());
    }
    auto field_digest = native_reset_field_proof_digest(proof.field_proof);
    h.update(field_digest.data(), field_digest.size());
    sha256_acc_u64(h, proof.sha_repetitions);
    sha256_acc_u64(h, proof.sha_soundness_bits);
    sha256_acc_u64(h, proof.sha_target_bits);
    sha256_acc_u64(h, proof.sha_slots);
    sha256_acc_u64(h, proof.trace_commits.size());
    for (const auto& commit : proof.trace_commits) {
        h.update(commit.data(), commit.size());
    }
    std::array<uint8_t, 32> out{};
    h.finish(out.data());
    return out;
}

inline size_t native_reset_layer_trace_opened_branch(const NativeResetArithParams& params, const std::array<uint8_t, 32>& challenge, size_t round, size_t slot) {
    return native_reset_arith_opened_branch(params, challenge, round, slot);
}

inline std::array<uint8_t, 32> native_reset_layer_trace_response_digest(const NativeResetLayerTraceProof& proof) {
    Sha256 h;
    h.init();
    native_hash_domain(h, "pvac.native.reset.layer.trace.response");
    native_hash_arith_params(h, proof.params);
    h.update(proof.challenge.data(), proof.challenge.size());
    sha256_acc_u64(h, proof.sha_proofs.size());
    for (const auto& branch_proof : proof.sha_proofs) {
        auto digest = sha256_hidden_trace_branch_proof_digest(branch_proof);
        h.update(digest.data(), digest.size());
    }
    auto field_digest = native_reset_field_proof_digest(proof.field_proof);
    h.update(field_digest.data(), field_digest.size());
    sha256_acc_u64(h, proof.openings.size());
    for (const auto& opening : proof.openings) {
        native_hash_layer_trace_opening(h, opening);
        h.update(opening.commit.data(), opening.commit.size());
    }
    std::array<uint8_t, 32> out{};
    h.finish(out.data());
    return out;
}

inline std::array<uint8_t, 32> native_reset_layer_trace_branch_digest(const std::array<uint8_t, 32>& seed, const std::array<uint8_t, 32>& old_layer_digest, const std::array<uint8_t, 32>& new_layer_digest, size_t round, size_t branch) {
    Sha256 h;
    h.init();
    native_hash_domain(h, "pvac.native.reset.layer.trace.branch_digest");
    h.update(seed.data(), seed.size());
    h.update(old_layer_digest.data(), old_layer_digest.size());
    h.update(new_layer_digest.data(), new_layer_digest.size());
    sha256_acc_u64(h, round);
    sha256_acc_u64(h, branch);
    std::array<uint8_t, 32> out{};
    h.finish(out.data());
    return out;
}

inline Fp native_reset_layer_trace_fp(const std::array<uint8_t, 32>& seed, const char* domain, size_t layer, size_t rep, size_t side) {
    Sha256 h;
    h.init();
    native_hash_domain(h, domain);
    h.update(seed.data(), seed.size());
    sha256_acc_u64(h, layer);
    sha256_acc_u64(h, rep);
    sha256_acc_u64(h, side);
    std::array<uint8_t, 32> digest{};
    h.finish(digest.data());
    uint64_t lo = 0;
    uint64_t hi = 0;
    for (size_t i = 0; i < 8; ++i) {
        lo |= static_cast<uint64_t>(digest[i]) << (i * 8);
        hi |= static_cast<uint64_t>(digest[i + 8]) << (i * 8);
    }
    return Fp{lo, hi & MASK63};
}

inline size_t native_reset_layer_trace_base_len(size_t slots) {
    return 14 + 8 * 5 + slots * 16;
}

inline size_t native_reset_layer_trace_prod_len() {
    return 14 + 32 * 2;
}

inline size_t native_reset_layer_trace_soundness_bits(size_t repetitions) {
    return repetitions;
}

inline Sha256HiddenTraceBranchProof native_reset_layer_trace_branch_for_trace(const Sha256Trace& trace, const std::array<uint8_t, 32>& seed, size_t layer, size_t rep) {
    auto a = native_reset_layer_trace_fp(seed, "pvac.native.reset.layer.sha.a", layer, rep, 0);
    auto b = native_reset_layer_trace_fp(seed, "pvac.native.reset.layer.sha.b", layer, rep, 1);
    auto hidden = make_sha256_hidden_trace_proof(trace, a, b);
    return make_sha256_hidden_trace_branch_proof(hidden);
}

inline Sha256Trace native_reset_layer_trace_for_layer(uint64_t canon_tag, const std::vector<Layer>& layers, const std::vector<std::vector<Fp>>& r, size_t layer) {
    if (layer >= layers.size())
        throw std::runtime_error("pvac: native reset layer trace layer index rejected");
    const auto& item = layers[layer];
    if (item.rule == RRule::BASE)
        return make_r_com_base_sha256_trace(canon_tag, item.seed.ztag, item.seed.nonce.lo, item.seed.nonce.hi, r[layer]);
    if (item.rule != RRule::PROD)
        throw std::runtime_error("pvac: native reset layer trace layer rule rejected");
    if (item.pa >= layer || item.pb >= layer)
        throw std::runtime_error("pvac: native reset layer trace product parent rejected");
    return make_r_com_prod_sha256_trace(layers[item.pa].R_com, layers[item.pb].R_com);
}

inline void native_reset_layer_trace_push_stack_sha(NativeResetLayerTraceProof& proof, uint64_t canon_tag, const std::vector<Layer>& layers, const std::vector<std::vector<Fp>>& r, const std::array<uint8_t, 32>& seed, size_t side) {
    for (size_t rep = 0; rep < proof.sha_repetitions; ++rep) {
        for (size_t layer = 0; layer < layers.size(); ++layer) {
            auto trace = native_reset_layer_trace_for_layer(canon_tag, layers, r, layer);
            proof.sha_proofs.push_back(native_reset_layer_trace_branch_for_trace(trace, seed, layer, rep + side * 1000000));
        }
    }
}

inline bool native_reset_layer_trace_product_stack_ok(const std::vector<Layer>& layers) {
    for (size_t i = 0; i < layers.size(); ++i) {
        if (layers[i].rule == RRule::BASE)
            continue;
        if (layers[i].rule != RRule::PROD)
            return false;
        if (layers[i].pa >= i || layers[i].pb >= i)
            return false;
        auto expected = compute_R_com_prod(layers[layers[i].pa].R_com, layers[layers[i].pb].R_com);
        if (!native_digest_eq(expected, layers[i].R_com))
            return false;
    }
    return true;
}

inline bool native_reset_layer_trace_sha_stack_ok(const NativeResetLayerTraceProof& proof) {
    if (proof.sha_target_bits == 0)
        return false;
    if (proof.sha_soundness_bits != native_reset_layer_trace_soundness_bits(proof.sha_repetitions))
        return false;
    if (proof.sha_soundness_bits < proof.sha_target_bits)
        return false;
    if (proof.sha_transition != (proof.sha_soundness_bits >= proof.sha_target_bits))
        return false;
    if (proof.sha_repetitions == 0)
        return false;
    if (proof.sha_slots == 0)
        return false;
    if (!native_digest_eq(native_reset_layer_stack_digest(proof.old_layers), proof.old_layer_digest))
        return false;
    if (!native_digest_eq(native_reset_layer_stack_digest(proof.new_layers), proof.new_layer_digest))
        return false;
    if (!native_reset_layer_trace_product_stack_ok(proof.old_layers))
        return false;
    if (!native_reset_layer_trace_product_stack_ok(proof.new_layers))
        return false;
    size_t layers = proof.old_layers.size() + proof.new_layers.size();
    if (proof.sha_proofs.size() != proof.sha_repetitions * layers)
        return false;
    size_t pos = 0;
    for (size_t rep = 0; rep < proof.sha_repetitions; ++rep) {
        (void)rep;
        for (const auto& layer : proof.old_layers) {
            const auto& sha = proof.sha_proofs[pos++];
            if (!verify_sha256_hidden_trace_branch_proof(sha))
                return false;
            if (!native_digest_eq(sha.digest, layer.R_com))
                return false;
            size_t expected_len = layer.rule == RRule::BASE ? native_reset_layer_trace_base_len(proof.sha_slots) : native_reset_layer_trace_prod_len();
            if (sha.byte_len != expected_len)
                return false;
        }
        for (const auto& layer : proof.new_layers) {
            const auto& sha = proof.sha_proofs[pos++];
            if (!verify_sha256_hidden_trace_branch_proof(sha))
                return false;
            if (!native_digest_eq(sha.digest, layer.R_com))
                return false;
            size_t expected_len = layer.rule == RRule::BASE ? native_reset_layer_trace_base_len(proof.sha_slots) : native_reset_layer_trace_prod_len();
            if (sha.byte_len != expected_len)
                return false;
        }
    }
    return true;
}

inline NativeResetLayerTraceProof make_native_reset_sha_compat_trace_boundary(const NativeResetLayerWitness& wit, const NativeResetProofParams& params, const std::array<uint8_t, 32>& seed) {
    NativeResetLayerTraceProof proof;
    proof.kind = NativeResetLayerTraceKind::BRANCH_SHA256;
    proof.params = native_reset_arith_params_from_proof(params);
    proof.old_layers = wit.old_layers;
    proof.new_layers = wit.new_layers;
    proof.sha_repetitions = 1;
    proof.sha_target_bits = proof.params.target_bits;
    proof.sha_soundness_bits = native_reset_layer_trace_soundness_bits(proof.sha_repetitions);
    proof.sha_slots = wit.old_r.empty() ? 0 : wit.old_r[0].size();
    proof.old_layer_digest = native_reset_layer_stack_digest(wit.old_layers);
    proof.new_layer_digest = native_reset_layer_stack_digest(wit.new_layers);
    proof.base_binding_relation = true;
    proof.product_binding_relation = true;
    proof.message_bound = true;
    proof.digest_bound = true;
    proof.sha_transition = proof.sha_soundness_bits >= proof.sha_target_bits;
    proof.hides_witness = true;
    proof.no_basis_oracle = true;
    proof.native_backend = true;
    if (!native_reset_arith_params_ok(proof.params))
        throw std::runtime_error("pvac: native reset layer trace params rejected");
    native_reset_layer_trace_push_stack_sha(proof, wit.canon_tag, wit.old_layers, wit.old_r, seed, 0);
    native_reset_layer_trace_push_stack_sha(proof, wit.canon_tag, wit.new_layers, wit.new_r, seed, 1);
    proof.trace_commits.reserve(proof.params.rounds * proof.params.branches);
    std::vector<NativeResetLayerTraceOpening> branches;
    branches.reserve(proof.params.rounds * proof.params.branches);
    for (size_t round = 0; round < proof.params.rounds; ++round) {
        for (size_t branch = 0; branch < proof.params.branches; ++branch) {
            NativeResetLayerTraceOpening opening;
            opening.round = round;
            opening.branch = branch;
            opening.branch_digest = native_reset_layer_trace_branch_digest(seed, proof.old_layer_digest, proof.new_layer_digest, round, branch);
            opening.message_trace = true;
            opening.schedule_trace = true;
            opening.compression_trace = true;
            opening.digest_trace = true;
            opening.commit = native_reset_layer_trace_opening_commit(opening);
            branches.push_back(opening);
            proof.trace_commits.push_back(opening.commit);
        }
    }
    proof.challenge = native_reset_layer_trace_challenge(proof, proof.old_layer_digest, proof.new_layer_digest);
    for (size_t round = 0; round < proof.params.rounds; ++round) {
        for (size_t slot = 0; slot < proof.params.opened_branches; ++slot) {
            size_t branch = native_reset_layer_trace_opened_branch(proof.params, proof.challenge, round, slot);
            proof.openings.push_back(branches[round * proof.params.branches + branch]);
        }
    }
    proof.response_digest = native_reset_layer_trace_response_digest(proof);
    return proof;
}

inline bool native_reset_layer_trace_openings_ok(const NativeResetLayerTraceProof& proof) {
    if (!native_reset_arith_params_ok(proof.params))
        return false;
    if (proof.trace_commits.size() != proof.params.rounds * proof.params.branches)
        return false;
    if (proof.openings.size() != proof.params.rounds * proof.params.opened_branches)
        return false;
    for (size_t round = 0; round < proof.params.rounds; ++round) {
        for (size_t slot = 0; slot < proof.params.opened_branches; ++slot) {
            size_t id = round * proof.params.opened_branches + slot;
            size_t branch = native_reset_layer_trace_opened_branch(proof.params, proof.challenge, round, slot);
            if (branch >= proof.params.branches)
                return false;
            const auto& opening = proof.openings[id];
            if (opening.round != round || opening.branch != branch)
                return false;
            if (!opening.message_trace || !opening.schedule_trace || !opening.compression_trace || !opening.digest_trace)
                return false;
            auto commit = native_reset_layer_trace_opening_commit(opening);
            if (!native_digest_eq(commit, opening.commit))
                return false;
            size_t commit_id = round * proof.params.branches + branch;
            if (!native_digest_eq(commit, proof.trace_commits[commit_id]))
                return false;
        }
    }
    return true;
}

inline NativeResetLayerTraceDecision decide_native_reset_layer_trace(const NativeResetLayerTraceProof& proof, const std::array<uint8_t, 32>& old_layer_digest, const std::array<uint8_t, 32>& new_layer_digest) {
    NativeResetLayerTraceDecision decision;
    decision.rejects_digest_only = proof.kind == NativeResetLayerTraceKind::DIGEST_ONLY;
    decision.rejects_open_witness = proof.kind == NativeResetLayerTraceKind::OPEN_WITNESS_LOCAL;
    decision.rejects_raw_witness = proof.has_raw_witness;
    decision.rejects_basis_oracle = !proof.no_basis_oracle;
    decision.params = native_reset_arith_params_ok(proof.params);
    decision.transcript =
        proof.kind == NativeResetLayerTraceKind::FIELD_NATIVE &&
        native_digest_eq(proof.old_layer_digest, old_layer_digest) &&
        native_digest_eq(proof.new_layer_digest, new_layer_digest) &&
        native_digest_eq(proof.challenge, native_reset_layer_trace_challenge(proof, old_layer_digest, new_layer_digest));
    decision.openings = decision.transcript;
    decision.response = decision.openings && native_digest_eq(proof.response_digest, native_reset_layer_trace_response_digest(proof));
    decision.message = decision.response && proof.message_bound;
    decision.digest = decision.response && proof.digest_bound;
    decision.base_binding = false;
    decision.product_binding = decision.response && proof.product_binding_relation;
    auto field_decision = decide_native_reset_field_proof(proof.field_proof, old_layer_digest, new_layer_digest);
    decision.sha = decision.response && proof.field_transition && field_decision.admitted;
    decision.secrecy =
        decision.response &&
        proof.hides_witness &&
        proof.no_basis_oracle &&
        proof.native_backend &&
        !proof.has_raw_witness &&
        !decision.rejects_digest_only &&
        !decision.rejects_open_witness;
    decision.ready = decision.params && decision.transcript && decision.openings && decision.response;
    decision.admitted = decision.ready && decision.message && decision.digest && decision.base_binding && decision.product_binding && decision.sha && decision.secrecy;
    return decision;
}

inline NativeResetProofCircuit plan_native_reset_proof_circuit(const NativeResetStmt& stmt) {
    NativeResetProofCircuit circuit;
    if (!native_reset_stmt_shape(stmt))
        return circuit;
    circuit.slots = stmt.c.size();
    circuit.old_terms = stmt.alpha.size();
    circuit.target_terms = stmt.target_terms;
    circuit.relation_mul = circuit.old_terms * circuit.target_terms * circuit.slots;
    circuit.inverse_mul = (circuit.old_terms + circuit.target_terms) * circuit.slots;
    circuit.hash_openings = circuit.old_terms + circuit.target_terms;
    circuit.field_checks =
        circuit.relation_mul +
        circuit.inverse_mul +
        circuit.old_terms * circuit.slots +
        circuit.target_terms * circuit.slots;
    circuit.admitted =
        circuit.slots != 0 &&
        circuit.old_terms != 0 &&
        circuit.target_terms != 0 &&
        circuit.relation_mul != 0 &&
        circuit.inverse_mul != 0 &&
        circuit.hash_openings != 0;
    return circuit;
}

inline void native_hash_proof_params(Sha256& h, const NativeResetProofParams& params) {
    sha256_acc_u64(h, params.rounds);
    sha256_acc_u64(h, params.branches);
    sha256_acc_u64(h, params.opened_branches);
    sha256_acc_u64(h, params.target_bits);
}

inline void native_hash_limb_plan(Sha256& h, const NativeResetLimbPlan& plan) {
    sha256_acc_u64(h, plan.limb_bits);
    sha256_acc_u64(h, plan.alpha_limbs);
    sha256_acc_u64(h, plan.row_limbs);
    sha256_acc_u64(h, plan.chunk_terms);
    sha256_acc_u64(h, plan.chunks);
    sha256_acc_u64(h, plan.partial_bits);
    sha256_acc_u64(h, plan.needs_p_correction ? 1 : 0);
    sha256_acc_u64(h, plan.needs_wide_correction ? 1 : 0);
    sha256_acc_u64(h, plan.admitted ? 1 : 0);
}

inline void native_hash_proof_circuit(Sha256& h, const NativeResetProofCircuit& circuit) {
    sha256_acc_u64(h, circuit.slots);
    sha256_acc_u64(h, circuit.old_terms);
    sha256_acc_u64(h, circuit.target_terms);
    sha256_acc_u64(h, circuit.relation_mul);
    sha256_acc_u64(h, circuit.inverse_mul);
    sha256_acc_u64(h, circuit.hash_openings);
    sha256_acc_u64(h, circuit.field_checks);
    sha256_acc_u64(h, circuit.admitted ? 1 : 0);
}

inline std::array<uint8_t, 32> native_reset_proof_challenge(const NativeResetStmt& stmt, const NativeResetOutput& out, const NativeResetCert& cert, const NativeResetPublicSpec& spec, const NativeResetProofPayload& payload) {
    Sha256 h;
    h.init();
    native_hash_domain(h, "pvac.native.reset.proof.challenge");
    auto sd = native_reset_stmt_digest(stmt);
    auto od = native_reset_output_digest(out);
    h.update(sd.data(), sd.size());
    h.update(od.data(), od.size());
    h.update(cert.stmt_digest.data(), cert.stmt_digest.size());
    h.update(cert.output_digest.data(), cert.output_digest.size());
    h.update(cert.relation_digest.data(), cert.relation_digest.size());
    sha256_acc_u64(h, static_cast<uint8_t>(spec.bind));
    sha256_acc_u64(h, spec.stmt_bound ? 1 : 0);
    sha256_acc_u64(h, spec.output_bound ? 1 : 0);
    sha256_acc_u64(h, spec.material_bound ? 1 : 0);
    sha256_acc_u64(h, spec.relation_bound ? 1 : 0);
    sha256_acc_u64(h, spec.no_basis_oracle ? 1 : 0);
    sha256_acc_u64(h, spec.native_backend ? 1 : 0);
    native_hash_proof_params(h, payload.params);
    native_hash_limb_plan(h, payload.limb);
    native_hash_proof_circuit(h, payload.circuit);
    sha256_acc_u64(h, payload.trace_commits.size());
    for (const auto& commit : payload.trace_commits) {
        h.update(commit.data(), commit.size());
    }
    std::array<uint8_t, 32> out_digest{};
    h.finish(out_digest.data());
    return out_digest;
}

inline void native_hash_trace_opening(Sha256& h, const NativeResetTraceOpening& opening) {
    sha256_acc_u64(h, opening.round);
    sha256_acc_u64(h, opening.branch);
    h.update(opening.branch_digest.data(), opening.branch_digest.size());
    sha256_acc_u64(h, opening.mul_trace ? 1 : 0);
    sha256_acc_u64(h, opening.layer_trace ? 1 : 0);
    sha256_acc_u64(h, opening.inverse_trace ? 1 : 0);
}

inline std::array<uint8_t, 32> native_reset_trace_commit(const NativeResetTraceOpening& opening) {
    Sha256 h;
    h.init();
    native_hash_domain(h, "pvac.native.reset.proof.branch");
    native_hash_trace_opening(h, opening);
    std::array<uint8_t, 32> out{};
    h.finish(out.data());
    return out;
}

inline size_t native_reset_challenge_branch(size_t branches, const std::array<uint8_t, 32>& challenge, size_t round, size_t slot, const char* domain) {
    if (branches == 0)
        return 0;
    uint64_t branch_count = static_cast<uint64_t>(branches);
    uint64_t max = std::numeric_limits<uint64_t>::max();
    uint64_t limit = max - (max % branch_count);
    for (uint64_t counter = 0;; ++counter) {
        Sha256 h;
        h.init();
        native_hash_domain(h, domain);
        h.update(challenge.data(), challenge.size());
        sha256_acc_u64(h, branch_count);
        sha256_acc_u64(h, round);
        sha256_acc_u64(h, slot);
        sha256_acc_u64(h, counter);
        std::array<uint8_t, 32> digest{};
        h.finish(digest.data());
        uint64_t value = load_le64(digest.data());
        if (value < limit)
            return static_cast<size_t>(value % branch_count);
    }
}

inline size_t native_reset_proof_opened_branch(const NativeResetProofParams& params, const std::array<uint8_t, 32>& challenge, size_t round, size_t slot) {
    if (params.branches == 0 || params.opened_branches != 1 || slot >= params.opened_branches)
        return params.branches;
    return native_reset_challenge_branch(params.branches, challenge, round, slot, "pvac.native.reset.proof.open");
}

inline std::array<uint8_t, 32> native_reset_proof_response_digest(const NativeResetProofPayload& payload) {
    Sha256 h;
    h.init();
    native_hash_domain(h, "pvac.native.reset.proof.response");
    native_hash_proof_params(h, payload.params);
    native_hash_limb_plan(h, payload.limb);
    native_hash_proof_circuit(h, payload.circuit);
    h.update(payload.challenge.data(), payload.challenge.size());
    sha256_acc_u64(h, payload.trace_openings.size());
    for (const auto& opening : payload.trace_openings) {
        native_hash_trace_opening(h, opening);
        h.update(opening.commit.data(), opening.commit.size());
    }
    std::array<uint8_t, 32> out{};
    h.finish(out.data());
    return out;
}

inline bool native_reset_proof_traces_ok(const NativeResetProofPayload& payload) {
    if (!payload.has_mul_trace || !payload.has_layer_trace || !payload.has_inverse_trace)
        return false;
    if (!native_reset_proof_params_ok(payload.params))
        return false;
    if (payload.trace_commits.size() != payload.params.rounds * payload.params.branches)
        return false;
    if (payload.trace_openings.size() != payload.params.rounds * payload.params.opened_branches)
        return false;
    for (size_t round = 0; round < payload.params.rounds; ++round) {
        for (size_t slot = 0; slot < payload.params.opened_branches; ++slot) {
            size_t opening_id = round * payload.params.opened_branches + slot;
            size_t branch = native_reset_proof_opened_branch(payload.params, payload.challenge, round, slot);
            if (branch >= payload.params.branches)
                return false;
            const auto& opening = payload.trace_openings[opening_id];
            if (opening.round != round || opening.branch != branch)
                return false;
            if (!opening.mul_trace || !opening.layer_trace || !opening.inverse_trace)
                return false;
            auto commit = native_reset_trace_commit(opening);
            if (!native_digest_eq(commit, opening.commit))
                return false;
            size_t commit_id = round * payload.params.branches + branch;
            if (!native_digest_eq(commit, payload.trace_commits[commit_id]))
                return false;
        }
    }
    return true;
}

inline NativeResetProofPayload make_native_reset_proof_payload(const NativeResetStmt& stmt, const NativeResetOutput& out, const NativeResetCert& cert, const NativeResetPublicSpec& spec) {
    NativeResetProofPayload proof;
    proof.params = make_native_reset_proof_params();
    proof.limb = plan_native_reset_limbs(stmt.bound);
    proof.circuit = plan_native_reset_proof_circuit(stmt);
    std::vector<NativeResetTraceOpening> branches;
    branches.reserve(proof.params.rounds * proof.params.branches);
    proof.trace_commits.reserve(proof.params.rounds * proof.params.branches);
    for (size_t round = 0; round < proof.params.rounds; ++round) {
        for (size_t branch = 0; branch < proof.params.branches; ++branch) {
            NativeResetTraceOpening opening;
            opening.round = round;
            opening.branch = branch;
            opening.branch_digest = native_reset_layer_trace_branch_digest(cert.relation_digest, native_reset_stmt_digest(stmt), native_reset_output_digest(out), round, branch);
            opening.mul_trace = true;
            opening.layer_trace = true;
            opening.inverse_trace = true;
            opening.commit = native_reset_trace_commit(opening);
            branches.push_back(opening);
            proof.trace_commits.push_back(opening.commit);
        }
    }
    proof.has_mul_trace = true;
    proof.has_layer_trace = true;
    proof.has_inverse_trace = true;
    proof.challenge = native_reset_proof_challenge(stmt, out, cert, spec, proof);
    for (size_t round = 0; round < proof.params.rounds; ++round) {
        for (size_t slot = 0; slot < proof.params.opened_branches; ++slot) {
            size_t branch = native_reset_proof_opened_branch(proof.params, proof.challenge, round, slot);
            proof.trace_openings.push_back(branches[round * proof.params.branches + branch]);
        }
    }
    proof.response_digest = native_reset_proof_response_digest(proof);
    return proof;
}

inline NativeResetProofDecision decide_native_reset_proof_payload(const NativeResetStmt& stmt, const NativeResetOutput& out, const NativeResetCert& cert, const NativeResetPublicSpec& spec, const NativeResetProofPayload& payload) {
    NativeResetProofDecision decision;
    decision.params = native_reset_proof_params_ok(payload.params);
    auto spec_decision = decide_native_reset_public_limb_spec(spec, stmt.bound);
    decision.spec = spec_decision.admitted;
    auto expected_circuit = plan_native_reset_proof_circuit(stmt);
    auto expected_limb = plan_native_reset_limbs(stmt.bound);
    decision.circuit =
        expected_circuit.admitted &&
        payload.circuit.slots == expected_circuit.slots &&
        payload.circuit.old_terms == expected_circuit.old_terms &&
        payload.circuit.target_terms == expected_circuit.target_terms &&
        payload.circuit.relation_mul == expected_circuit.relation_mul &&
        payload.circuit.inverse_mul == expected_circuit.inverse_mul &&
        payload.circuit.hash_openings == expected_circuit.hash_openings &&
        payload.circuit.field_checks == expected_circuit.field_checks &&
        payload.circuit.admitted == expected_circuit.admitted &&
        payload.limb.limb_bits == expected_limb.limb_bits &&
        payload.limb.alpha_limbs == expected_limb.alpha_limbs &&
        payload.limb.row_limbs == expected_limb.row_limbs &&
        payload.limb.chunk_terms == expected_limb.chunk_terms &&
        payload.limb.chunks == expected_limb.chunks &&
        payload.limb.partial_bits == expected_limb.partial_bits &&
        payload.limb.needs_p_correction == expected_limb.needs_p_correction &&
        payload.limb.needs_wide_correction == expected_limb.needs_wide_correction &&
        payload.limb.admitted == expected_limb.admitted;
    decision.transcript =
        cert.kind == NativeResetCertKind::HIDDEN_PUBLIC &&
        native_reset_output_shape(stmt, out) &&
        native_digest_eq(cert.stmt_digest, native_reset_stmt_digest(stmt)) &&
        native_digest_eq(cert.output_digest, native_reset_output_digest(out)) &&
        payload.trace_commits.size() == payload.params.rounds * payload.params.branches &&
        native_digest_eq(payload.challenge, native_reset_proof_challenge(stmt, out, cert, spec, payload));
    decision.traces = decision.transcript && native_reset_proof_traces_ok(payload);
    decision.response = decision.traces && native_digest_eq(payload.response_digest, native_reset_proof_response_digest(payload));
    decision.arithmetic = decide_native_reset_arith_proof(stmt, out, cert, payload.arith).admitted;
    decision.layer_binding = decide_native_reset_layer_proof(stmt, out, payload.layer).admitted;
    decision.ready = decision.params && decision.spec && decision.circuit && decision.transcript && decision.traces && decision.response;
    decision.admitted = decision.ready && decision.arithmetic && decision.layer_binding;
    return decision;
}

inline bool native_limb_plan_eq(const NativeResetLimbPlan& left, const NativeResetLimbPlan& right) {
    return
        left.limb_bits == right.limb_bits &&
        left.alpha_limbs == right.alpha_limbs &&
        left.row_limbs == right.row_limbs &&
        left.chunk_terms == right.chunk_terms &&
        left.chunks == right.chunks &&
        left.partial_bits == right.partial_bits &&
        left.needs_p_correction == right.needs_p_correction &&
        left.needs_wide_correction == right.needs_wide_correction &&
        left.admitted == right.admitted;
}

inline bool native_reset_proof_circuit_eq(const NativeResetProofCircuit& left, const NativeResetProofCircuit& right) {
    return
        left.slots == right.slots &&
        left.old_terms == right.old_terms &&
        left.target_terms == right.target_terms &&
        left.relation_mul == right.relation_mul &&
        left.inverse_mul == right.inverse_mul &&
        left.hash_openings == right.hash_openings &&
        left.field_checks == right.field_checks &&
        left.admitted == right.admitted;
}

inline std::array<uint8_t, 32> native_reset_proof_trace_digest(const NativeResetProofPayload& payload) {
    Sha256 h;
    h.init();
    native_hash_domain(h, "pvac.native.reset.proof.trace");
    native_hash_proof_params(h, payload.params);
    native_hash_limb_plan(h, payload.limb);
    native_hash_proof_circuit(h, payload.circuit);
    sha256_acc_u64(h, payload.trace_commits.size());
    for (const auto& commit : payload.trace_commits) {
        h.update(commit.data(), commit.size());
    }
    h.update(payload.challenge.data(), payload.challenge.size());
    h.update(payload.response_digest.data(), payload.response_digest.size());
    auto arith_digest = native_reset_arith_digest(payload.arith);
    h.update(arith_digest.data(), arith_digest.size());
    auto layer_digest = native_reset_layer_digest(payload.layer);
    h.update(layer_digest.data(), layer_digest.size());
    sha256_acc_u64(h, payload.has_mul_trace ? 1 : 0);
    sha256_acc_u64(h, payload.has_layer_trace ? 1 : 0);
    sha256_acc_u64(h, payload.has_inverse_trace ? 1 : 0);
    std::array<uint8_t, 32> out{};
    h.finish(out.data());
    return out;
}

inline std::array<uint8_t, 32> native_reset_public_eval_label(const NativeResetStmt& stmt, const NativeResetOutput& out, const NativeResetCert& cert, const NativeResetProofPayload& payload, NativeResetPublicEvalKind kind, bool reusable, NativeResetReuseKind reuse) {
    Sha256 h;
    h.init();
    native_hash_domain(h, "pvac.native.reset.public_eval_material");
    sha256_acc_u64(h, static_cast<uint8_t>(kind));
    sha256_acc_u64(h, reusable ? 1 : 0);
    sha256_acc_u64(h, static_cast<uint8_t>(reuse));
    auto sd = native_reset_stmt_digest(stmt);
    auto od = native_reset_output_digest(out);
    auto td = native_reset_proof_trace_digest(payload);
    h.update(sd.data(), sd.size());
    h.update(od.data(), od.size());
    h.update(cert.relation_digest.data(), cert.relation_digest.size());
    h.update(td.data(), td.size());
    std::array<uint8_t, 32> label{};
    h.finish(label.data());
    return label;
}

inline NativeResetPublicEvalMaterial make_native_reset_public_eval_material(const NativeResetStmt& stmt, const NativeResetOutput& out, const NativeResetCert& cert, const NativeResetPublicSpec& spec, const NativeResetProofPayload& payload, NativeResetPublicEvalKind kind = NativeResetPublicEvalKind::STATEMENT_TRACE) {
    if (!native_reset_output_shape(stmt, out))
        throw std::runtime_error("pvac: native reset public eval material shape rejected");
    auto payload_decision = decide_native_reset_proof_payload(stmt, out, cert, spec, payload);
    if (!payload_decision.ready)
        throw std::runtime_error("pvac: native reset public eval material proof rejected");
    NativeResetPublicEvalMaterial material;
    material.kind = kind;
    material.stmt_digest = native_reset_stmt_digest(stmt);
    material.output_digest = native_reset_output_digest(out);
    material.relation_digest = cert.relation_digest;
    material.trace_digest = native_reset_proof_trace_digest(payload);
    material.material_digest = native_reset_public_eval_label(stmt, out, cert, payload, kind, false, NativeResetReuseKind::NONE);
    material.limb = payload.limb;
    material.circuit = payload.circuit;
    material.statement_bound = true;
    material.output_bound = true;
    material.relation_bound = true;
    material.trace_bound = true;
    material.material_bound = true;
    material.hides_rows = true;
    material.no_basis_oracle = true;
    material.native_backend = true;
    return material;
}

inline NativeResetPublicEvalMaterial make_native_reset_replay_eval_material(const NativeResetStmt& stmt, const NativeResetOutput& out, const NativeResetCert& cert, const NativeResetPublicSpec& spec, const NativeResetProofPayload& payload, NativeResetPublicEvalKind kind = NativeResetPublicEvalKind::STATEMENT_TRACE) {
    auto material = make_native_reset_public_eval_material(stmt, out, cert, spec, payload, kind);
    material.reusable = true;
    material.reuse = NativeResetReuseKind::STATEMENT_REPLAY;
    material.material_digest = native_reset_public_eval_label(stmt, out, cert, payload, kind, true, material.reuse);
    return material;
}

inline NativeResetPublicEvalPrivacy decide_native_reset_public_eval_privacy(const NativeResetPublicEvalMaterial& material, const NativeResetProofDecision& payload_decision) {
    NativeResetPublicEvalPrivacy decision;
    decision.rejects_raw = material.kind == NativeResetPublicEvalKind::RAW_ROWS || material.has_raw_rows;
    decision.rejects_oracle =
        !material.hides_rows ||
        !material.no_basis_oracle ||
        material.reuse == NativeResetReuseKind::CHOSEN_STATEMENT ||
        material.reuse == NativeResetReuseKind::RAW_ROW_API;
    decision.rejects_unbound =
        !material.statement_bound ||
        !material.output_bound ||
        !material.relation_bound ||
        !material.trace_bound ||
        !material.material_bound ||
        !material.native_backend;
    decision.statement_replay = material.reusable && material.reuse == NativeResetReuseKind::STATEMENT_REPLAY;
    decision.rejects_unadmitted_payload = material.reusable && !payload_decision.admitted;
    decision.publish_safe =
        payload_decision.ready &&
        !decision.rejects_raw &&
        !decision.rejects_oracle &&
        !decision.rejects_unbound;
    decision.reusable_safe =
        !material.reusable ||
        (
            decision.statement_replay &&
            payload_decision.admitted &&
            material.kind != NativeResetPublicEvalKind::RAW_ROWS &&
            !decision.rejects_raw &&
            !decision.rejects_oracle &&
            !decision.rejects_unbound
        );
    decision.admitted = decision.publish_safe && decision.reusable_safe;
    return decision;
}

inline NativeResetPublicEvalDecision decide_native_reset_public_eval_material(const NativeResetStmt& stmt, const NativeResetOutput& out, const NativeResetCert& cert, const NativeResetPublicSpec& spec, const NativeResetProofPayload& payload, const NativeResetPublicEvalMaterial& material) {
    NativeResetPublicEvalDecision decision;
    auto spec_decision = decide_native_reset_public_limb_spec(spec, stmt.bound);
    auto payload_decision = decide_native_reset_proof_payload(stmt, out, cert, spec, payload);
    auto privacy_decision = decide_native_reset_public_eval_privacy(material, payload_decision);
    decision.spec = spec_decision.admitted;
    decision.payload = payload_decision.ready;
    decision.privacy = privacy_decision.admitted;
    decision.reusable_safe = privacy_decision.reusable_safe;
    decision.rejects_raw = material.kind == NativeResetPublicEvalKind::RAW_ROWS || material.has_raw_rows;
    decision.rejects_reusable = material.reusable && !privacy_decision.reusable_safe;
    decision.rejects_unbound =
        !material.statement_bound ||
        !material.output_bound ||
        !material.relation_bound ||
        !material.trace_bound ||
        !material.material_bound ||
        !material.native_backend;
    decision.rejects_basis_oracle = !material.hides_rows || !material.no_basis_oracle;
    auto expected_trace = native_reset_proof_trace_digest(payload);
    auto expected_label = native_reset_public_eval_label(stmt, out, cert, payload, material.kind, material.reusable, material.reuse);
    decision.trace = native_digest_eq(material.trace_digest, expected_trace);
    decision.material =
        (material.kind == NativeResetPublicEvalKind::STATEMENT_TRACE || material.kind == NativeResetPublicEvalKind::HIDDEN_CARRIER) &&
        !decision.rejects_raw &&
        !decision.rejects_reusable &&
        !decision.rejects_unbound &&
        !decision.rejects_basis_oracle &&
        decision.privacy &&
        native_digest_eq(material.stmt_digest, native_reset_stmt_digest(stmt)) &&
        native_digest_eq(material.output_digest, native_reset_output_digest(out)) &&
        native_digest_eq(material.relation_digest, cert.relation_digest) &&
        native_digest_eq(material.material_digest, expected_label) &&
        native_limb_plan_eq(material.limb, payload.limb) &&
        native_reset_proof_circuit_eq(material.circuit, payload.circuit) &&
        decision.trace;
    decision.publish_safe = decision.spec && decision.payload && decision.material && decision.trace;
    decision.admitted = decision.publish_safe && payload_decision.admitted;
    return decision;
}

inline bool verify_native_reset_public_eval_material(const NativeResetStmt& stmt, const NativeResetOutput& out, const NativeResetCert& cert, const NativeResetPublicSpec& spec, const NativeResetProofPayload& payload, const NativeResetPublicEvalMaterial& material) {
    return decide_native_reset_public_eval_material(stmt, out, cert, spec, payload, material).admitted;
}

inline bool verify_native_reset_proof_public_cert(const NativeResetStmt& stmt, const NativeResetOutput& out, const NativeResetCert& cert, const NativeResetPublicSpec& spec, const NativeResetProofPayload& payload) {
    return decide_native_reset_proof_payload(stmt, out, cert, spec, payload).admitted;
}

inline bool native_fp_vec_eq(const std::vector<Fp>& a, const std::vector<Fp>& b) {
    if (a.size() != b.size())
        return false;
    for (size_t i = 0; i < a.size(); ++i) {
        uint64_t diff = (a[i].lo ^ b[i].lo) | ((a[i].hi ^ b[i].hi) & MASK63);
        if (diff != 0)
            return false;
    }
    return true;
}

inline bool native_digest_eq(const std::array<uint8_t, 32>& a, const std::array<uint8_t, 32>& b) {
    uint8_t diff = 0;
    for (size_t i = 0; i < a.size(); ++i) {
        diff |= static_cast<uint8_t>(a[i] ^ b[i]);
    }
    return diff == 0;
}

inline std::vector<Fp> native_fp_zeros(size_t n) {
    return std::vector<Fp>(n, fp_from_u64(0));
}

inline void native_hash_domain(Sha256& h, const char* domain) {
    h.update(domain, std::strlen(domain));
}

inline void native_hash_fp(Sha256& h, const Fp& x) {
    sha256_acc_u64(h, x.lo);
    sha256_acc_u64(h, x.hi & MASK63);
}

inline void native_hash_vec(Sha256& h, const std::vector<Fp>& xs) {
    sha256_acc_u64(h, xs.size());
    for (const auto& x : xs) {
        native_hash_fp(h, x);
    }
}

inline void native_hash_matrix(Sha256& h, const std::vector<std::vector<Fp>>& x) {
    sha256_acc_u64(h, x.size());
    for (const auto& row : x) {
        native_hash_vec(h, row);
    }
}

inline void native_hash_cube(Sha256& h, const std::vector<std::vector<std::vector<Fp>>>& x) {
    sha256_acc_u64(h, x.size());
    for (const auto& row : x) {
        native_hash_matrix(h, row);
    }
}

inline void native_hash_plan(Sha256& h, const HiddenCoeffPlan& plan) {
    sha256_acc_u64(h, plan.sum_bits);
    sha256_acc_u64(h, plan.needs_p_correction ? 1 : 0);
    sha256_acc_u64(h, plan.needs_wide_correction ? 1 : 0);
    sha256_acc_u64(h, plan.admitted ? 1 : 0);
}

inline void native_hash_check(Sha256& h, const NativeResetCheck& check) {
    sha256_acc_u64(h, check.shape ? 1 : 0);
    sha256_acc_u64(h, check.aggregation ? 1 : 0);
    sha256_acc_u64(h, check.witness ? 1 : 0);
    sha256_acc_u64(h, check.value ? 1 : 0);
    sha256_acc_u64(h, check.support ? 1 : 0);
    sha256_acc_u64(h, check.admitted ? 1 : 0);
}

inline bool native_matrix_shape(const std::vector<std::vector<Fp>>& x, size_t rows, size_t slots) {
    if (x.size() != rows)
        return false;
    for (const auto& row : x) {
        if (row.size() != slots)
            return false;
    }
    return true;
}

inline bool native_cube_shape(const std::vector<std::vector<std::vector<Fp>>>& x, size_t rows, size_t cols, size_t slots) {
    if (x.size() != rows)
        return false;
    for (const auto& row : x) {
        if (row.size() != cols)
            return false;
        for (const auto& cell : row) {
            if (cell.size() != slots)
                return false;
        }
    }
    return true;
}

inline bool native_reset_stmt_shape(const NativeResetStmt& stmt) {
    if (stmt.c.empty())
        return false;
    if (stmt.alpha.empty())
        return false;
    if (stmt.target_terms == 0)
        return false;
    if (!native_matrix_shape(stmt.alpha, stmt.alpha.size(), stmt.c.size()))
        return false;
    if (stmt.bound.terms != stmt.alpha.size())
        return false;
    return plan_hidden_coeff(stmt.bound).admitted;
}

inline bool native_reset_rows_shape(const NativeResetStmt& stmt, const NativeResetRows& rows) {
    if (!native_reset_stmt_shape(stmt))
        return false;
    if (!native_matrix_shape(rows.bias, stmt.alpha.size(), stmt.c.size()))
        return false;
    return native_cube_shape(rows.mix, stmt.alpha.size(), stmt.target_terms, stmt.c.size());
}

inline bool native_reset_secret_shape(const NativeResetStmt& stmt, const NativeResetSecrets& sec) {
    if (!native_reset_stmt_shape(stmt))
        return false;
    if (!native_matrix_shape(sec.old_x, stmt.alpha.size(), stmt.c.size()))
        return false;
    return native_matrix_shape(sec.new_y, stmt.target_terms, stmt.c.size());
}

inline NativeResetOutput native_reset_aggregate(const NativeResetStmt& stmt, const NativeResetRows& rows) {
    if (!native_reset_rows_shape(stmt, rows))
        throw std::runtime_error("pvac: native reset aggregate shape rejected");
    NativeResetOutput out;
    out.c = stmt.c;
    out.beta.assign(stmt.target_terms, native_fp_zeros(stmt.c.size()));
    for (size_t i = 0; i < stmt.alpha.size(); ++i) {
        for (size_t j = 0; j < stmt.c.size(); ++j) {
            out.c[j] = fp_add(out.c[j], fp_mul(stmt.alpha[i][j], rows.bias[i][j]));
        }
        for (size_t t = 0; t < stmt.target_terms; ++t) {
            for (size_t j = 0; j < stmt.c.size(); ++j) {
                out.beta[t][j] = fp_add(out.beta[t][j], fp_mul(stmt.alpha[i][j], rows.mix[i][t][j]));
            }
        }
    }
    return out;
}

inline bool native_reset_output_shape(const NativeResetStmt& stmt, const NativeResetOutput& out) {
    if (!native_reset_stmt_shape(stmt))
        return false;
    if (out.c.size() != stmt.c.size())
        return false;
    return native_matrix_shape(out.beta, stmt.target_terms, stmt.c.size());
}

inline bool native_reset_arith_params_ok(const NativeResetArithParams& params) {
    if (params.target_bits < 128)
        return false;
    if (params.branches != 3)
        return false;
    if (params.opened_branches != 1)
        return false;
    NativeResetProofParams proof;
    proof.rounds = params.rounds;
    proof.branches = params.branches;
    proof.opened_branches = params.opened_branches;
    proof.target_bits = params.target_bits;
    return native_reset_proof_soundness_bits(proof) >= params.target_bits;
}

inline NativeResetArithParams native_reset_arith_params_from_proof(const NativeResetProofParams& params) {
    NativeResetArithParams out;
    out.rounds = params.rounds;
    out.branches = params.branches;
    out.opened_branches = params.opened_branches;
    out.target_bits = params.target_bits;
    return out;
}

inline bool native_reset_arith_share_shape(const NativeResetStmt& stmt, const NativeResetArithShareSet& share) {
    if (!native_reset_stmt_shape(stmt))
        return false;
    if (!native_matrix_shape(share.old_x, stmt.alpha.size(), stmt.c.size()))
        return false;
    if (!native_matrix_shape(share.new_y, stmt.target_terms, stmt.c.size()))
        return false;
    if (!native_matrix_shape(share.bias, stmt.alpha.size(), stmt.c.size()))
        return false;
    return native_cube_shape(share.mix, stmt.alpha.size(), stmt.target_terms, stmt.c.size());
}

inline bool native_reset_arith_residual_shape(const NativeResetStmt& stmt, const NativeResetArithResidual& residual) {
    if (!native_reset_stmt_shape(stmt))
        return false;
    if (!native_matrix_shape(residual.old_x, stmt.alpha.size(), stmt.c.size()))
        return false;
    if (residual.c.size() != stmt.c.size())
        return false;
    return native_matrix_shape(residual.beta, stmt.target_terms, stmt.c.size());
}

inline bool native_reset_arith_residual_eq(const NativeResetArithResidual& left, const NativeResetArithResidual& right) {
    if (left.old_x.size() != right.old_x.size())
        return false;
    for (size_t i = 0; i < left.old_x.size(); ++i) {
        if (!native_fp_vec_eq(left.old_x[i], right.old_x[i]))
            return false;
    }
    if (!native_fp_vec_eq(left.c, right.c))
        return false;
    if (left.beta.size() != right.beta.size())
        return false;
    for (size_t t = 0; t < left.beta.size(); ++t) {
        if (!native_fp_vec_eq(left.beta[t], right.beta[t]))
            return false;
    }
    return true;
}

inline NativeResetArithResidual native_reset_arith_zero_residual(const NativeResetStmt& stmt) {
    NativeResetArithResidual out;
    out.old_x.assign(stmt.alpha.size(), native_fp_zeros(stmt.c.size()));
    out.c = native_fp_zeros(stmt.c.size());
    out.beta.assign(stmt.target_terms, native_fp_zeros(stmt.c.size()));
    return out;
}

inline NativeResetArithResidual native_reset_arith_add_residual(const NativeResetStmt& stmt, const NativeResetArithResidual& left, const NativeResetArithResidual& right) {
    if (!native_reset_arith_residual_shape(stmt, left) || !native_reset_arith_residual_shape(stmt, right))
        throw std::runtime_error("pvac: native reset arithmetic residual shape rejected");
    NativeResetArithResidual out = native_reset_arith_zero_residual(stmt);
    for (size_t i = 0; i < stmt.alpha.size(); ++i) {
        for (size_t j = 0; j < stmt.c.size(); ++j) {
            out.old_x[i][j] = fp_add(left.old_x[i][j], right.old_x[i][j]);
        }
    }
    for (size_t j = 0; j < stmt.c.size(); ++j) {
        out.c[j] = fp_add(left.c[j], right.c[j]);
    }
    for (size_t t = 0; t < stmt.target_terms; ++t) {
        for (size_t j = 0; j < stmt.c.size(); ++j) {
            out.beta[t][j] = fp_add(left.beta[t][j], right.beta[t][j]);
        }
    }
    return out;
}

inline bool native_reset_arith_residual_zero(const NativeResetStmt& stmt, const NativeResetArithResidual& residual) {
    return native_reset_arith_residual_shape(stmt, residual) && native_reset_arith_residual_eq(residual, native_reset_arith_zero_residual(stmt));
}

inline NativeResetArithResidual native_reset_arith_residual_sum(const NativeResetStmt& stmt, const std::vector<NativeResetArithResidual>& residuals, size_t offset) {
    if (offset + 3 > residuals.size())
        throw std::runtime_error("pvac: native reset arithmetic residual window rejected");
    auto out = native_reset_arith_zero_residual(stmt);
    for (size_t branch = 0; branch < 3; ++branch) {
        out = native_reset_arith_add_residual(stmt, out, residuals[offset + branch]);
    }
    return out;
}

inline void native_hash_arith_params(Sha256& h, const NativeResetArithParams& params) {
    sha256_acc_u64(h, params.rounds);
    sha256_acc_u64(h, params.branches);
    sha256_acc_u64(h, params.opened_branches);
    sha256_acc_u64(h, params.target_bits);
}

inline void native_hash_arith_share(Sha256& h, const NativeResetArithShareSet& share) {
    native_hash_matrix(h, share.old_x);
    native_hash_matrix(h, share.new_y);
    native_hash_matrix(h, share.bias);
    native_hash_cube(h, share.mix);
}

inline void native_hash_arith_residual(Sha256& h, const NativeResetArithResidual& residual) {
    native_hash_matrix(h, residual.old_x);
    native_hash_vec(h, residual.c);
    native_hash_matrix(h, residual.beta);
}

inline void native_hash_arith_opening(Sha256& h, const NativeResetArithOpening& opening) {
    sha256_acc_u64(h, opening.round);
    sha256_acc_u64(h, opening.branch);
    native_hash_arith_share(h, opening.self);
    native_hash_arith_share(h, opening.next);
    native_hash_arith_residual(h, opening.residual);
}

inline std::array<uint8_t, 32> native_reset_arith_opening_commit(const NativeResetArithOpening& opening) {
    Sha256 h;
    h.init();
    native_hash_domain(h, "pvac.native.reset.arith.branch");
    native_hash_arith_opening(h, opening);
    std::array<uint8_t, 32> out{};
    h.finish(out.data());
    return out;
}

inline std::array<uint8_t, 32> native_reset_arith_digest(const NativeResetArithProof& proof) {
    Sha256 h;
    h.init();
    native_hash_domain(h, "pvac.native.reset.arith.proof");
    sha256_acc_u64(h, static_cast<uint8_t>(proof.kind));
    native_hash_arith_params(h, proof.params);
    h.update(proof.stmt_digest.data(), proof.stmt_digest.size());
    h.update(proof.output_digest.data(), proof.output_digest.size());
    h.update(proof.relation_digest.data(), proof.relation_digest.size());
    h.update(proof.challenge.data(), proof.challenge.size());
    h.update(proof.response_digest.data(), proof.response_digest.size());
    sha256_acc_u64(h, proof.branch_commits.size());
    for (const auto& commit : proof.branch_commits) {
        h.update(commit.data(), commit.size());
    }
    sha256_acc_u64(h, proof.residuals.size());
    for (const auto& residual : proof.residuals) {
        native_hash_arith_residual(h, residual);
    }
    sha256_acc_u64(h, proof.openings.size());
    for (const auto& opening : proof.openings) {
        native_hash_arith_opening(h, opening);
        h.update(opening.commit.data(), opening.commit.size());
    }
    sha256_acc_u64(h, proof.product_relation ? 1 : 0);
    sha256_acc_u64(h, proof.reset_relation ? 1 : 0);
    sha256_acc_u64(h, proof.hides_witness ? 1 : 0);
    sha256_acc_u64(h, proof.no_basis_oracle ? 1 : 0);
    sha256_acc_u64(h, proof.native_backend ? 1 : 0);
    sha256_acc_u64(h, proof.has_raw_witness ? 1 : 0);
    std::array<uint8_t, 32> out{};
    h.finish(out.data());
    return out;
}

inline std::array<uint8_t, 32> native_reset_arith_challenge(const NativeResetStmt& stmt, const NativeResetOutput& out, const NativeResetCert& cert, const NativeResetArithProof& proof) {
    Sha256 h;
    h.init();
    native_hash_domain(h, "pvac.native.reset.arith.challenge");
    auto sd = native_reset_stmt_digest(stmt);
    auto od = native_reset_output_digest(out);
    h.update(sd.data(), sd.size());
    h.update(od.data(), od.size());
    h.update(cert.relation_digest.data(), cert.relation_digest.size());
    native_hash_arith_params(h, proof.params);
    sha256_acc_u64(h, proof.branch_commits.size());
    for (const auto& commit : proof.branch_commits) {
        h.update(commit.data(), commit.size());
    }
    sha256_acc_u64(h, proof.residuals.size());
    for (const auto& residual : proof.residuals) {
        native_hash_arith_residual(h, residual);
    }
    std::array<uint8_t, 32> out_digest{};
    h.finish(out_digest.data());
    return out_digest;
}

inline size_t native_reset_arith_opened_branch(const NativeResetArithParams& params, const std::array<uint8_t, 32>& challenge, size_t round, size_t slot) {
    if (params.branches == 0 || params.opened_branches != 1 || slot >= params.opened_branches)
        return params.branches;
    return native_reset_challenge_branch(params.branches, challenge, round, slot, "pvac.native.reset.arith.open");
}

inline std::array<uint8_t, 32> native_reset_arith_response_digest(const NativeResetArithProof& proof) {
    Sha256 h;
    h.init();
    native_hash_domain(h, "pvac.native.reset.arith.response");
    native_hash_arith_params(h, proof.params);
    h.update(proof.challenge.data(), proof.challenge.size());
    sha256_acc_u64(h, proof.openings.size());
    for (const auto& opening : proof.openings) {
        native_hash_arith_opening(h, opening);
        h.update(opening.commit.data(), opening.commit.size());
    }
    std::array<uint8_t, 32> out{};
    h.finish(out.data());
    return out;
}

inline Fp native_reset_arith_seed_fp(const std::array<uint8_t, 32>& seed, const char* domain, size_t round, size_t branch, size_t a, size_t b, size_t c) {
    Sha256 h;
    h.init();
    native_hash_domain(h, domain);
    h.update(seed.data(), seed.size());
    sha256_acc_u64(h, round);
    sha256_acc_u64(h, branch);
    sha256_acc_u64(h, a);
    sha256_acc_u64(h, b);
    sha256_acc_u64(h, c);
    std::array<uint8_t, 32> digest{};
    h.finish(digest.data());
    uint64_t lo = load_le64(digest.data());
    uint64_t hi = load_le64(digest.data() + 8) & MASK63;
    return fp_from_words(lo, hi);
}

inline std::array<Fp, 3> native_reset_arith_split_fp(const Fp& value, const std::array<uint8_t, 32>& seed, const char* domain, size_t round, size_t a, size_t b, size_t c) {
    std::array<Fp, 3> out{};
    out[0] = native_reset_arith_seed_fp(seed, domain, round, 0, a, b, c);
    out[1] = native_reset_arith_seed_fp(seed, domain, round, 1, a, b, c);
    out[2] = fp_sub(fp_sub(value, out[0]), out[1]);
    return out;
}

inline std::array<NativeResetArithShareSet, 3> native_reset_arith_split_witness(const NativeResetStmt& stmt, const NativeResetRows& rows, const NativeResetSecrets& sec, const std::array<uint8_t, 32>& seed, size_t round) {
    if (!native_reset_rows_shape(stmt, rows) || !native_reset_secret_shape(stmt, sec))
        throw std::runtime_error("pvac: native reset arithmetic witness shape rejected");
    std::array<NativeResetArithShareSet, 3> out;
    for (auto& share : out) {
        share.old_x.assign(stmt.alpha.size(), native_fp_zeros(stmt.c.size()));
        share.new_y.assign(stmt.target_terms, native_fp_zeros(stmt.c.size()));
        share.bias.assign(stmt.alpha.size(), native_fp_zeros(stmt.c.size()));
        share.mix.assign(stmt.alpha.size(), std::vector<std::vector<Fp>>(stmt.target_terms, native_fp_zeros(stmt.c.size())));
    }
    for (size_t i = 0; i < stmt.alpha.size(); ++i) {
        for (size_t j = 0; j < stmt.c.size(); ++j) {
            auto old_share = native_reset_arith_split_fp(sec.old_x[i][j], seed, "pvac.native.reset.arith.old", round, i, j, 0);
            auto bias_share = native_reset_arith_split_fp(rows.bias[i][j], seed, "pvac.native.reset.arith.bias", round, i, j, 0);
            for (size_t branch = 0; branch < 3; ++branch) {
                out[branch].old_x[i][j] = old_share[branch];
                out[branch].bias[i][j] = bias_share[branch];
            }
        }
    }
    for (size_t t = 0; t < stmt.target_terms; ++t) {
        for (size_t j = 0; j < stmt.c.size(); ++j) {
            auto share = native_reset_arith_split_fp(sec.new_y[t][j], seed, "pvac.native.reset.arith.new", round, t, j, 0);
            for (size_t branch = 0; branch < 3; ++branch) {
                out[branch].new_y[t][j] = share[branch];
            }
        }
    }
    for (size_t i = 0; i < stmt.alpha.size(); ++i) {
        for (size_t t = 0; t < stmt.target_terms; ++t) {
            for (size_t j = 0; j < stmt.c.size(); ++j) {
                auto share = native_reset_arith_split_fp(rows.mix[i][t][j], seed, "pvac.native.reset.arith.mix", round, i, t, j);
                for (size_t branch = 0; branch < 3; ++branch) {
                    out[branch].mix[i][t][j] = share[branch];
                }
            }
        }
    }
    return out;
}

inline Fp native_reset_arith_mul_share(const Fp& a, const Fp& b, const Fp& an, const Fp& bn) {
    return fp_add(fp_add(fp_mul(a, b), fp_mul(a, bn)), fp_mul(an, b));
}

inline bool native_reset_field_share_shape(const NativeResetFieldProof& proof, const NativeResetFieldShareSet& share) {
    if (proof.slots == 0)
        return false;
    if (!native_matrix_shape(share.old_r, proof.old_layers.size(), proof.slots))
        return false;
    return native_matrix_shape(share.new_r, proof.new_layers.size(), proof.slots);
}

inline bool native_reset_field_residual_shape(const NativeResetFieldProof& proof, const NativeResetFieldResidual& residual) {
    if (proof.slots == 0)
        return false;
    if (!native_matrix_shape(residual.old_prod, proof.old_layers.size(), proof.slots))
        return false;
    return native_matrix_shape(residual.new_prod, proof.new_layers.size(), proof.slots);
}

inline bool native_reset_field_residual_eq(const NativeResetFieldResidual& left, const NativeResetFieldResidual& right) {
    if (left.old_prod.size() != right.old_prod.size())
        return false;
    for (size_t i = 0; i < left.old_prod.size(); ++i) {
        if (!native_fp_vec_eq(left.old_prod[i], right.old_prod[i]))
            return false;
    }
    if (left.new_prod.size() != right.new_prod.size())
        return false;
    for (size_t i = 0; i < left.new_prod.size(); ++i) {
        if (!native_fp_vec_eq(left.new_prod[i], right.new_prod[i]))
            return false;
    }
    return true;
}

inline NativeResetFieldResidual native_reset_field_zero_residual(size_t old_layers, size_t new_layers, size_t slots) {
    NativeResetFieldResidual out;
    out.old_prod.assign(old_layers, native_fp_zeros(slots));
    out.new_prod.assign(new_layers, native_fp_zeros(slots));
    return out;
}

inline NativeResetFieldResidual native_reset_field_add_residual(const NativeResetFieldProof& proof, const NativeResetFieldResidual& left, const NativeResetFieldResidual& right) {
    if (!native_reset_field_residual_shape(proof, left) || !native_reset_field_residual_shape(proof, right))
        throw std::runtime_error("pvac: native reset field residual shape rejected");
    auto out = native_reset_field_zero_residual(proof.old_layers.size(), proof.new_layers.size(), proof.slots);
    for (size_t i = 0; i < proof.old_layers.size(); ++i) {
        for (size_t j = 0; j < proof.slots; ++j) {
            out.old_prod[i][j] = fp_add(left.old_prod[i][j], right.old_prod[i][j]);
        }
    }
    for (size_t i = 0; i < proof.new_layers.size(); ++i) {
        for (size_t j = 0; j < proof.slots; ++j) {
            out.new_prod[i][j] = fp_add(left.new_prod[i][j], right.new_prod[i][j]);
        }
    }
    return out;
}

inline bool native_reset_field_residual_zero(const NativeResetFieldProof& proof, const NativeResetFieldResidual& residual) {
    return native_reset_field_residual_shape(proof, residual) && native_reset_field_residual_eq(residual, native_reset_field_zero_residual(proof.old_layers.size(), proof.new_layers.size(), proof.slots));
}

inline NativeResetFieldResidual native_reset_field_residual_sum(const NativeResetFieldProof& proof, size_t offset) {
    if (offset + 3 > proof.residuals.size())
        throw std::runtime_error("pvac: native reset field residual window rejected");
    auto out = native_reset_field_zero_residual(proof.old_layers.size(), proof.new_layers.size(), proof.slots);
    for (size_t branch = 0; branch < 3; ++branch) {
        out = native_reset_field_add_residual(proof, out, proof.residuals[offset + branch]);
    }
    return out;
}

inline void native_hash_field_share(Sha256& h, const NativeResetFieldShareSet& share) {
    native_hash_matrix(h, share.old_r);
    native_hash_matrix(h, share.new_r);
}

inline void native_hash_field_residual(Sha256& h, const NativeResetFieldResidual& residual) {
    native_hash_matrix(h, residual.old_prod);
    native_hash_matrix(h, residual.new_prod);
}

inline void native_hash_field_opening(Sha256& h, const NativeResetFieldOpening& opening) {
    sha256_acc_u64(h, opening.round);
    sha256_acc_u64(h, opening.branch);
    native_hash_field_share(h, opening.self);
    native_hash_field_share(h, opening.next);
    native_hash_field_residual(h, opening.residual);
}

inline std::array<uint8_t, 32> native_reset_field_opening_commit(const NativeResetFieldOpening& opening) {
    Sha256 h;
    h.init();
    native_hash_domain(h, "pvac.native.reset.field.branch");
    native_hash_field_opening(h, opening);
    std::array<uint8_t, 32> out{};
    h.finish(out.data());
    return out;
}

inline std::array<uint8_t, 32> native_reset_field_proof_digest(const NativeResetFieldProof& proof) {
    Sha256 h;
    h.init();
    native_hash_domain(h, "pvac.native.reset.field.proof");
    native_hash_arith_params(h, proof.params);
    native_hash_layer_trace_layers(h, proof.old_layers);
    native_hash_layer_trace_layers(h, proof.new_layers);
    h.update(proof.old_layer_digest.data(), proof.old_layer_digest.size());
    h.update(proof.new_layer_digest.data(), proof.new_layer_digest.size());
    h.update(proof.challenge.data(), proof.challenge.size());
    h.update(proof.response_digest.data(), proof.response_digest.size());
    sha256_acc_u64(h, proof.branch_commits.size());
    for (const auto& commit : proof.branch_commits) {
        h.update(commit.data(), commit.size());
    }
    sha256_acc_u64(h, proof.residuals.size());
    for (const auto& residual : proof.residuals) {
        native_hash_field_residual(h, residual);
    }
    sha256_acc_u64(h, proof.openings.size());
    for (const auto& opening : proof.openings) {
        native_hash_field_opening(h, opening);
        h.update(opening.commit.data(), opening.commit.size());
    }
    sha256_acc_u64(h, proof.slots);
    sha256_acc_u64(h, proof.product_relation ? 1 : 0);
    sha256_acc_u64(h, proof.hides_witness ? 1 : 0);
    sha256_acc_u64(h, proof.no_basis_oracle ? 1 : 0);
    sha256_acc_u64(h, proof.native_backend ? 1 : 0);
    sha256_acc_u64(h, proof.has_raw_witness ? 1 : 0);
    std::array<uint8_t, 32> out{};
    h.finish(out.data());
    return out;
}

inline std::array<uint8_t, 32> native_reset_field_challenge(const NativeResetFieldProof& proof, const std::array<uint8_t, 32>& old_layer_digest, const std::array<uint8_t, 32>& new_layer_digest) {
    Sha256 h;
    h.init();
    native_hash_domain(h, "pvac.native.reset.field.challenge");
    h.update(old_layer_digest.data(), old_layer_digest.size());
    h.update(new_layer_digest.data(), new_layer_digest.size());
    native_hash_arith_params(h, proof.params);
    native_hash_layer_trace_layers(h, proof.old_layers);
    native_hash_layer_trace_layers(h, proof.new_layers);
    sha256_acc_u64(h, proof.branch_commits.size());
    for (const auto& commit : proof.branch_commits) {
        h.update(commit.data(), commit.size());
    }
    sha256_acc_u64(h, proof.residuals.size());
    for (const auto& residual : proof.residuals) {
        native_hash_field_residual(h, residual);
    }
    sha256_acc_u64(h, proof.slots);
    std::array<uint8_t, 32> out{};
    h.finish(out.data());
    return out;
}

inline std::array<uint8_t, 32> native_reset_field_response_digest(const NativeResetFieldProof& proof) {
    Sha256 h;
    h.init();
    native_hash_domain(h, "pvac.native.reset.field.response");
    native_hash_arith_params(h, proof.params);
    h.update(proof.challenge.data(), proof.challenge.size());
    sha256_acc_u64(h, proof.openings.size());
    for (const auto& opening : proof.openings) {
        native_hash_field_opening(h, opening);
        h.update(opening.commit.data(), opening.commit.size());
    }
    std::array<uint8_t, 32> out{};
    h.finish(out.data());
    return out;
}

inline std::array<NativeResetFieldShareSet, 3> native_reset_field_split_witness(const NativeResetFieldProof& proof, const std::vector<std::vector<Fp>>& old_r, const std::vector<std::vector<Fp>>& new_r, const std::array<uint8_t, 32>& seed, size_t round) {
    if (!native_matrix_shape(old_r, proof.old_layers.size(), proof.slots))
        throw std::runtime_error("pvac: native reset field old witness shape rejected");
    if (!native_matrix_shape(new_r, proof.new_layers.size(), proof.slots))
        throw std::runtime_error("pvac: native reset field new witness shape rejected");
    std::array<NativeResetFieldShareSet, 3> out;
    for (auto& share : out) {
        share.old_r.assign(proof.old_layers.size(), native_fp_zeros(proof.slots));
        share.new_r.assign(proof.new_layers.size(), native_fp_zeros(proof.slots));
    }
    for (size_t i = 0; i < proof.old_layers.size(); ++i) {
        for (size_t j = 0; j < proof.slots; ++j) {
            auto split = native_reset_arith_split_fp(old_r[i][j], seed, "pvac.native.reset.field.old_r", round, i, j, 0);
            for (size_t branch = 0; branch < 3; ++branch) {
                out[branch].old_r[i][j] = split[branch];
            }
        }
    }
    for (size_t i = 0; i < proof.new_layers.size(); ++i) {
        for (size_t j = 0; j < proof.slots; ++j) {
            auto split = native_reset_arith_split_fp(new_r[i][j], seed, "pvac.native.reset.field.new_r", round, i, j, 0);
            for (size_t branch = 0; branch < 3; ++branch) {
                out[branch].new_r[i][j] = split[branch];
            }
        }
    }
    return out;
}

inline void native_reset_field_stack_residual(const std::vector<Layer>& layers, const std::vector<std::vector<Fp>>& self, const std::vector<std::vector<Fp>>& next, std::vector<std::vector<Fp>>& out) {
    for (size_t i = 0; i < layers.size(); ++i) {
        if (layers[i].rule == RRule::BASE)
            continue;
        if (layers[i].rule != RRule::PROD)
            throw std::runtime_error("pvac: native reset field layer rule rejected");
        if (layers[i].pa >= i || layers[i].pb >= i)
            throw std::runtime_error("pvac: native reset field product parent rejected");
        for (size_t j = 0; j < self[i].size(); ++j) {
            auto mul = native_reset_arith_mul_share(self[layers[i].pa][j], self[layers[i].pb][j], next[layers[i].pa][j], next[layers[i].pb][j]);
            out[i][j] = fp_sub(self[i][j], mul);
        }
    }
}

inline NativeResetFieldResidual native_reset_field_branch_residual(const NativeResetFieldProof& proof, const NativeResetFieldShareSet& self, const NativeResetFieldShareSet& next) {
    if (!native_reset_field_share_shape(proof, self) || !native_reset_field_share_shape(proof, next))
        throw std::runtime_error("pvac: native reset field branch shape rejected");
    auto residual = native_reset_field_zero_residual(proof.old_layers.size(), proof.new_layers.size(), proof.slots);
    native_reset_field_stack_residual(proof.old_layers, self.old_r, next.old_r, residual.old_prod);
    native_reset_field_stack_residual(proof.new_layers, self.new_r, next.new_r, residual.new_prod);
    return residual;
}

inline NativeResetFieldProof make_native_reset_field_proof(const NativeResetLayerWitness& wit, const NativeResetProofParams& params, const std::array<uint8_t, 32>& seed) {
    NativeResetFieldProof proof;
    proof.params = native_reset_arith_params_from_proof(params);
    proof.old_layers = wit.old_layers;
    proof.new_layers = wit.new_layers;
    proof.old_layer_digest = native_reset_layer_stack_digest(wit.old_layers);
    proof.new_layer_digest = native_reset_layer_stack_digest(wit.new_layers);
    proof.slots = wit.old_r.empty() ? 0 : wit.old_r[0].size();
    proof.product_relation = true;
    proof.hides_witness = true;
    proof.no_basis_oracle = true;
    proof.native_backend = true;
    if (!native_reset_arith_params_ok(proof.params))
        throw std::runtime_error("pvac: native reset field params rejected");
    if (proof.slots == 0)
        throw std::runtime_error("pvac: native reset field slots rejected");
    if (!native_matrix_shape(wit.old_r, proof.old_layers.size(), proof.slots))
        throw std::runtime_error("pvac: native reset field old matrix rejected");
    if (!native_matrix_shape(wit.new_r, proof.new_layers.size(), proof.slots))
        throw std::runtime_error("pvac: native reset field new matrix rejected");
    proof.branch_commits.reserve(proof.params.rounds * proof.params.branches);
    proof.residuals.reserve(proof.params.rounds * proof.params.branches);
    std::vector<NativeResetFieldOpening> branches;
    branches.reserve(proof.params.rounds * proof.params.branches);
    for (size_t round = 0; round < proof.params.rounds; ++round) {
        auto shares = native_reset_field_split_witness(proof, wit.old_r, wit.new_r, seed, round);
        for (size_t branch = 0; branch < proof.params.branches; ++branch) {
            NativeResetFieldOpening opening;
            opening.round = round;
            opening.branch = branch;
            opening.self = shares[branch];
            opening.next = shares[(branch + 1) % proof.params.branches];
            opening.residual = native_reset_field_branch_residual(proof, opening.self, opening.next);
            opening.commit = native_reset_field_opening_commit(opening);
            branches.push_back(opening);
            proof.branch_commits.push_back(opening.commit);
            proof.residuals.push_back(opening.residual);
        }
    }
    proof.challenge = native_reset_field_challenge(proof, proof.old_layer_digest, proof.new_layer_digest);
    for (size_t round = 0; round < proof.params.rounds; ++round) {
        for (size_t slot = 0; slot < proof.params.opened_branches; ++slot) {
            size_t branch = native_reset_arith_opened_branch(proof.params, proof.challenge, round, slot);
            proof.openings.push_back(branches[round * proof.params.branches + branch]);
        }
    }
    proof.response_digest = native_reset_field_response_digest(proof);
    return proof;
}

inline bool native_reset_field_commits_ok(const NativeResetFieldProof& proof) {
    if (!native_reset_arith_params_ok(proof.params))
        return false;
    if (proof.branch_commits.size() != proof.params.rounds * proof.params.branches)
        return false;
    if (proof.residuals.size() != proof.params.rounds * proof.params.branches)
        return false;
    for (size_t round = 0; round < proof.params.rounds; ++round) {
        auto sum = native_reset_field_residual_sum(proof, round * proof.params.branches);
        if (!native_reset_field_residual_zero(proof, sum))
            return false;
    }
    return true;
}

inline bool native_reset_field_openings_ok(const NativeResetFieldProof& proof) {
    if (!native_reset_field_commits_ok(proof))
        return false;
    if (proof.openings.size() != proof.params.rounds * proof.params.opened_branches)
        return false;
    for (size_t round = 0; round < proof.params.rounds; ++round) {
        for (size_t slot = 0; slot < proof.params.opened_branches; ++slot) {
            size_t id = round * proof.params.opened_branches + slot;
            size_t branch = native_reset_arith_opened_branch(proof.params, proof.challenge, round, slot);
            if (branch >= proof.params.branches)
                return false;
            const auto& opening = proof.openings[id];
            if (opening.round != round || opening.branch != branch)
                return false;
            if (!native_reset_field_share_shape(proof, opening.self))
                return false;
            if (!native_reset_field_share_shape(proof, opening.next))
                return false;
            if (!native_reset_field_residual_shape(proof, opening.residual))
                return false;
            auto expected_residual = native_reset_field_branch_residual(proof, opening.self, opening.next);
            if (!native_reset_field_residual_eq(expected_residual, opening.residual))
                return false;
            auto expected_commit = native_reset_field_opening_commit(opening);
            if (!native_digest_eq(expected_commit, opening.commit))
                return false;
            size_t commit_id = round * proof.params.branches + branch;
            if (!native_digest_eq(opening.commit, proof.branch_commits[commit_id]))
                return false;
            if (!native_reset_field_residual_eq(opening.residual, proof.residuals[commit_id]))
                return false;
        }
    }
    return true;
}

inline NativeResetFieldDecision decide_native_reset_field_proof(const NativeResetFieldProof& proof, const std::array<uint8_t, 32>& old_layer_digest, const std::array<uint8_t, 32>& new_layer_digest) {
    NativeResetFieldDecision decision;
    decision.rejects_raw_witness = proof.has_raw_witness;
    decision.rejects_basis_oracle = !proof.no_basis_oracle;
    decision.params = native_reset_arith_params_ok(proof.params);
    decision.transcript =
        native_digest_eq(proof.old_layer_digest, old_layer_digest) &&
        native_digest_eq(proof.new_layer_digest, new_layer_digest) &&
        native_digest_eq(proof.old_layer_digest, native_reset_layer_stack_digest(proof.old_layers)) &&
        native_digest_eq(proof.new_layer_digest, native_reset_layer_stack_digest(proof.new_layers)) &&
        native_digest_eq(proof.challenge, native_reset_field_challenge(proof, old_layer_digest, new_layer_digest));
    decision.commits = decision.transcript && native_reset_field_commits_ok(proof);
    decision.openings = decision.commits && native_reset_field_openings_ok(proof);
    decision.residuals = decision.openings;
    decision.response = decision.openings && native_digest_eq(proof.response_digest, native_reset_field_response_digest(proof));
    decision.product = decision.response && proof.product_relation;
    decision.secrecy =
        decision.response &&
        proof.hides_witness &&
        proof.no_basis_oracle &&
        proof.native_backend &&
        !proof.has_raw_witness;
    decision.ready = decision.params && decision.transcript && decision.commits && decision.openings && decision.response;
    decision.admitted = decision.ready && decision.product && decision.secrecy;
    return decision;
}

inline NativeResetLayerTraceProof make_native_reset_field_layer_trace_boundary(const NativeResetLayerWitness& wit, const NativeResetProofParams& params, const std::array<uint8_t, 32>& seed) {
    NativeResetLayerTraceProof proof;
    proof.kind = NativeResetLayerTraceKind::FIELD_NATIVE;
    proof.params = native_reset_arith_params_from_proof(params);
    proof.old_layers = wit.old_layers;
    proof.new_layers = wit.new_layers;
    proof.field_proof = make_native_reset_field_proof(wit, params, seed);
    proof.old_layer_digest = proof.field_proof.old_layer_digest;
    proof.new_layer_digest = proof.field_proof.new_layer_digest;
    proof.base_binding_relation = true;
    proof.product_binding_relation = true;
    proof.message_bound = true;
    proof.digest_bound = true;
    proof.field_transition = true;
    proof.hides_witness = true;
    proof.no_basis_oracle = true;
    proof.native_backend = true;
    if (!native_reset_arith_params_ok(proof.params))
        throw std::runtime_error("pvac: native reset field trace params rejected");
    proof.challenge = native_reset_layer_trace_challenge(proof, proof.old_layer_digest, proof.new_layer_digest);
    proof.response_digest = native_reset_layer_trace_response_digest(proof);
    return proof;
}

inline NativeResetArithResidual native_reset_arith_branch_residual(const NativeResetStmt& stmt, const NativeResetOutput& out, const NativeResetArithShareSet& self, const NativeResetArithShareSet& next, size_t branch) {
    if (!native_reset_output_shape(stmt, out))
        throw std::runtime_error("pvac: native reset arithmetic output shape rejected");
    if (!native_reset_arith_share_shape(stmt, self) || !native_reset_arith_share_shape(stmt, next))
        throw std::runtime_error("pvac: native reset arithmetic branch shape rejected");
    auto residual = native_reset_arith_zero_residual(stmt);
    for (size_t i = 0; i < stmt.alpha.size(); ++i) {
        for (size_t j = 0; j < stmt.c.size(); ++j) {
            Fp acc = fp_sub(self.old_x[i][j], self.bias[i][j]);
            for (size_t t = 0; t < stmt.target_terms; ++t) {
                auto mul = native_reset_arith_mul_share(self.mix[i][t][j], self.new_y[t][j], next.mix[i][t][j], next.new_y[t][j]);
                acc = fp_sub(acc, mul);
            }
            residual.old_x[i][j] = acc;
        }
    }
    for (size_t j = 0; j < stmt.c.size(); ++j) {
        Fp acc = branch == 0 ? fp_sub(out.c[j], stmt.c[j]) : fp_from_u64(0);
        for (size_t i = 0; i < stmt.alpha.size(); ++i) {
            acc = fp_sub(acc, fp_mul(stmt.alpha[i][j], self.bias[i][j]));
        }
        residual.c[j] = acc;
    }
    for (size_t t = 0; t < stmt.target_terms; ++t) {
        for (size_t j = 0; j < stmt.c.size(); ++j) {
            Fp acc = branch == 0 ? out.beta[t][j] : fp_from_u64(0);
            for (size_t i = 0; i < stmt.alpha.size(); ++i) {
                acc = fp_sub(acc, fp_mul(stmt.alpha[i][j], self.mix[i][t][j]));
            }
            residual.beta[t][j] = acc;
        }
    }
    return residual;
}

inline NativeResetArithProof make_native_reset_arith_proof(const NativeResetStmt& stmt, const NativeResetRows& rows, const NativeResetSecrets& sec, const NativeResetOutput& out, const NativeResetCert& cert, const NativeResetProofParams& params, const std::array<uint8_t, 32>& seed) {
    if (!native_reset_output_shape(stmt, out))
        throw std::runtime_error("pvac: native reset arithmetic proof output rejected");
    if (!verify_native_reset_witness_cert(stmt, rows, sec, out, cert))
        throw std::runtime_error("pvac: native reset arithmetic proof witness rejected");
    NativeResetArithProof proof;
    proof.kind = NativeResetArithKind::BRANCH_PRODUCT;
    proof.params = native_reset_arith_params_from_proof(params);
    proof.stmt_digest = native_reset_stmt_digest(stmt);
    proof.output_digest = native_reset_output_digest(out);
    proof.relation_digest = cert.relation_digest;
    proof.product_relation = true;
    proof.reset_relation = true;
    proof.hides_witness = true;
    proof.no_basis_oracle = true;
    proof.native_backend = true;
    if (!native_reset_arith_params_ok(proof.params))
        throw std::runtime_error("pvac: native reset arithmetic params rejected");
    proof.branch_commits.reserve(proof.params.rounds * proof.params.branches);
    proof.residuals.reserve(proof.params.rounds * proof.params.branches);
    std::vector<NativeResetArithOpening> branches;
    branches.reserve(proof.params.rounds * proof.params.branches);
    for (size_t round = 0; round < proof.params.rounds; ++round) {
        auto shares = native_reset_arith_split_witness(stmt, rows, sec, seed, round);
        for (size_t branch = 0; branch < proof.params.branches; ++branch) {
            NativeResetArithOpening opening;
            opening.round = round;
            opening.branch = branch;
            opening.self = shares[branch];
            opening.next = shares[(branch + 1) % proof.params.branches];
            opening.residual = native_reset_arith_branch_residual(stmt, out, opening.self, opening.next, branch);
            opening.commit = native_reset_arith_opening_commit(opening);
            branches.push_back(opening);
            proof.branch_commits.push_back(opening.commit);
            proof.residuals.push_back(opening.residual);
        }
    }
    proof.challenge = native_reset_arith_challenge(stmt, out, cert, proof);
    for (size_t round = 0; round < proof.params.rounds; ++round) {
        for (size_t slot = 0; slot < proof.params.opened_branches; ++slot) {
            size_t branch = native_reset_arith_opened_branch(proof.params, proof.challenge, round, slot);
            proof.openings.push_back(branches[round * proof.params.branches + branch]);
        }
    }
    proof.response_digest = native_reset_arith_response_digest(proof);
    return proof;
}

inline bool native_reset_arith_commits_ok(const NativeResetStmt& stmt, const NativeResetArithProof& proof) {
    if (!native_reset_arith_params_ok(proof.params))
        return false;
    if (proof.branch_commits.size() != proof.params.rounds * proof.params.branches)
        return false;
    if (proof.residuals.size() != proof.params.rounds * proof.params.branches)
        return false;
    for (size_t round = 0; round < proof.params.rounds; ++round) {
        auto sum = native_reset_arith_residual_sum(stmt, proof.residuals, round * proof.params.branches);
        if (!native_reset_arith_residual_zero(stmt, sum))
            return false;
    }
    return true;
}

inline bool native_reset_arith_openings_ok(const NativeResetStmt& stmt, const NativeResetOutput& out, const NativeResetArithProof& proof) {
    if (!native_reset_arith_commits_ok(stmt, proof))
        return false;
    if (proof.openings.size() != proof.params.rounds * proof.params.opened_branches)
        return false;
    for (size_t round = 0; round < proof.params.rounds; ++round) {
        for (size_t slot = 0; slot < proof.params.opened_branches; ++slot) {
            size_t id = round * proof.params.opened_branches + slot;
            size_t branch = native_reset_arith_opened_branch(proof.params, proof.challenge, round, slot);
            if (branch >= proof.params.branches)
                return false;
            const auto& opening = proof.openings[id];
            if (opening.round != round || opening.branch != branch)
                return false;
            if (!native_reset_arith_share_shape(stmt, opening.self))
                return false;
            if (!native_reset_arith_share_shape(stmt, opening.next))
                return false;
            if (!native_reset_arith_residual_shape(stmt, opening.residual))
                return false;
            auto expected_residual = native_reset_arith_branch_residual(stmt, out, opening.self, opening.next, branch);
            if (!native_reset_arith_residual_eq(expected_residual, opening.residual))
                return false;
            auto expected_commit = native_reset_arith_opening_commit(opening);
            if (!native_digest_eq(expected_commit, opening.commit))
                return false;
            size_t commit_id = round * proof.params.branches + branch;
            if (!native_digest_eq(opening.commit, proof.branch_commits[commit_id]))
                return false;
            if (!native_reset_arith_residual_eq(opening.residual, proof.residuals[commit_id]))
                return false;
        }
    }
    return true;
}

inline NativeResetArithDecision decide_native_reset_arith_proof(const NativeResetStmt& stmt, const NativeResetOutput& out, const NativeResetCert& cert, const NativeResetArithProof& proof) {
    NativeResetArithDecision decision;
    decision.rejects_digest_only = proof.kind == NativeResetArithKind::DIGEST_ONLY;
    decision.rejects_open_witness = proof.kind == NativeResetArithKind::OPEN_WITNESS_LOCAL;
    decision.rejects_raw_witness = proof.has_raw_witness;
    decision.rejects_basis_oracle = !proof.no_basis_oracle;
    decision.params = native_reset_arith_params_ok(proof.params);
    decision.transcript =
        proof.kind == NativeResetArithKind::BRANCH_PRODUCT &&
        native_reset_output_shape(stmt, out) &&
        cert.kind == NativeResetCertKind::HIDDEN_PUBLIC &&
        native_digest_eq(proof.stmt_digest, native_reset_stmt_digest(stmt)) &&
        native_digest_eq(proof.output_digest, native_reset_output_digest(out)) &&
        native_digest_eq(proof.relation_digest, cert.relation_digest) &&
        native_digest_eq(proof.challenge, native_reset_arith_challenge(stmt, out, cert, proof));
    decision.commits = decision.transcript && native_reset_arith_commits_ok(stmt, proof);
    decision.openings = decision.commits && native_reset_arith_openings_ok(stmt, out, proof);
    decision.residuals = decision.openings;
    decision.response = decision.openings && native_digest_eq(proof.response_digest, native_reset_arith_response_digest(proof));
    decision.product = decision.response && proof.product_relation;
    decision.reset = decision.response && proof.reset_relation;
    decision.secrecy =
        decision.response &&
        proof.hides_witness &&
        proof.no_basis_oracle &&
        proof.native_backend &&
        !proof.has_raw_witness &&
        !decision.rejects_digest_only &&
        !decision.rejects_open_witness;
    decision.ready = decision.params && decision.transcript && decision.commits && decision.openings && decision.response;
    decision.admitted = decision.ready && decision.product && decision.reset && decision.secrecy;
    return decision;
}

inline bool native_reset_layer_matrix_shape(const std::vector<std::vector<Fp>>& x, size_t rows, size_t slots) {
    return native_matrix_shape(x, rows, slots);
}

inline bool native_reset_layer_witness_shape(const NativeResetStmt& stmt, const NativeResetLayerWitness& wit) {
    if (!native_reset_stmt_shape(stmt))
        return false;
    if (wit.old_layers.size() != stmt.alpha.size())
        return false;
    if (wit.new_layers.size() != stmt.target_terms)
        return false;
    if (!native_reset_layer_matrix_shape(wit.old_r, stmt.alpha.size(), stmt.c.size()))
        return false;
    return native_reset_layer_matrix_shape(wit.new_r, stmt.target_terms, stmt.c.size());
}

inline bool native_reset_layer_base_binding_holds(uint64_t canon_tag, const Layer& layer, const std::vector<Fp>& r) {
    if (layer.rule != RRule::BASE)
        return false;
    return native_digest_eq(
        compute_R_com_base(canon_tag, layer.seed.ztag, layer.seed.nonce.lo, layer.seed.nonce.hi, r),
        layer.R_com
    );
}

inline bool native_reset_layer_stack_holds(uint64_t canon_tag, const std::vector<Layer>& layers, const std::vector<std::vector<Fp>>& r) {
    if (layers.size() != r.size())
        return false;
    for (size_t i = 0; i < layers.size(); ++i) {
        if (layers[i].rule == RRule::BASE) {
            if (!native_reset_layer_base_binding_holds(canon_tag, layers[i], r[i]))
                return false;
            continue;
        }
        if (layers[i].rule != RRule::PROD)
            return false;
        if (layers[i].pa >= i || layers[i].pb >= i)
            return false;
        if (!native_digest_eq(compute_R_com_prod(layers[layers[i].pa].R_com, layers[layers[i].pb].R_com), layers[i].R_com))
            return false;
        if (r[i].size() != r[layers[i].pa].size() || r[i].size() != r[layers[i].pb].size())
            return false;
        for (size_t j = 0; j < r[i].size(); ++j) {
            if (!native_fp_vec_eq({r[i][j]}, {fp_mul(r[layers[i].pa][j], r[layers[i].pb][j])}))
                return false;
        }
    }
    return true;
}

inline bool native_reset_layer_witness_hash_holds(const NativeResetStmt& stmt, const NativeResetLayerWitness& wit) {
    if (!native_reset_layer_witness_shape(stmt, wit))
        return false;
    if (!native_reset_layer_stack_holds(wit.canon_tag, wit.old_layers, wit.old_r))
        return false;
    return native_reset_layer_stack_holds(wit.canon_tag, wit.new_layers, wit.new_r);
}

inline bool native_reset_layer_witness_inverse_holds(const NativeResetStmt& stmt, const NativeResetLayerWitness& wit, const NativeResetSecrets& sec) {
    if (!native_reset_layer_witness_shape(stmt, wit) || !native_reset_secret_shape(stmt, sec))
        return false;
    auto one = fp_from_u64(1);
    for (size_t i = 0; i < stmt.alpha.size(); ++i) {
        for (size_t j = 0; j < stmt.c.size(); ++j) {
            if (!native_fp_vec_eq({fp_mul(wit.old_r[i][j], sec.old_x[i][j])}, {one}))
                return false;
        }
    }
    for (size_t t = 0; t < stmt.target_terms; ++t) {
        for (size_t j = 0; j < stmt.c.size(); ++j) {
            if (!native_fp_vec_eq({fp_mul(wit.new_r[t][j], sec.new_y[t][j])}, {one}))
                return false;
        }
    }
    return true;
}

inline bool native_reset_layer_witness_holds(const NativeResetStmt& stmt, const NativeResetLayerWitness& wit, const NativeResetSecrets& sec) {
    return
        native_reset_layer_witness_hash_holds(stmt, wit) &&
        native_reset_layer_witness_inverse_holds(stmt, wit, sec);
}

inline void native_hash_layer(Sha256& h, const Layer& layer) {
    sha256_acc_u64(h, static_cast<uint8_t>(layer.rule));
    sha256_acc_u64(h, layer.seed.ztag);
    sha256_acc_u64(h, layer.seed.nonce.lo);
    sha256_acc_u64(h, layer.seed.nonce.hi);
    sha256_acc_u64(h, layer.pa);
    sha256_acc_u64(h, layer.pb);
    h.update(layer.R_com.data(), layer.R_com.size());
    sha256_acc_u64(h, layer.PC.size());
    for (const auto& pc : layer.PC) {
        h.update(pc.data(), pc.size());
    }
}

inline std::array<uint8_t, 32> native_reset_layer_stack_digest(const std::vector<Layer>& layers) {
    Sha256 h;
    h.init();
    native_hash_domain(h, "pvac.native.reset.layer.stack");
    sha256_acc_u64(h, layers.size());
    for (const auto& layer : layers) {
        native_hash_layer(h, layer);
    }
    std::array<uint8_t, 32> out{};
    h.finish(out.data());
    return out;
}

inline bool native_reset_layer_share_shape(const NativeResetStmt& stmt, const NativeResetLayerShareSet& share) {
    if (!native_reset_stmt_shape(stmt))
        return false;
    if (!native_matrix_shape(share.old_r, stmt.alpha.size(), stmt.c.size()))
        return false;
    if (!native_matrix_shape(share.new_r, stmt.target_terms, stmt.c.size()))
        return false;
    if (!native_matrix_shape(share.old_x, stmt.alpha.size(), stmt.c.size()))
        return false;
    return native_matrix_shape(share.new_y, stmt.target_terms, stmt.c.size());
}

inline bool native_reset_layer_residual_shape(const NativeResetStmt& stmt, const NativeResetLayerResidual& residual) {
    if (!native_reset_stmt_shape(stmt))
        return false;
    if (!native_matrix_shape(residual.old_inv, stmt.alpha.size(), stmt.c.size()))
        return false;
    return native_matrix_shape(residual.new_inv, stmt.target_terms, stmt.c.size());
}

inline bool native_reset_layer_residual_eq(const NativeResetLayerResidual& left, const NativeResetLayerResidual& right) {
    if (left.old_inv.size() != right.old_inv.size())
        return false;
    for (size_t i = 0; i < left.old_inv.size(); ++i) {
        if (!native_fp_vec_eq(left.old_inv[i], right.old_inv[i]))
            return false;
    }
    if (left.new_inv.size() != right.new_inv.size())
        return false;
    for (size_t t = 0; t < left.new_inv.size(); ++t) {
        if (!native_fp_vec_eq(left.new_inv[t], right.new_inv[t]))
            return false;
    }
    return true;
}

inline NativeResetLayerResidual native_reset_layer_zero_residual(const NativeResetStmt& stmt) {
    NativeResetLayerResidual out;
    out.old_inv.assign(stmt.alpha.size(), native_fp_zeros(stmt.c.size()));
    out.new_inv.assign(stmt.target_terms, native_fp_zeros(stmt.c.size()));
    return out;
}

inline NativeResetLayerResidual native_reset_layer_add_residual(const NativeResetStmt& stmt, const NativeResetLayerResidual& left, const NativeResetLayerResidual& right) {
    if (!native_reset_layer_residual_shape(stmt, left) || !native_reset_layer_residual_shape(stmt, right))
        throw std::runtime_error("pvac: native reset layer residual shape rejected");
    auto out = native_reset_layer_zero_residual(stmt);
    for (size_t i = 0; i < stmt.alpha.size(); ++i) {
        for (size_t j = 0; j < stmt.c.size(); ++j) {
            out.old_inv[i][j] = fp_add(left.old_inv[i][j], right.old_inv[i][j]);
        }
    }
    for (size_t t = 0; t < stmt.target_terms; ++t) {
        for (size_t j = 0; j < stmt.c.size(); ++j) {
            out.new_inv[t][j] = fp_add(left.new_inv[t][j], right.new_inv[t][j]);
        }
    }
    return out;
}

inline bool native_reset_layer_residual_zero(const NativeResetStmt& stmt, const NativeResetLayerResidual& residual) {
    return native_reset_layer_residual_shape(stmt, residual) && native_reset_layer_residual_eq(residual, native_reset_layer_zero_residual(stmt));
}

inline NativeResetLayerResidual native_reset_layer_residual_sum(const NativeResetStmt& stmt, const std::vector<NativeResetLayerResidual>& residuals, size_t offset) {
    if (offset + 3 > residuals.size())
        throw std::runtime_error("pvac: native reset layer residual window rejected");
    auto out = native_reset_layer_zero_residual(stmt);
    for (size_t branch = 0; branch < 3; ++branch) {
        out = native_reset_layer_add_residual(stmt, out, residuals[offset + branch]);
    }
    return out;
}

inline void native_hash_layer_share(Sha256& h, const NativeResetLayerShareSet& share) {
    native_hash_matrix(h, share.old_r);
    native_hash_matrix(h, share.new_r);
    native_hash_matrix(h, share.old_x);
    native_hash_matrix(h, share.new_y);
}

inline void native_hash_layer_residual(Sha256& h, const NativeResetLayerResidual& residual) {
    native_hash_matrix(h, residual.old_inv);
    native_hash_matrix(h, residual.new_inv);
}

inline void native_hash_layer_opening(Sha256& h, const NativeResetLayerOpening& opening) {
    sha256_acc_u64(h, opening.round);
    sha256_acc_u64(h, opening.branch);
    native_hash_layer_share(h, opening.self);
    native_hash_layer_share(h, opening.next);
    native_hash_layer_residual(h, opening.residual);
}

inline std::array<uint8_t, 32> native_reset_layer_opening_commit(const NativeResetLayerOpening& opening) {
    Sha256 h;
    h.init();
    native_hash_domain(h, "pvac.native.reset.layer.branch");
    native_hash_layer_opening(h, opening);
    std::array<uint8_t, 32> out{};
    h.finish(out.data());
    return out;
}

inline std::array<uint8_t, 32> native_reset_layer_digest(const NativeResetLayerProof& proof) {
    Sha256 h;
    h.init();
    native_hash_domain(h, "pvac.native.reset.layer.proof");
    sha256_acc_u64(h, static_cast<uint8_t>(proof.kind));
    native_hash_arith_params(h, proof.params);
    h.update(proof.stmt_digest.data(), proof.stmt_digest.size());
    h.update(proof.output_digest.data(), proof.output_digest.size());
    h.update(proof.old_layer_digest.data(), proof.old_layer_digest.size());
    h.update(proof.new_layer_digest.data(), proof.new_layer_digest.size());
    auto layer_trace_digest = native_reset_layer_trace_digest(proof.layer_trace);
    h.update(layer_trace_digest.data(), layer_trace_digest.size());
    h.update(proof.challenge.data(), proof.challenge.size());
    h.update(proof.response_digest.data(), proof.response_digest.size());
    sha256_acc_u64(h, proof.branch_commits.size());
    for (const auto& commit : proof.branch_commits) {
        h.update(commit.data(), commit.size());
    }
    sha256_acc_u64(h, proof.residuals.size());
    for (const auto& residual : proof.residuals) {
        native_hash_layer_residual(h, residual);
    }
    sha256_acc_u64(h, proof.openings.size());
    for (const auto& opening : proof.openings) {
        native_hash_layer_opening(h, opening);
        h.update(opening.commit.data(), opening.commit.size());
    }
    sha256_acc_u64(h, proof.inverse_relation ? 1 : 0);
    sha256_acc_u64(h, proof.binding_relation ? 1 : 0);
    sha256_acc_u64(h, proof.product_layer_relation ? 1 : 0);
    sha256_acc_u64(h, proof.hides_witness ? 1 : 0);
    sha256_acc_u64(h, proof.no_basis_oracle ? 1 : 0);
    sha256_acc_u64(h, proof.native_backend ? 1 : 0);
    sha256_acc_u64(h, proof.has_raw_witness ? 1 : 0);
    std::array<uint8_t, 32> out{};
    h.finish(out.data());
    return out;
}

inline std::array<uint8_t, 32> native_reset_layer_challenge(const NativeResetStmt& stmt, const NativeResetOutput& out, const NativeResetLayerProof& proof) {
    Sha256 h;
    h.init();
    native_hash_domain(h, "pvac.native.reset.layer.challenge");
    auto sd = native_reset_stmt_digest(stmt);
    auto od = native_reset_output_digest(out);
    h.update(sd.data(), sd.size());
    h.update(od.data(), od.size());
    h.update(proof.old_layer_digest.data(), proof.old_layer_digest.size());
    h.update(proof.new_layer_digest.data(), proof.new_layer_digest.size());
    auto layer_trace_digest = native_reset_layer_trace_digest(proof.layer_trace);
    h.update(layer_trace_digest.data(), layer_trace_digest.size());
    native_hash_arith_params(h, proof.params);
    sha256_acc_u64(h, proof.branch_commits.size());
    for (const auto& commit : proof.branch_commits) {
        h.update(commit.data(), commit.size());
    }
    sha256_acc_u64(h, proof.residuals.size());
    for (const auto& residual : proof.residuals) {
        native_hash_layer_residual(h, residual);
    }
    std::array<uint8_t, 32> out_digest{};
    h.finish(out_digest.data());
    return out_digest;
}

inline size_t native_reset_layer_opened_branch(const NativeResetArithParams& params, const std::array<uint8_t, 32>& challenge, size_t round, size_t slot) {
    return native_reset_arith_opened_branch(params, challenge, round, slot);
}

inline std::array<uint8_t, 32> native_reset_layer_response_digest(const NativeResetLayerProof& proof) {
    Sha256 h;
    h.init();
    native_hash_domain(h, "pvac.native.reset.layer.response");
    native_hash_arith_params(h, proof.params);
    h.update(proof.challenge.data(), proof.challenge.size());
    sha256_acc_u64(h, proof.openings.size());
    for (const auto& opening : proof.openings) {
        native_hash_layer_opening(h, opening);
        h.update(opening.commit.data(), opening.commit.size());
    }
    std::array<uint8_t, 32> out{};
    h.finish(out.data());
    return out;
}

inline std::array<NativeResetLayerShareSet, 3> native_reset_layer_split_witness(const NativeResetStmt& stmt, const NativeResetLayerWitness& wit, const NativeResetSecrets& sec, const std::array<uint8_t, 32>& seed, size_t round) {
    if (!native_reset_layer_witness_shape(stmt, wit) || !native_reset_secret_shape(stmt, sec))
        throw std::runtime_error("pvac: native reset layer proof witness shape rejected");
    std::array<NativeResetLayerShareSet, 3> out;
    for (auto& share : out) {
        share.old_r.assign(stmt.alpha.size(), native_fp_zeros(stmt.c.size()));
        share.new_r.assign(stmt.target_terms, native_fp_zeros(stmt.c.size()));
        share.old_x.assign(stmt.alpha.size(), native_fp_zeros(stmt.c.size()));
        share.new_y.assign(stmt.target_terms, native_fp_zeros(stmt.c.size()));
    }
    for (size_t i = 0; i < stmt.alpha.size(); ++i) {
        for (size_t j = 0; j < stmt.c.size(); ++j) {
            auto r_share = native_reset_arith_split_fp(wit.old_r[i][j], seed, "pvac.native.reset.layer.old_r", round, i, j, 0);
            auto x_share = native_reset_arith_split_fp(sec.old_x[i][j], seed, "pvac.native.reset.layer.old_x", round, i, j, 0);
            for (size_t branch = 0; branch < 3; ++branch) {
                out[branch].old_r[i][j] = r_share[branch];
                out[branch].old_x[i][j] = x_share[branch];
            }
        }
    }
    for (size_t t = 0; t < stmt.target_terms; ++t) {
        for (size_t j = 0; j < stmt.c.size(); ++j) {
            auto r_share = native_reset_arith_split_fp(wit.new_r[t][j], seed, "pvac.native.reset.layer.new_r", round, t, j, 0);
            auto y_share = native_reset_arith_split_fp(sec.new_y[t][j], seed, "pvac.native.reset.layer.new_y", round, t, j, 0);
            for (size_t branch = 0; branch < 3; ++branch) {
                out[branch].new_r[t][j] = r_share[branch];
                out[branch].new_y[t][j] = y_share[branch];
            }
        }
    }
    return out;
}

inline NativeResetLayerResidual native_reset_layer_branch_residual(const NativeResetStmt& stmt, const NativeResetLayerShareSet& self, const NativeResetLayerShareSet& next, size_t branch) {
    if (!native_reset_layer_share_shape(stmt, self) || !native_reset_layer_share_shape(stmt, next))
        throw std::runtime_error("pvac: native reset layer branch shape rejected");
    auto residual = native_reset_layer_zero_residual(stmt);
    for (size_t i = 0; i < stmt.alpha.size(); ++i) {
        for (size_t j = 0; j < stmt.c.size(); ++j) {
            auto mul = native_reset_arith_mul_share(self.old_r[i][j], self.old_x[i][j], next.old_r[i][j], next.old_x[i][j]);
            residual.old_inv[i][j] = branch == 0 ? fp_sub(fp_from_u64(1), mul) : fp_neg(mul);
        }
    }
    for (size_t t = 0; t < stmt.target_terms; ++t) {
        for (size_t j = 0; j < stmt.c.size(); ++j) {
            auto mul = native_reset_arith_mul_share(self.new_r[t][j], self.new_y[t][j], next.new_r[t][j], next.new_y[t][j]);
            residual.new_inv[t][j] = branch == 0 ? fp_sub(fp_from_u64(1), mul) : fp_neg(mul);
        }
    }
    return residual;
}

inline NativeResetLayerProof make_native_reset_layer_sha_compat_proof(const NativeResetStmt& stmt, const NativeResetOutput& out, const NativeResetLayerWitness& wit, const NativeResetSecrets& sec, const NativeResetProofParams& params, const std::array<uint8_t, 32>& seed) {
    if (!native_reset_output_shape(stmt, out))
        throw std::runtime_error("pvac: native reset layer proof output rejected");
    if (!native_reset_layer_witness_holds(stmt, wit, sec))
        throw std::runtime_error("pvac: native reset layer witness rejected");
    NativeResetLayerProof proof;
    proof.kind = NativeResetLayerKind::BRANCH_INVERSE;
    proof.params = native_reset_arith_params_from_proof(params);
    proof.stmt_digest = native_reset_stmt_digest(stmt);
    proof.output_digest = native_reset_output_digest(out);
    proof.old_layer_digest = native_reset_layer_stack_digest(wit.old_layers);
    proof.new_layer_digest = native_reset_layer_stack_digest(wit.new_layers);
    proof.layer_trace = make_native_reset_sha_compat_trace_boundary(wit, params, seed);
    proof.inverse_relation = true;
    proof.product_layer_relation = true;
    proof.hides_witness = true;
    proof.no_basis_oracle = true;
    proof.native_backend = true;
    if (!native_reset_arith_params_ok(proof.params))
        throw std::runtime_error("pvac: native reset layer params rejected");
    proof.branch_commits.reserve(proof.params.rounds * proof.params.branches);
    proof.residuals.reserve(proof.params.rounds * proof.params.branches);
    std::vector<NativeResetLayerOpening> branches;
    branches.reserve(proof.params.rounds * proof.params.branches);
    for (size_t round = 0; round < proof.params.rounds; ++round) {
        auto shares = native_reset_layer_split_witness(stmt, wit, sec, seed, round);
        for (size_t branch = 0; branch < proof.params.branches; ++branch) {
            NativeResetLayerOpening opening;
            opening.round = round;
            opening.branch = branch;
            opening.self = shares[branch];
            opening.next = shares[(branch + 1) % proof.params.branches];
            opening.residual = native_reset_layer_branch_residual(stmt, opening.self, opening.next, branch);
            opening.commit = native_reset_layer_opening_commit(opening);
            branches.push_back(opening);
            proof.branch_commits.push_back(opening.commit);
            proof.residuals.push_back(opening.residual);
        }
    }
    proof.challenge = native_reset_layer_challenge(stmt, out, proof);
    for (size_t round = 0; round < proof.params.rounds; ++round) {
        for (size_t slot = 0; slot < proof.params.opened_branches; ++slot) {
            size_t branch = native_reset_layer_opened_branch(proof.params, proof.challenge, round, slot);
            proof.openings.push_back(branches[round * proof.params.branches + branch]);
        }
    }
    proof.response_digest = native_reset_layer_response_digest(proof);
    return proof;
}

inline NativeResetLayerProof make_native_reset_layer_field_proof(const NativeResetStmt& stmt, const NativeResetOutput& out, const NativeResetLayerWitness& wit, const NativeResetSecrets& sec, const NativeResetProofParams& params, const std::array<uint8_t, 32>& seed) {
    if (!native_reset_output_shape(stmt, out))
        throw std::runtime_error("pvac: native reset field layer proof output rejected");
    if (!native_reset_layer_witness_inverse_holds(stmt, wit, sec))
        throw std::runtime_error("pvac: native reset field layer inverse witness rejected");
    NativeResetLayerProof proof;
    proof.kind = NativeResetLayerKind::BRANCH_INVERSE;
    proof.params = native_reset_arith_params_from_proof(params);
    proof.stmt_digest = native_reset_stmt_digest(stmt);
    proof.output_digest = native_reset_output_digest(out);
    proof.old_layer_digest = native_reset_layer_stack_digest(wit.old_layers);
    proof.new_layer_digest = native_reset_layer_stack_digest(wit.new_layers);
    proof.layer_trace = make_native_reset_field_layer_trace_boundary(wit, params, seed);
    proof.inverse_relation = true;
    proof.product_layer_relation = true;
    proof.hides_witness = true;
    proof.no_basis_oracle = true;
    proof.native_backend = true;
    if (!native_reset_arith_params_ok(proof.params))
        throw std::runtime_error("pvac: native reset field layer params rejected");
    proof.branch_commits.reserve(proof.params.rounds * proof.params.branches);
    proof.residuals.reserve(proof.params.rounds * proof.params.branches);
    std::vector<NativeResetLayerOpening> branches;
    branches.reserve(proof.params.rounds * proof.params.branches);
    for (size_t round = 0; round < proof.params.rounds; ++round) {
        auto shares = native_reset_layer_split_witness(stmt, wit, sec, seed, round);
        for (size_t branch = 0; branch < proof.params.branches; ++branch) {
            NativeResetLayerOpening opening;
            opening.round = round;
            opening.branch = branch;
            opening.self = shares[branch];
            opening.next = shares[(branch + 1) % proof.params.branches];
            opening.residual = native_reset_layer_branch_residual(stmt, opening.self, opening.next, branch);
            opening.commit = native_reset_layer_opening_commit(opening);
            branches.push_back(opening);
            proof.branch_commits.push_back(opening.commit);
            proof.residuals.push_back(opening.residual);
        }
    }
    proof.challenge = native_reset_layer_challenge(stmt, out, proof);
    for (size_t round = 0; round < proof.params.rounds; ++round) {
        for (size_t slot = 0; slot < proof.params.opened_branches; ++slot) {
            size_t branch = native_reset_layer_opened_branch(proof.params, proof.challenge, round, slot);
            proof.openings.push_back(branches[round * proof.params.branches + branch]);
        }
    }
    proof.response_digest = native_reset_layer_response_digest(proof);
    return proof;
}

inline bool native_reset_layer_commits_ok(const NativeResetStmt& stmt, const NativeResetLayerProof& proof) {
    if (!native_reset_arith_params_ok(proof.params))
        return false;
    if (proof.branch_commits.size() != proof.params.rounds * proof.params.branches)
        return false;
    if (proof.residuals.size() != proof.params.rounds * proof.params.branches)
        return false;
    for (size_t round = 0; round < proof.params.rounds; ++round) {
        auto sum = native_reset_layer_residual_sum(stmt, proof.residuals, round * proof.params.branches);
        if (!native_reset_layer_residual_zero(stmt, sum))
            return false;
    }
    return true;
}

inline bool native_reset_layer_openings_ok(const NativeResetStmt& stmt, const NativeResetLayerProof& proof) {
    if (!native_reset_layer_commits_ok(stmt, proof))
        return false;
    if (proof.openings.size() != proof.params.rounds * proof.params.opened_branches)
        return false;
    for (size_t round = 0; round < proof.params.rounds; ++round) {
        for (size_t slot = 0; slot < proof.params.opened_branches; ++slot) {
            size_t id = round * proof.params.opened_branches + slot;
            size_t branch = native_reset_layer_opened_branch(proof.params, proof.challenge, round, slot);
            if (branch >= proof.params.branches)
                return false;
            const auto& opening = proof.openings[id];
            if (opening.round != round || opening.branch != branch)
                return false;
            if (!native_reset_layer_share_shape(stmt, opening.self))
                return false;
            if (!native_reset_layer_share_shape(stmt, opening.next))
                return false;
            if (!native_reset_layer_residual_shape(stmt, opening.residual))
                return false;
            auto expected_residual = native_reset_layer_branch_residual(stmt, opening.self, opening.next, branch);
            if (!native_reset_layer_residual_eq(expected_residual, opening.residual))
                return false;
            auto expected_commit = native_reset_layer_opening_commit(opening);
            if (!native_digest_eq(expected_commit, opening.commit))
                return false;
            size_t commit_id = round * proof.params.branches + branch;
            if (!native_digest_eq(opening.commit, proof.branch_commits[commit_id]))
                return false;
            if (!native_reset_layer_residual_eq(opening.residual, proof.residuals[commit_id]))
                return false;
        }
    }
    return true;
}

inline NativeResetLayerDecision decide_native_reset_layer_proof(const NativeResetStmt& stmt, const NativeResetOutput& out, const NativeResetLayerProof& proof) {
    NativeResetLayerDecision decision;
    decision.rejects_digest_only = proof.kind == NativeResetLayerKind::DIGEST_ONLY;
    decision.rejects_open_witness = proof.kind == NativeResetLayerKind::OPEN_WITNESS_LOCAL;
    decision.rejects_raw_witness = proof.has_raw_witness;
    decision.rejects_basis_oracle = !proof.no_basis_oracle;
    decision.params = native_reset_arith_params_ok(proof.params);
    decision.transcript =
        proof.kind == NativeResetLayerKind::BRANCH_INVERSE &&
        native_reset_output_shape(stmt, out) &&
        native_digest_eq(proof.stmt_digest, native_reset_stmt_digest(stmt)) &&
        native_digest_eq(proof.output_digest, native_reset_output_digest(out)) &&
        native_digest_eq(proof.challenge, native_reset_layer_challenge(stmt, out, proof));
    decision.commits = decision.transcript && native_reset_layer_commits_ok(stmt, proof);
    decision.openings = decision.commits && native_reset_layer_openings_ok(stmt, proof);
    decision.residuals = decision.openings;
    decision.response = decision.openings && native_digest_eq(proof.response_digest, native_reset_layer_response_digest(proof));
    decision.inverse = decision.response && proof.inverse_relation;
    auto binding_decision = decide_native_reset_layer_trace(proof.layer_trace, proof.old_layer_digest, proof.new_layer_digest);
    decision.binding = binding_decision.admitted;
    decision.product_layers = decision.response && proof.product_layer_relation;
    decision.secrecy =
        decision.response &&
        proof.hides_witness &&
        proof.no_basis_oracle &&
        proof.native_backend &&
        !proof.has_raw_witness &&
        !decision.rejects_digest_only &&
        !decision.rejects_open_witness;
    decision.ready = decision.params && decision.transcript && decision.commits && decision.openings && decision.response;
    decision.admitted = decision.ready && decision.inverse && decision.binding && decision.product_layers && decision.secrecy;
    return decision;
}

inline bool native_reset_aggregation_holds(const NativeResetStmt& stmt, const NativeResetRows& rows, const NativeResetOutput& out) {
    if (!native_reset_output_shape(stmt, out))
        return false;
    if (!native_reset_rows_shape(stmt, rows))
        return false;
    auto expected = native_reset_aggregate(stmt, rows);
    if (!native_fp_vec_eq(expected.c, out.c))
        return false;
    for (size_t t = 0; t < expected.beta.size(); ++t) {
        if (!native_fp_vec_eq(expected.beta[t], out.beta[t]))
            return false;
    }
    return true;
}

inline bool native_reset_witness_holds(const NativeResetStmt& stmt, const NativeResetRows& rows, const NativeResetSecrets& sec) {
    if (!native_reset_rows_shape(stmt, rows))
        return false;
    if (!native_reset_secret_shape(stmt, sec))
        return false;
    for (size_t i = 0; i < stmt.alpha.size(); ++i) {
        for (size_t j = 0; j < stmt.c.size(); ++j) {
            Fp rhs = rows.bias[i][j];
            for (size_t t = 0; t < stmt.target_terms; ++t) {
                rhs = fp_add(rhs, fp_mul(rows.mix[i][t][j], sec.new_y[t][j]));
            }
            uint64_t diff = (sec.old_x[i][j].lo ^ rhs.lo) | ((sec.old_x[i][j].hi ^ rhs.hi) & MASK63);
            if (diff != 0)
                return false;
        }
    }
    return true;
}

inline std::vector<Fp> native_reset_old_value(const NativeResetStmt& stmt, const NativeResetSecrets& sec) {
    if (!native_reset_secret_shape(stmt, sec))
        throw std::runtime_error("pvac: native reset old value shape rejected");
    auto out = stmt.c;
    for (size_t i = 0; i < stmt.alpha.size(); ++i) {
        for (size_t j = 0; j < stmt.c.size(); ++j) {
            out[j] = fp_add(out[j], fp_mul(stmt.alpha[i][j], sec.old_x[i][j]));
        }
    }
    return out;
}

inline std::vector<Fp> native_reset_new_value(const NativeResetOutput& out, const NativeResetSecrets& sec) {
    if (out.c.empty())
        throw std::runtime_error("pvac: native reset new value shape rejected");
    if (!native_matrix_shape(out.beta, out.beta.size(), out.c.size()))
        throw std::runtime_error("pvac: native reset new beta shape rejected");
    if (!native_matrix_shape(sec.new_y, out.beta.size(), out.c.size()))
        throw std::runtime_error("pvac: native reset new secret shape rejected");
    auto val = out.c;
    for (size_t t = 0; t < out.beta.size(); ++t) {
        for (size_t j = 0; j < out.c.size(); ++j) {
            val[j] = fp_add(val[j], fp_mul(out.beta[t][j], sec.new_y[t][j]));
        }
    }
    return val;
}

inline bool native_reset_value_holds(const NativeResetStmt& stmt, const NativeResetOutput& out, const NativeResetSecrets& sec) {
    if (!native_reset_output_shape(stmt, out))
        return false;
    if (!native_reset_secret_shape(stmt, sec))
        return false;
    return native_fp_vec_eq(native_reset_old_value(stmt, sec), native_reset_new_value(out, sec));
}

inline bool native_reset_support_holds(const NativeResetStmt& stmt, const NativeResetOutput& out) {
    if (!native_reset_output_shape(stmt, out))
        return false;
    if (out.beta.size() != stmt.target_terms)
        return false;
    return out.beta.size() < stmt.alpha.size();
}

inline NativeResetCheck check_native_reset_relation(const NativeResetStmt& stmt, const NativeResetRows& rows, const NativeResetSecrets& sec, const NativeResetOutput& out) {
    NativeResetCheck check;
    check.shape =
        native_reset_rows_shape(stmt, rows) &&
        native_reset_secret_shape(stmt, sec) &&
        native_reset_output_shape(stmt, out);
    check.aggregation = check.shape && native_reset_aggregation_holds(stmt, rows, out);
    check.witness = check.shape && native_reset_witness_holds(stmt, rows, sec);
    check.value = check.shape && native_reset_value_holds(stmt, out, sec);
    check.support = check.shape && native_reset_support_holds(stmt, out);
    check.admitted = check.shape && check.aggregation && check.witness && check.value && check.support;
    return check;
}

inline std::array<uint8_t, 32> native_reset_stmt_digest(const NativeResetStmt& stmt) {
    Sha256 h;
    h.init();
    native_hash_domain(h, "pvac.native.reset.stmt");
    native_hash_vec(h, stmt.c);
    native_hash_matrix(h, stmt.alpha);
    sha256_acc_u64(h, stmt.target_terms);
    hidden_coeff_acc_bound(h, stmt.bound);
    std::array<uint8_t, 32> out{};
    h.finish(out.data());
    return out;
}

inline std::array<uint8_t, 32> native_reset_rows_digest(const NativeResetRows& rows) {
    Sha256 h;
    h.init();
    native_hash_domain(h, "pvac.native.reset.rows");
    native_hash_matrix(h, rows.bias);
    native_hash_cube(h, rows.mix);
    std::array<uint8_t, 32> out{};
    h.finish(out.data());
    return out;
}

inline std::array<uint8_t, 32> native_reset_output_digest(const NativeResetOutput& out) {
    Sha256 h;
    h.init();
    native_hash_domain(h, "pvac.native.reset.output");
    native_hash_vec(h, out.c);
    native_hash_matrix(h, out.beta);
    std::array<uint8_t, 32> digest{};
    h.finish(digest.data());
    return digest;
}

inline std::array<uint8_t, 32> native_reset_relation_digest(const NativeResetStmt& stmt, const NativeResetRows& rows, const NativeResetOutput& out, const HiddenCoeffPlan& plan, const NativeResetCheck& check) {
    Sha256 h;
    h.init();
    native_hash_domain(h, "pvac.native.reset.relation");
    auto sd = native_reset_stmt_digest(stmt);
    auto rd = native_reset_rows_digest(rows);
    auto od = native_reset_output_digest(out);
    h.update(sd.data(), sd.size());
    h.update(rd.data(), rd.size());
    h.update(od.data(), od.size());
    native_hash_plan(h, plan);
    native_hash_check(h, check);
    std::array<uint8_t, 32> digest{};
    h.finish(digest.data());
    return digest;
}

inline NativeResetCert make_native_reset_witness_cert(const NativeResetStmt& stmt, const NativeResetRows& rows, const NativeResetSecrets& sec, const NativeResetOutput& out) {
    auto check = check_native_reset_relation(stmt, rows, sec, out);
    if (!check.admitted)
        throw std::runtime_error("pvac: native reset witness certificate rejected");
    NativeResetCert cert;
    cert.kind = NativeResetCertKind::WITNESS_LOCAL;
    cert.stmt_digest = native_reset_stmt_digest(stmt);
    cert.rows_digest = native_reset_rows_digest(rows);
    cert.output_digest = native_reset_output_digest(out);
    cert.plan = plan_hidden_coeff(stmt.bound);
    cert.check = check;
    cert.relation_digest = native_reset_relation_digest(stmt, rows, out, cert.plan, cert.check);
    return cert;
}

inline NativeResetCert make_native_hidden_reset_cert(const NativeResetStmt& stmt, const NativeResetRows& rows, const NativeResetSecrets& sec, const NativeResetOutput& out) {
    auto check = check_native_reset_relation(stmt, rows, sec, out);
    if (!check.admitted)
        throw std::runtime_error("pvac: native hidden reset certificate rejected");
    NativeResetCert cert;
    cert.kind = NativeResetCertKind::HIDDEN_PUBLIC;
    cert.stmt_digest = native_reset_stmt_digest(stmt);
    cert.rows_digest = native_reset_rows_digest(rows);
    cert.output_digest = native_reset_output_digest(out);
    cert.plan = plan_hidden_coeff(stmt.bound);
    cert.check = check;
    cert.relation_digest = native_reset_relation_digest(stmt, rows, out, cert.plan, cert.check);
    return cert;
}

inline bool verify_native_reset_witness_cert(const NativeResetStmt& stmt, const NativeResetRows& rows, const NativeResetSecrets& sec, const NativeResetOutput& out, const NativeResetCert& cert) {
    if (cert.kind != NativeResetCertKind::WITNESS_LOCAL)
        return false;
    auto check = check_native_reset_relation(stmt, rows, sec, out);
    if (!check.admitted)
        return false;
    auto plan = plan_hidden_coeff(stmt.bound);
    if (cert.plan.sum_bits != plan.sum_bits ||
        cert.plan.needs_p_correction != plan.needs_p_correction ||
        cert.plan.needs_wide_correction != plan.needs_wide_correction ||
        cert.plan.admitted != plan.admitted)
        return false;
    if (!native_digest_eq(cert.stmt_digest, native_reset_stmt_digest(stmt)))
        return false;
    if (!native_digest_eq(cert.rows_digest, native_reset_rows_digest(rows)))
        return false;
    if (!native_digest_eq(cert.output_digest, native_reset_output_digest(out)))
        return false;
    if (!native_digest_eq(cert.relation_digest, native_reset_relation_digest(stmt, rows, out, plan, check)))
        return false;
    return
        cert.check.shape == check.shape &&
        cert.check.aggregation == check.aggregation &&
        cert.check.witness == check.witness &&
        cert.check.value == check.value &&
        cert.check.support == check.support &&
        cert.check.admitted == check.admitted;
}

inline bool verify_native_reset_public_cert(const NativeResetStmt& stmt, const NativeResetOutput& out, const NativeResetCert& cert, const NativeResetPublicSpec& spec) {
    if (cert.kind != NativeResetCertKind::HIDDEN_PUBLIC)
        return false;
    if (!native_reset_output_shape(stmt, out))
        return false;
    if (!native_digest_eq(cert.stmt_digest, native_reset_stmt_digest(stmt)))
        return false;
    if (!native_digest_eq(cert.output_digest, native_reset_output_digest(out)))
        return false;
    auto plan = plan_hidden_coeff(stmt.bound);
    if (!plan.admitted || plan.needs_wide_correction)
        return false;
    if (!decide_native_reset_public_spec(spec, plan).admitted)
        return false;
    if (cert.plan.sum_bits != plan.sum_bits ||
        cert.plan.needs_p_correction != plan.needs_p_correction ||
        cert.plan.needs_wide_correction != plan.needs_wide_correction ||
        cert.plan.admitted != plan.admitted)
        return false;
    return false;
}

inline bool verify_native_reset_public_cert(const NativeResetStmt& stmt, const NativeResetOutput& out, const NativeResetCert& cert) {
    NativeResetPublicSpec spec;
    return verify_native_reset_public_cert(stmt, out, cert, spec);
}

inline HiddenCoeffBound native_reset_bound_from_stmt(const NativeResetStmt& stmt, size_t alpha_bits, size_t row_bits) {
    HiddenCoeffBound bound;
    bound.terms = stmt.alpha.size();
    bound.alpha_bits = alpha_bits;
    bound.row_bits = row_bits;
    return bound;
}

}