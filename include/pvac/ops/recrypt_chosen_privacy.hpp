/*
 * Octra Labs
 * Internal use only
 * December 2025
 */

#pragma once

#include <array>
#include <cstdint>
#include <cstring>
#include <limits>
#include <stdexcept>
#include <vector>

#include "../core/hash.hpp"
#include "../core/types.hpp"
#include "recrypt_hidden_coeff.hpp"
#include "recrypt_proof_profile.hpp"

namespace pvac {

enum class NativeResetChosenMaterialKind : uint8_t {
    NONE = 0,
    HIDDEN_CARRIER = 1,
    VISIBLE_COEFFS = 2,
    RAW_ROWS = 3
};

struct NativeResetChosenPolicy {
    bool reusable = true;
    bool hidden_output = true;
    bool statement_bound = false;
    bool transcript_bound = false;
    bool material_bound = false;
    bool no_basis_oracle = false;
    bool native_backend = false;
    size_t max_queries = 0;
    HiddenCoeffCertKind cert = HiddenCoeffCertKind::NONE;
};

struct NativeResetChosenMaterial {
    NativeResetChosenMaterialKind kind = NativeResetChosenMaterialKind::NONE;
    HiddenCoeffMaterial coeff;
    size_t target_terms = 0;
    size_t slots = 0;
    bool reusable = false;
    bool has_raw_rows = false;
    bool visible_coeffs = false;
    bool hides_rows = false;
    bool no_basis_oracle = false;
    bool native_backend = false;
};

struct NativeResetChosenStmt {
    HiddenCoeffStmt coeff;
    size_t target_terms = 0;
    size_t slots = 0;
    size_t query = 0;
};

struct NativeResetHiddenOutput {
    size_t target_terms = 0;
    size_t slots = 0;
    std::vector<std::array<uint8_t, 32>> coeff_tags;
    std::array<uint8_t, 32> material_digest = {};
    std::array<uint8_t, 32> statement_digest = {};
    std::array<uint8_t, 32> output_digest = {};
    bool hidden_coeffs = false;
    bool visible_beta = true;
};

struct NativeResetChosenTranscript {
    HiddenCoeffPlan plan;
    std::array<uint8_t, 32> material_digest = {};
    std::array<uint8_t, 32> statement_digest = {};
    std::array<uint8_t, 32> output_digest = {};
    std::array<uint8_t, 32> transcript_digest = {};
    bool statement_bound = false;
    bool material_bound = false;
    bool hidden_output = false;
    bool no_basis_oracle = false;
    bool native_backend = false;
};

struct NativeResetChosenDecision {
    bool admitted = false;
    bool policy = false;
    bool material = false;
    bool statement = false;
    bool output = false;
    bool transcript = false;
    bool privacy = false;
    bool rejects_raw = false;
    bool rejects_visible = false;
    bool rejects_unbound = false;
    bool rejects_basis_oracle = false;
    bool rejects_query_budget = false;
    bool rejects_wide = false;
};

struct NativeResetReusableBudget {
    NativeResetProofProfileKind proof = NativeResetProofProfileKind::FIELD_NATIVE;
    size_t target_bits = 128;
    size_t max_trace_units = 1024;
    size_t max_output_tags = 1 << 16;
    size_t max_proof_bytes = 1 << 20;
};

struct NativeResetReusableDecision {
    NativeResetChosenDecision chosen;
    NativeResetProofProfile profile;
    std::array<uint8_t, 32> output_digest = {};
    std::array<uint8_t, 32> material_digest = {};
    std::array<uint8_t, 32> statement_digest = {};
    bool admitted = false;
    bool privacy = false;
    bool proof = false;
    bool compact = false;
    bool output = false;
    bool budget = false;
    bool rejects_sha_compat = false;
    bool rejects_noncompact = false;
    bool rejects_underbudget = false;
    bool rejects_output_wide = false;
    bool rejects_proof_wide = false;
};

inline void native_chosen_acc_size(Sha256& h, size_t x) {
    sha256_acc_u64(h, x);
}

inline void native_chosen_acc_bool(Sha256& h, bool x) {
    sha256_acc_u64(h, x ? 1 : 0);
}

inline bool native_chosen_digest_eq(const std::array<uint8_t, 32>& a, const std::array<uint8_t, 32>& b) {
    uint8_t diff = 0;
    for (size_t i = 0; i < a.size(); ++i) {
        diff |= static_cast<uint8_t>(a[i] ^ b[i]);
    }
    return diff == 0;
}

inline std::array<uint8_t, 32> native_chosen_material_digest(const NativeResetChosenMaterial& material) {
    Sha256 h;
    h.init();
    h.update("pvac.native.reset.chosen.material", std::strlen("pvac.native.reset.chosen.material"));
    sha256_acc_u64(h, static_cast<uint8_t>(material.kind));
    auto coeff_digest = hidden_coeff_material_digest(material.coeff);
    h.update(coeff_digest.data(), coeff_digest.size());
    native_chosen_acc_size(h, material.target_terms);
    native_chosen_acc_size(h, material.slots);
    native_chosen_acc_bool(h, material.reusable);
    native_chosen_acc_bool(h, material.has_raw_rows);
    native_chosen_acc_bool(h, material.visible_coeffs);
    native_chosen_acc_bool(h, material.hides_rows);
    native_chosen_acc_bool(h, material.no_basis_oracle);
    native_chosen_acc_bool(h, material.native_backend);
    std::array<uint8_t, 32> out{};
    h.finish(out.data());
    return out;
}

inline std::array<uint8_t, 32> native_chosen_stmt_digest(const NativeResetChosenStmt& stmt) {
    Sha256 h;
    h.init();
    h.update("pvac.native.reset.chosen.statement", std::strlen("pvac.native.reset.chosen.statement"));
    auto coeff_digest = hidden_coeff_stmt_digest(stmt.coeff);
    h.update(coeff_digest.data(), coeff_digest.size());
    native_chosen_acc_size(h, stmt.target_terms);
    native_chosen_acc_size(h, stmt.slots);
    native_chosen_acc_size(h, stmt.query);
    std::array<uint8_t, 32> out{};
    h.finish(out.data());
    return out;
}

inline std::array<uint8_t, 32> native_chosen_coeff_tag(const NativeResetChosenMaterial& material, const NativeResetChosenStmt& stmt, size_t target, size_t slot) {
    Sha256 h;
    h.init();
    h.update("pvac.native.reset.chosen.output.coeff", std::strlen("pvac.native.reset.chosen.output.coeff"));
    auto md = native_chosen_material_digest(material);
    auto sd = native_chosen_stmt_digest(stmt);
    h.update(md.data(), md.size());
    h.update(sd.data(), sd.size());
    native_chosen_acc_size(h, target);
    native_chosen_acc_size(h, slot);
    std::array<uint8_t, 32> out{};
    h.finish(out.data());
    return out;
}

inline std::array<uint8_t, 32> native_chosen_output_digest(const NativeResetHiddenOutput& out) {
    Sha256 h;
    h.init();
    h.update("pvac.native.reset.chosen.output", std::strlen("pvac.native.reset.chosen.output"));
    native_chosen_acc_size(h, out.target_terms);
    native_chosen_acc_size(h, out.slots);
    native_chosen_acc_size(h, out.coeff_tags.size());
    for (const auto& tag : out.coeff_tags) {
        h.update(tag.data(), tag.size());
    }
    h.update(out.material_digest.data(), out.material_digest.size());
    h.update(out.statement_digest.data(), out.statement_digest.size());
    native_chosen_acc_bool(h, out.hidden_coeffs);
    native_chosen_acc_bool(h, out.visible_beta);
    std::array<uint8_t, 32> digest{};
    h.finish(digest.data());
    return digest;
}

inline std::array<uint8_t, 32> native_chosen_transcript_digest(const NativeResetChosenTranscript& transcript) {
    Sha256 h;
    h.init();
    h.update("pvac.native.reset.chosen.transcript", std::strlen("pvac.native.reset.chosen.transcript"));
    h.update(transcript.material_digest.data(), transcript.material_digest.size());
    h.update(transcript.statement_digest.data(), transcript.statement_digest.size());
    h.update(transcript.output_digest.data(), transcript.output_digest.size());
    sha256_acc_u64(h, transcript.plan.sum_bits);
    native_chosen_acc_bool(h, transcript.plan.needs_p_correction);
    native_chosen_acc_bool(h, transcript.plan.needs_wide_correction);
    native_chosen_acc_bool(h, transcript.plan.admitted);
    native_chosen_acc_bool(h, transcript.statement_bound);
    native_chosen_acc_bool(h, transcript.material_bound);
    native_chosen_acc_bool(h, transcript.hidden_output);
    native_chosen_acc_bool(h, transcript.no_basis_oracle);
    native_chosen_acc_bool(h, transcript.native_backend);
    std::array<uint8_t, 32> out{};
    h.finish(out.data());
    return out;
}

inline NativeResetChosenMaterial make_native_reset_chosen_material(const HiddenCoeffMaterial& coeff, size_t target_terms, size_t slots) {
    if (target_terms == 0 || slots == 0)
        throw std::runtime_error("pvac: native chosen material shape rejected");
    NativeResetChosenMaterial material;
    material.kind = NativeResetChosenMaterialKind::HIDDEN_CARRIER;
    material.coeff = coeff;
    material.target_terms = target_terms;
    material.slots = slots;
    material.reusable = true;
    material.hides_rows = true;
    material.no_basis_oracle = true;
    material.native_backend = true;
    return material;
}

inline NativeResetChosenStmt make_native_reset_chosen_stmt(const std::vector<Fp>& alpha, const HiddenCoeffBound& bound, size_t target_terms, size_t slots, size_t query) {
    NativeResetChosenStmt stmt;
    stmt.coeff = make_hidden_coeff_stmt(alpha, bound);
    stmt.target_terms = target_terms;
    stmt.slots = slots;
    stmt.query = query;
    return stmt;
}

inline NativeResetHiddenOutput make_native_reset_hidden_output(const NativeResetChosenMaterial& material, const NativeResetChosenStmt& stmt) {
    if (material.target_terms == 0 || material.slots == 0)
        throw std::runtime_error("pvac: native hidden output material shape rejected");
    if (stmt.target_terms != material.target_terms || stmt.slots != material.slots)
        throw std::runtime_error("pvac: native hidden output statement shape rejected");
    NativeResetHiddenOutput out;
    out.target_terms = stmt.target_terms;
    out.slots = stmt.slots;
    out.material_digest = native_chosen_material_digest(material);
    out.statement_digest = native_chosen_stmt_digest(stmt);
    out.hidden_coeffs = true;
    out.visible_beta = false;
    if (out.target_terms > std::numeric_limits<size_t>::max() / out.slots)
        throw std::runtime_error("pvac: native hidden output size rejected");
    out.coeff_tags.reserve(out.target_terms * out.slots);
    for (size_t t = 0; t < out.target_terms; ++t) {
        for (size_t j = 0; j < out.slots; ++j) {
            out.coeff_tags.push_back(native_chosen_coeff_tag(material, stmt, t, j));
        }
    }
    out.output_digest = native_chosen_output_digest(out);
    return out;
}

inline NativeResetChosenTranscript make_native_reset_chosen_transcript(const NativeResetChosenMaterial& material, const NativeResetChosenStmt& stmt, const NativeResetHiddenOutput& out) {
    NativeResetChosenTranscript transcript;
    transcript.plan = plan_hidden_coeff(stmt.coeff.bound);
    transcript.material_digest = native_chosen_material_digest(material);
    transcript.statement_digest = native_chosen_stmt_digest(stmt);
    transcript.output_digest = native_chosen_output_digest(out);
    transcript.statement_bound = true;
    transcript.material_bound = true;
    transcript.hidden_output = true;
    transcript.no_basis_oracle = true;
    transcript.native_backend = true;
    transcript.transcript_digest = native_chosen_transcript_digest(transcript);
    return transcript;
}

inline bool native_reset_chosen_policy_ok(const NativeResetChosenPolicy& policy) {
    return
        policy.reusable &&
        policy.hidden_output &&
        policy.statement_bound &&
        policy.transcript_bound &&
        policy.material_bound &&
        policy.no_basis_oracle &&
        policy.native_backend &&
        policy.max_queries != 0 &&
        policy.cert == HiddenCoeffCertKind::PVAC_NATIVE;
}

inline bool native_reset_chosen_material_ok(const NativeResetChosenMaterial& material) {
    return
        material.kind == NativeResetChosenMaterialKind::HIDDEN_CARRIER &&
        material.reusable &&
        !material.has_raw_rows &&
        !material.visible_coeffs &&
        material.hides_rows &&
        material.no_basis_oracle &&
        material.native_backend &&
        material.target_terms != 0 &&
        material.slots != 0 &&
        material.coeff.row_tags.size() == material.coeff.bound.terms;
}

inline bool native_reset_chosen_stmt_ok(const NativeResetChosenMaterial& material, const NativeResetChosenStmt& stmt, const NativeResetChosenPolicy& policy) {
    return
        stmt.coeff.alpha.size() == material.coeff.bound.terms &&
        stmt.coeff.bound.terms == material.coeff.bound.terms &&
        stmt.coeff.bound.alpha_bits == material.coeff.bound.alpha_bits &&
        stmt.coeff.bound.row_bits == material.coeff.bound.row_bits &&
        stmt.target_terms == material.target_terms &&
        stmt.slots == material.slots &&
        stmt.query < policy.max_queries;
}

inline bool native_reset_hidden_output_ok(const NativeResetChosenMaterial& material, const NativeResetChosenStmt& stmt, const NativeResetHiddenOutput& out) {
    if (out.target_terms != material.target_terms || out.slots != material.slots)
        return false;
    if (!out.hidden_coeffs || out.visible_beta)
        return false;
    if (!native_chosen_digest_eq(out.material_digest, native_chosen_material_digest(material)))
        return false;
    if (!native_chosen_digest_eq(out.statement_digest, native_chosen_stmt_digest(stmt)))
        return false;
    if (out.target_terms > std::numeric_limits<size_t>::max() / out.slots)
        return false;
    if (out.coeff_tags.size() != out.target_terms * out.slots)
        return false;
    for (size_t t = 0; t < out.target_terms; ++t) {
        for (size_t j = 0; j < out.slots; ++j) {
            size_t id = t * out.slots + j;
            if (!native_chosen_digest_eq(out.coeff_tags[id], native_chosen_coeff_tag(material, stmt, t, j)))
                return false;
        }
    }
    return native_chosen_digest_eq(out.output_digest, native_chosen_output_digest(out));
}

inline NativeResetChosenDecision decide_native_reset_chosen_statement(const NativeResetChosenPolicy& policy, const NativeResetChosenMaterial& material, const NativeResetChosenStmt& stmt, const NativeResetHiddenOutput& out, const NativeResetChosenTranscript& transcript) {
    NativeResetChosenDecision decision;
    decision.policy = native_reset_chosen_policy_ok(policy);
    decision.material = native_reset_chosen_material_ok(material);
    decision.statement = decision.material && native_reset_chosen_stmt_ok(material, stmt, policy);
    decision.output = decision.statement && native_reset_hidden_output_ok(material, stmt, out);
    auto plan = plan_hidden_coeff(stmt.coeff.bound);
    decision.rejects_raw =
        material.kind == NativeResetChosenMaterialKind::RAW_ROWS ||
        material.has_raw_rows;
    decision.rejects_visible =
        material.kind == NativeResetChosenMaterialKind::VISIBLE_COEFFS ||
        material.visible_coeffs ||
        out.visible_beta ||
        !out.hidden_coeffs;
    decision.rejects_unbound =
        !policy.statement_bound ||
        !policy.transcript_bound ||
        !policy.material_bound ||
        !transcript.statement_bound ||
        !transcript.material_bound ||
        !transcript.hidden_output ||
        !transcript.native_backend;
    decision.rejects_basis_oracle =
        !policy.no_basis_oracle ||
        !material.no_basis_oracle ||
        !material.hides_rows ||
        !transcript.no_basis_oracle;
    decision.rejects_query_budget = stmt.query >= policy.max_queries;
    decision.rejects_wide = plan.needs_wide_correction;
    decision.privacy =
        decision.policy &&
        decision.material &&
        decision.output &&
        !decision.rejects_raw &&
        !decision.rejects_visible &&
        !decision.rejects_unbound &&
        !decision.rejects_basis_oracle &&
        !decision.rejects_query_budget &&
        !decision.rejects_wide;
    decision.transcript =
        decision.privacy &&
        transcript.plan.sum_bits == plan.sum_bits &&
        transcript.plan.needs_p_correction == plan.needs_p_correction &&
        transcript.plan.needs_wide_correction == plan.needs_wide_correction &&
        transcript.plan.admitted == plan.admitted &&
        native_chosen_digest_eq(transcript.material_digest, native_chosen_material_digest(material)) &&
        native_chosen_digest_eq(transcript.statement_digest, native_chosen_stmt_digest(stmt)) &&
        native_chosen_digest_eq(transcript.output_digest, native_chosen_output_digest(out)) &&
        native_chosen_digest_eq(transcript.transcript_digest, native_chosen_transcript_digest(transcript));
    decision.admitted = decision.privacy && decision.transcript && plan.admitted;
    return decision;
}

inline NativeResetReusableDecision decide_native_reset_reusable_statement(const NativeResetChosenPolicy& policy, const NativeResetChosenMaterial& material, const NativeResetChosenStmt& stmt, const NativeResetHiddenOutput& out, const NativeResetChosenTranscript& transcript, const NativeResetReusableBudget& budget = NativeResetReusableBudget{}) {
    NativeResetReusableDecision decision;
    decision.chosen = decide_native_reset_chosen_statement(policy, material, stmt, out, transcript);
    decision.profile = plan_native_reset_proof_profile(budget.proof, budget.target_bits);
    decision.output_digest = out.output_digest;
    decision.material_digest = out.material_digest;
    decision.statement_digest = out.statement_digest;
    decision.privacy = decision.chosen.admitted;
    decision.rejects_sha_compat = budget.proof != NativeResetProofProfileKind::FIELD_NATIVE;
    decision.rejects_underbudget =
        !decision.profile.admitted ||
        !native_reset_proof_params_ok(decision.profile.params) ||
        decision.profile.soundness_bits < budget.target_bits;
    decision.rejects_noncompact =
        decision.profile.trace_units > budget.max_trace_units;
    decision.rejects_output_wide =
        out.coeff_tags.empty() ||
        out.coeff_tags.size() > budget.max_output_tags;
    decision.rejects_proof_wide =
        decision.profile.total_bytes == std::numeric_limits<size_t>::max() ||
        decision.profile.total_bytes > budget.max_proof_bytes;
    decision.proof =
        !decision.rejects_sha_compat &&
        !decision.rejects_underbudget;
    decision.compact =
        decision.proof &&
        !decision.rejects_noncompact &&
        !decision.rejects_proof_wide;
    decision.output =
        decision.privacy &&
        out.hidden_coeffs &&
        !out.visible_beta &&
        !decision.rejects_output_wide;
    decision.budget =
        decision.compact &&
        decision.output &&
        policy.max_queries != 0 &&
        stmt.query < policy.max_queries;
    decision.admitted =
        decision.privacy &&
        decision.proof &&
        decision.compact &&
        decision.output &&
        decision.budget;
    return decision;
}

}