/*
 * Octra Labs
 * Internal use only
 * December 2025
 */

#pragma once

#include <array>
#include <cstring>
#include <stdexcept>
#include <vector>

#include "../core/hash.hpp"
#include "../core/types.hpp"

namespace pvac {

enum class HiddenCoeffCertKind : uint8_t {
    NONE = 0,
    PVAC_NATIVE = 1
};

struct HiddenCoeffProfile {
    bool reusable = true;
    bool visible_output = false;
    bool statement_bound = false;
    bool transcript_bound = false;
    HiddenCoeffCertKind cert = HiddenCoeffCertKind::NONE;
};

struct HiddenCoeffDecision {
    bool admitted = false;
    bool rejects_basis_oracle = false;
    bool needs_native_certificate = true;
};

struct HiddenCoeffBound {
    size_t terms = 0;
    size_t alpha_bits = 0;
    size_t row_bits = 0;
};

struct HiddenCoeffPlan {
    size_t sum_bits = 0;
    bool needs_p_correction = false;
    bool needs_wide_correction = false;
    bool admitted = false;
};

struct HiddenCoeffMaterial {
    std::vector<std::array<uint8_t, 32>> row_tags;
    HiddenCoeffBound bound;
};

struct HiddenCoeffStmt {
    std::vector<Fp> alpha;
    HiddenCoeffBound bound;
};

struct HiddenCoeffTranscript {
    std::array<uint8_t, 32> aggregate_tag = {};
    HiddenCoeffPlan plan;
    std::array<uint8_t, 32> material_digest = {};
    std::array<uint8_t, 32> statement_digest = {};
};

inline size_t hidden_coeff_ceil_log2(size_t x) {
    if (x <= 1)
        return 0;
    size_t n = x - 1;
    size_t bits = 0;
    while (n != 0) {
        n >>= 1;
        ++bits;
    }
    return bits;
}

inline HiddenCoeffPlan plan_hidden_coeff(const HiddenCoeffBound& bound) {
    HiddenCoeffPlan plan;
    plan.sum_bits = bound.alpha_bits + bound.row_bits + hidden_coeff_ceil_log2(bound.terms);
    plan.needs_p_correction = plan.sum_bits >= 127;
    plan.needs_wide_correction = plan.sum_bits >= 252;
    plan.admitted = bound.terms != 0 && bound.alpha_bits <= 127 && bound.row_bits <= 127;
    return plan;
}

inline HiddenCoeffPlan plan_hidden_coeff_proof(const HiddenCoeffBound& bound) {
    return plan_hidden_coeff(bound);
}

inline void hidden_coeff_acc_bound(Sha256& h, const HiddenCoeffBound& bound) {
    sha256_acc_u64(h, bound.terms);
    sha256_acc_u64(h, bound.alpha_bits);
    sha256_acc_u64(h, bound.row_bits);
}

inline void hidden_coeff_acc_fp(Sha256& h, const Fp& x) {
    sha256_acc_u64(h, x.lo);
    sha256_acc_u64(h, x.hi & MASK63);
}

inline bool hidden_coeff_digest_eq(const std::array<uint8_t, 32>& a, const std::array<uint8_t, 32>& b) {
    uint8_t diff = 0;
    for (size_t i = 0; i < a.size(); ++i) {
        diff |= static_cast<uint8_t>(a[i] ^ b[i]);
    }
    return diff == 0;
}

inline std::array<uint8_t, 32> hidden_coeff_material_digest(const HiddenCoeffMaterial& material) {
    Sha256 h;
    h.init();
    h.update("pvac.native.reset.material", std::strlen("pvac.native.reset.material"));
    hidden_coeff_acc_bound(h, material.bound);
    sha256_acc_u64(h, material.row_tags.size());
    for (const auto& tag : material.row_tags) {
        h.update(tag.data(), tag.size());
    }
    std::array<uint8_t, 32> out{};
    h.finish(out.data());
    return out;
}

inline std::array<uint8_t, 32> hidden_coeff_stmt_digest(const HiddenCoeffStmt& stmt) {
    Sha256 h;
    h.init();
    h.update("pvac.native.reset.statement", std::strlen("pvac.native.reset.statement"));
    hidden_coeff_acc_bound(h, stmt.bound);
    sha256_acc_u64(h, stmt.alpha.size());
    for (const auto& alpha : stmt.alpha) {
        hidden_coeff_acc_fp(h, alpha);
    }
    std::array<uint8_t, 32> out{};
    h.finish(out.data());
    return out;
}

inline HiddenCoeffDecision decide_hidden_coeff_profile(const HiddenCoeffProfile& profile) {
    HiddenCoeffDecision decision;
    decision.rejects_basis_oracle = !(profile.reusable && profile.visible_output);
    decision.needs_native_certificate = profile.cert != HiddenCoeffCertKind::PVAC_NATIVE;
    decision.admitted =
        decision.rejects_basis_oracle &&
        !decision.needs_native_certificate &&
        profile.statement_bound &&
        profile.transcript_bound;
    return decision;
}

inline void require_hidden_coeff_profile(const HiddenCoeffProfile& profile) {
    if (!decide_hidden_coeff_profile(profile).admitted)
        throw std::runtime_error("pvac: native hidden coefficient profile rejected");
}

inline HiddenCoeffMaterial make_hidden_coeff_material(const std::vector<std::array<uint8_t, 32>>& row_tags, const HiddenCoeffBound& bound) {
    if (row_tags.empty())
        throw std::runtime_error("pvac: native hidden coefficient material is empty");
    if (row_tags.size() != bound.terms)
        throw std::runtime_error("pvac: native hidden coefficient material bound mismatch");
    HiddenCoeffMaterial material;
    material.row_tags = row_tags;
    material.bound = bound;
    return material;
}

inline HiddenCoeffStmt make_hidden_coeff_stmt(const std::vector<Fp>& alpha, const HiddenCoeffBound& bound) {
    if (alpha.empty())
        throw std::runtime_error("pvac: native hidden coefficient statement is empty");
    if (alpha.size() != bound.terms)
        throw std::runtime_error("pvac: native hidden coefficient statement bound mismatch");
    HiddenCoeffStmt stmt;
    stmt.alpha = alpha;
    stmt.bound = bound;
    return stmt;
}

inline std::array<uint8_t, 32> native_hidden_coeff_tag(const HiddenCoeffMaterial& material, const HiddenCoeffStmt& stmt, const HiddenCoeffPlan& plan) {
    Sha256 h;
    h.init();
    h.update("pvac.native.reset.aggregate", std::strlen("pvac.native.reset.aggregate"));
    auto material_digest = hidden_coeff_material_digest(material);
    auto stmt_digest = hidden_coeff_stmt_digest(stmt);
    h.update(material_digest.data(), material_digest.size());
    h.update(stmt_digest.data(), stmt_digest.size());
    sha256_acc_u64(h, plan.sum_bits);
    sha256_acc_u64(h, plan.needs_p_correction ? 1 : 0);
    sha256_acc_u64(h, plan.needs_wide_correction ? 1 : 0);
    std::array<uint8_t, 32> out{};
    h.finish(out.data());
    return out;
}

inline HiddenCoeffTranscript make_native_hidden_coeff_transcript(const HiddenCoeffMaterial& material, const HiddenCoeffStmt& stmt) {
    if (material.row_tags.size() != stmt.alpha.size())
        throw std::runtime_error("pvac: native hidden coefficient shape mismatch");
    HiddenCoeffTranscript transcript;
    transcript.plan = plan_hidden_coeff(stmt.bound);
    transcript.material_digest = hidden_coeff_material_digest(material);
    transcript.statement_digest = hidden_coeff_stmt_digest(stmt);
    transcript.aggregate_tag = native_hidden_coeff_tag(material, stmt, transcript.plan);
    return transcript;
}

inline bool verify_native_hidden_coeff_transcript(const HiddenCoeffMaterial& material, const HiddenCoeffStmt& stmt, const HiddenCoeffTranscript& transcript) {
    if (material.row_tags.size() != stmt.alpha.size())
        return false;
    auto plan = plan_hidden_coeff(stmt.bound);
    if (!plan.admitted)
        return false;
    if (!hidden_coeff_digest_eq(transcript.material_digest, hidden_coeff_material_digest(material)))
        return false;
    if (!hidden_coeff_digest_eq(transcript.statement_digest, hidden_coeff_stmt_digest(stmt)))
        return false;
    if (transcript.plan.sum_bits != plan.sum_bits ||
        transcript.plan.needs_p_correction != plan.needs_p_correction ||
        transcript.plan.needs_wide_correction != plan.needs_wide_correction ||
        transcript.plan.admitted != plan.admitted)
        return false;
    return hidden_coeff_digest_eq(transcript.aggregate_tag, native_hidden_coeff_tag(material, stmt, plan));
}

inline bool accept_native_public_reset_profile(const HiddenCoeffProfile& profile, const HiddenCoeffPlan& plan) {
    auto decision = decide_hidden_coeff_profile(profile);
    if (!decision.admitted)
        return false;
    if (!plan.admitted)
        return false;
    return !plan.needs_wide_correction;
}

}