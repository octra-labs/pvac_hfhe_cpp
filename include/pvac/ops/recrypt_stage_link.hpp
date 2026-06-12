/*
 * octra labs
 * lambda0xe, denis cmix, J.
 */

#pragma once

#include <array>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <vector>

#include "../core/hash.hpp"
#include "recrypt_chosen_privacy.hpp"

namespace pvac {

struct NativeResetStageDecision {
    bool admitted = false;
    bool input = false;
    bool material = false;
    bool chosen = false;
    bool privacy = false;
    bool rejects_visible = false;
    bool rejects_raw = false;
    bool rejects_unbound = false;
    bool rejects_basis_oracle = false;
    bool rejects_query_budget = false;
    bool rejects_wide = false;
};

inline bool native_reset_stage_source_ok(const NativeResetHiddenOutput& source) {
    if (!source.hidden_coeffs || source.visible_beta)
        return false;
    if (source.target_terms == 0 || source.slots == 0)
        return false;
    if (source.target_terms > std::numeric_limits<size_t>::max() / source.slots)
        return false;
    if (source.coeff_tags.size() != source.target_terms * source.slots)
        return false;
    return native_chosen_digest_eq(source.output_digest, native_chosen_output_digest(source));
}

inline std::array<uint8_t, 32> native_reset_stage_row_tag(const NativeResetHiddenOutput& source, size_t term) {
    Sha256 h;
    h.init();
    h.update("pvac.native.reset.stage.row", std::strlen("pvac.native.reset.stage.row"));
    h.update(source.output_digest.data(), source.output_digest.size());
    h.update(source.material_digest.data(), source.material_digest.size());
    h.update(source.statement_digest.data(), source.statement_digest.size());
    sha256_acc_u64(h, source.target_terms);
    sha256_acc_u64(h, source.slots);
    sha256_acc_u64(h, term);
    for (size_t j = 0; j < source.slots; ++j) {
        size_t id = term * source.slots + j;
        h.update(source.coeff_tags[id].data(), source.coeff_tags[id].size());
    }
    std::array<uint8_t, 32> out{};
    h.finish(out.data());
    return out;
}

inline std::vector<std::array<uint8_t, 32>> native_reset_stage_row_tags(const NativeResetHiddenOutput& source) {
    std::vector<std::array<uint8_t, 32>> tags;
    tags.reserve(source.target_terms);
    for (size_t term = 0; term < source.target_terms; ++term) {
        tags.push_back(native_reset_stage_row_tag(source, term));
    }
    return tags;
}

inline NativeResetChosenMaterial make_native_reset_stage_material(const NativeResetHiddenOutput& source, size_t next_target_terms, size_t alpha_bits, size_t row_bits) {
    if (!native_reset_stage_source_ok(source))
        throw std::runtime_error("pvac: native reset stage source rejected");
    auto tags = native_reset_stage_row_tags(source);
    auto coeff = make_hidden_coeff_material(tags, HiddenCoeffBound{source.target_terms, alpha_bits, row_bits});
    return make_native_reset_chosen_material(coeff, next_target_terms, source.slots);
}

inline bool native_reset_stage_material_ok(const NativeResetHiddenOutput& source, const NativeResetChosenMaterial& material) {
    if (!native_reset_stage_source_ok(source))
        return false;
    if (!native_reset_chosen_material_ok(material))
        return false;
    if (material.coeff.bound.terms != source.target_terms)
        return false;
    if (material.slots != source.slots)
        return false;
    auto tags = native_reset_stage_row_tags(source);
    if (material.coeff.row_tags.size() != tags.size())
        return false;
    for (size_t i = 0; i < tags.size(); ++i) {
        if (!native_chosen_digest_eq(material.coeff.row_tags[i], tags[i]))
            return false;
    }
    return true;
}

inline NativeResetStageDecision decide_native_reset_stage_link(const NativeResetChosenPolicy& policy, const NativeResetHiddenOutput& source, const NativeResetChosenMaterial& material, const NativeResetChosenStmt& stmt, const NativeResetHiddenOutput& out, const NativeResetChosenTranscript& transcript) {
    NativeResetStageDecision decision;
    decision.input = native_reset_stage_source_ok(source);
    decision.material = decision.input && native_reset_stage_material_ok(source, material);
    auto chosen = decide_native_reset_chosen_statement(policy, material, stmt, out, transcript);
    decision.chosen = chosen.admitted;
    decision.rejects_visible =
        !source.hidden_coeffs ||
        source.visible_beta ||
        chosen.rejects_visible;
    decision.rejects_raw = chosen.rejects_raw;
    decision.rejects_unbound = chosen.rejects_unbound;
    decision.rejects_basis_oracle = chosen.rejects_basis_oracle;
    decision.rejects_query_budget = chosen.rejects_query_budget;
    decision.rejects_wide = chosen.rejects_wide;
    decision.privacy =
        decision.input &&
        decision.material &&
        chosen.privacy &&
        !decision.rejects_visible &&
        !decision.rejects_raw &&
        !decision.rejects_unbound &&
        !decision.rejects_basis_oracle &&
        !decision.rejects_query_budget &&
        !decision.rejects_wide;
    decision.admitted = decision.privacy && chosen.admitted;
    return decision;
}

}