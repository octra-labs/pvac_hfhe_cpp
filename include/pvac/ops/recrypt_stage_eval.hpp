/*
 * octra labs
 * lambda0xe, denis cmix, J.
 */

#pragma once

#include <stdexcept>
#include <vector>

#include "recrypt_stage_link.hpp"

namespace pvac {

struct NativeResetStageRequest {
    std::vector<Fp> alpha;
    size_t next_terms = 0;
    size_t alpha_bits = 0;
    size_t row_bits = 0;
    size_t query = 0;
};

struct NativeResetStageRecord {
    NativeResetChosenMaterial material;
    NativeResetChosenStmt stmt;
    NativeResetHiddenOutput output;
    NativeResetChosenTranscript transcript;
    NativeResetStageDecision decision;
};

struct NativeResetStageChain {
    NativeResetHiddenOutput source;
    std::vector<NativeResetStageRecord> records;
    NativeResetHiddenOutput output;
};

struct NativeResetStageChainDecision {
    bool admitted = false;
    bool source = false;
    bool non_empty = false;
    bool stages = false;
    bool final_output = false;
    bool privacy = false;
    bool rejects_visible = false;
    bool rejects_raw = false;
    bool rejects_unbound = false;
    bool rejects_basis_oracle = false;
    bool rejects_query_budget = false;
    bool rejects_wide = false;
};

inline bool native_reset_hidden_output_same(const NativeResetHiddenOutput& a, const NativeResetHiddenOutput& b) {
    if (a.target_terms != b.target_terms || a.slots != b.slots)
        return false;
    if (a.hidden_coeffs != b.hidden_coeffs || a.visible_beta != b.visible_beta)
        return false;
    if (!native_chosen_digest_eq(a.material_digest, b.material_digest))
        return false;
    if (!native_chosen_digest_eq(a.statement_digest, b.statement_digest))
        return false;
    if (!native_chosen_digest_eq(a.output_digest, b.output_digest))
        return false;
    if (a.coeff_tags.size() != b.coeff_tags.size())
        return false;
    for (size_t i = 0; i < a.coeff_tags.size(); ++i) {
        if (!native_chosen_digest_eq(a.coeff_tags[i], b.coeff_tags[i]))
            return false;
    }
    return true;
}

inline bool native_reset_stage_request_ok(const NativeResetChosenPolicy& policy, const NativeResetHiddenOutput& source, const NativeResetStageRequest& req) {
    if (!native_reset_stage_source_ok(source))
        return false;
    if (req.alpha.size() != source.target_terms)
        return false;
    if (req.next_terms == 0 || req.alpha_bits == 0 || req.row_bits == 0)
        return false;
    if (req.alpha_bits > 127 || req.row_bits > 127)
        return false;
    return req.query < policy.max_queries;
}

inline NativeResetStageRecord make_native_reset_stage_record(const NativeResetChosenPolicy& policy, const NativeResetHiddenOutput& source, const NativeResetStageRequest& req) {
    if (!native_reset_stage_request_ok(policy, source, req))
        throw std::runtime_error("pvac: native reset stage request rejected");
    NativeResetStageRecord record;
    record.material = make_native_reset_stage_material(source, req.next_terms, req.alpha_bits, req.row_bits);
    record.stmt = make_native_reset_chosen_stmt(req.alpha, record.material.coeff.bound, record.material.target_terms, record.material.slots, req.query);
    record.output = make_native_reset_hidden_output(record.material, record.stmt);
    record.transcript = make_native_reset_chosen_transcript(record.material, record.stmt, record.output);
    record.decision = decide_native_reset_stage_link(policy, source, record.material, record.stmt, record.output, record.transcript);
    if (!record.decision.admitted)
        throw std::runtime_error("pvac: native reset stage record rejected");
    return record;
}

inline NativeResetStageChain eval_native_reset_stage_chain(const NativeResetChosenPolicy& policy, const NativeResetHiddenOutput& source, const std::vector<NativeResetStageRequest>& requests) {
    if (!native_reset_stage_source_ok(source))
        throw std::runtime_error("pvac: native reset stage chain source rejected");
    if (requests.empty())
        throw std::runtime_error("pvac: native reset stage chain empty");
    NativeResetStageChain chain;
    chain.source = source;
    chain.output = source;
    chain.records.reserve(requests.size());
    for (const auto& req : requests) {
        auto record = make_native_reset_stage_record(policy, chain.output, req);
        chain.output = record.output;
        chain.records.push_back(record);
    }
    return chain;
}

inline NativeResetStageChainDecision decide_native_reset_stage_chain(const NativeResetChosenPolicy& policy, const NativeResetStageChain& chain) {
    NativeResetStageChainDecision decision;
    decision.source = native_reset_stage_source_ok(chain.source);
    decision.non_empty = !chain.records.empty();
    decision.rejects_visible = !chain.source.hidden_coeffs || chain.source.visible_beta;
    auto current = chain.source;
    bool stages_ok = decision.source && decision.non_empty;
    for (const auto& record : chain.records) {
        auto stage = decide_native_reset_stage_link(policy, current, record.material, record.stmt, record.output, record.transcript);
        stages_ok = stages_ok && stage.admitted;
        decision.rejects_visible = decision.rejects_visible || stage.rejects_visible;
        decision.rejects_raw = decision.rejects_raw || stage.rejects_raw;
        decision.rejects_unbound = decision.rejects_unbound || stage.rejects_unbound;
        decision.rejects_basis_oracle = decision.rejects_basis_oracle || stage.rejects_basis_oracle;
        decision.rejects_query_budget = decision.rejects_query_budget || stage.rejects_query_budget;
        decision.rejects_wide = decision.rejects_wide || stage.rejects_wide;
        current = record.output;
    }
    decision.stages = stages_ok;
    decision.final_output = decision.stages && native_reset_stage_source_ok(chain.output) && native_reset_hidden_output_same(chain.output, current);
    decision.privacy =
        decision.source &&
        decision.non_empty &&
        decision.stages &&
        decision.final_output &&
        !decision.rejects_visible &&
        !decision.rejects_raw &&
        !decision.rejects_unbound &&
        !decision.rejects_basis_oracle &&
        !decision.rejects_query_budget &&
        !decision.rejects_wide;
    decision.admitted = decision.privacy;
    return decision;
}

inline bool verify_native_reset_stage_chain(const NativeResetChosenPolicy& policy, const NativeResetStageChain& chain) {
    return decide_native_reset_stage_chain(policy, chain).admitted;
}

}