/*
 * Octra Labs
 * Internal use only
 * December 2025
 */

#pragma once

#include <array>
#include <cstdint>
#include <vector>

#include "../core/types.hpp"
#include "recrypt_arith_proof.hpp"
#include "sha256_hidden_trace.hpp"

namespace pvac {

enum class NativeResetLayerKind : uint8_t {
    NONE = 0,
    DIGEST_ONLY = 1,
    OPEN_WITNESS_LOCAL = 2,
    BRANCH_INVERSE = 3
};

enum class NativeResetLayerTraceKind : uint8_t {
    NONE = 0,
    DIGEST_ONLY = 1,
    OPEN_WITNESS_LOCAL = 2,
    BRANCH_SHA256 = 3,
    FIELD_NATIVE = 4
};

struct NativeResetLayerTraceOpening {
    size_t round = 0;
    size_t branch = 0;
    std::array<uint8_t, 32> branch_digest = {};
    std::array<uint8_t, 32> commit = {};
    bool message_trace = false;
    bool schedule_trace = false;
    bool compression_trace = false;
    bool digest_trace = false;
};

struct NativeResetFieldShareSet {
    std::vector<std::vector<Fp>> old_r;
    std::vector<std::vector<Fp>> new_r;
};

struct NativeResetFieldResidual {
    std::vector<std::vector<Fp>> old_prod;
    std::vector<std::vector<Fp>> new_prod;
};

struct NativeResetFieldOpening {
    size_t round = 0;
    size_t branch = 0;
    NativeResetFieldShareSet self;
    NativeResetFieldShareSet next;
    NativeResetFieldResidual residual;
    std::array<uint8_t, 32> commit = {};
};

struct NativeResetFieldProof {
    NativeResetArithParams params;
    std::vector<Layer> old_layers;
    std::vector<Layer> new_layers;
    std::array<uint8_t, 32> old_layer_digest = {};
    std::array<uint8_t, 32> new_layer_digest = {};
    std::array<uint8_t, 32> challenge = {};
    std::array<uint8_t, 32> response_digest = {};
    std::vector<std::array<uint8_t, 32>> branch_commits;
    std::vector<NativeResetFieldResidual> residuals;
    std::vector<NativeResetFieldOpening> openings;
    size_t slots = 0;
    bool product_relation = false;
    bool hides_witness = false;
    bool no_basis_oracle = false;
    bool native_backend = false;
    bool has_raw_witness = false;
};

struct NativeResetFieldDecision {
    bool admitted = false;
    bool ready = false;
    bool params = false;
    bool transcript = false;
    bool commits = false;
    bool openings = false;
    bool residuals = false;
    bool response = false;
    bool product = false;
    bool secrecy = false;
    bool rejects_raw_witness = false;
    bool rejects_basis_oracle = false;
};

struct NativeResetLayerTraceProof {
    NativeResetLayerTraceKind kind = NativeResetLayerTraceKind::NONE;
    NativeResetArithParams params;
    std::vector<Layer> old_layers;
    std::vector<Layer> new_layers;
    std::vector<Sha256HiddenTraceBranchProof> sha_proofs;
    NativeResetFieldProof field_proof;
    std::array<uint8_t, 32> old_layer_digest = {};
    std::array<uint8_t, 32> new_layer_digest = {};
    std::array<uint8_t, 32> challenge = {};
    std::array<uint8_t, 32> response_digest = {};
    std::vector<std::array<uint8_t, 32>> trace_commits;
    std::vector<NativeResetLayerTraceOpening> openings;
    size_t sha_repetitions = 0;
    size_t sha_soundness_bits = 0;
    size_t sha_target_bits = 0;
    size_t sha_slots = 0;
    bool base_binding_relation = false;
    bool product_binding_relation = false;
    bool message_bound = false;
    bool digest_bound = false;
    bool sha_transition = false;
    bool field_transition = false;
    bool hides_witness = false;
    bool no_basis_oracle = false;
    bool native_backend = false;
    bool has_raw_witness = false;
};

struct NativeResetLayerTraceDecision {
    bool admitted = false;
    bool ready = false;
    bool params = false;
    bool transcript = false;
    bool openings = false;
    bool response = false;
    bool message = false;
    bool digest = false;
    bool base_binding = false;
    bool product_binding = false;
    bool sha = false;
    bool secrecy = false;
    bool rejects_digest_only = false;
    bool rejects_open_witness = false;
    bool rejects_raw_witness = false;
    bool rejects_basis_oracle = false;
};

struct NativeResetLayerWitness {
    uint64_t canon_tag = 0;
    std::vector<Layer> old_layers;
    std::vector<Layer> new_layers;
    std::vector<std::vector<Fp>> old_r;
    std::vector<std::vector<Fp>> new_r;
};

struct NativeResetLayerShareSet {
    std::vector<std::vector<Fp>> old_r;
    std::vector<std::vector<Fp>> new_r;
    std::vector<std::vector<Fp>> old_x;
    std::vector<std::vector<Fp>> new_y;
};

struct NativeResetLayerResidual {
    std::vector<std::vector<Fp>> old_inv;
    std::vector<std::vector<Fp>> new_inv;
};

struct NativeResetLayerOpening {
    size_t round = 0;
    size_t branch = 0;
    NativeResetLayerShareSet self;
    NativeResetLayerShareSet next;
    NativeResetLayerResidual residual;
    std::array<uint8_t, 32> commit = {};
};

struct NativeResetLayerProof {
    NativeResetLayerKind kind = NativeResetLayerKind::NONE;
    NativeResetArithParams params;
    NativeResetLayerTraceProof layer_trace;
    std::array<uint8_t, 32> stmt_digest = {};
    std::array<uint8_t, 32> output_digest = {};
    std::array<uint8_t, 32> old_layer_digest = {};
    std::array<uint8_t, 32> new_layer_digest = {};
    std::array<uint8_t, 32> challenge = {};
    std::array<uint8_t, 32> response_digest = {};
    std::vector<std::array<uint8_t, 32>> branch_commits;
    std::vector<NativeResetLayerResidual> residuals;
    std::vector<NativeResetLayerOpening> openings;
    bool inverse_relation = false;
    bool binding_relation = false;
    bool product_layer_relation = false;
    bool hides_witness = false;
    bool no_basis_oracle = false;
    bool native_backend = false;
    bool has_raw_witness = false;
};

struct NativeResetLayerDecision {
    bool admitted = false;
    bool ready = false;
    bool params = false;
    bool transcript = false;
    bool commits = false;
    bool openings = false;
    bool residuals = false;
    bool response = false;
    bool inverse = false;
    bool binding = false;
    bool product_layers = false;
    bool secrecy = false;
    bool rejects_digest_only = false;
    bool rejects_open_witness = false;
    bool rejects_raw_witness = false;
    bool rejects_basis_oracle = false;
};

}