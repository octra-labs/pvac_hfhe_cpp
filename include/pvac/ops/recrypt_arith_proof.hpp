/*
 * Octra Labs
 * Internal use only
 * December 2025
 */

#pragma once

#include <array>
#include <cstdint>
#include <vector>

#include "../core/field.hpp"

namespace pvac {

enum class NativeResetArithKind : uint8_t {
    NONE = 0,
    DIGEST_ONLY = 1,
    OPEN_WITNESS_LOCAL = 2,
    BRANCH_PRODUCT = 3
};

struct NativeResetArithParams {
    size_t rounds = 0;
    size_t branches = 0;
    size_t opened_branches = 0;
    size_t target_bits = 0;
};

struct NativeResetArithShareSet {
    std::vector<std::vector<Fp>> old_x;
    std::vector<std::vector<Fp>> new_y;
    std::vector<std::vector<Fp>> bias;
    std::vector<std::vector<std::vector<Fp>>> mix;
};

struct NativeResetArithResidual {
    std::vector<std::vector<Fp>> old_x;
    std::vector<Fp> c;
    std::vector<std::vector<Fp>> beta;
};

struct NativeResetArithOpening {
    size_t round = 0;
    size_t branch = 0;
    NativeResetArithShareSet self;
    NativeResetArithShareSet next;
    NativeResetArithResidual residual;
    std::array<uint8_t, 32> commit = {};
};

struct NativeResetArithProof {
    NativeResetArithKind kind = NativeResetArithKind::NONE;
    NativeResetArithParams params;
    std::array<uint8_t, 32> stmt_digest = {};
    std::array<uint8_t, 32> output_digest = {};
    std::array<uint8_t, 32> relation_digest = {};
    std::array<uint8_t, 32> challenge = {};
    std::array<uint8_t, 32> response_digest = {};
    std::vector<std::array<uint8_t, 32>> branch_commits;
    std::vector<NativeResetArithResidual> residuals;
    std::vector<NativeResetArithOpening> openings;
    bool product_relation = false;
    bool reset_relation = false;
    bool hides_witness = false;
    bool no_basis_oracle = false;
    bool native_backend = false;
    bool has_raw_witness = false;
};

struct NativeResetArithDecision {
    bool admitted = false;
    bool ready = false;
    bool params = false;
    bool transcript = false;
    bool commits = false;
    bool openings = false;
    bool residuals = false;
    bool response = false;
    bool product = false;
    bool reset = false;
    bool secrecy = false;
    bool rejects_digest_only = false;
    bool rejects_open_witness = false;
    bool rejects_raw_witness = false;
    bool rejects_basis_oracle = false;
};

}