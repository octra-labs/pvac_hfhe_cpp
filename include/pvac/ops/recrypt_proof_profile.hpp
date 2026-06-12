/*
 * octra labs
 * lambda0xe, denis cmix, J.
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <limits>

namespace pvac {

struct NativeResetProofParams {
    size_t rounds = 0;
    size_t branches = 0;
    size_t opened_branches = 0;
    size_t target_bits = 0;
};

enum class NativeResetProofProfileKind : uint8_t {
    NONE = 0,
    FIELD_NATIVE = 1,
    SHA_COMPAT = 2
};

struct NativeResetProofProfile {
    NativeResetProofProfileKind kind = NativeResetProofProfileKind::NONE;
    NativeResetProofParams params;
    size_t soundness_bits = 0;
    size_t branch_commits = 0;
    size_t branch_openings = 0;
    size_t trace_units = 0;
    size_t commit_bytes = 0;
    size_t opening_bytes = 0;
    size_t transcript_bytes = 0;
    size_t total_bytes = 0;
    size_t baseline_bytes = 0;
    size_t ratio_milli = 0;
    bool compact = false;
    bool admitted = false;
};

inline size_t native_reset_profile_div_ceil(size_t a, size_t b) {
    if (b == 0)
        return 0;
    return (a + b - 1) / b;
}

inline size_t native_reset_branch_soundness_milli_bits(size_t branches, size_t opened_branches) {
    if (branches != 3)
        return 0;
    if (opened_branches != 1)
        return 0;
    return 584;
}

inline size_t native_reset_rounds_for_target(size_t target_bits, size_t branches, size_t opened_branches) {
    size_t milli_bits = native_reset_branch_soundness_milli_bits(branches, opened_branches);
    if (milli_bits == 0)
        return 0;
    if (target_bits > std::numeric_limits<size_t>::max() / 1000)
        return 0;
    return native_reset_profile_div_ceil(target_bits * 1000, milli_bits);
}

inline size_t native_reset_proof_soundness_bits(const NativeResetProofParams& params) {
    size_t milli_bits = native_reset_branch_soundness_milli_bits(params.branches, params.opened_branches);
    if (milli_bits == 0)
        return 0;
    if (params.rounds > std::numeric_limits<size_t>::max() / milli_bits)
        return std::numeric_limits<size_t>::max();
    return (params.rounds * milli_bits) / 1000;
}

inline NativeResetProofParams make_native_reset_proof_params(size_t target_bits = 128, size_t branches = 3, size_t opened_branches = 1) {
    NativeResetProofParams params;
    params.target_bits = target_bits;
    params.branches = branches;
    params.opened_branches = opened_branches;
    params.rounds = native_reset_rounds_for_target(target_bits, branches, opened_branches);
    return params;
}

inline NativeResetProofParams make_native_reset_sha_compat_proof_params(size_t target_bits = 128) {
    return make_native_reset_proof_params(target_bits, 3, 1);
}

inline size_t native_reset_proof_branch_commits(const NativeResetProofParams& params) {
    if (params.branches == 0)
        return 0;
    if (params.rounds > std::numeric_limits<size_t>::max() / params.branches)
        return 0;
    return params.rounds * params.branches;
}

inline size_t native_reset_proof_branch_openings(const NativeResetProofParams& params) {
    if (params.opened_branches == 0)
        return 0;
    if (params.rounds > std::numeric_limits<size_t>::max() / params.opened_branches)
        return 0;
    return params.rounds * params.opened_branches;
}

inline size_t native_reset_profile_bytes(size_t units) {
    if (units > std::numeric_limits<size_t>::max() / 32)
        return std::numeric_limits<size_t>::max();
    auto bytes = units * 32;
    if (bytes > std::numeric_limits<size_t>::max() - 128)
        return std::numeric_limits<size_t>::max();
    return bytes + 128;
}

inline size_t native_reset_profile_add(size_t a, size_t b) {
    if (a == std::numeric_limits<size_t>::max() || b == std::numeric_limits<size_t>::max())
        return std::numeric_limits<size_t>::max();
    if (a > std::numeric_limits<size_t>::max() - b)
        return std::numeric_limits<size_t>::max();
    return a + b;
}

inline NativeResetProofProfile plan_native_reset_proof_profile(NativeResetProofProfileKind kind, size_t target_bits = 128) {
    NativeResetProofProfile profile;
    profile.kind = kind;
    if (kind == NativeResetProofProfileKind::FIELD_NATIVE) {
        profile.params = make_native_reset_proof_params(target_bits);
    } else if (kind == NativeResetProofProfileKind::SHA_COMPAT) {
        profile.params = make_native_reset_sha_compat_proof_params(target_bits);
    } else {
        return profile;
    }
    profile.soundness_bits = native_reset_proof_soundness_bits(profile.params);
    profile.branch_commits = native_reset_proof_branch_commits(profile.params);
    profile.branch_openings = native_reset_proof_branch_openings(profile.params);
    profile.trace_units = profile.branch_commits + profile.branch_openings;
    profile.commit_bytes = native_reset_profile_bytes(profile.branch_commits);
    profile.opening_bytes = native_reset_profile_bytes(profile.branch_openings);
    profile.transcript_bytes = native_reset_profile_bytes(profile.trace_units);
    profile.total_bytes = native_reset_profile_add(native_reset_profile_add(profile.commit_bytes, profile.opening_bytes), profile.transcript_bytes);
    auto sha_params = make_native_reset_sha_compat_proof_params(target_bits);
    auto sha_units = native_reset_proof_branch_commits(sha_params) + native_reset_proof_branch_openings(sha_params);
    auto baseline_unit_bytes = native_reset_profile_bytes(sha_units);
    profile.baseline_bytes = native_reset_profile_add(native_reset_profile_add(baseline_unit_bytes, baseline_unit_bytes), baseline_unit_bytes);
    profile.ratio_milli = profile.baseline_bytes == 0 ? 0 : (profile.total_bytes * 1000) / profile.baseline_bytes;
    profile.compact =
        kind == NativeResetProofProfileKind::FIELD_NATIVE &&
        profile.params.rounds < sha_params.rounds &&
        profile.total_bytes < profile.baseline_bytes;
    profile.admitted =
        profile.params.target_bits >= 128 &&
        profile.params.branches == 3 &&
        profile.params.opened_branches == 1 &&
        profile.soundness_bits >= profile.params.target_bits;
    return profile;
}

inline bool native_reset_proof_params_ok(const NativeResetProofParams& params) {
    if (params.target_bits < 128)
        return false;
    if (params.branches != 3)
        return false;
    if (params.opened_branches != 1)
        return false;
    return native_reset_proof_soundness_bits(params) >= params.target_bits;
}

}