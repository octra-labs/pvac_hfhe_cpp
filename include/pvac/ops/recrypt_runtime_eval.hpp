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

#include "../core/hash.hpp"
#include "../core/types.hpp"
#include "layer_coeffs.hpp"
#include "recrypt_com.hpp"
#include "recrypt_com_reset.hpp"
#include "recrypt_stage_eval.hpp"

namespace pvac {

enum class NativeRuntimeHiddenKind : uint8_t {
    NONE = 0,
    SOURCE_CIPHER = 1,
    PRODUCT = 2,
    RESET_CHAIN = 3,
    ADD = 4,
    SUB = 5,
    SCALE = 6,
    ADD_CONST = 7
};

enum class NativeRuntimeOpeningKind : uint8_t {
    NONE = 0,
    SEALED_FINAL_CIPHER = 1,
    INTERMEDIATE_CIPHER = 2,
    REUSABLE_CIPHER = 3
};

struct NativeRuntimeHiddenCarrier {
    NativeRuntimeHiddenKind kind = NativeRuntimeHiddenKind::NONE;
    NativeResetHiddenOutput out;
    std::array<uint8_t, 32> source_digest = {};
    std::array<uint8_t, 32> left_digest = {};
    std::array<uint8_t, 32> right_digest = {};
    bool materialized_cipher = false;
    bool hidden_coeffs = false;
    bool no_basis_oracle = false;
    bool native_backend = false;
};

struct NativeRuntimeHiddenResetChain {
    NativeRuntimeHiddenCarrier source;
    NativeResetStageChain chain;
    NativeRuntimeHiddenCarrier output;
};

struct NativeRuntimeHiddenDecision {
    bool admitted = false;
    bool source = false;
    bool product = false;
    bool reset = false;
    bool output = false;
    bool hidden = false;
    bool rejects_materialized_cipher = false;
    bool rejects_visible = false;
    bool rejects_raw = false;
    bool rejects_unbound = false;
    bool rejects_basis_oracle = false;
    bool rejects_query_budget = false;
    bool rejects_wide = false;
};

struct NativeRuntimeOpening {
    NativeRuntimeOpeningKind kind = NativeRuntimeOpeningKind::NONE;
    std::array<uint8_t, 32> hidden_digest = {};
    std::array<uint8_t, 32> cipher_digest = {};
    std::array<uint8_t, 32> delivery_tag = {};
    std::array<uint8_t, 32> opening_digest = {};
    bool materialized_cipher = false;
    bool final_only = false;
    bool one_shot = false;
    bool reusable = false;
    bool intermediate = false;
    bool hidden_bound = false;
    bool cipher_bound = false;
    bool material_bound = false;
    bool no_basis_oracle = false;
    bool native_backend = false;
};

struct NativeRuntimeEqProof {
    std::array<uint8_t, 32> hidden_digest = {};
    std::array<uint8_t, 32> cipher_digest = {};
    std::array<uint8_t, 32> delivery_tag = {};
    std::vector<std::vector<Fp>> beta;
    std::vector<std::array<uint8_t, 32>> coeff_openings;
    ComCell value_source;
    ComCell value_output;
    ComCell value_expr;
    ComResetProof value_proof;
    std::array<uint8_t, 32> proof_digest = {};
    bool one_shot = false;
    bool final_only = false;
    bool hidden_bound = false;
    bool cipher_bound = false;
    bool coeff_bound = false;
    bool value_commit = false;
    bool no_basis_oracle = false;
    bool native_backend = false;
    bool has_raw_rows = false;
    bool reusable = false;
};

struct NativeRuntimeResetHandoff {
    NativeRuntimeHiddenCarrier source;
    NativeRuntimeHiddenCarrier output;
    NativeRuntimeEqProof input_eq;
    NativeRuntimeEqProof output_eq;
    ComResetProof reset_proof;
    std::array<uint8_t, 32> handoff_digest = {};
    bool one_shot = false;
    bool native = false;
    bool basis_closed = false;
};

struct NativeRuntimeEqDecision {
    bool admitted = false;
    bool source = false;
    bool cipher = false;
    bool shape = false;
    bool coeffs = false;
    bool openings = false;
    bool digest = false;
    bool value_commit = false;
    bool privacy = false;
    bool rejects_raw = false;
    bool rejects_reusable = false;
    bool rejects_unbound = false;
    bool rejects_basis_oracle = false;
    bool rejects_hidden_mismatch = false;
    bool rejects_cipher_mismatch = false;
};

struct NativeRuntimeResetHandoffDecision {
    bool admitted = false;
    bool source = false;
    bool input = false;
    bool stmt = false;
    bool reset = false;
    bool output = false;
    bool output_eq = false;
    bool digest = false;
    bool one_shot = false;
    bool native = false;
    bool basis_closed = false;
    bool rejects_input_mismatch = false;
    bool rejects_output_mismatch = false;
    bool rejects_unbound = false;
    bool rejects_basis_open = false;
};

struct NativeRuntimeClaim {
    bool admitted = false;
    bool eq = false;
    bool perf = false;
    bool value_commit = false;
    bool basis_closed = false;
    bool reusable = false;
    bool rejects_reusable_gate = false;
    bool production = false;
};

struct NativeRuntimeOpeningDecision {
    bool admitted = false;
    bool source = false;
    bool cipher = false;
    bool opening = false;
    bool finality = false;
    bool privacy = false;
    bool rejects_reusable = false;
    bool rejects_intermediate = false;
    bool rejects_unbound = false;
    bool rejects_basis_oracle = false;
    bool rejects_hidden_mismatch = false;
    bool rejects_cipher_mismatch = false;
};

struct NativeRuntimePerfProfile {
    size_t stages = 0;
    size_t tags = 0;
    size_t openings = 0;
    size_t digest_bytes = 0;
    size_t coeff_bytes = 0;
    size_t total_bytes = 0;
    bool compact = false;
    bool admitted = false;
};

struct NativeRuntimeReusableBudget {
    NativeResetProofProfileKind proof = NativeResetProofProfileKind::FIELD_NATIVE;
    size_t target_bits = 128;
    size_t max_trace_units = 1024;
    size_t max_output_tags = 1 << 16;
    size_t max_proof_bytes = 1 << 20;
};

struct NativeRuntimeReusableDecision {
    NativeResetProofProfile profile;
    std::array<uint8_t, 32> output_digest = {};
    bool admitted = false;
    bool source = false;
    bool proof = false;
    bool compact = false;
    bool output = false;
    bool basis_closed = false;
    bool rejects_sha_compat = false;
    bool rejects_noncompact = false;
    bool rejects_underbudget = false;
    bool rejects_output_wide = false;
    bool rejects_proof_wide = false;
    bool rejects_basis_oracle = false;
    bool rejects_materialized = false;
};

inline void native_runtime_acc_size(Sha256& h, size_t x) {
    sha256_acc_u64(h, x);
}

inline void native_runtime_acc_fp(Sha256& h, const Fp& x) {
    sha256_acc_u64(h, x.lo);
    sha256_acc_u64(h, x.hi & MASK63);
}

inline bool native_runtime_eq_fp(const Fp& a, const Fp& b) {
    uint64_t diff = (a.lo ^ b.lo) | ((a.hi ^ b.hi) & MASK63);
    return diff == 0;
}

inline bool native_runtime_vec_eq(const std::vector<Fp>& a, const std::vector<Fp>& b) {
    if (a.size() != b.size())
        return false;
    for (size_t i = 0; i < a.size(); ++i) {
        if (!native_runtime_eq_fp(a[i], b[i]))
            return false;
    }
    return true;
}

inline bool native_runtime_matrix_eq(const std::vector<std::vector<Fp>>& a, const std::vector<std::vector<Fp>>& b) {
    if (a.size() != b.size())
        return false;
    for (size_t i = 0; i < a.size(); ++i) {
        if (!native_runtime_vec_eq(a[i], b[i]))
            return false;
    }
    return true;
}

inline std::vector<Fp> native_runtime_c0(const Cipher& cipher) {
    return cipher.c0.empty() ? field::Op::zeros(cipher.slots) : cipher.c0;
}

inline bool native_runtime_zero_row(const std::vector<Fp>& row) {
    for (const auto& x : row) {
        if (!native_runtime_eq_fp(x, Fp{0, 0}))
            return false;
    }
    return true;
}

inline void native_runtime_acc_bitvec(Sha256& h, const BitVec& v) {
    sha256_acc_u64(h, v.nbits);
    sha256_acc_u64(h, v.w.size());
    for (auto x : v.w) {
        sha256_acc_u64(h, x);
    }
}

inline std::array<uint8_t, 32> native_runtime_pubkey_digest(const PubKey& pk) {
    if (!is_valid_pubkey_shape(pk))
        throw std::runtime_error("pvac: native runtime pubkey rejected");
    Sha256 h;
    h.init();
    h.update("pvac.native.runtime.pubkey", std::strlen("pvac.native.runtime.pubkey"));
    sha256_acc_u64(h, pk.prm.B);
    sha256_acc_u64(h, pk.prm.m_bits);
    sha256_acc_u64(h, pk.prm.n_bits);
    sha256_acc_u64(h, pk.prm.h_col_wt);
    sha256_acc_u64(h, pk.prm.x_col_wt);
    sha256_acc_u64(h, pk.prm.err_wt);
    sha256_acc_u64(h, pk.prm.edge_budget);
    sha256_acc_u64(h, pk.prm.lpn_n);
    sha256_acc_u64(h, pk.prm.lpn_t);
    sha256_acc_u64(h, pk.prm.lpn_tau_num);
    sha256_acc_u64(h, pk.prm.lpn_tau_den);
    sha256_acc_u64(h, pk.prm.recrypt_rounds);
    sha256_acc_u64(h, pk.canon_tag);
    h.update(pk.H_digest.data(), pk.H_digest.size());
    native_runtime_acc_fp(h, pk.omega_B);
    sha256_acc_u64(h, pk.powg_B.size());
    for (const auto& x : pk.powg_B) {
        native_runtime_acc_fp(h, x);
    }
    sha256_acc_u64(h, pk.ubk.perm.size());
    for (auto x : pk.ubk.perm) {
        sha256_acc_u64(h, static_cast<uint64_t>(x));
    }
    sha256_acc_u64(h, pk.ubk.inv.size());
    for (auto x : pk.ubk.inv) {
        sha256_acc_u64(h, static_cast<uint64_t>(x));
    }
    std::array<uint8_t, 32> out{};
    h.finish(out.data());
    return out;
}

inline std::array<uint8_t, 32> native_runtime_seckey_digest(const PubKey& pk, const SecKey& sk) {
    auto key = native_runtime_pubkey_digest(pk);
    Sha256 h;
    h.init();
    h.update("pvac.native.runtime.seckey", std::strlen("pvac.native.runtime.seckey"));
    h.update(key.data(), key.size());
    for (auto x : sk.prf_k) {
        sha256_acc_u64(h, x);
    }
    sha256_acc_u64(h, sk.lpn_s_bits.size());
    for (auto x : sk.lpn_s_bits) {
        sha256_acc_u64(h, x);
    }
    std::array<uint8_t, 32> out{};
    h.finish(out.data());
    return out;
}

inline void native_runtime_acc_layer(Sha256& h, const Layer& layer) {
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

inline std::array<uint8_t, 32> native_runtime_cipher_digest(const PubKey& pk, const Cipher& cipher) {
    if (!is_cipher_compatible_with_pubkey(pk, cipher))
        throw std::runtime_error("pvac: native runtime cipher rejected");
    Sha256 h;
    h.init();
    h.update("pvac.native.runtime.cipher", std::strlen("pvac.native.runtime.cipher"));
    sha256_acc_u64(h, pk.canon_tag);
    sha256_acc_u64(h, cipher.slots);
    sha256_acc_u64(h, cipher.c0.size());
    for (const auto& x : cipher.c0) {
        native_runtime_acc_fp(h, x);
    }
    sha256_acc_u64(h, cipher.L.size());
    for (const auto& layer : cipher.L) {
        native_runtime_acc_layer(h, layer);
    }
    sha256_acc_u64(h, cipher.E.size());
    for (const auto& edge : cipher.E) {
        sha256_acc_u64(h, edge.layer_id);
        sha256_acc_u64(h, edge.idx);
        sha256_acc_u64(h, edge.ch);
        sha256_acc_u64(h, edge.w.size());
        for (const auto& x : edge.w) {
            native_runtime_acc_fp(h, x);
        }
        native_runtime_acc_bitvec(h, edge.s);
    }
    std::array<uint8_t, 32> out{};
    h.finish(out.data());
    return out;
}

inline std::array<uint8_t, 32> native_runtime_digest2(const char* domain, const std::array<uint8_t, 32>& a, const std::array<uint8_t, 32>& b) {
    Sha256 h;
    h.init();
    h.update(domain, std::strlen(domain));
    h.update(a.data(), a.size());
    h.update(b.data(), b.size());
    std::array<uint8_t, 32> out{};
    h.finish(out.data());
    return out;
}

inline std::array<uint8_t, 32> native_runtime_digest3(const char* domain, const std::array<uint8_t, 32>& a, const std::array<uint8_t, 32>& b, const std::array<uint8_t, 32>& c) {
    Sha256 h;
    h.init();
    h.update(domain, std::strlen(domain));
    h.update(a.data(), a.size());
    h.update(b.data(), b.size());
    h.update(c.data(), c.size());
    std::array<uint8_t, 32> out{};
    h.finish(out.data());
    return out;
}

inline std::array<uint8_t, 32> native_runtime_digest2_flag(const char* domain, const std::array<uint8_t, 32>& a, const std::array<uint8_t, 32>& b, bool flag) {
    Sha256 h;
    h.init();
    h.update(domain, std::strlen(domain));
    h.update(a.data(), a.size());
    h.update(b.data(), b.size());
    sha256_acc_u64(h, flag ? 1 : 0);
    std::array<uint8_t, 32> out{};
    h.finish(out.data());
    return out;
}

inline std::array<uint8_t, 32> native_runtime_digest_fp(const char* domain, const std::array<uint8_t, 32>& a, const Fp& x) {
    Sha256 h;
    h.init();
    h.update(domain, std::strlen(domain));
    h.update(a.data(), a.size());
    native_runtime_acc_fp(h, x);
    std::array<uint8_t, 32> out{};
    h.finish(out.data());
    return out;
}

inline std::array<uint8_t, 32> native_runtime_opening_digest(const NativeRuntimeOpening& opening) {
    Sha256 h;
    h.init();
    h.update("pvac.native.runtime.opening", std::strlen("pvac.native.runtime.opening"));
    sha256_acc_u64(h, static_cast<uint8_t>(opening.kind));
    h.update(opening.hidden_digest.data(), opening.hidden_digest.size());
    h.update(opening.cipher_digest.data(), opening.cipher_digest.size());
    h.update(opening.delivery_tag.data(), opening.delivery_tag.size());
    sha256_acc_u64(h, opening.materialized_cipher ? 1 : 0);
    sha256_acc_u64(h, opening.final_only ? 1 : 0);
    sha256_acc_u64(h, opening.one_shot ? 1 : 0);
    sha256_acc_u64(h, opening.reusable ? 1 : 0);
    sha256_acc_u64(h, opening.intermediate ? 1 : 0);
    sha256_acc_u64(h, opening.hidden_bound ? 1 : 0);
    sha256_acc_u64(h, opening.cipher_bound ? 1 : 0);
    sha256_acc_u64(h, opening.material_bound ? 1 : 0);
    sha256_acc_u64(h, opening.no_basis_oracle ? 1 : 0);
    sha256_acc_u64(h, opening.native_backend ? 1 : 0);
    std::array<uint8_t, 32> out{};
    h.finish(out.data());
    return out;
}

inline std::array<uint8_t, 32> native_runtime_eq_coeff_opening(const std::array<uint8_t, 32>& hidden_tag, const Fp& beta, const std::array<uint8_t, 32>& delivery_tag, size_t term, size_t slot) {
    Sha256 h;
    h.init();
    h.update("pvac.native.runtime.eq.coeff", std::strlen("pvac.native.runtime.eq.coeff"));
    h.update(hidden_tag.data(), hidden_tag.size());
    h.update(delivery_tag.data(), delivery_tag.size());
    sha256_acc_u64(h, term);
    sha256_acc_u64(h, slot);
    native_runtime_acc_fp(h, beta);
    std::array<uint8_t, 32> out{};
    h.finish(out.data());
    return out;
}

inline std::array<uint8_t, 32> native_runtime_eq_proof_digest(const NativeRuntimeEqProof& proof) {
    Sha256 h;
    h.init();
    h.update("pvac.native.runtime.eq.proof", std::strlen("pvac.native.runtime.eq.proof"));
    h.update(proof.hidden_digest.data(), proof.hidden_digest.size());
    h.update(proof.cipher_digest.data(), proof.cipher_digest.size());
    h.update(proof.delivery_tag.data(), proof.delivery_tag.size());
    sha256_acc_u64(h, proof.beta.size());
    for (const auto& row : proof.beta) {
        sha256_acc_u64(h, row.size());
        for (const auto& x : row) {
            native_runtime_acc_fp(h, x);
        }
    }
    sha256_acc_u64(h, proof.coeff_openings.size());
    for (const auto& opening : proof.coeff_openings) {
        h.update(opening.data(), opening.size());
    }
    h.update(proof.value_source.tag.data(), proof.value_source.tag.size());
    h.update(proof.value_source.digest.data(), proof.value_source.digest.size());
    h.update(proof.value_output.tag.data(), proof.value_output.tag.size());
    h.update(proof.value_output.digest.data(), proof.value_output.digest.size());
    h.update(proof.value_expr.tag.data(), proof.value_expr.tag.size());
    h.update(proof.value_expr.digest.data(), proof.value_expr.digest.size());
    h.update(proof.value_proof.proof_digest.data(), proof.value_proof.proof_digest.size());
    sha256_acc_u64(h, proof.one_shot ? 1 : 0);
    sha256_acc_u64(h, proof.final_only ? 1 : 0);
    sha256_acc_u64(h, proof.hidden_bound ? 1 : 0);
    sha256_acc_u64(h, proof.cipher_bound ? 1 : 0);
    sha256_acc_u64(h, proof.coeff_bound ? 1 : 0);
    sha256_acc_u64(h, proof.value_commit ? 1 : 0);
    sha256_acc_u64(h, proof.no_basis_oracle ? 1 : 0);
    sha256_acc_u64(h, proof.native_backend ? 1 : 0);
    sha256_acc_u64(h, proof.has_raw_rows ? 1 : 0);
    sha256_acc_u64(h, proof.reusable ? 1 : 0);
    std::array<uint8_t, 32> out{};
    h.finish(out.data());
    return out;
}

inline bool native_runtime_stmt_matches_cipher(const PubKey& pk, const Cipher& input, const NativeResetStmt& stmt, size_t target_terms) {
    if (!is_cipher_compatible_with_pubkey(pk, input))
        return false;
    auto c = input.c0.empty() ? field::Op::zeros(input.slots) : input.c0;
    auto alpha = compute_layer_coeffs(pk, input);
    return
        stmt.target_terms == target_terms &&
        native_runtime_vec_eq(stmt.c, c) &&
        native_runtime_matrix_eq(stmt.alpha, alpha);
}

inline bool native_runtime_output_matches_cipher(const PubKey& pk, const Cipher& output, const NativeResetOutput& out) {
    if (!is_cipher_compatible_with_pubkey(pk, output))
        return false;
    auto c = output.c0.empty() ? field::Op::zeros(output.slots) : output.c0;
    auto beta = compute_layer_coeffs(pk, output);
    return native_runtime_vec_eq(out.c, c) && native_runtime_matrix_eq(out.beta, beta);
}

inline std::array<uint8_t, 32> native_runtime_com_reset_tag(const std::array<uint8_t, 32>& digest, size_t term, size_t slot, const Fp& beta) {
    Sha256 h;
    h.init();
    h.update("pvac.native.runtime.com.reset.coeff", std::strlen("pvac.native.runtime.com.reset.coeff"));
    h.update(digest.data(), digest.size());
    sha256_acc_u64(h, term);
    sha256_acc_u64(h, slot);
    native_runtime_acc_fp(h, beta);
    std::array<uint8_t, 32> out{};
    h.finish(out.data());
    return out;
}

inline NativeResetHiddenOutput make_native_runtime_hidden_output(size_t target_terms, size_t slots, const std::array<uint8_t, 32>& material_digest, const std::array<uint8_t, 32>& statement_digest, std::vector<std::array<uint8_t, 32>> tags) {
    if (target_terms == 0 || slots == 0)
        throw std::runtime_error("pvac: native runtime hidden output shape rejected");
    if (target_terms > std::numeric_limits<size_t>::max() / slots)
        throw std::runtime_error("pvac: native runtime hidden output size rejected");
    if (tags.size() != target_terms * slots)
        throw std::runtime_error("pvac: native runtime hidden output tag shape rejected");
    NativeResetHiddenOutput out;
    out.target_terms = target_terms;
    out.slots = slots;
    out.coeff_tags = std::move(tags);
    out.material_digest = material_digest;
    out.statement_digest = statement_digest;
    out.hidden_coeffs = true;
    out.visible_beta = false;
    out.output_digest = native_chosen_output_digest(out);
    return out;
}

inline std::array<uint8_t, 32> native_runtime_source_tag(const std::array<uint8_t, 32>& digest, size_t term, size_t slot, const Fp& alpha) {
    Sha256 h;
    h.init();
    h.update("pvac.native.runtime.source.coeff", std::strlen("pvac.native.runtime.source.coeff"));
    h.update(digest.data(), digest.size());
    sha256_acc_u64(h, term);
    sha256_acc_u64(h, slot);
    native_runtime_acc_fp(h, alpha);
    std::array<uint8_t, 32> out{};
    h.finish(out.data());
    return out;
}

inline NativeRuntimeHiddenCarrier make_native_runtime_source_carrier(const PubKey& pk, const Cipher& cipher) {
    auto digest = native_runtime_cipher_digest(pk, cipher);
    auto alpha = compute_layer_coeffs(pk, cipher);
    if (alpha.empty())
        throw std::runtime_error("pvac: native runtime source terms rejected");
    std::vector<std::array<uint8_t, 32>> tags;
    tags.reserve(alpha.size() * cipher.slots);
    for (size_t i = 0; i < alpha.size(); ++i) {
        for (size_t j = 0; j < cipher.slots; ++j) {
            tags.push_back(native_runtime_source_tag(digest, i, j, alpha[i][j]));
        }
    }
    NativeRuntimeHiddenCarrier carrier;
    carrier.kind = NativeRuntimeHiddenKind::SOURCE_CIPHER;
    carrier.source_digest = digest;
    carrier.out = make_native_runtime_hidden_output(alpha.size(), cipher.slots, native_runtime_digest2("pvac.native.runtime.source.material", digest, digest), native_runtime_digest2("pvac.native.runtime.source.statement", digest, digest), std::move(tags));
    carrier.hidden_coeffs = true;
    carrier.no_basis_oracle = true;
    carrier.native_backend = true;
    return carrier;
}

inline std::array<uint8_t, 32> native_runtime_product_tag(const NativeResetHiddenOutput& left, const NativeResetHiddenOutput& right, size_t left_term, size_t right_term, size_t slot) {
    Sha256 h;
    h.init();
    h.update("pvac.native.runtime.product.coeff", std::strlen("pvac.native.runtime.product.coeff"));
    h.update(left.output_digest.data(), left.output_digest.size());
    h.update(right.output_digest.data(), right.output_digest.size());
    sha256_acc_u64(h, left_term);
    sha256_acc_u64(h, right_term);
    sha256_acc_u64(h, slot);
    auto left_id = left_term * left.slots + slot;
    auto right_id = right_term * right.slots + slot;
    h.update(left.coeff_tags[left_id].data(), left.coeff_tags[left_id].size());
    h.update(right.coeff_tags[right_id].data(), right.coeff_tags[right_id].size());
    std::array<uint8_t, 32> out{};
    h.finish(out.data());
    return out;
}

inline std::array<uint8_t, 32> native_runtime_zero_tag(const std::array<uint8_t, 32>& digest, size_t term, size_t slot) {
    Sha256 h;
    h.init();
    h.update("pvac.native.runtime.zero.coeff", std::strlen("pvac.native.runtime.zero.coeff"));
    h.update(digest.data(), digest.size());
    sha256_acc_u64(h, term);
    sha256_acc_u64(h, slot);
    std::array<uint8_t, 32> out{};
    h.finish(out.data());
    return out;
}

inline bool native_runtime_carrier_ok(const NativeRuntimeHiddenCarrier& carrier) {
    if (carrier.kind == NativeRuntimeHiddenKind::NONE)
        return false;
    if (carrier.materialized_cipher)
        return false;
    if (!carrier.hidden_coeffs || !carrier.no_basis_oracle || !carrier.native_backend)
        return false;
    return native_reset_stage_source_ok(carrier.out);
}

inline bool native_recrypt_carrier_eq(const NativeRuntimeHiddenCarrier& a, const NativeRuntimeHiddenCarrier& b) {
    return
        a.kind == b.kind &&
        native_chosen_digest_eq(a.source_digest, b.source_digest) &&
        native_chosen_digest_eq(a.left_digest, b.left_digest) &&
        native_chosen_digest_eq(a.right_digest, b.right_digest) &&
        a.materialized_cipher == b.materialized_cipher &&
        a.hidden_coeffs == b.hidden_coeffs &&
        a.no_basis_oracle == b.no_basis_oracle &&
        a.native_backend == b.native_backend &&
        native_reset_hidden_output_same(a.out, b.out);
}

inline NativeRuntimeHiddenCarrier make_native_runtime_com_reset_carrier(const NativeResetOutput& out, const NativeResetCert& cert, const NativeResetPublicSpec& spec) {
    if (out.beta.empty())
        throw std::runtime_error("pvac: native runtime com reset terms rejected");
    auto slots = out.beta[0].size();
    if (slots == 0)
        throw std::runtime_error("pvac: native runtime com reset slots rejected");
    for (const auto& row : out.beta) {
        if (row.size() != slots)
            throw std::runtime_error("pvac: native runtime com reset row shape rejected");
    }
    auto cell = make_com_reset_output(out, cert, spec);
    std::vector<std::array<uint8_t, 32>> tags;
    tags.reserve(out.beta.size() * slots);
    for (size_t i = 0; i < out.beta.size(); ++i) {
        for (size_t j = 0; j < slots; ++j) {
            tags.push_back(native_runtime_com_reset_tag(cell.digest, i, j, out.beta[i][j]));
        }
    }
    NativeRuntimeHiddenCarrier carrier;
    carrier.kind = NativeRuntimeHiddenKind::RESET_CHAIN;
    carrier.source_digest = cell.digest;
    carrier.out = make_native_runtime_hidden_output(out.beta.size(), slots, cell.digest, native_reset_output_digest(out), std::move(tags));
    carrier.hidden_coeffs = true;
    carrier.no_basis_oracle = true;
    carrier.native_backend = true;
    return carrier;
}

inline std::array<uint8_t, 32> native_runtime_linear_tag(const char* domain, const NativeResetHiddenOutput& out, size_t term, size_t slot, bool neg) {
    Sha256 h;
    h.init();
    h.update(domain, std::strlen(domain));
    h.update(out.output_digest.data(), out.output_digest.size());
    sha256_acc_u64(h, term);
    sha256_acc_u64(h, slot);
    sha256_acc_u64(h, neg ? 1 : 0);
    auto id = term * out.slots + slot;
    h.update(out.coeff_tags[id].data(), out.coeff_tags[id].size());
    std::array<uint8_t, 32> tag{};
    h.finish(tag.data());
    return tag;
}

inline std::array<uint8_t, 32> native_runtime_scale_tag(const NativeResetHiddenOutput& out, size_t term, size_t slot, const Fp& scalar) {
    Sha256 h;
    h.init();
    h.update("pvac.native.runtime.scale.coeff", std::strlen("pvac.native.runtime.scale.coeff"));
    h.update(out.output_digest.data(), out.output_digest.size());
    sha256_acc_u64(h, term);
    sha256_acc_u64(h, slot);
    native_runtime_acc_fp(h, scalar);
    auto id = term * out.slots + slot;
    h.update(out.coeff_tags[id].data(), out.coeff_tags[id].size());
    std::array<uint8_t, 32> tag{};
    h.finish(tag.data());
    return tag;
}

inline NativeRuntimeHiddenCarrier make_native_runtime_linear_carrier(const NativeRuntimeHiddenCarrier& left, const NativeRuntimeHiddenCarrier& right, bool subtract) {
    if (!native_runtime_carrier_ok(left) || !native_runtime_carrier_ok(right))
        throw std::runtime_error("pvac: native runtime linear input rejected");
    if (left.out.slots != right.out.slots)
        throw std::runtime_error("pvac: native runtime linear slot mismatch");
    if (left.out.target_terms > std::numeric_limits<size_t>::max() - right.out.target_terms)
        throw std::runtime_error("pvac: native runtime linear term overflow");
    auto target_terms = left.out.target_terms + right.out.target_terms;
    if (target_terms > std::numeric_limits<size_t>::max() / left.out.slots)
        throw std::runtime_error("pvac: native runtime linear tag overflow");
    std::vector<std::array<uint8_t, 32>> tags;
    tags.reserve(target_terms * left.out.slots);
    for (size_t i = 0; i < left.out.target_terms; ++i) {
        for (size_t j = 0; j < left.out.slots; ++j) {
            tags.push_back(native_runtime_linear_tag("pvac.native.runtime.linear.left", left.out, i, j, false));
        }
    }
    for (size_t i = 0; i < right.out.target_terms; ++i) {
        for (size_t j = 0; j < right.out.slots; ++j) {
            tags.push_back(native_runtime_linear_tag("pvac.native.runtime.linear.right", right.out, i, j, subtract));
        }
    }
    NativeRuntimeHiddenCarrier carrier;
    carrier.kind = subtract ? NativeRuntimeHiddenKind::SUB : NativeRuntimeHiddenKind::ADD;
    carrier.left_digest = left.out.output_digest;
    carrier.right_digest = right.out.output_digest;
    auto material = native_runtime_digest2_flag("pvac.native.runtime.linear.material", left.out.output_digest, right.out.output_digest, subtract);
    auto statement = native_runtime_digest2_flag("pvac.native.runtime.linear.statement", left.out.output_digest, right.out.output_digest, subtract);
    carrier.out = make_native_runtime_hidden_output(target_terms, left.out.slots, material, statement, std::move(tags));
    carrier.hidden_coeffs = true;
    carrier.no_basis_oracle = true;
    carrier.native_backend = true;
    return carrier;
}

inline NativeRuntimeHiddenCarrier make_native_runtime_add_carrier(const NativeRuntimeHiddenCarrier& left, const NativeRuntimeHiddenCarrier& right) {
    return make_native_runtime_linear_carrier(left, right, false);
}

inline NativeRuntimeHiddenCarrier make_native_runtime_sub_carrier(const NativeRuntimeHiddenCarrier& left, const NativeRuntimeHiddenCarrier& right) {
    return make_native_runtime_linear_carrier(left, right, true);
}

inline NativeRuntimeHiddenCarrier make_native_runtime_scale_carrier(const NativeRuntimeHiddenCarrier& source, const Fp& scalar) {
    if (!native_runtime_carrier_ok(source))
        throw std::runtime_error("pvac: native runtime scale input rejected");
    std::vector<std::array<uint8_t, 32>> tags;
    tags.reserve(source.out.coeff_tags.size());
    for (size_t i = 0; i < source.out.target_terms; ++i) {
        for (size_t j = 0; j < source.out.slots; ++j) {
            tags.push_back(native_runtime_scale_tag(source.out, i, j, scalar));
        }
    }
    NativeRuntimeHiddenCarrier carrier;
    carrier.kind = NativeRuntimeHiddenKind::SCALE;
    carrier.left_digest = source.out.output_digest;
    auto material = native_runtime_digest_fp("pvac.native.runtime.scale.material", source.out.output_digest, scalar);
    auto statement = native_runtime_digest_fp("pvac.native.runtime.scale.statement", source.out.output_digest, scalar);
    carrier.out = make_native_runtime_hidden_output(source.out.target_terms, source.out.slots, material, statement, std::move(tags));
    carrier.hidden_coeffs = true;
    carrier.no_basis_oracle = true;
    carrier.native_backend = true;
    return carrier;
}

inline NativeRuntimeHiddenCarrier make_native_runtime_add_const_carrier(const NativeRuntimeHiddenCarrier& source, const Fp& constant) {
    if (!native_runtime_carrier_ok(source))
        throw std::runtime_error("pvac: native runtime const input rejected");
    std::vector<std::array<uint8_t, 32>> tags;
    tags.reserve(source.out.coeff_tags.size());
    for (size_t i = 0; i < source.out.target_terms; ++i) {
        for (size_t j = 0; j < source.out.slots; ++j) {
            tags.push_back(native_runtime_scale_tag(source.out, i, j, fp_from_u64(1)));
        }
    }
    NativeRuntimeHiddenCarrier carrier;
    carrier.kind = NativeRuntimeHiddenKind::ADD_CONST;
    carrier.left_digest = source.out.output_digest;
    auto material = native_runtime_digest_fp("pvac.native.runtime.const.material", source.out.output_digest, constant);
    auto statement = native_runtime_digest_fp("pvac.native.runtime.const.statement", source.out.output_digest, constant);
    carrier.out = make_native_runtime_hidden_output(source.out.target_terms, source.out.slots, material, statement, std::move(tags));
    carrier.hidden_coeffs = true;
    carrier.no_basis_oracle = true;
    carrier.native_backend = true;
    return carrier;
}

inline bool native_runtime_product_shape_ok(const Cipher& output, size_t left_terms, size_t right_terms) {
    if (left_terms > std::numeric_limits<size_t>::max() / right_terms)
        return false;
    auto active_terms = left_terms * right_terms;
    if (left_terms > std::numeric_limits<size_t>::max() - right_terms)
        return false;
    auto prefix_terms = left_terms + right_terms;
    if (prefix_terms > std::numeric_limits<size_t>::max() - active_terms)
        return false;
    if (output.L.size() != prefix_terms + active_terms)
        return false;
    for (size_t i = 0; i < active_terms; ++i) {
        auto row = prefix_terms + i;
        auto left_id = i / right_terms;
        auto right_id = i % right_terms;
        const auto& layer = output.L[row];
        if (layer.rule != RRule::PROD)
            return false;
        if (layer.pa != left_id)
            return false;
        if (layer.pb != left_terms + right_id)
            return false;
    }
    return true;
}

inline bool native_runtime_product_coeffs_ok(const std::vector<std::vector<Fp>>& left_alpha, const std::vector<std::vector<Fp>>& right_alpha, const std::vector<Fp>& left_c0, const std::vector<Fp>& right_c0, const std::vector<std::vector<Fp>>& beta, const std::vector<Fp>& out_c0, size_t slots) {
    if (left_c0.size() != slots || right_c0.size() != slots || out_c0.size() != slots)
        return false;
    if (!native_runtime_vec_eq(out_c0, field::Op::mul(left_c0, right_c0)))
        return false;
    auto prefix_terms = left_alpha.size() + right_alpha.size();
    if (left_alpha.size() > std::numeric_limits<size_t>::max() / right_alpha.size())
        return false;
    auto active_terms = left_alpha.size() * right_alpha.size();
    if (beta.size() != prefix_terms + active_terms)
        return false;
    for (size_t i = 0; i < left_alpha.size(); ++i) {
        if (left_alpha[i].size() != slots || beta[i].size() != slots)
            return false;
        for (size_t j = 0; j < slots; ++j) {
            if (!native_runtime_eq_fp(beta[i][j], fp_mul(left_alpha[i][j], right_c0[j])))
                return false;
        }
    }
    for (size_t k = 0; k < right_alpha.size(); ++k) {
        auto row = left_alpha.size() + k;
        if (right_alpha[k].size() != slots || beta[row].size() != slots)
            return false;
        for (size_t j = 0; j < slots; ++j) {
            if (!native_runtime_eq_fp(beta[row][j], fp_mul(right_alpha[k][j], left_c0[j])))
                return false;
        }
    }
    for (size_t i = 0; i < left_alpha.size(); ++i) {
        for (size_t k = 0; k < right_alpha.size(); ++k) {
            auto row = prefix_terms + i * right_alpha.size() + k;
            if (beta[row].size() != slots)
                return false;
            for (size_t j = 0; j < slots; ++j) {
                if (!native_runtime_eq_fp(beta[row][j], fp_mul(left_alpha[i][j], right_alpha[k][j])))
                    return false;
            }
        }
    }
    return true;
}

inline std::array<uint8_t, 32> native_runtime_prefix_tag(const NativeResetHiddenOutput& out, const std::array<uint8_t, 32>& zero_digest, size_t term, size_t slot, const Fp& scalar, const Fp& beta) {
    if (native_runtime_eq_fp(beta, Fp{0, 0}))
        return native_runtime_zero_tag(zero_digest, term, slot);
    return native_runtime_scale_tag(out, term, slot, scalar);
}

inline NativeRuntimeHiddenCarrier make_native_runtime_product_carrier(const PubKey& pk, const NativeRuntimeHiddenCarrier& left, const NativeRuntimeHiddenCarrier& right, const Cipher& left_cipher, const Cipher& right_cipher, const Cipher& output) {
    if (!native_runtime_carrier_ok(left) || !native_runtime_carrier_ok(right))
        throw std::runtime_error("pvac: native runtime product input rejected");
    if (left.out.slots != right.out.slots)
        throw std::runtime_error("pvac: native runtime product slot mismatch");
    if (left_cipher.slots != left.out.slots || right_cipher.slots != right.out.slots || output.slots != left.out.slots)
        throw std::runtime_error("pvac: native runtime product cipher slot mismatch");
    auto left_cipher_digest = native_runtime_cipher_digest(pk, left_cipher);
    auto right_cipher_digest = native_runtime_cipher_digest(pk, right_cipher);
    auto cipher_digest = native_runtime_cipher_digest(pk, output);
    auto left_alpha = compute_layer_coeffs(pk, left_cipher);
    auto right_alpha = compute_layer_coeffs(pk, right_cipher);
    auto beta = compute_layer_coeffs(pk, output);
    if (left_alpha.size() != left.out.target_terms || right_alpha.size() != right.out.target_terms)
        throw std::runtime_error("pvac: native runtime product operand shape rejected");
    if (!native_runtime_product_shape_ok(output, left.out.target_terms, right.out.target_terms))
        throw std::runtime_error("pvac: native runtime product support shape rejected");
    auto left_c0 = native_runtime_c0(left_cipher);
    auto right_c0 = native_runtime_c0(right_cipher);
    auto out_c0 = native_runtime_c0(output);
    if (!native_runtime_product_coeffs_ok(left_alpha, right_alpha, left_c0, right_c0, beta, out_c0, left.out.slots))
        throw std::runtime_error("pvac: native runtime product coeff relation rejected");
    auto prefix_terms = left.out.target_terms + right.out.target_terms;
    std::vector<std::array<uint8_t, 32>> tags;
    tags.reserve(beta.size() * left.out.slots);
    for (size_t i = 0; i < left.out.target_terms; ++i) {
        for (size_t j = 0; j < left.out.slots; ++j) {
            tags.push_back(native_runtime_prefix_tag(left.out, cipher_digest, i, j, right_c0[j], beta[i][j]));
        }
    }
    for (size_t k = 0; k < right.out.target_terms; ++k) {
        auto row = left.out.target_terms + k;
        for (size_t j = 0; j < right.out.slots; ++j) {
            tags.push_back(native_runtime_prefix_tag(right.out, cipher_digest, row, j, left_c0[j], beta[row][j]));
        }
    }
    for (size_t i = 0; i < left.out.target_terms; ++i) {
        for (size_t k = 0; k < right.out.target_terms; ++k) {
            for (size_t j = 0; j < left.out.slots; ++j) {
                tags.push_back(native_runtime_product_tag(left.out, right.out, i, k, j));
            }
        }
    }
    NativeRuntimeHiddenCarrier carrier;
    carrier.kind = NativeRuntimeHiddenKind::PRODUCT;
    carrier.left_digest = left.out.output_digest;
    carrier.right_digest = right.out.output_digest;
    auto operand_digest = native_runtime_digest2("pvac.native.runtime.product.norm.operands", left_cipher_digest, right_cipher_digest);
    auto shape_digest = native_runtime_digest2("pvac.native.runtime.product.norm.shape", operand_digest, cipher_digest);
    auto material = native_runtime_digest3("pvac.native.runtime.product.norm.material", left.out.output_digest, right.out.output_digest, shape_digest);
    auto statement = native_runtime_digest3("pvac.native.runtime.product.norm.statement", left.out.output_digest, right.out.output_digest, shape_digest);
    carrier.out = make_native_runtime_hidden_output(prefix_terms + left.out.target_terms * right.out.target_terms, left.out.slots, material, statement, std::move(tags));
    carrier.hidden_coeffs = true;
    carrier.no_basis_oracle = true;
    carrier.native_backend = true;
    return carrier;
}

inline NativeRuntimeHiddenCarrier make_native_runtime_product_carrier(const PubKey& pk, const NativeRuntimeHiddenCarrier& left, const NativeRuntimeHiddenCarrier& right, const Cipher& output) {
    if (!native_runtime_carrier_ok(left) || !native_runtime_carrier_ok(right))
        throw std::runtime_error("pvac: native runtime product input rejected");
    if (left.out.slots != right.out.slots)
        throw std::runtime_error("pvac: native runtime product slot mismatch");
    auto cipher_digest = native_runtime_cipher_digest(pk, output);
    auto beta = compute_layer_coeffs(pk, output);
    if (output.slots != left.out.slots)
        throw std::runtime_error("pvac: native runtime product output slot mismatch");
    if (!native_runtime_product_shape_ok(output, left.out.target_terms, right.out.target_terms))
        throw std::runtime_error("pvac: native runtime product support shape rejected");
    auto active_terms = left.out.target_terms * right.out.target_terms;
    auto prefix_terms = left.out.target_terms + right.out.target_terms;
    if (beta.size() != prefix_terms + active_terms)
        throw std::runtime_error("pvac: native runtime product beta shape rejected");
    for (size_t i = 0; i < prefix_terms; ++i) {
        if (beta[i].size() != left.out.slots || !native_runtime_zero_row(beta[i]))
            throw std::runtime_error("pvac: native runtime product affine support rejected");
    }
    for (size_t i = prefix_terms; i < beta.size(); ++i) {
        if (beta[i].size() != left.out.slots)
            throw std::runtime_error("pvac: native runtime product active support rejected");
    }
    std::vector<std::array<uint8_t, 32>> tags;
    tags.reserve(beta.size() * left.out.slots);
    for (size_t i = 0; i < prefix_terms; ++i) {
        for (size_t j = 0; j < left.out.slots; ++j) {
            tags.push_back(native_runtime_zero_tag(cipher_digest, i, j));
        }
    }
    for (size_t i = 0; i < left.out.target_terms; ++i) {
        for (size_t k = 0; k < right.out.target_terms; ++k) {
            for (size_t j = 0; j < left.out.slots; ++j) {
                tags.push_back(native_runtime_product_tag(left.out, right.out, i, k, j));
            }
        }
    }
    NativeRuntimeHiddenCarrier carrier;
    carrier.kind = NativeRuntimeHiddenKind::PRODUCT;
    carrier.left_digest = left.out.output_digest;
    carrier.right_digest = right.out.output_digest;
    auto material = native_runtime_digest3("pvac.native.runtime.product.norm.material", left.out.output_digest, right.out.output_digest, cipher_digest);
    auto statement = native_runtime_digest3("pvac.native.runtime.product.norm.statement", left.out.output_digest, right.out.output_digest, cipher_digest);
    carrier.out = make_native_runtime_hidden_output(beta.size(), left.out.slots, material, statement, std::move(tags));
    carrier.hidden_coeffs = true;
    carrier.no_basis_oracle = true;
    carrier.native_backend = true;
    return carrier;
}

inline NativeRuntimeHiddenCarrier make_native_runtime_product_carrier(const NativeRuntimeHiddenCarrier& left, const NativeRuntimeHiddenCarrier& right) {
    if (!native_runtime_carrier_ok(left) || !native_runtime_carrier_ok(right))
        throw std::runtime_error("pvac: native runtime product input rejected");
    if (left.out.slots != right.out.slots)
        throw std::runtime_error("pvac: native runtime product slot mismatch");
    if (left.out.target_terms > std::numeric_limits<size_t>::max() / right.out.target_terms)
        throw std::runtime_error("pvac: native runtime product term overflow");
    auto target_terms = left.out.target_terms * right.out.target_terms;
    if (target_terms > std::numeric_limits<size_t>::max() / left.out.slots)
        throw std::runtime_error("pvac: native runtime product tag overflow");
    std::vector<std::array<uint8_t, 32>> tags;
    tags.reserve(target_terms * left.out.slots);
    for (size_t i = 0; i < left.out.target_terms; ++i) {
        for (size_t k = 0; k < right.out.target_terms; ++k) {
            for (size_t j = 0; j < left.out.slots; ++j) {
                tags.push_back(native_runtime_product_tag(left.out, right.out, i, k, j));
            }
        }
    }
    NativeRuntimeHiddenCarrier carrier;
    carrier.kind = NativeRuntimeHiddenKind::PRODUCT;
    carrier.left_digest = left.out.output_digest;
    carrier.right_digest = right.out.output_digest;
    auto material = native_runtime_digest2("pvac.native.runtime.product.material", left.out.output_digest, right.out.output_digest);
    auto statement = native_runtime_digest2("pvac.native.runtime.product.statement", left.out.output_digest, right.out.output_digest);
    carrier.out = make_native_runtime_hidden_output(target_terms, left.out.slots, material, statement, std::move(tags));
    carrier.hidden_coeffs = true;
    carrier.no_basis_oracle = true;
    carrier.native_backend = true;
    return carrier;
}

inline NativeRuntimeHiddenResetChain eval_native_runtime_hidden_reset_chain(const NativeResetChosenPolicy& policy, const NativeRuntimeHiddenCarrier& source, const std::vector<NativeResetStageRequest>& requests) {
    if (!native_runtime_carrier_ok(source))
        throw std::runtime_error("pvac: native runtime reset source rejected");
    NativeRuntimeHiddenResetChain out;
    out.source = source;
    out.chain = eval_native_reset_stage_chain(policy, source.out, requests);
    out.output.kind = NativeRuntimeHiddenKind::RESET_CHAIN;
    out.output.left_digest = source.out.output_digest;
    out.output.out = out.chain.output;
    out.output.hidden_coeffs = true;
    out.output.no_basis_oracle = true;
    out.output.native_backend = true;
    return out;
}

inline NativeRuntimeHiddenDecision decide_native_runtime_hidden_reset_chain(const NativeResetChosenPolicy& policy, const NativeRuntimeHiddenResetChain& chain) {
    NativeRuntimeHiddenDecision decision;
    decision.source = native_runtime_carrier_ok(chain.source);
    auto stage = decide_native_reset_stage_chain(policy, chain.chain);
    decision.reset = stage.admitted;
    decision.output = native_runtime_carrier_ok(chain.output) && native_reset_hidden_output_same(chain.output.out, chain.chain.output);
    decision.rejects_materialized_cipher = chain.source.materialized_cipher || chain.output.materialized_cipher;
    decision.rejects_visible = stage.rejects_visible || chain.source.out.visible_beta || chain.output.out.visible_beta;
    decision.rejects_raw = stage.rejects_raw;
    decision.rejects_unbound = stage.rejects_unbound;
    decision.rejects_basis_oracle = stage.rejects_basis_oracle || !chain.source.no_basis_oracle || !chain.output.no_basis_oracle;
    decision.rejects_query_budget = stage.rejects_query_budget;
    decision.rejects_wide = stage.rejects_wide;
    decision.hidden =
        decision.source &&
        decision.reset &&
        decision.output &&
        !decision.rejects_materialized_cipher &&
        !decision.rejects_visible &&
        !decision.rejects_raw &&
        !decision.rejects_unbound &&
        !decision.rejects_basis_oracle &&
        !decision.rejects_query_budget &&
        !decision.rejects_wide;
    decision.admitted = decision.hidden;
    return decision;
}

inline bool verify_native_runtime_hidden_reset_chain(const NativeResetChosenPolicy& policy, const NativeRuntimeHiddenResetChain& chain) {
    return decide_native_runtime_hidden_reset_chain(policy, chain).admitted;
}

inline NativeRuntimeOpening make_native_runtime_sealed_opening(const PubKey& pk, const NativeRuntimeHiddenCarrier& source, const Cipher& output, const std::array<uint8_t, 32>& delivery_tag) {
    if (!native_runtime_carrier_ok(source))
        throw std::runtime_error("pvac: native runtime opening source rejected");
    auto cipher_digest = native_runtime_cipher_digest(pk, output);
    NativeRuntimeOpening opening;
    opening.kind = NativeRuntimeOpeningKind::SEALED_FINAL_CIPHER;
    opening.hidden_digest = source.out.output_digest;
    opening.cipher_digest = cipher_digest;
    opening.delivery_tag = delivery_tag;
    opening.materialized_cipher = true;
    opening.final_only = true;
    opening.one_shot = true;
    opening.hidden_bound = true;
    opening.cipher_bound = true;
    opening.material_bound = true;
    opening.no_basis_oracle = true;
    opening.native_backend = true;
    opening.opening_digest = native_runtime_opening_digest(opening);
    return opening;
}

inline NativeRuntimeOpeningDecision decide_native_runtime_sealed_opening(const PubKey& pk, const NativeRuntimeHiddenCarrier& source, const Cipher& output, const NativeRuntimeOpening& opening) {
    NativeRuntimeOpeningDecision decision;
    decision.source = native_runtime_carrier_ok(source);
    std::array<uint8_t, 32> cipher_digest{};
    try {
        cipher_digest = native_runtime_cipher_digest(pk, output);
        decision.cipher = true;
    } catch (...) {
        decision.cipher = false;
    }
    decision.rejects_hidden_mismatch = !native_chosen_digest_eq(opening.hidden_digest, source.out.output_digest);
    decision.rejects_cipher_mismatch = !native_chosen_digest_eq(opening.cipher_digest, cipher_digest);
    decision.rejects_reusable = opening.reusable || opening.kind == NativeRuntimeOpeningKind::REUSABLE_CIPHER;
    decision.rejects_intermediate = opening.intermediate || opening.kind == NativeRuntimeOpeningKind::INTERMEDIATE_CIPHER;
    decision.rejects_unbound =
        !opening.hidden_bound ||
        !opening.cipher_bound ||
        !opening.material_bound ||
        !opening.materialized_cipher ||
        !opening.final_only ||
        !opening.one_shot ||
        opening.kind != NativeRuntimeOpeningKind::SEALED_FINAL_CIPHER ||
        !opening.native_backend;
    decision.rejects_basis_oracle = !opening.no_basis_oracle;
    decision.opening =
        decision.source &&
        decision.cipher &&
        native_chosen_digest_eq(opening.opening_digest, native_runtime_opening_digest(opening)) &&
        !decision.rejects_hidden_mismatch &&
        !decision.rejects_cipher_mismatch;
    decision.finality =
        decision.opening &&
        opening.final_only &&
        opening.one_shot &&
        !decision.rejects_reusable &&
        !decision.rejects_intermediate;
    decision.privacy =
        decision.finality &&
        !decision.rejects_unbound &&
        !decision.rejects_basis_oracle;
    decision.admitted = decision.privacy;
    return decision;
}

inline bool verify_native_runtime_sealed_opening(const PubKey& pk, const NativeRuntimeHiddenCarrier& source, const Cipher& output, const NativeRuntimeOpening& opening) {
    return decide_native_runtime_sealed_opening(pk, source, output, opening).admitted;
}

inline NativeRuntimeEqProof make_native_runtime_eq_proof(const PubKey& pk, const NativeRuntimeHiddenCarrier& source, const Cipher& output, const std::array<uint8_t, 32>& delivery_tag) {
    if (!native_runtime_carrier_ok(source))
        throw std::runtime_error("pvac: native runtime eq source rejected");
    auto cipher_digest = native_runtime_cipher_digest(pk, output);
    auto beta = compute_layer_coeffs(pk, output);
    if (beta.size() != source.out.target_terms)
        throw std::runtime_error("pvac: native runtime eq term shape rejected");
    for (const auto& row : beta) {
        if (row.size() != source.out.slots)
            throw std::runtime_error("pvac: native runtime eq slot shape rejected");
    }
    NativeRuntimeEqProof proof;
    proof.hidden_digest = source.out.output_digest;
    proof.cipher_digest = cipher_digest;
    proof.delivery_tag = delivery_tag;
    proof.beta = beta;
    proof.coeff_openings.reserve(source.out.coeff_tags.size());
    for (size_t i = 0; i < source.out.target_terms; ++i) {
        for (size_t j = 0; j < source.out.slots; ++j) {
            auto id = i * source.out.slots + j;
            proof.coeff_openings.push_back(native_runtime_eq_coeff_opening(source.out.coeff_tags[id], proof.beta[i][j], delivery_tag, i, j));
        }
    }
    proof.one_shot = true;
    proof.final_only = true;
    proof.hidden_bound = true;
    proof.cipher_bound = true;
    proof.coeff_bound = true;
    proof.value_commit = false;
    proof.no_basis_oracle = true;
    proof.native_backend = true;
    proof.proof_digest = native_runtime_eq_proof_digest(proof);
    return proof;
}

inline NativeRuntimeEqProof make_native_runtime_eq_proof(const PubKey& pk, const NativeRuntimeHiddenCarrier& source, const Cipher& output, const std::array<uint8_t, 32>& delivery_tag, const NativeResetStmt& stmt, const NativeResetOutput& reset_out, const NativeResetCert& cert, const NativeResetPublicSpec& spec, const NativeResetProofPayload& payload) {
    auto proof = make_native_runtime_eq_proof(pk, source, output, delivery_tag);
    auto expected_source = make_native_runtime_com_reset_carrier(reset_out, cert, spec);
    auto value_source = make_com_reset_source(stmt, cert, spec);
    auto value_output = make_com_reset_output(reset_out, cert, spec);
    auto value_proof = make_com_reset_proof(value_source, value_output, stmt, reset_out, cert, spec, payload);
    auto value_expr = make_com_reset_expr(value_source, value_output, value_proof);
    auto reset_decision = decide_com_reset_proof(value_source, value_output, value_expr, stmt, reset_out, cert, spec, payload, value_proof);
    proof.value_source = value_source;
    proof.value_output = value_output;
    proof.value_expr = value_expr;
    proof.value_proof = value_proof;
    proof.value_commit =
        reset_decision.admitted &&
        native_runtime_output_matches_cipher(pk, output, reset_out) &&
        native_reset_hidden_output_same(source.out, expected_source.out);
    proof.proof_digest = native_runtime_eq_proof_digest(proof);
    return proof;
}

inline NativeRuntimeEqDecision decide_native_runtime_eq_proof(const PubKey& pk, const NativeRuntimeHiddenCarrier& source, const Cipher& output, const NativeRuntimeEqProof& proof) {
    NativeRuntimeEqDecision decision;
    decision.source = native_runtime_carrier_ok(source);
    std::array<uint8_t, 32> cipher_digest{};
    std::vector<std::vector<Fp>> beta;
    try {
        cipher_digest = native_runtime_cipher_digest(pk, output);
        beta = compute_layer_coeffs(pk, output);
        decision.cipher = true;
    } catch (...) {
        decision.cipher = false;
    }
    decision.rejects_hidden_mismatch = !native_chosen_digest_eq(proof.hidden_digest, source.out.output_digest);
    decision.rejects_cipher_mismatch = !native_chosen_digest_eq(proof.cipher_digest, cipher_digest);
    decision.rejects_raw = proof.has_raw_rows;
    decision.rejects_reusable = proof.reusable;
    decision.rejects_unbound =
        !proof.one_shot ||
        !proof.final_only ||
        !proof.hidden_bound ||
        !proof.cipher_bound ||
        !proof.coeff_bound ||
        !proof.native_backend;
    decision.rejects_basis_oracle = !proof.no_basis_oracle;
    decision.shape =
        decision.source &&
        decision.cipher &&
        proof.beta.size() == source.out.target_terms &&
        beta.size() == proof.beta.size() &&
        proof.coeff_openings.size() == source.out.coeff_tags.size();
    bool coeffs_ok = decision.shape;
    for (size_t i = 0; coeffs_ok && i < proof.beta.size(); ++i) {
        coeffs_ok = proof.beta[i].size() == source.out.slots && beta[i].size() == proof.beta[i].size();
        for (size_t j = 0; coeffs_ok && j < proof.beta[i].size(); ++j) {
            coeffs_ok = native_runtime_eq_fp(proof.beta[i][j], beta[i][j]);
        }
    }
    decision.coeffs = coeffs_ok;
    bool openings_ok = decision.coeffs;
    for (size_t i = 0; openings_ok && i < source.out.target_terms; ++i) {
        for (size_t j = 0; openings_ok && j < source.out.slots; ++j) {
            auto id = i * source.out.slots + j;
            auto expected = native_runtime_eq_coeff_opening(source.out.coeff_tags[id], proof.beta[i][j], proof.delivery_tag, i, j);
            openings_ok = native_chosen_digest_eq(proof.coeff_openings[id], expected);
        }
    }
    decision.openings = openings_ok;
    decision.digest = decision.openings && native_chosen_digest_eq(proof.proof_digest, native_runtime_eq_proof_digest(proof));
    decision.value_commit = false;
    decision.privacy =
        decision.digest &&
        !decision.rejects_hidden_mismatch &&
        !decision.rejects_cipher_mismatch &&
        !decision.rejects_raw &&
        !decision.rejects_reusable &&
        !decision.rejects_unbound &&
        !decision.rejects_basis_oracle;
    decision.admitted = decision.privacy;
    return decision;
}

inline NativeRuntimeEqDecision decide_native_runtime_eq_proof(const PubKey& pk, const NativeRuntimeHiddenCarrier& source, const Cipher& output, const NativeRuntimeEqProof& proof, const NativeResetStmt& stmt, const NativeResetOutput& reset_out, const NativeResetCert& cert, const NativeResetPublicSpec& spec, const NativeResetProofPayload& payload) {
    auto decision = decide_native_runtime_eq_proof(pk, source, output, proof);
    auto expected_source = make_native_runtime_com_reset_carrier(reset_out, cert, spec);
    auto reset_decision = decide_com_reset_proof(proof.value_source, proof.value_output, proof.value_expr, stmt, reset_out, cert, spec, payload, proof.value_proof);
    decision.value_commit =
        decision.digest &&
        proof.value_commit &&
        native_runtime_output_matches_cipher(pk, output, reset_out) &&
        reset_decision.admitted &&
        native_reset_hidden_output_same(source.out, expected_source.out);
    decision.admitted = decision.privacy;
    return decision;
}

inline bool verify_native_runtime_eq_proof(const PubKey& pk, const NativeRuntimeHiddenCarrier& source, const Cipher& output, const NativeRuntimeEqProof& proof) {
    return decide_native_runtime_eq_proof(pk, source, output, proof).admitted;
}

inline std::array<uint8_t, 32> native_runtime_handoff_digest(const NativeRuntimeResetHandoff& handoff) {
    Sha256 h;
    h.init();
    h.update("pvac.native.runtime.handoff", std::strlen("pvac.native.runtime.handoff"));
    h.update(handoff.source.out.output_digest.data(), handoff.source.out.output_digest.size());
    h.update(handoff.output.out.output_digest.data(), handoff.output.out.output_digest.size());
    h.update(handoff.input_eq.proof_digest.data(), handoff.input_eq.proof_digest.size());
    h.update(handoff.output_eq.proof_digest.data(), handoff.output_eq.proof_digest.size());
    h.update(handoff.reset_proof.proof_digest.data(), handoff.reset_proof.proof_digest.size());
    sha256_acc_u64(h, handoff.one_shot ? 1 : 0);
    sha256_acc_u64(h, handoff.native ? 1 : 0);
    sha256_acc_u64(h, handoff.basis_closed ? 1 : 0);
    std::array<uint8_t, 32> out{};
    h.finish(out.data());
    return out;
}

inline NativeRuntimeResetHandoff make_native_runtime_reset_handoff(const PubKey& pk, const NativeRuntimeHiddenCarrier& source, const Cipher& input, const Cipher& output, const std::array<uint8_t, 32>& tag, const NativeResetStmt& stmt, const NativeResetOutput& reset_out, const NativeResetCert& cert, const NativeResetPublicSpec& spec, const NativeResetProofPayload& payload) {
    NativeRuntimeResetHandoff handoff;
    handoff.source = source;
    handoff.input_eq = make_native_runtime_eq_proof(pk, source, input, tag);
    handoff.output = make_native_runtime_com_reset_carrier(reset_out, cert, spec);
    handoff.output_eq = make_native_runtime_eq_proof(pk, handoff.output, output, tag, stmt, reset_out, cert, spec, payload);
    handoff.reset_proof = handoff.output_eq.value_proof;
    handoff.one_shot = true;
    handoff.native = true;
    handoff.basis_closed = true;
    handoff.handoff_digest = native_runtime_handoff_digest(handoff);
    return handoff;
}

inline NativeRuntimeResetHandoffDecision decide_native_runtime_reset_handoff(const PubKey& pk, const NativeRuntimeResetHandoff& handoff, const Cipher& input, const Cipher& output, const NativeResetStmt& stmt, const NativeResetOutput& reset_out, const NativeResetCert& cert, const NativeResetPublicSpec& spec, const NativeResetProofPayload& payload) {
    NativeRuntimeResetHandoffDecision decision;
    auto expected_output = make_native_runtime_com_reset_carrier(reset_out, cert, spec);
    auto input_eq = decide_native_runtime_eq_proof(pk, handoff.source, input, handoff.input_eq);
    auto output_eq = decide_native_runtime_eq_proof(pk, handoff.output, output, handoff.output_eq, stmt, reset_out, cert, spec, payload);
    auto reset_decision = decide_com_reset_proof(handoff.output_eq.value_source, handoff.output_eq.value_output, handoff.output_eq.value_expr, stmt, reset_out, cert, spec, payload, handoff.reset_proof);
    decision.source = native_runtime_carrier_ok(handoff.source);
    decision.input = input_eq.admitted;
    decision.stmt = native_runtime_stmt_matches_cipher(pk, input, stmt, output.L.size()) && native_runtime_output_matches_cipher(pk, output, reset_out);
    decision.reset = reset_decision.admitted;
    decision.output = native_runtime_carrier_ok(handoff.output) && native_reset_hidden_output_same(handoff.output.out, expected_output.out);
    decision.output_eq = output_eq.admitted && output_eq.value_commit;
    decision.digest = native_chosen_digest_eq(handoff.handoff_digest, native_runtime_handoff_digest(handoff));
    decision.one_shot = handoff.one_shot;
    decision.native = handoff.native;
    decision.basis_closed = handoff.basis_closed;
    decision.rejects_input_mismatch = !decision.input || !decision.stmt;
    decision.rejects_output_mismatch = !decision.output || !decision.output_eq;
    decision.rejects_unbound = !decision.one_shot || !decision.native;
    decision.rejects_basis_open = !decision.basis_closed;
    decision.admitted =
        decision.source &&
        decision.input &&
        decision.stmt &&
        decision.reset &&
        decision.output &&
        decision.output_eq &&
        decision.digest &&
        decision.one_shot &&
        decision.native &&
        decision.basis_closed;
    return decision;
}

inline NativeRuntimePerfProfile plan_native_runtime_perf_profile(const NativeRuntimeHiddenResetChain& chain, const NativeRuntimeEqProof& proof, size_t max_bytes = 1 << 20) {
    NativeRuntimePerfProfile profile;
    profile.stages = chain.chain.records.size();
    profile.tags = chain.source.out.coeff_tags.size() + chain.output.out.coeff_tags.size();
    for (const auto& record : chain.chain.records) {
        profile.tags += record.output.coeff_tags.size();
    }
    profile.openings = proof.coeff_openings.size();
    profile.digest_bytes = (profile.tags + profile.openings + profile.stages * 4 + 8) * 32;
    profile.coeff_bytes = profile.openings * 16;
    profile.total_bytes = profile.digest_bytes + profile.coeff_bytes;
    profile.compact = profile.total_bytes <= max_bytes;
    profile.admitted = profile.compact && profile.openings != 0 && profile.stages != 0;
    return profile;
}

inline NativeRuntimePerfProfile plan_native_runtime_perf_profile(const NativeRuntimeResetHandoff& handoff, const NativeRuntimeEqProof& proof, size_t max_bytes = 1 << 20) {
    NativeRuntimePerfProfile profile;
    profile.stages = 1;
    profile.tags = handoff.source.out.coeff_tags.size() + handoff.output.out.coeff_tags.size();
    profile.openings = proof.coeff_openings.size();
    profile.digest_bytes = (profile.tags + profile.openings + 12) * 32;
    profile.coeff_bytes = profile.openings * 16;
    profile.total_bytes = profile.digest_bytes + profile.coeff_bytes;
    profile.compact = profile.total_bytes <= max_bytes;
    profile.admitted =
        profile.compact &&
        profile.openings != 0 &&
        handoff.one_shot &&
        handoff.native &&
        handoff.basis_closed;
    return profile;
}

inline NativeRuntimeClaim decide_native_runtime_claim(const NativeRuntimeEqDecision& eq, const NativeRuntimePerfProfile& perf) {
    NativeRuntimeClaim claim;
    claim.eq = eq.admitted;
    claim.perf = perf.admitted;
    claim.value_commit = eq.value_commit;
    claim.basis_closed =
        !eq.rejects_basis_oracle &&
        !eq.rejects_reusable &&
        !eq.rejects_raw &&
        !eq.rejects_unbound;
    claim.reusable = false;
    claim.rejects_reusable_gate = true;
    claim.production = false;
    claim.admitted = false;
    return claim;
}

inline NativeRuntimeClaim decide_native_runtime_claim(const NativeRuntimeEqDecision& eq, const NativeRuntimePerfProfile& perf, const NativeRuntimeHiddenCarrier& source, const NativeResetReusableDecision& reusable) {
    auto claim = decide_native_runtime_claim(eq, perf);
    claim.reusable =
        native_runtime_carrier_ok(source) &&
        reusable.admitted &&
        native_chosen_digest_eq(reusable.output_digest, source.out.output_digest);
    claim.rejects_reusable_gate = !claim.reusable;
    claim.production =
        claim.eq &&
        claim.perf &&
        claim.value_commit &&
        claim.basis_closed &&
        claim.reusable;
    claim.admitted = claim.production;
    return claim;
}

inline NativeRuntimeReusableDecision decide_native_runtime_reusable(const NativeRuntimeHiddenCarrier& source, const NativeRuntimeReusableBudget& budget = NativeRuntimeReusableBudget{}) {
    NativeRuntimeReusableDecision decision;
    decision.profile = plan_native_reset_proof_profile(budget.proof, budget.target_bits);
    decision.source = native_runtime_carrier_ok(source);
    decision.output_digest = source.out.output_digest;
    decision.rejects_sha_compat = budget.proof != NativeResetProofProfileKind::FIELD_NATIVE;
    decision.rejects_underbudget =
        !decision.profile.admitted ||
        !native_reset_proof_params_ok(decision.profile.params) ||
        decision.profile.soundness_bits < budget.target_bits;
    decision.rejects_noncompact =
        decision.profile.trace_units > budget.max_trace_units;
    decision.rejects_output_wide =
        source.out.coeff_tags.empty() ||
        source.out.coeff_tags.size() > budget.max_output_tags ||
        !source.out.hidden_coeffs ||
        source.out.visible_beta;
    decision.rejects_proof_wide =
        decision.profile.total_bytes == std::numeric_limits<size_t>::max() ||
        decision.profile.total_bytes > budget.max_proof_bytes;
    decision.rejects_basis_oracle =
        !source.no_basis_oracle ||
        !source.hidden_coeffs ||
        !source.native_backend;
    decision.rejects_materialized = source.materialized_cipher;
    decision.proof =
        !decision.rejects_sha_compat &&
        !decision.rejects_underbudget;
    decision.compact =
        decision.proof &&
        !decision.rejects_noncompact &&
        !decision.rejects_proof_wide;
    decision.output =
        decision.source &&
        !decision.rejects_output_wide;
    decision.basis_closed =
        decision.source &&
        !decision.rejects_basis_oracle &&
        !decision.rejects_materialized;
    decision.admitted =
        decision.source &&
        decision.proof &&
        decision.compact &&
        decision.output &&
        decision.basis_closed;
    return decision;
}

inline NativeRuntimeClaim decide_native_runtime_claim(const NativeRuntimeEqDecision& eq, const NativeRuntimePerfProfile& perf, const NativeRuntimeHiddenCarrier& source, const NativeRuntimeReusableDecision& reusable) {
    auto claim = decide_native_runtime_claim(eq, perf);
    claim.reusable =
        native_runtime_carrier_ok(source) &&
        reusable.admitted &&
        native_chosen_digest_eq(reusable.output_digest, source.out.output_digest);
    claim.rejects_reusable_gate = !claim.reusable;
    claim.production =
        claim.eq &&
        claim.perf &&
        claim.value_commit &&
        claim.basis_closed &&
        claim.reusable;
    claim.admitted = claim.production;
    return claim;
}

}