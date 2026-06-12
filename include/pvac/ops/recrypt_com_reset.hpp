/*
 * Octra Labs
 * Internal use only
 * December 2025
 */

#pragma once

#include "recrypt_com.hpp"
#include "recrypt_native_cert.hpp"

namespace pvac {

struct ComResetProof {
    std::array<uint8_t, 32> source_digest = {};
    std::array<uint8_t, 32> output_digest = {};
    std::array<uint8_t, 32> expr_tag = {};
    std::array<uint8_t, 32> stmt_digest = {};
    std::array<uint8_t, 32> reset_digest = {};
    std::array<uint8_t, 32> spec_digest = {};
    std::array<uint8_t, 32> cert_digest = {};
    std::array<uint8_t, 32> payload_digest = {};
    std::array<uint8_t, 32> proof_digest = {};
    bool native = false;
    bool basis_closed = false;
    bool relation = false;
    bool bound = false;
};

struct ComResetDecision {
    bool admitted = false;
    bool source = false;
    bool output = false;
    bool expr = false;
    bool proof = false;
    bool native = false;
    bool basis_closed = false;
    bool relation = false;
    bool bound = false;
    bool rejects_unbound = false;
    bool rejects_basis_open = false;
    bool rejects_nonclosed = false;
};

inline std::array<uint8_t, 32> com_reset_spec_digest(const NativeResetPublicSpec& spec) {
    Sha256 h;
    h.init();
    native_hash_domain(h, "pvac.native.com.reset.spec");
    sha256_acc_u64(h, static_cast<uint8_t>(spec.bind));
    sha256_acc_u64(h, spec.stmt_bound ? 1 : 0);
    sha256_acc_u64(h, spec.output_bound ? 1 : 0);
    sha256_acc_u64(h, spec.material_bound ? 1 : 0);
    sha256_acc_u64(h, spec.relation_bound ? 1 : 0);
    sha256_acc_u64(h, spec.no_basis_oracle ? 1 : 0);
    sha256_acc_u64(h, spec.native_backend ? 1 : 0);
    std::array<uint8_t, 32> out{};
    h.finish(out.data());
    return out;
}

inline std::array<uint8_t, 32> com_reset_cert_digest(const NativeResetCert& cert) {
    Sha256 h;
    h.init();
    native_hash_domain(h, "pvac.native.com.reset.cert");
    sha256_acc_u64(h, static_cast<uint8_t>(cert.kind));
    h.update(cert.stmt_digest.data(), cert.stmt_digest.size());
    h.update(cert.rows_digest.data(), cert.rows_digest.size());
    h.update(cert.output_digest.data(), cert.output_digest.size());
    h.update(cert.relation_digest.data(), cert.relation_digest.size());
    native_hash_plan(h, cert.plan);
    native_hash_check(h, cert.check);
    std::array<uint8_t, 32> out{};
    h.finish(out.data());
    return out;
}

inline std::array<uint8_t, 32> com_reset_payload_digest(const NativeResetProofPayload& payload) {
    Sha256 h;
    h.init();
    native_hash_domain(h, "pvac.native.com.reset.payload");
    native_hash_proof_params(h, payload.params);
    native_hash_limb_plan(h, payload.limb);
    native_hash_proof_circuit(h, payload.circuit);
    auto trace_digest = native_reset_proof_trace_digest(payload);
    auto arith_digest = native_reset_arith_digest(payload.arith);
    auto layer_digest = native_reset_layer_digest(payload.layer);
    h.update(trace_digest.data(), trace_digest.size());
    h.update(arith_digest.data(), arith_digest.size());
    h.update(layer_digest.data(), layer_digest.size());
    h.update(payload.challenge.data(), payload.challenge.size());
    h.update(payload.response_digest.data(), payload.response_digest.size());
    sha256_acc_u64(h, payload.has_mul_trace ? 1 : 0);
    sha256_acc_u64(h, payload.has_layer_trace ? 1 : 0);
    sha256_acc_u64(h, payload.has_inverse_trace ? 1 : 0);
    std::array<uint8_t, 32> out{};
    h.finish(out.data());
    return out;
}

inline std::array<uint8_t, 32> com_reset_source_tag(const NativeResetStmt& stmt, const NativeResetCert& cert, const NativeResetPublicSpec& spec) {
    Sha256 h;
    h.init();
    native_hash_domain(h, "pvac.native.com.reset.source.tag");
    auto stmt_digest = native_reset_stmt_digest(stmt);
    auto spec_digest = com_reset_spec_digest(spec);
    h.update(stmt_digest.data(), stmt_digest.size());
    h.update(cert.stmt_digest.data(), cert.stmt_digest.size());
    h.update(cert.relation_digest.data(), cert.relation_digest.size());
    h.update(spec_digest.data(), spec_digest.size());
    std::array<uint8_t, 32> out{};
    h.finish(out.data());
    return out;
}

inline std::array<uint8_t, 32> com_reset_output_tag(const NativeResetOutput& out, const NativeResetCert& cert, const NativeResetPublicSpec& spec) {
    Sha256 h;
    h.init();
    native_hash_domain(h, "pvac.native.com.reset.output.tag");
    auto output_digest = native_reset_output_digest(out);
    auto spec_digest = com_reset_spec_digest(spec);
    h.update(output_digest.data(), output_digest.size());
    h.update(cert.output_digest.data(), cert.output_digest.size());
    h.update(cert.relation_digest.data(), cert.relation_digest.size());
    h.update(spec_digest.data(), spec_digest.size());
    std::array<uint8_t, 32> ret{};
    h.finish(ret.data());
    return ret;
}

inline std::array<uint8_t, 32> com_reset_source_digest(const NativeResetStmt& stmt, const NativeResetCert& cert, const NativeResetPublicSpec& spec) {
    Sha256 h;
    h.init();
    native_hash_domain(h, "pvac.native.com.reset.source.cell");
    auto tag = com_reset_source_tag(stmt, cert, spec);
    auto stmt_digest = native_reset_stmt_digest(stmt);
    auto spec_digest = com_reset_spec_digest(spec);
    auto cert_digest = com_reset_cert_digest(cert);
    h.update(tag.data(), tag.size());
    h.update(stmt_digest.data(), stmt_digest.size());
    h.update(spec_digest.data(), spec_digest.size());
    h.update(cert_digest.data(), cert_digest.size());
    std::array<uint8_t, 32> out{};
    h.finish(out.data());
    return out;
}

inline std::array<uint8_t, 32> com_reset_output_digest(const NativeResetOutput& out, const NativeResetCert& cert, const NativeResetPublicSpec& spec) {
    Sha256 h;
    h.init();
    native_hash_domain(h, "pvac.native.com.reset.output.cell");
    auto tag = com_reset_output_tag(out, cert, spec);
    auto output_digest = native_reset_output_digest(out);
    auto spec_digest = com_reset_spec_digest(spec);
    auto cert_digest = com_reset_cert_digest(cert);
    h.update(tag.data(), tag.size());
    h.update(output_digest.data(), output_digest.size());
    h.update(spec_digest.data(), spec_digest.size());
    h.update(cert_digest.data(), cert_digest.size());
    std::array<uint8_t, 32> ret{};
    h.finish(ret.data());
    return ret;
}

inline ComCell make_com_reset_source(const NativeResetStmt& stmt, const NativeResetCert& cert, const NativeResetPublicSpec& spec) {
    ComCell cell;
    cell.kind = ComKind::CELL;
    cell.op = ComOp::SOURCE;
    cell.tag = com_reset_source_tag(stmt, cert, spec);
    cell.digest = com_reset_source_digest(stmt, cert, spec);
    cell.bound = true;
    cell.hiding = true;
    cell.native = true;
    cell.basis_closed = true;
    cell.prebound = true;
    cell.composable = false;
    return cell;
}

inline ComCell make_com_reset_output(const NativeResetOutput& out, const NativeResetCert& cert, const NativeResetPublicSpec& spec) {
    ComCell cell;
    cell.kind = ComKind::CELL;
    cell.op = ComOp::RESET;
    cell.tag = com_reset_output_tag(out, cert, spec);
    cell.digest = com_reset_output_digest(out, cert, spec);
    cell.bound = true;
    cell.hiding = true;
    cell.native = true;
    cell.basis_closed = true;
    cell.prebound = true;
    cell.composable = false;
    return cell;
}

inline std::array<uint8_t, 32> com_reset_proof_digest(const ComResetProof& proof) {
    Sha256 h;
    h.init();
    native_hash_domain(h, "pvac.native.com.reset.proof");
    h.update(proof.source_digest.data(), proof.source_digest.size());
    h.update(proof.output_digest.data(), proof.output_digest.size());
    h.update(proof.expr_tag.data(), proof.expr_tag.size());
    h.update(proof.stmt_digest.data(), proof.stmt_digest.size());
    h.update(proof.reset_digest.data(), proof.reset_digest.size());
    h.update(proof.spec_digest.data(), proof.spec_digest.size());
    h.update(proof.cert_digest.data(), proof.cert_digest.size());
    h.update(proof.payload_digest.data(), proof.payload_digest.size());
    sha256_acc_u64(h, proof.native ? 1 : 0);
    sha256_acc_u64(h, proof.basis_closed ? 1 : 0);
    sha256_acc_u64(h, proof.relation ? 1 : 0);
    sha256_acc_u64(h, proof.bound ? 1 : 0);
    std::array<uint8_t, 32> out{};
    h.finish(out.data());
    return out;
}

inline ComResetProof make_com_reset_proof(const ComCell& source, const ComCell& output, const NativeResetStmt& stmt, const NativeResetOutput& out, const NativeResetCert& cert, const NativeResetPublicSpec& spec, const NativeResetProofPayload& payload) {
    auto native = decide_native_reset_proof_payload(stmt, out, cert, spec, payload);
    ComResetProof proof;
    proof.source_digest = source.digest;
    proof.output_digest = output.digest;
    proof.expr_tag = com_expr_digest(ComOp::RESET, source.digest, output.digest, fp_from_u64(0));
    proof.stmt_digest = native_reset_stmt_digest(stmt);
    proof.reset_digest = native_reset_output_digest(out);
    proof.spec_digest = com_reset_spec_digest(spec);
    proof.cert_digest = com_reset_cert_digest(cert);
    proof.payload_digest = com_reset_payload_digest(payload);
    proof.native = native.admitted;
    proof.basis_closed = source.basis_closed && output.basis_closed && spec.no_basis_oracle;
    proof.relation = native.admitted;
    proof.bound = source.prebound && output.prebound && spec.stmt_bound && spec.output_bound && spec.relation_bound && spec.material_bound;
    proof.proof_digest = com_reset_proof_digest(proof);
    return proof;
}

inline ComCell make_com_reset_expr(const ComCell& source, const ComCell& output, const ComResetProof& proof) {
    auto cell = make_com_expr(ComOp::RESET, source, output, fp_from_u64(0));
    cell.tag = proof.expr_tag;
    cell.digest = proof.proof_digest;
    cell.composable = proof.relation;
    return cell;
}

inline bool com_reset_cell_eq(const ComCell& a, const ComCell& b) {
    return
        a.kind == b.kind &&
        a.op == b.op &&
        com_digest_eq(a.tag, b.tag) &&
        com_digest_eq(a.digest, b.digest) &&
        a.bound == b.bound &&
        a.hiding == b.hiding &&
        a.native == b.native &&
        a.basis_closed == b.basis_closed &&
        a.prebound == b.prebound;
}

inline bool com_reset_proof_eq(const ComResetProof& a, const ComResetProof& b) {
    return
        com_digest_eq(a.source_digest, b.source_digest) &&
        com_digest_eq(a.output_digest, b.output_digest) &&
        com_digest_eq(a.expr_tag, b.expr_tag) &&
        com_digest_eq(a.stmt_digest, b.stmt_digest) &&
        com_digest_eq(a.reset_digest, b.reset_digest) &&
        com_digest_eq(a.spec_digest, b.spec_digest) &&
        com_digest_eq(a.cert_digest, b.cert_digest) &&
        com_digest_eq(a.payload_digest, b.payload_digest) &&
        com_digest_eq(a.proof_digest, b.proof_digest) &&
        a.native == b.native &&
        a.basis_closed == b.basis_closed &&
        a.relation == b.relation &&
        a.bound == b.bound;
}

inline ComResetDecision decide_com_reset_proof(const ComCell& source, const ComCell& output, const ComCell& expr, const NativeResetStmt& stmt, const NativeResetOutput& out, const NativeResetCert& cert, const NativeResetPublicSpec& spec, const NativeResetProofPayload& payload, const ComResetProof& proof) {
    ComResetDecision decision;
    auto expected_source = make_com_reset_source(stmt, cert, spec);
    auto expected_output = make_com_reset_output(out, cert, spec);
    auto expected_proof = make_com_reset_proof(expected_source, expected_output, stmt, out, cert, spec, payload);
    auto expected_expr = make_com_reset_expr(expected_source, expected_output, expected_proof);
    decision.source = com_reset_cell_eq(source, expected_source);
    decision.output = com_reset_cell_eq(output, expected_output);
    decision.expr =
        expr.kind == ComKind::EXPR &&
        expr.op == ComOp::RESET &&
        com_digest_eq(expr.tag, expected_expr.tag) &&
        com_digest_eq(expr.digest, expected_expr.digest) &&
        expr.bound &&
        expr.hiding &&
        expr.native &&
        expr.basis_closed &&
        expr.prebound &&
        expr.composable;
    decision.proof = com_reset_proof_eq(proof, expected_proof);
    decision.native = proof.native && expected_proof.native;
    decision.basis_closed = proof.basis_closed && source.basis_closed && output.basis_closed && expr.basis_closed;
    decision.relation = proof.relation && expected_proof.relation;
    decision.bound = proof.bound && source.prebound && output.prebound && expr.prebound;
    decision.rejects_unbound = !decision.bound;
    decision.rejects_basis_open = !decision.basis_closed;
    decision.rejects_nonclosed = !expr.composable || !decision.relation;
    decision.admitted =
        decision.source &&
        decision.output &&
        decision.expr &&
        decision.proof &&
        decision.native &&
        decision.basis_closed &&
        decision.relation &&
        decision.bound;
    return decision;
}

}