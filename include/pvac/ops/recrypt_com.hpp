/*
 * Octra Labs
 * Internal use only
 * December 2025
 */

#pragma once

#include <array>
#include <cstring>

#include "../core/hash.hpp"
#include "../core/types.hpp"

namespace pvac {

enum class ComKind : uint8_t {
    NONE = 0,
    CELL = 1,
    EXPR = 2
};

enum class ComOp : uint8_t {
    NONE = 0,
    SOURCE = 1,
    ADD = 2,
    SUB = 3,
    SCALE = 4,
    ADD_CONST = 5,
    PRODUCT = 6,
    RESET = 7
};

struct ComOpen {
    Fp value;
    std::array<uint8_t, 32> blind = {};
};

struct ComCell {
    ComKind kind = ComKind::NONE;
    ComOp op = ComOp::NONE;
    std::array<uint8_t, 32> tag = {};
    std::array<uint8_t, 32> digest = {};
    bool bound = false;
    bool hiding = false;
    bool native = false;
    bool basis_closed = false;
    bool prebound = false;
    bool composable = false;
};

struct ComDecision {
    bool admitted = false;
    bool digest = false;
    bool bound = false;
    bool hiding = false;
    bool native = false;
    bool basis_closed = false;
    bool prebound = false;
    bool composable = false;
    bool rejects_unbound = false;
    bool rejects_basis_open = false;
    bool rejects_posthoc = false;
    bool rejects_nonclosed = false;
};

inline void com_acc_fp(Sha256& h, const Fp& x) {
    sha256_acc_u64(h, x.lo);
    sha256_acc_u64(h, x.hi & MASK63);
}

inline bool com_digest_eq(const std::array<uint8_t, 32>& a, const std::array<uint8_t, 32>& b) {
    uint8_t diff = 0;
    for (size_t i = 0; i < a.size(); ++i) {
        diff |= static_cast<uint8_t>(a[i] ^ b[i]);
    }
    return diff == 0;
}

inline std::array<uint8_t, 32> com_cell_digest(const std::array<uint8_t, 32>& tag, const ComOpen& open) {
    Sha256 h;
    h.init();
    h.update("pvac.native.com.cell", std::strlen("pvac.native.com.cell"));
    h.update(tag.data(), tag.size());
    com_acc_fp(h, open.value);
    h.update(open.blind.data(), open.blind.size());
    std::array<uint8_t, 32> out{};
    h.finish(out.data());
    return out;
}

inline std::array<uint8_t, 32> com_expr_digest(ComOp op, const std::array<uint8_t, 32>& left, const std::array<uint8_t, 32>& right, const Fp& scalar) {
    Sha256 h;
    h.init();
    h.update("pvac.native.com.expr", std::strlen("pvac.native.com.expr"));
    sha256_acc_u64(h, static_cast<uint8_t>(op));
    h.update(left.data(), left.size());
    h.update(right.data(), right.size());
    com_acc_fp(h, scalar);
    std::array<uint8_t, 32> out{};
    h.finish(out.data());
    return out;
}

inline ComOpen make_com_open(Fp value, const std::array<uint8_t, 32>& blind) {
    ComOpen open;
    open.value = value;
    open.blind = blind;
    return open;
}

inline std::array<uint8_t, 32> com_blind_expr(ComOp op, const std::array<uint8_t, 32>& left, const std::array<uint8_t, 32>& right, const Fp& scalar) {
    Sha256 h;
    h.init();
    h.update("pvac.native.com.blind", std::strlen("pvac.native.com.blind"));
    sha256_acc_u64(h, static_cast<uint8_t>(op));
    h.update(left.data(), left.size());
    h.update(right.data(), right.size());
    com_acc_fp(h, scalar);
    std::array<uint8_t, 32> out{};
    h.finish(out.data());
    return out;
}

inline ComOpen com_open_add(const ComOpen& left, const ComOpen& right) {
    return make_com_open(fp_add(left.value, right.value), com_blind_expr(ComOp::ADD, left.blind, right.blind, fp_from_u64(0)));
}

inline ComOpen com_open_sub(const ComOpen& left, const ComOpen& right) {
    return make_com_open(fp_sub(left.value, right.value), com_blind_expr(ComOp::SUB, left.blind, right.blind, fp_from_u64(0)));
}

inline ComOpen com_open_scale(const ComOpen& source, const Fp& scalar) {
    std::array<uint8_t, 32> zero{};
    return make_com_open(fp_mul(source.value, scalar), com_blind_expr(ComOp::SCALE, source.blind, zero, scalar));
}

inline ComOpen com_open_add_const(const ComOpen& source, const Fp& constant) {
    std::array<uint8_t, 32> zero{};
    return make_com_open(fp_add(source.value, constant), com_blind_expr(ComOp::ADD_CONST, source.blind, zero, constant));
}

inline ComOpen com_open_product(const ComOpen& left, const ComOpen& right) {
    return make_com_open(fp_mul(left.value, right.value), com_blind_expr(ComOp::PRODUCT, left.blind, right.blind, fp_from_u64(0)));
}

inline bool com_op_closed(ComOp op) {
    return
        op == ComOp::ADD ||
        op == ComOp::SUB ||
        op == ComOp::SCALE ||
        op == ComOp::ADD_CONST ||
        op == ComOp::PRODUCT;
}

inline bool com_fp_eq(const Fp& a, const Fp& b) {
    return a.lo == b.lo && ((a.hi ^ b.hi) & MASK63) == 0;
}

inline ComCell make_com_cell(const std::array<uint8_t, 32>& tag, const ComOpen& open, bool prebound) {
    ComCell cell;
    cell.kind = ComKind::CELL;
    cell.op = ComOp::SOURCE;
    cell.tag = tag;
    cell.digest = com_cell_digest(tag, open);
    cell.bound = true;
    cell.hiding = true;
    cell.native = true;
    cell.basis_closed = true;
    cell.prebound = prebound;
    cell.composable = false;
    return cell;
}

inline ComCell make_com_expr(ComOp op, const ComCell& left, const ComCell& right, const Fp& scalar) {
    ComCell cell;
    cell.kind = ComKind::EXPR;
    cell.op = op;
    cell.tag = com_expr_digest(op, left.digest, right.digest, scalar);
    cell.digest = cell.tag;
    cell.bound = left.bound && right.bound;
    cell.hiding = left.hiding && right.hiding;
    cell.native = left.native && right.native;
    cell.basis_closed = left.basis_closed && right.basis_closed;
    cell.prebound = left.prebound && right.prebound;
    cell.composable = com_op_closed(op);
    return cell;
}

inline ComCell make_com_expr(ComOp op, const ComCell& left, const ComCell& right, const Fp& scalar, const ComOpen& out_open) {
    auto cell = make_com_expr(op, left, right, scalar);
    cell.digest = com_cell_digest(cell.tag, out_open);
    return cell;
}

inline ComDecision decide_com_open(const ComCell& cell, const ComOpen& open) {
    ComDecision decision;
    decision.digest =
        cell.kind == ComKind::CELL &&
        com_digest_eq(cell.digest, com_cell_digest(cell.tag, open));
    decision.bound = cell.bound;
    decision.hiding = cell.hiding;
    decision.native = cell.native;
    decision.basis_closed = cell.basis_closed;
    decision.prebound = cell.prebound;
    decision.composable = cell.composable;
    decision.rejects_unbound = !cell.bound || !cell.hiding || !cell.native;
    decision.rejects_basis_open = !cell.basis_closed;
    decision.rejects_posthoc = !cell.prebound;
    decision.rejects_nonclosed = false;
    decision.admitted =
        decision.digest &&
        decision.bound &&
        decision.hiding &&
        decision.native &&
        decision.basis_closed &&
        decision.prebound;
    return decision;
}

inline ComDecision decide_com_claim(const ComCell& cell) {
    ComDecision decision;
    decision.digest = cell.kind != ComKind::NONE;
    decision.bound = cell.bound;
    decision.hiding = cell.hiding;
    decision.native = cell.native;
    decision.basis_closed = cell.basis_closed;
    decision.prebound = cell.prebound;
    decision.composable = cell.composable;
    decision.rejects_unbound = !cell.bound || !cell.hiding || !cell.native;
    decision.rejects_basis_open = !cell.basis_closed;
    decision.rejects_posthoc = !cell.prebound;
    decision.rejects_nonclosed = cell.kind == ComKind::EXPR && !cell.composable;
    decision.admitted = false;
    return decision;
}

inline ComDecision decide_com_expr_open(ComOp op, const ComCell& left, const ComOpen& left_open, const ComCell& right, const ComOpen& right_open, const Fp& scalar, const ComCell& out, const ComOpen& out_open) {
    ComDecision decision;
    auto left_decision = decide_com_open(left, left_open);
    auto right_decision = (op == ComOp::SCALE || op == ComOp::ADD_CONST) ? left_decision : decide_com_open(right, right_open);
    ComOpen expected;
    if (op == ComOp::ADD) {
        expected = com_open_add(left_open, right_open);
    } else if (op == ComOp::SUB) {
        expected = com_open_sub(left_open, right_open);
    } else if (op == ComOp::SCALE) {
        expected = com_open_scale(left_open, scalar);
    } else if (op == ComOp::ADD_CONST) {
        expected = com_open_add_const(left_open, scalar);
    } else if (op == ComOp::PRODUCT) {
        expected = com_open_product(left_open, right_open);
    } else {
        decision.rejects_nonclosed = true;
        return decision;
    }
    auto expected_cell = make_com_expr(op, left, right, scalar, expected);
    decision.digest =
        left_decision.admitted &&
        right_decision.admitted &&
        com_digest_eq(out.tag, expected_cell.tag) &&
        com_digest_eq(out.digest, expected_cell.digest) &&
        com_digest_eq(out.digest, com_cell_digest(out.tag, out_open)) &&
        com_digest_eq(out_open.blind, expected.blind) &&
        com_fp_eq(out_open.value, expected.value);
    decision.bound = out.bound && left_decision.bound && right_decision.bound;
    decision.hiding = out.hiding && left_decision.hiding && right_decision.hiding;
    decision.native = out.native && left_decision.native && right_decision.native;
    decision.basis_closed = out.basis_closed && left_decision.basis_closed && right_decision.basis_closed;
    decision.prebound = out.prebound && left_decision.prebound && right_decision.prebound;
    decision.composable = out.composable;
    decision.rejects_unbound = !decision.bound || !decision.hiding || !decision.native;
    decision.rejects_basis_open = !decision.basis_closed;
    decision.rejects_posthoc = !decision.prebound;
    decision.rejects_nonclosed = !decision.composable;
    decision.admitted =
        decision.digest &&
        decision.bound &&
        decision.hiding &&
        decision.native &&
        decision.basis_closed &&
        decision.prebound &&
        decision.composable;
    return decision;
}

}