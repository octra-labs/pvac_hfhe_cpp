#pragma once

#include <cstdint>
#include <vector>
#include <algorithm>
#include <functional>
#include <numeric>
#include <utility>

#include "../core/types.hpp"
#include "encrypt.hpp"

namespace pvac {

namespace detail {

inline Fp fp_from_i64(int64_t x) {
    return x >= 0 ? fp_from_u64(static_cast<uint64_t>(x))
                  : fp_neg(fp_from_u64(static_cast<uint64_t>(-(x + 1)) + 1));
}

template<typename F>
inline auto fold_edges(const Cipher& ct, const PubKey& pk, F&& acc_fn) {
    size_t S = ct.slots;
    std::vector<std::vector<Fp>> out(ct.L.size(), field::Op::zeros(S));
    for (const auto& e : ct.E) {
        Fp gp = pk.powg_B[e.idx];
        for (size_t j = 0; j < S; ++j) {
            Fp term = fp_mul(e.w[j], gp);
            out[e.layer_id][j] = acc_fn(out[e.layer_id][j], term, e.ch);
        }
    }
    return out;
}

inline auto gsum_accumulator = [](const Fp& acc, const Fp& term, uint8_t ch) -> Fp {
    return ch == SGN_P ? fp_add(acc, term) : fp_sub(acc, term);
};

inline void sample_unique_indices(uint16_t* dst, size_t n, int B) {
    for (size_t i = 0; i < n; ++i) {
        uint16_t x;
        do {
            x = static_cast<uint16_t>(csprng_u64() % static_cast<uint64_t>(B));
        } while (std::any_of(dst, dst + i, [x](uint16_t v) { return v == x; }));
        dst[i] = x;
    }
}

inline void sample_unique_indices(uint16_t* dst, size_t n, int B, SeedableRng& rng) {
    for (size_t i = 0; i < n; ++i) {
        uint16_t x;
        do {
            x = static_cast<uint16_t>(rng.bounded(static_cast<uint64_t>(B)));
        } while (std::any_of(dst, dst + i, [x](uint16_t v) { return v == x; }));
        dst[i] = x;
    }
}

inline Edge make_repack_edge(const PubKey& pk, const Layer& L, uint32_t lid,
                             uint16_t idx, uint8_t ch, std::vector<Fp> w) {
    return {lid, idx, ch, std::move(w), sigma_from_H(pk, L.seed.ztag, L.seed.nonce, idx, ch, csprng_u64())};
}

inline Edge make_repack_edge(const PubKey& pk, const Layer& L, uint32_t lid,
                             uint16_t idx, uint8_t ch, std::vector<Fp> w, SeedableRng& rng) {
    return {lid, idx, ch, std::move(w), sigma_from_H(pk, L.seed.ztag, L.seed.nonce, idx, ch, rng.u64())};
}

inline auto emit_repack_edges(const PubKey& pk, uint32_t lid, const Layer& L,
                              const std::vector<Fp>& target, size_t s) -> std::vector<Edge> {
    if (s == 0) return {};
    size_t S = target.size();

    std::vector<uint16_t> idxs(s);
    sample_unique_indices(idxs.data(), s, pk.prm.B);

    std::vector<std::pair<uint16_t, uint8_t>> specs(s);
    std::transform(idxs.begin(), idxs.end(), specs.begin(), [](uint16_t idx) {
        return std::make_pair(idx, static_cast<uint8_t>(csprng_u64() & 1));
    });

    auto sum = field::Op::zeros(S);
    std::vector<Edge> edges;
    edges.reserve(s);

    for (size_t i = 0; i + 1 < s; ++i) {
        auto [idx, ch] = specs[i];
        std::vector<Fp> w(S);
        for (auto& x : w) x = rand_fp_nonzero();
        auto t = field::Op::mul(w, pk.powg_B[idx]);
        sum = ch == SGN_P ? field::Op::add(sum, t) : field::Op::sub(sum, t);
        edges.push_back(make_repack_edge(pk, L, lid, idx, ch, std::move(w)));
    }

    auto [last_idx, last_ch] = specs.back();
    auto diff = field::Op::sub(target, sum);
    Fp ginv = pk.powg_B[(pk.prm.B - last_idx) % pk.prm.B];
    auto final_w = field::Op::mul(last_ch == SGN_M ? field::Op::neg(diff) : diff, ginv);

    edges.push_back(make_repack_edge(pk, L, lid, last_idx, last_ch, std::move(final_w)));
    return edges;
}

inline auto emit_repack_edges(const PubKey& pk, uint32_t lid, const Layer& L,
                              const std::vector<Fp>& target, size_t s, SeedableRng& rng) -> std::vector<Edge> {
    if (s == 0) return {};
    size_t S = target.size();

    std::vector<uint16_t> idxs(s);
    sample_unique_indices(idxs.data(), s, pk.prm.B, rng);

    std::vector<std::pair<uint16_t, uint8_t>> specs(s);
    std::transform(idxs.begin(), idxs.end(), specs.begin(), [&rng](uint16_t idx) {
        return std::make_pair(idx, static_cast<uint8_t>(rng.u64() & 1));
    });

    auto sum = field::Op::zeros(S);
    std::vector<Edge> edges;
    edges.reserve(s);

    for (size_t i = 0; i + 1 < s; ++i) {
        auto [idx, ch] = specs[i];
        std::vector<Fp> w(S);
        for (auto& x : w) x = rng.fp_nonzero();
        auto t = field::Op::mul(w, pk.powg_B[idx]);
        sum = ch == SGN_P ? field::Op::add(sum, t) : field::Op::sub(sum, t);
        edges.push_back(make_repack_edge(pk, L, lid, idx, ch, std::move(w), rng));
    }

    auto [last_idx, last_ch] = specs.back();
    auto diff = field::Op::sub(target, sum);
    Fp ginv = pk.powg_B[(pk.prm.B - last_idx) % pk.prm.B];
    auto final_w = field::Op::mul(last_ch == SGN_M ? field::Op::neg(diff) : diff, ginv);

    edges.push_back(make_repack_edge(pk, L, lid, last_idx, last_ch, std::move(final_w), rng));
    return edges;
}

inline Layer make_prod_layer(const PubKey& pk, uint32_t pa, uint32_t pb,
                             const std::array<uint8_t,32>& R_com_a,
                             const std::array<uint8_t,32>& R_com_b) {
    auto nonce = make_nonce128();
    Layer L;
    L.rule = RRule::PROD;
    L.seed = {prg_layer_ztag(pk.canon_tag, nonce), nonce};
    L.pa = pa < pb ? pa : pb;
    L.pb = pa < pb ? pb : pa;
    L.R_com = (pa < pb) ? compute_R_com_prod(R_com_a, R_com_b)
                        : compute_R_com_prod(R_com_b, R_com_a);

    return L;
}

inline Layer make_prod_layer(const PubKey& pk, uint32_t pa, uint32_t pb,
                             const std::array<uint8_t,32>& R_com_a,
                             const std::array<uint8_t,32>& R_com_b,
                             SeedableRng& rng) {
    auto nonce = rng.nonce128();
    Layer L;
    L.rule = RRule::PROD;
    L.seed = {prg_layer_ztag(pk.canon_tag, nonce), nonce};
    L.pa = pa < pb ? pa : pb;
    L.pb = pa < pb ? pb : pa;
    L.R_com = (pa < pb) ? compute_R_com_prod(R_com_a, R_com_b)
                        : compute_R_com_prod(R_com_b, R_com_a);

    return L;
}

inline void append_scaled_edges(std::vector<Edge>& dest, const std::vector<Edge>& src,
                                const std::vector<Fp>& scale, uint32_t layer_offset = 0) {
    if (!field::Op::nz(scale)) return;
    dest.reserve(dest.size() + src.size());
    std::transform(src.begin(), src.end(), std::back_inserter(dest),
        [&](Edge e) {
            e.layer_id += layer_offset;
            e.w = field::Op::mul(e.w, scale);
            return e;
        });
}

template<typename LayerGen, typename TargetGen>
inline Cipher build_product_cipher_seeded(const PubKey& pk, const Cipher& A, const Cipher* B,
                                          LayerGen&& layer_gen, TargetGen&& target_gen,
                                          size_t num_prods, size_t S, const char* tag, SeedableRng& rng) {
    Cipher C;
    C.slots = A.slots;
    C.c0 = field::Op::zeros(A.slots);
    auto gA = fold_edges(A, pk, gsum_accumulator);
    auto gB = B ? fold_edges(*B, pk, gsum_accumulator) : gA;

    C.L = A.L;
    uint32_t off = static_cast<uint32_t>(C.L.size());

    if (B) {
        C.L.reserve(C.L.size() + B->L.size() + num_prods);
        std::transform(B->L.begin(), B->L.end(), std::back_inserter(C.L),
            [off](Layer L) {
                if (L.rule == RRule::PROD) { L.pa += off; L.pb += off; }
                return L;
            });
    } else {
        C.L.reserve(C.L.size() + num_prods);
    }

    C.E.reserve(num_prods * S);

    layer_gen([&](uint32_t la, uint32_t lb_raw) {
        uint32_t lb = B ? (off + lb_raw) : lb_raw;
        Layer L = make_prod_layer(pk, la, lb, C.L[la].R_com, C.L[lb].R_com, rng);
        uint32_t lid = static_cast<uint32_t>(C.L.size());
        C.L.push_back(L);

        auto target = target_gen(gA, gB, la, lb_raw);
        auto edges = emit_repack_edges(pk, lid, C.L[lid], target, S, rng);
        std::move(edges.begin(), edges.end(), std::back_inserter(C.E));
    });

    guard_budget(pk, C, tag);
    compact_layers(C);
    return C;
}

template<typename LayerGen, typename TargetGen>
inline Cipher build_product_cipher(const PubKey& pk, const Cipher& A, const Cipher* B,
                                   LayerGen&& layer_gen, TargetGen&& target_gen,
                                   size_t num_prods, size_t S, const char* tag) {
    Cipher C;
    C.slots = A.slots;
    C.c0 = field::Op::zeros(A.slots);
    auto gA = fold_edges(A, pk, gsum_accumulator);
    auto gB = B ? fold_edges(*B, pk, gsum_accumulator) : gA;

    C.L = A.L;
    uint32_t off = static_cast<uint32_t>(C.L.size());

    if (B) {
        C.L.reserve(C.L.size() + B->L.size() + num_prods);
        std::transform(B->L.begin(), B->L.end(), std::back_inserter(C.L),
            [off](Layer L) {
                if (L.rule == RRule::PROD) { L.pa += off; L.pb += off; }
                return L;
            });
    } else {
        C.L.reserve(C.L.size() + num_prods);
    }

    C.E.reserve(num_prods * S);

    layer_gen([&](uint32_t la, uint32_t lb_raw) {
        uint32_t lb = B ? (off + lb_raw) : lb_raw;
        Layer L = make_prod_layer(pk, la, lb, C.L[la].R_com, C.L[lb].R_com);
        uint32_t lid = static_cast<uint32_t>(C.L.size());
        C.L.push_back(L);

        auto target = target_gen(gA, gB, la, lb_raw);
        auto edges = emit_repack_edges(pk, lid, C.L[lid], target, S);
        std::move(edges.begin(), edges.end(), std::back_inserter(C.E));
    });

    guard_budget(pk, C, tag);
    compact_layers(C);
    return C;
}

}

inline Cipher ct_scale(const PubKey&, const Cipher& A, const Fp& s) {
    Cipher C = A;
    for (auto& e : C.E)
        e.w = field::Op::mul(e.w, s);
    for (size_t j = 0; j < C.c0.size(); ++j)
        C.c0[j] = fp_mul(C.c0[j], s);
    return C;
}

inline Cipher ct_neg(const PubKey& pk, const Cipher& A) {
    return ct_scale(pk, A, fp_neg(fp_from_u64(1)));
}

inline Cipher ct_add(const PubKey& pk, const Cipher& A, const Cipher& B) {
    if (A.slots != B.slots)
        throw std::runtime_error("pvac: ct_add: slot count mismatch between operands");
    Cipher C;
    C.slots = A.slots;
    C.c0 = A.c0.empty() ? B.c0 : B.c0.empty() ? A.c0 : field::Op::add(A.c0, B.c0);
    C.L.reserve(A.L.size() + B.L.size());
    C.E.reserve(A.E.size() + B.E.size());

    C.L = A.L;
    uint32_t off = static_cast<uint32_t>(A.L.size());

    std::transform(B.L.begin(), B.L.end(), std::back_inserter(C.L),
        [off](Layer L) {
            if (L.rule == RRule::PROD) { L.pa += off; L.pb += off; }
            return L;
        });

    C.E = A.E;
    std::transform(B.E.begin(), B.E.end(), std::back_inserter(C.E),
        [off](Edge e) { e.layer_id += off; return e; });

    guard_budget(pk, C, "add");
    compact_layers(C);
    return C;
}

inline Cipher ct_sub(const PubKey& pk, const Cipher& A, const Cipher& B) {
    return ct_add(pk, A, ct_neg(pk, B));
}

inline Cipher ct_mul(const PubKey& pk, const Cipher& A, const Cipher& B, size_t S = 8) {
    auto a0 = A.c0;
    auto b0 = B.c0;

    Cipher A_g = A;
    Cipher B_g = B;
    A_g.c0 = field::Op::zeros(A.slots);
    B_g.c0 = field::Op::zeros(B.slots);

    uint32_t LA = static_cast<uint32_t>(A_g.L.size());
    uint32_t LB = static_cast<uint32_t>(B_g.L.size());
    uint32_t off = LA;

    Cipher C = detail::build_product_cipher(pk, A_g, &B_g,
        [LA, LB](auto&& emit) {
            for (uint32_t la = 0; la < LA; ++la)
                for (uint32_t lb = 0; lb < LB; ++lb)
                    emit(la, lb);
        },
        [](const auto& gA, const auto& gB, uint32_t la, uint32_t lb) {
            return field::Op::mul(gA[la], gB[lb]);
        },
        static_cast<size_t>(LA) * LB, S ? S : 1, "mul");

    detail::append_scaled_edges(C.E, B_g.E, a0, off);
    detail::append_scaled_edges(C.E, A_g.E, b0, 0);
    C.c0 = field::Op::mul(a0, b0);

    guard_budget(pk, C, "mul");
    compact_layers(C);
    return C;
}

inline Cipher ct_square(const PubKey& pk, const Cipher& A, size_t S = 8) {
    auto a0 = A.c0;

    Cipher A_g = A;
    A_g.c0 = field::Op::zeros(A.slots);

    uint32_t LA = static_cast<uint32_t>(A_g.L.size());
    size_t triangular = static_cast<size_t>(LA) * (LA + 1) / 2;

    Cipher C = detail::build_product_cipher(pk, A_g, nullptr,
        [LA](auto&& emit) {
            for (uint32_t la = 0; la < LA; ++la)
                for (uint32_t lb = la; lb < LA; ++lb)
                    emit(la, lb);
        },
        [](const auto& gA, const auto&, uint32_t la, uint32_t lb) {
            auto prod = field::Op::mul(gA[la], gA[lb]);
            return la != lb ? field::Op::add(prod, prod) : prod;
        },
        triangular, S ? S : 1, "square");

    auto two_a0 = field::Op::add(a0, a0);
    detail::append_scaled_edges(C.E, A_g.E, two_a0, 0);
    C.c0 = field::Op::mul(a0, a0);

    guard_budget(pk, C, "square");
    compact_layers(C);
    return C;
}

inline Cipher ct_mul_seeded(const PubKey& pk, const Cipher& A, const Cipher& B, const uint8_t seed[32], size_t S = 8) {
    SeedableRng rng = make_seeded_rng(seed);
    auto a0 = A.c0;
    auto b0 = B.c0;

    Cipher A_g = A;
    Cipher B_g = B;
    A_g.c0 = field::Op::zeros(A.slots);
    B_g.c0 = field::Op::zeros(B.slots);

    uint32_t LA = static_cast<uint32_t>(A_g.L.size());
    uint32_t LB = static_cast<uint32_t>(B_g.L.size());
    uint32_t off = LA;

    Cipher C = detail::build_product_cipher_seeded(pk, A_g, &B_g,
        [LA, LB](auto&& emit) {
            for (uint32_t la = 0; la < LA; ++la)
                for (uint32_t lb = 0; lb < LB; ++lb)
                    emit(la, lb);
        },
        [](const auto& gA, const auto& gB, uint32_t la, uint32_t lb) {
            return field::Op::mul(gA[la], gB[lb]);
        },
        static_cast<size_t>(LA) * LB, S ? S : 1, "mul", rng);

    detail::append_scaled_edges(C.E, B_g.E, a0, off);
    detail::append_scaled_edges(C.E, A_g.E, b0, 0);
    C.c0 = field::Op::mul(a0, b0);

    guard_budget(pk, C, "mul");
    compact_layers(C);
    return C;
}

inline Cipher ct_square_seeded(const PubKey& pk, const Cipher& A, const uint8_t seed[32], size_t S = 8) {
    SeedableRng rng = make_seeded_rng(seed);
    auto a0 = A.c0;

    Cipher A_g = A;
    A_g.c0 = field::Op::zeros(A.slots);

    uint32_t LA = static_cast<uint32_t>(A_g.L.size());
    size_t triangular = static_cast<size_t>(LA) * (LA + 1) / 2;

    Cipher C = detail::build_product_cipher_seeded(pk, A_g, nullptr,
        [LA](auto&& emit) {
            for (uint32_t la = 0; la < LA; ++la)
                for (uint32_t lb = la; lb < LA; ++lb)
                    emit(la, lb);
        },
        [](const auto& gA, const auto&, uint32_t la, uint32_t lb) {
            auto prod = field::Op::mul(gA[la], gA[lb]);
            return la != lb ? field::Op::add(prod, prod) : prod;
        },
        triangular, S ? S : 1, "square", rng);

    auto two_a0 = field::Op::add(a0, a0);
    detail::append_scaled_edges(C.E, A_g.E, two_a0, 0);
    C.c0 = field::Op::mul(a0, a0);

    guard_budget(pk, C, "square");
    compact_layers(C);
    return C;
}

inline Cipher ct_div_const(const PubKey& pk, const Cipher& A, const Fp& k) {
    return ct_scale(pk, A, fp_inv(k));
}

inline Cipher ct_mul_const(const PubKey& pk, const Cipher& A, uint64_t k) {
    return ct_scale(pk, A, fp_from_u64(k));
}

inline Cipher ct_mul_const(const PubKey& pk, const Cipher& A, int64_t k) {
    return ct_scale(pk, A, detail::fp_from_i64(k));
}

inline Cipher ct_add_const(const PubKey&, const Cipher& A, uint64_t k) {
    Cipher C = A;
    Fp v = fp_from_u64(k);
    for (size_t j = 0; j < C.c0.size(); ++j)
        C.c0[j] = fp_add(C.c0[j], v);
    return C;
}

inline Cipher ct_add_const(const PubKey&, const Cipher& A, int64_t k) {
    Cipher C = A;
    Fp v = detail::fp_from_i64(k);
    for (size_t j = 0; j < C.c0.size(); ++j)
        C.c0[j] = fp_add(C.c0[j], v);
    return C;
}

inline Cipher ct_sub_const(const PubKey& pk, const Cipher& A, uint64_t k) {
    return ct_add_const(pk, A, -static_cast<int64_t>(k));
}

inline Cipher ct_sub_const(const PubKey& pk, const Cipher& A, int64_t k) {
    return ct_add_const(pk, A, -k);
}

}