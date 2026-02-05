#pragma once

#include <cstdint>
#include <cmath>
#include <cassert>
#include <vector>
#include <array>
#include <tuple>
#include <numeric>
#include <algorithm>
#include <functional>
#include <type_traits>

#include "../core/types.hpp"
#include "../core/hash.hpp"
#include "../crypto/lpn.hpp"
#include "../crypto/matrix.hpp"
#include "../core/ct_safe.hpp"

namespace pvac {

namespace alg {

template<typename T>
struct Carrier {
    std::vector<T> data;
    
    Carrier() = default;
    explicit Carrier(std::vector<T> v) : data(std::move(v)) {}
    Carrier(std::initializer_list<T> init) : data(init) {}
    
    Carrier(Carrier&&) = default;
    Carrier(const Carrier&) = default;
    Carrier& operator=(Carrier&&) = default;
    Carrier& operator=(const Carrier&) = default;
    
    template<typename F>
    auto fmap(F&& f) const -> Carrier<std::invoke_result_t<F, const T&>> {
        using R = std::invoke_result_t<F, const T&>;
        std::vector<R> img;
        img.reserve(data.size());
        for (const auto& x : data) {
            img.push_back(f(x));
        }
        return Carrier<R>{ std::move(img) };
    }
    
    template<typename F, typename A>
    A fold(A init, F&& f) const {
        for (const auto& x : data) {
            init = f(std::move(init), x);
        }
        return init;
    }
    
    template<typename P>
    Carrier<T> where(P&& p) const {
        std::vector<T> out;
        for (const auto& x : data) {
            if (p(x)) out.push_back(x);
        }
        return Carrier<T>{ std::move(out) };
    }
    
    Carrier<T>& operator+=(const Carrier<T>& rhs) {
        data.reserve(data.size() + rhs.data.size());
        data.insert(data.end(), rhs.data.begin(), rhs.data.end());
        return *this;
    }
    
    Carrier<T>& operator+=(Carrier<T>&& rhs) {
        data.reserve(data.size() + rhs.data.size());
        for (auto& x : rhs.data) {
            data.push_back(std::move(x));
        }
        return *this;
    }
    
    friend Carrier<T> operator+(Carrier<T> lhs, const Carrier<T>& rhs) {
        lhs += rhs;
        return lhs;
    }
    
    friend Carrier<T> operator+(Carrier<T> lhs, Carrier<T>&& rhs) {
        lhs += std::move(rhs);
        return lhs;
    }
    
    size_t len() const { return data.size(); }
    bool nil() const { return data.empty(); }
    
    T& operator[](size_t i) { return data[i]; }
    const T& operator[](size_t i) const { return data[i]; }
    
    T& back() { return data.back(); }
    const T& back() const { return data.back(); }
    
    auto begin() { return data.begin(); }
    auto end() { return data.end(); }
    auto begin() const { return data.begin(); }
    auto end() const { return data.end(); }
    
    std::vector<T> unwrap() && { return std::move(data); }
    std::vector<T> unwrap() const& { return data; }
};

template<typename G>
inline auto gen(size_t n, G&& g) -> Carrier<std::invoke_result_t<G, size_t>> {
    using T = std::invoke_result_t<G, size_t>;
    std::vector<T> out;
    out.reserve(n);
    for (size_t i = 0; i < n; ++i) {
        out.push_back(g(i));
    }
    return Carrier<T>{ std::move(out) };
}

}

namespace field {

struct Op {
    static Fp zero() { return fp_from_u64(0); }
    static Fp one() { return fp_from_u64(1); }
    
    static Fp add(Fp a, Fp b) { return fp_add(a, b); }
    static Fp sub(Fp a, Fp b) { return fp_sub(a, b); }
    static Fp mul(Fp a, Fp b) { return fp_mul(a, b); }
    static Fp inv(Fp a) { return fp_inv(a); }
    static Fp neg(Fp a) { return fp_neg(a); }
    
    static Fp sgn(Fp x, uint8_t s) {
        return sgn_val(s) > 0 ? x : neg(x);
    }
    
    static Fp sum(const alg::Carrier<Fp>& xs) {
        return xs.fold(zero(), [](Fp a, const Fp& b) { return add(a, b); });
    }
    
    static Fp rnd() { return rand_fp_nonzero(); }

    static std::vector<Fp> zeros(size_t n) {
        return std::vector<Fp>(n, Fp{0, 0});
    }

    static std::vector<Fp> fill(Fp v, size_t n) {
        return std::vector<Fp>(n, v);
    }

    static std::vector<Fp> add(const std::vector<Fp>& a, const std::vector<Fp>& b) {
        std::vector<Fp> r(a.size());
        for (size_t i = 0; i < a.size(); ++i) r[i] = fp_add(a[i], b[i]);
        return r;
    }

    static std::vector<Fp> sub(const std::vector<Fp>& a, const std::vector<Fp>& b) {
        std::vector<Fp> r(a.size());
        for (size_t i = 0; i < a.size(); ++i) r[i] = fp_sub(a[i], b[i]);
        return r;
    }

    static std::vector<Fp> mul(const std::vector<Fp>& a, const std::vector<Fp>& b) {
        std::vector<Fp> r(a.size());
        for (size_t i = 0; i < a.size(); ++i) r[i] = fp_mul(a[i], b[i]);
        return r;
    }

    static std::vector<Fp> mul(const std::vector<Fp>& a, Fp b) {
        std::vector<Fp> r(a.size());
        for (size_t i = 0; i < a.size(); ++i) r[i] = fp_mul(a[i], b);
        return r;
    }

    static std::vector<Fp> neg(const std::vector<Fp>& a) {
        std::vector<Fp> r(a.size());
        for (size_t i = 0; i < a.size(); ++i) r[i] = fp_neg(a[i]);
        return r;
    }

    static std::vector<Fp> sgn(const std::vector<Fp>& x, uint8_t s) {
        return sgn_val(s) > 0 ? x : neg(x);
    }

    static bool nz(const std::vector<Fp>& a) {
        for (const auto& x : a) if (x.lo || x.hi) return true;
        return false;
    }
};

}

namespace entropy {

struct Budget {
    int n2;
    int n3;
    
    int vol() const { return n2 + n3; }
    
    static Budget compute(const Params& p, int d) {
        double cap = p.noise_entropy_bits + p.depth_slope_bits * std::max(0, d);
        double c2 = 2.0 * std::log2(static_cast<double>(p.B));
        double c3 = 3.0 * std::log2(static_cast<double>(p.B));
        
        int q2 = std::max(0, static_cast<int>(std::floor(cap * p.tuple2_fraction / std::max(1e-6, c2))));
        int q3 = std::max(0, static_cast<int>(std::floor(cap * (1.0 - p.tuple2_fraction) / std::max(1e-6, c3))));
        
        if (q2 + q3 == 1) {
            q3 > 0 ? ++q3 : ++q2;
        }
        
        return { q2, q3 };
    }
};

}

namespace idx {

class Selector {
    int B_;
    mutable std::vector<uint8_t> taken_;
    
public:
    explicit Selector(int B) : B_(B), taken_(B, 0) {}
    
    int fresh() const {
        int x;
        do {
            x = static_cast<int>(csprng_u64() % static_cast<uint64_t>(B_));
        } while (taken_[x]);
        taken_[x] = 1;
        return x;
    }
    
    int avoid(int a) const {
        int x;
        do {
            x = static_cast<int>(csprng_u64() % static_cast<uint64_t>(B_));
        } while (x == a);
        return x;
    }
    
    int avoid(int a, int b) const {
        int x;
        do {
            x = static_cast<int>(csprng_u64() % static_cast<uint64_t>(B_));
        } while (x == a || x == b);
        return x;
    }
    
    static uint8_t bit() {
        return static_cast<uint8_t>(csprng_u64() & 1);
    }
};

}

namespace delta {

struct Gen {
    const PubKey& pk;
    const SecKey& sk;
    const RSeed& seed;
    
    Fp scalar(uint32_t i, uint8_t d) const {
        RSeed s = seed;
        uint64_t ii = static_cast<uint64_t>(i) + 1;
        uint64_t dd = static_cast<uint64_t>(d) + 1;
        
        s.nonce.lo ^= 0x9e3779b97f4a7c15ull * ii;
        s.nonce.hi ^= 0x94d049bb133111ebull * ii;
        s.ztag ^= 0x517cc1b727220a95ull * ii;
        
        s.nonce.lo ^= dd;
        s.nonce.hi ^= dd << 32;
        s.ztag ^= dd << 48;
        
        return prf_R_noise(pk, sk, s);
    }

    Fp operator()(uint32_t i, uint8_t d) const {
        return scalar(i, d);
    }

    std::vector<Fp> per_slot(uint32_t i, uint8_t d, size_t S) const {
        if (S == 1) return { scalar(i, d) };
        uint64_t ii = static_cast<uint64_t>(i) + 1;
        uint64_t dd = static_cast<uint64_t>(d) + 1;
        XofShake xof;
        xof.init("pvac.delta.slot", {
            sk.prf_k[0], sk.prf_k[1], sk.prf_k[2], sk.prf_k[3],
            seed.ztag, seed.nonce.lo, seed.nonce.hi, ii, dd
        });
        std::vector<Fp> r(S);
        for (size_t j = 0; j < S; ++j) {
            for (;;) {
                uint64_t lo = xof.take_u64();
                uint64_t hi = xof.take_u64() & MASK63;
                if (lo || hi) { r[j] = fp_from_words(lo, hi); break; }
            }
        }
        return r;
    }
};

struct Set {
    alg::Carrier<std::vector<Fp>> vals;
    std::vector<Fp> agg;
    
    static Set make(const Gen& g, const entropy::Budget& b, size_t S) {
        alg::Carrier<std::vector<Fp>> v = alg::gen(static_cast<size_t>(b.vol()), [&](size_t i) {
            uint8_t dom = (i < static_cast<size_t>(b.n2)) ? 0 : 1;
            return g.per_slot(static_cast<uint32_t>(i), dom, S);
        });
        auto s = field::Op::zeros(S);
        for (size_t i = 0; i < v.len(); ++i)
            s = field::Op::add(s, v[i]);
        return { std::move(v), std::move(s) };
    }
    
    const std::vector<Fp>& operator[](size_t i) const { return vals[i]; }
};

}

namespace graph {

struct Emitter {
    const PubKey& pk;
    const RSeed& seed;
    
    Edge operator()(uint16_t pos, uint8_t pol, std::vector<Fp> w) const {
        return { 0, pos, pol, std::move(w), sigma_from_H(pk, seed.ztag, seed.nonce, pos, pol, csprng_u64()) };
    }
};

struct SigNode {
    int pos;
    uint8_t pol;
    std::vector<Fp> coef;
};

class SigEdge {
    const PubKey& pk_;
    const idx::Selector& sel_;
    static constexpr int K = 8;
    
public:
    SigEdge(const PubKey& pk, const idx::Selector& sel) : pk_(pk), sel_(sel) {}
    
    alg::Carrier<SigNode> build(const std::vector<Fp>& target) const {
        size_t S = target.size();
        alg::Carrier<SigNode> nodes = alg::gen(K, [&](size_t) -> SigNode {
            std::vector<Fp> c(S);
            for (auto& x : c) x = field::Op::rnd();
            return { sel_.fresh(), idx::Selector::bit(), std::move(c) };
        });
        
        auto acc = field::Op::zeros(S);
        for (size_t i = 0; i + 1 < nodes.len(); ++i) {
            const SigNode& n = nodes[i];
            acc = field::Op::add(acc, field::Op::sgn(field::Op::mul(n.coef, pk_.powg_B[n.pos]), n.pol));
        }
        
        SigNode& last = nodes.back();
        auto rem = field::Op::sub(target, acc);
        auto q = field::Op::mul(rem, field::Op::inv(pk_.powg_B[last.pos]));
        last.coef = sgn_val(last.pol) < 0 ? field::Op::neg(q) : q;
        
        return nodes;
    }
};

struct N2 {
    int pa, pb;
    uint8_t sa, sb;
    std::vector<Fp> ra, rb;
};

class N2Edge {
    const PubKey& pk_;
    const idx::Selector& sel_;
    
public:
    N2Edge(const PubKey& pk, const idx::Selector& sel) : pk_(pk), sel_(sel) {}
    
    N2 build(const std::vector<Fp>& dt, size_t slots) const {
        int a = static_cast<int>(csprng_u64() % static_cast<uint64_t>(pk_.prm.B));
        int b = sel_.avoid(a);
        uint8_t sa = idx::Selector::bit();
        uint8_t sb = sa ^ 1;
        Fp gb_inv = field::Op::inv(pk_.powg_B[b]);
        std::vector<Fp> ra(slots), rb(slots);
        for (size_t j = 0; j < slots; ++j) {
            Fp d = sgn_val(sa) > 0 ? dt[j] : field::Op::neg(dt[j]);
            ra[j] = field::Op::rnd();
            rb[j] = field::Op::mul(field::Op::sub(field::Op::mul(ra[j], pk_.powg_B[a]), d), gb_inv);
        }
        return { a, b, sa, sb, std::move(ra), std::move(rb) };
    }
};

struct N3 {
    int pa, pb, pc;
    uint8_t sa, sb, sc;
    std::vector<Fp> ra, rb, rc;
};

class N3Edge {
    const PubKey& pk_;
    const idx::Selector& sel_;
    
public:
    N3Edge(const PubKey& pk, const idx::Selector& sel) : pk_(pk), sel_(sel) {}
    
    N3 build(const std::vector<Fp>& dt, size_t slots) const {
        int a = static_cast<int>(csprng_u64() % static_cast<uint64_t>(pk_.prm.B));
        int b = sel_.avoid(a);
        int c = sel_.avoid(a, b);
        
        uint8_t sa = idx::Selector::bit();
        uint8_t sb = idx::Selector::bit();
        uint8_t sc = idx::Selector::bit();
        
        Fp gc_inv = field::Op::inv(field::Op::sgn(pk_.powg_B[c], sc));
        std::vector<Fp> ra(slots), rb(slots), rc(slots);
        for (size_t j = 0; j < slots; ++j) {
            ra[j] = field::Op::rnd();
            rb[j] = field::Op::rnd();
            Fp ta = field::Op::sgn(field::Op::mul(ra[j], pk_.powg_B[a]), sa);
            Fp tb = field::Op::sgn(field::Op::mul(rb[j], pk_.powg_B[b]), sb);
            rc[j] = field::Op::mul(field::Op::sub(dt[j], field::Op::add(ta, tb)), gc_inv);
        }
        return { a, b, c, sa, sb, sc, std::move(ra), std::move(rb), std::move(rc) };
    }
};

inline alg::Carrier<Edge> realize(const Emitter& em, const std::vector<Fp>& R, const N2& n) {
    return alg::Carrier<Edge>{ {
        em(static_cast<uint16_t>(n.pa), n.sa, field::Op::mul(R, n.ra)),
        em(static_cast<uint16_t>(n.pb), n.sb, field::Op::mul(R, n.rb))
    } };
}

inline alg::Carrier<Edge> realize(const Emitter& em, const std::vector<Fp>& R, const N3& n) {
    return alg::Carrier<Edge>{ {
        em(static_cast<uint16_t>(n.pa), n.sa, field::Op::mul(R, n.ra)),
        em(static_cast<uint16_t>(n.pb), n.sb, field::Op::mul(R, n.rb)),
        em(static_cast<uint16_t>(n.pc), n.sc, field::Op::mul(R, n.rc))
    } };
}

}

namespace reduction {

inline alg::Carrier<Edge> merge(alg::Carrier<Edge> edges, const PubKey& pk) {
    if (edges.nil()) return {};
    
    const int B = pk.prm.B;
    size_t S = edges[0].w.size();
    
    uint32_t maxL = 0;
    for (const auto& e : edges) {
        if (e.layer_id > maxL) maxL = e.layer_id;
    }
    const size_t L = static_cast<size_t>(maxL) + 1;
    
    struct Slot {
        bool active = false;
        std::vector<Fp> w;
        BitVec s;
    };
    
    std::vector<Slot> acc_p(L * B);
    std::vector<Slot> acc_m(L * B);
    
    for (auto& e : edges) {
        size_t idx = static_cast<size_t>(e.layer_id) * B + e.idx;
        auto& acc = (e.ch == SGN_P) ? acc_p : acc_m;
        
        if (!acc[idx].active) {
            acc[idx].active = true;
            acc[idx].w = std::move(e.w);
            acc[idx].s = std::move(e.s);
        } else {
            for (size_t j = 0; j < S; ++j)
                acc[idx].w[j] = fp_add(acc[idx].w[j], e.w[j]);
            acc[idx].s.xor_with(e.s);
        }
    }
    
    auto nz = [](const std::vector<Fp>& w, const BitVec& s) {
        for (const auto& x : w)
            if (ct::fp_is_nonzero(x)) return true;
        return s.popcnt() != 0;
    };
    
    std::vector<Edge> out;
    out.reserve(edges.len());
    
    for (size_t lid = 0; lid < L; ++lid) {
        for (int k = 0; k < B; ++k) {
            size_t idx = lid * B + k;
            
            if (acc_p[idx].active && nz(acc_p[idx].w, acc_p[idx].s)) {
                out.push_back({
                    static_cast<uint32_t>(lid),
                    static_cast<uint16_t>(k),
                    SGN_P,
                    std::move(acc_p[idx].w),
                    std::move(acc_p[idx].s)
                });
            }
            if (acc_m[idx].active && nz(acc_m[idx].w, acc_m[idx].s)) {
                out.push_back({
                    static_cast<uint32_t>(lid),
                    static_cast<uint16_t>(k),
                    SGN_M,
                    std::move(acc_m[idx].w),
                    std::move(acc_m[idx].s)
                });
            }
        }
    }
    
    return alg::Carrier<Edge>{ std::move(out) };
}

inline alg::Carrier<Edge> permute(alg::Carrier<Edge> e) {
    for (size_t i = e.len(); i > 1; --i) {
        std::swap(e.data[i - 1], e.data[csprng_u64() % i]);
    }
    return e;
}

}

inline std::vector<Fp> prf_R_slots(const PubKey& pk, const SecKey& sk, const RSeed& seed, size_t slots) {
    std::vector<Fp> R(slots);
    if (slots == 1) {
        R[0] = prf_R(pk, sk, seed);
        return R;
    }
    for (size_t j = 0; j < slots; ++j) {
        RSeed s = seed;
        uint64_t t = static_cast<uint64_t>(j) * 0x9E3779B97F4A7C15ULL;
        s.nonce.hi ^= t;
        s.nonce.lo ^= (t << 32) ^ (t >> 32);
        s.ztag = prg_layer_ztag(pk.canon_tag, s.nonce);
        R[j] = prf_R(pk, sk, s);
    }
    return R;
}

namespace core {

inline Cipher synth(const PubKey& pk, const SecKey& sk, const std::vector<Fp>& v, int depth) {
    size_t S = v.size();
    
    Layer L{};
    L.rule = RRule::BASE;
    L.seed.nonce = make_nonce128();
    L.seed.ztag = prg_layer_ztag(pk.canon_tag, L.seed.nonce);
    
    entropy::Budget b = entropy::Budget::compute(pk.prm, depth);
    delta::Gen dg{ pk, sk, L.seed };
    delta::Set ds = delta::Set::make(dg, b, S);
    
    auto R = prf_R_slots(pk, sk, L.seed, S);
    auto va = field::Op::sub(v, ds.agg);
    
    idx::Selector sel(pk.prm.B);
    graph::Emitter em{ pk, L.seed };
    
    graph::SigEdge sig(pk, sel);
    alg::Carrier<graph::SigNode> sn = sig.build(va);
    
    alg::Carrier<Edge> se = sn.fmap([&](const graph::SigNode& n) {
        return em(static_cast<uint16_t>(n.pos), n.pol, field::Op::mul(n.coef, R));
    });
    
    graph::N2Edge n2e(pk, sel);
    for (int t = 0; t < b.n2; ++t) {
        se += graph::realize(em, R, n2e.build(ds[t], S));
    }
    
    graph::N3Edge n3e(pk, sel);
    for (int t = 0; t < b.n3; ++t) {
        se += graph::realize(em, R, n3e.build(ds[static_cast<size_t>(b.n2) + t], S));
    }
    
    alg::Carrier<Edge> all = reduction::permute(reduction::merge(std::move(se), pk));
    
    Cipher C;
    C.slots = S;
    C.c0 = field::Op::zeros(S);
    C.L.push_back(L);
    C.E = std::move(all).unwrap();
    return C;
}

inline Cipher fuse(const PubKey& pk, const Cipher& a, const Cipher& b) {
    assert(a.slots == b.slots && "fuse: slots mismatch");
    uint32_t off = static_cast<uint32_t>(a.L.size());
    
    std::vector<Layer> ls;
    ls.reserve(a.L.size() + b.L.size());
    ls.insert(ls.end(), a.L.begin(), a.L.end());
    
    for (Layer l : b.L) {
        if (l.rule == RRule::PROD) {
            l.pa += off;
            l.pb += off;
        }
        ls.push_back(l);
    }
    
    std::vector<Edge> es;
    es.reserve(a.E.size() + b.E.size());
    es.insert(es.end(), a.E.begin(), a.E.end());
    
    for (Edge e : b.E) {
        e.layer_id += off;
        es.push_back(std::move(e));
    }
    
    if (es.size() > pk.prm.edge_budget) {
        es = reduction::merge(alg::Carrier<Edge>{ std::move(es) }, pk).unwrap();
    }
    
    Cipher C;
    C.slots = a.slots;
    C.c0 = field::Op::add(a.c0, b.c0);
    C.L = std::move(ls);
    C.E = std::move(es);
    return C;
}

}

inline std::pair<int, int> plan_noise(const PubKey& pk, int depth_hint) {
    entropy::Budget b = entropy::Budget::compute(pk.prm, depth_hint);
    return { b.n2, b.n3 };
}

inline double sigma_density(const PubKey& pk, const Cipher& C) {
    if (C.E.empty()) return 0.0;
    long double o = 0, t = 0;
    for (const auto& e : C.E) {
        o += e.s.popcnt();
        t += pk.prm.m_bits;
    }
    return static_cast<double>(o / t);
}

inline void compact_edges(const PubKey& pk, Cipher& C) {
    C.E = reduction::merge(alg::Carrier<Edge>{ std::move(C.E) }, pk).unwrap();
}

inline void compact_layers(Cipher& C) {
    size_t L = C.L.size();
    if (L == 0) return;
    
    std::vector<uint8_t> live(L, 0);
    for (const auto& e : C.E) {
        if (e.layer_id < L) live[e.layer_id] = 1;
    }
    
    for (bool chg = true; chg; ) {
        chg = false;
        for (size_t i = 0; i < L; ++i) {
            if (!live[i] || C.L[i].rule != RRule::PROD) continue;
            auto mark = [&](uint32_t p) {
                if (p < L && !live[p]) { live[p] = 1; chg = true; }
            };
            mark(C.L[i].pa);
            mark(C.L[i].pb);
        }
    }
    
    std::vector<uint32_t> remap(L, UINT32_MAX);
    std::vector<Layer> nL;
    nL.reserve(L);
    
    for (size_t i = 0; i < L; ++i) {
        if (live[i]) {
            remap[i] = static_cast<uint32_t>(nL.size());
            nL.push_back(C.L[i]);
        }
    }
    
    if (nL.size() == L) return;
    
    for (auto& l : nL) {
        if (l.rule == RRule::PROD) {
            l.pa = remap[l.pa];
            l.pb = remap[l.pb];
        }
    }
    for (auto& e : C.E) {
        e.layer_id = remap[e.layer_id];
    }
    
    C.L.swap(nL);
}

inline void guard_budget(const PubKey& pk, Cipher& C, const char* ctx) {
    if (C.E.size() > pk.prm.edge_budget) {
        if (g_dbg) std::cout << "[guard] " << ctx << ": " << C.E.size() << " -> compact\n";
        compact_edges(pk, C);
    }
}

inline Fp prf_noise_delta(const PubKey& pk, const SecKey& sk, const RSeed& seed, uint32_t gid, uint8_t kind) {
    return delta::Gen{ pk, sk, seed }.scalar(gid, kind);
}

inline Cipher enc_fp_depth(const PubKey& pk, const SecKey& sk, const std::vector<Fp>& v, int d) {
    return core::synth(pk, sk, v, d);
}

inline Cipher enc_fp_depth(const PubKey& pk, const SecKey& sk, const Fp& v, int d) {
    return core::synth(pk, sk, {v}, d);
}

inline Cipher combine_ciphers(const PubKey& pk, const Cipher& a, const Cipher& b) {
    return core::fuse(pk, a, b);
}

inline Cipher enc_value_depth(const PubKey& pk, const SecKey& sk, uint64_t v, int d) {
    std::vector<Fp> vals = {fp_from_u64(v)};
    std::vector<Fp> m = {field::Op::rnd()};
    return combine_ciphers(pk,
        enc_fp_depth(pk, sk, field::Op::add(vals, m), d),
        enc_fp_depth(pk, sk, field::Op::neg(m), d));
}

inline Cipher enc_value(const PubKey& pk, const SecKey& sk, uint64_t v) {
    return enc_value_depth(pk, sk, v, 0);
}

inline Cipher enc_values_depth(const PubKey& pk, const SecKey& sk, const std::vector<uint64_t>& v, int d) {
    size_t S = v.size();
    std::vector<Fp> vals(S), m(S);
    for (size_t j = 0; j < S; ++j) { vals[j] = fp_from_u64(v[j]); m[j] = field::Op::rnd(); }
    return combine_ciphers(pk,
        enc_fp_depth(pk, sk, field::Op::add(vals, m), d),
        enc_fp_depth(pk, sk, field::Op::neg(m), d));
}

inline Cipher enc_values(const PubKey& pk, const SecKey& sk, const std::vector<uint64_t>& v) {
    return enc_values_depth(pk, sk, v, 0);
}

inline Cipher enc_zero_depth(const PubKey& pk, const SecKey& sk, int d) {
    std::vector<Fp> m = {field::Op::rnd()};
    return combine_ciphers(pk, enc_fp_depth(pk, sk, m, d), enc_fp_depth(pk, sk, field::Op::neg(m), d));
}

}