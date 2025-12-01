#pragma once

#include <cstdint>
#include <cmath>
#include <vector>
#include <unordered_set>
#include <utility>

#include "../core/types.hpp"
#include "../crypto/lpn.hpp"
#include "../crypto/matrix.hpp"

namespace pvac {

inline std::pair<int, int> plan_noise(const PubKey & pk, int depth_hint) {
    double budget = pk.prm.noise_entropy_bits +
                    pk.prm.depth_slope_bits * std::max(0, depth_hint);

    double per2 = 2.0 * std::log2((double)pk.prm.B);
    double per3 = 3.0 * std::log2((double)pk.prm.B);

    int z2 = (int)std::floor((budget * pk.prm.tuple2_fraction) / std::max(1e-6, per2));
    int z3 = (int)std::floor((budget * (1.0 - pk.prm.tuple2_fraction)) / std::max(1e-6, per3));

    z2 = std::max(0, z2);
    z3 = std::max(0, z3);

    return { z2, z3 };
}

inline double sigma_density(const PubKey & pk, const Cipher & C) {
    long double ones  = 0;
    long double total = 0;

    for (const auto & e : C.E) {
        ones  += e.s.popcnt();
        total += (long double)pk.prm.m_bits;
    }

    if (total == 0) {
        return 0.0;
    }


    
    return (double)(ones / total);
}

inline void compact_edges(const PubKey & pk, Cipher & C) {
    int B = pk.prm.B;
    size_t L = C.L.size();

    struct Agg {
        bool have_p;
        bool have_m;
        Fp wp;
        Fp wm;
        BitVec sp;
        BitVec sm;

        Agg() : have_p(false), have_m(false) {}
    };

    std::vector<Agg> acc(L * (size_t)B);

    auto ensureP = [&](Agg & a) {
        if (!a.have_p) {
            a.wp = fp_from_u64(0);
            a.sp  = BitVec::make(pk.prm.m_bits);
            a.have_p = true;
        }
    };

    auto ensureM = [&](Agg & a) {
        if (!a.have_m) {
            a.wm = fp_from_u64(0);
            a.sm = BitVec::make(pk.prm.m_bits);
            a.have_m = true;
        }
    };

    for (const auto & e : C.E) {
        Agg & a = acc[(size_t)e.layer_id * B + e.idx];

        if (e.ch == SGN_P) {
            ensureP(a);
            a.wp = fp_add(a.wp, e.w);
            a.sp.xor_with(e.s);
        } else {
            ensureM(a);
            a.wm = fp_add(a.wm, e.w);
            a.sm.xor_with(e.s);
        }
    }

    std::vector<Edge> out;
    out.reserve(C.E.size());

    auto nz = [&](const Fp & w, const BitVec & s) {
        return !(w.lo == 0 && w.hi == 0) || (s.popcnt() != 0);
    };

    for (size_t lid = 0; lid < L; lid++) {
        for (int k = 0; k < B; k++) {
            Agg & a = acc[lid * (size_t)B + (size_t)k];

            if (a.have_p && nz(a.wp, a.sp)) {
                Edge e;
                e.layer_id = (uint32_t)lid;
                e.idx      = (uint16_t)k;
                e.ch       = SGN_P;
                e.w        = a.wp;
                e.s        = a.sp;
                out.push_back(std::move(e));
            }

            if (a.have_m && nz(a.wm, a.sm)) {
                Edge e;
                e.layer_id = (uint32_t)lid;
                e.idx      = (uint16_t)k;
                e.ch       = SGN_M;
                e.w        = a.wm;
                e.s        = a.sm;
                out.push_back(std::move(e));
            }
        }
    }

    C.E.swap(out);
}

inline void guard_budget(const PubKey & pk, Cipher & C, const char * where) {
    if (C.E.size() > pk.prm.edge_budget) {
        if (g_dbg) {
            std::cout << "[guard] " << where << ": " << C.E.size() << " -> compact\n";
        }
        compact_edges(pk, C);
    }
}

inline Cipher enc_fp_depth(
    const PubKey & pk,
    const SecKey & sk,
    const Fp &     v,

    int            depth_hint
) {
    Cipher C;


    Layer L;
    L.rule       = RRule::BASE; // RULE??? todo: r_x for all rules

    L.seed.nonce = make_nonce128();

    L.seed.ztag  = prg_layer_ztag(pk.canon_tag, L.seed.nonce);
    C.L.push_back(L);

    const int S = 8;

    std::vector<int> idx(S);
    std::unordered_set<int> used;
    used.reserve(S * 2);

    for (int j = 0; j < S; j++) {
        int x;
        do {
             x = (int)(csprng_u64() % (uint64_t)pk.prm.B);
        } while (used.count(x));
        used.insert(x);
        idx[j] = x;
    }

    std::vector<uint8_t> ch(S);
    for (int i = 0; i < S; i++) 
    {
        ch[i] = (uint8_t)(csprng_u64() & 1ull);
    }

    std::vector<Fp> r(S);

    Fp sum1 = fp_from_u64(0);

    Fp sumg = fp_from_u64(0);


    for (int j = 0; j < S - 2; j++) {
        r[j]  = rand_fp_nonzero();
        int s = sgn_val(ch[j]);
        sum1 = (s > 0) ? fp_add(sum1, r[j]) : fp_sub(sum1, r[j]);

        Fp term = fp_mul(r[j], pk.powg_B[idx[j]]);
        
        sumg    = (s > 0) ? fp_add(sumg, term) : fp_sub(sumg, term);
    }



    // not sure (need to check)

    int     ia    = idx[S - 2];
    int     ib    = idx[S - 1];
    uint8_t sa_ch = ch[S - 2];
    uint8_t sb_ch = ch[S - 1];
    int     sa    = sgn_val(sa_ch);
    int     sb    = sgn_val(sb_ch);

    //

    Fp ga = pk.powg_B[ia];
    Fp gb = pk.powg_B[ib];

    Fp V   = fp_sub(v, sumg);
    Fp rhs = fp_sub(fp_neg(fp_mul(sum1, ga)), V);

    Fp den = fp_sub(ga, gb); // nVr

    Fp rb  = fp_mul(rhs, fp_inv(den));

    if (sb < 0) {
        rb = fp_neg(rb);
    }

    Fp tmp = (sb > 0) ? fp_sub(fp_neg(sum1), rb) : fp_add(fp_neg(sum1), rb);
    Fp ra  = (sa > 0) ? tmp : fp_neg(tmp);

    r[S - 2] = ra;

    r[S - 1] = rb;


    Fp R = prf_R(pk, sk, L.seed);

    for (int j = 0; j < S; j++) {
        Edge e;
        e.layer_id = 0;
        e.idx = (uint16_t)idx[j];
        e.ch = ch[j];
        e.w = fp_mul(r[j], R);
        e.s = sigma_from_H(pk, L.seed.ztag, L.seed.nonce, e.idx, e.ch, csprng_u64());
        C.E.push_back(std::move(e));
    }

    auto nz = plan_noise(pk, depth_hint);
    int  Z2 = nz.first;
    int  Z3 = nz.second;

    auto add_zero2 = [&](int i, int j) {
        if (i == j) {
            return;
        }

        Fp alpha = rand_fp_nonzero();
        Fp wi = fp_mul(alpha, R);
        Fp gamma = fp_mul(alpha, fp_mul(pk.powg_B[i], fp_inv(pk.powg_B[j])));
        Fp wj = fp_mul(gamma, R);

        Edge p {
            0,
            (uint16_t)i,
            SGN_P,
            wi,
            sigma_from_H(pk, L.seed.ztag, L.seed.nonce, (uint16_t)i, SGN_P, csprng_u64())
        };

        Edge m {
            0,
            (uint16_t)j,
            SGN_M,
            wj,
            sigma_from_H(pk, L.seed.ztag, L.seed.nonce, (uint16_t)j, SGN_M, csprng_u64())
        };

        C.E.push_back(std::move(p));
        C.E.push_back(std::move(m));
    };

    for (int t = 0; t < Z2; t++) {
        int i = (int)(csprng_u64() % (uint64_t)pk.prm.B);
        int j;

        do {
            j = (int)(csprng_u64() % (uint64_t)pk.prm.B);
        } while (j == i);

        add_zero2(i, j);
    }

    auto add_zero3 = [&](int i, int j, int k) {
        if (i == j || j == k || i == k) {
            return;
        }

        Fp a   = rand_fp_nonzero();
        Fp b   = rand_fp_nonzero();
        Fp sum = fp_add(fp_mul(a, pk.powg_B[i]), fp_mul(b, pk.powg_B[j]));
        Fp c   = fp_mul(fp_neg(sum), fp_inv(pk.powg_B[k]));

        Edge e1 {
            0,
            (uint16_t)i,
            SGN_P,
            fp_mul(a, R),
            sigma_from_H(pk, L.seed.ztag, L.seed.nonce, (uint16_t)i, SGN_P, csprng_u64())
        };

        Edge e2 {
            0,
            (uint16_t)j,
            SGN_P,
            fp_mul(b, R),
            sigma_from_H(pk, L.seed.ztag, L.seed.nonce, (uint16_t)j, SGN_P, csprng_u64())
        };

        Edge e3 {
            0,
            (uint16_t)k,
            SGN_P,
            fp_mul(c, R),
            sigma_from_H(pk, L.seed.ztag, L.seed.nonce, (uint16_t)k, SGN_P, csprng_u64())
        };

        C.E.push_back(std::move(e1));
        C.E.push_back(std::move(e2));
        C.E.push_back(std::move(e3));
    };

    for (int t = 0; t < Z3; t++) {
        int i = (int)(csprng_u64() % (uint64_t)pk.prm.B);
        int j;

        do {
            j = (int)(csprng_u64() % (uint64_t)pk.prm.B);
        } while (j == i);

        int k;

        do {
            k = (int)(csprng_u64() % (uint64_t)pk.prm.B);
        } while (k == i || k == j);

        add_zero3(i, j, k);
    }

    guard_budget(pk, C, "enc");

    return C;
}

inline Cipher enc_value_depth(
    const PubKey & pk,
    const SecKey & sk,
    uint64_t       v_u64,
    int            depth_hint
) {
    return enc_fp_depth(pk, sk, fp_from_u64(v_u64), depth_hint);
}

inline Cipher enc_value(const PubKey & pk, const SecKey & sk, uint64_t v) {
    return enc_value_depth(pk, sk, v, 0);
}

inline Cipher enc_zero_depth(const PubKey & pk, const SecKey & sk, int depth_hint) {
    Cipher Z;

    Layer L;
    L.rule       = RRule::BASE;
    L.seed.nonce = make_nonce128();
    L.seed.ztag  = prg_layer_ztag(pk.canon_tag, L.seed.nonce);
    Z.L.push_back(L);

    Fp R = prf_R(pk, sk, L.seed);

    auto nz = plan_noise(pk, depth_hint);
    int  Z2 = nz.first;
    int  Z3 = nz.second;

    for (int t = 0; t < Z2; t++) {
        int i = (int)(csprng_u64() % (uint64_t)pk.prm.B);
        int j;

        do {
            j = (int)(csprng_u64() % (uint64_t)pk.prm.B);
        } while (j == i);

        Fp a = rand_fp_nonzero();
        Fp wi = fp_mul(a, R);
        Fp gamma = fp_mul(a, fp_mul(pk.powg_B[i], fp_inv(pk.powg_B[j])));
        Fp wj = fp_mul(gamma, R);

        Edge p {
            0,
            (uint16_t)i,
            SGN_P,
            wi,
            sigma_from_H(pk, L.seed.ztag, L.seed.nonce, (uint16_t)i, SGN_P, csprng_u64())
        };

        Edge m {
            0,
            (uint16_t)j,
            SGN_M,
            wj,
            sigma_from_H(pk, L.seed.ztag, L.seed.nonce, (uint16_t)j, SGN_M, csprng_u64())
        };

        Z.E.push_back(std::move(p));
        Z.E.push_back(std::move(m));
    }

    for (int t = 0; t < Z3; t++) {
        int i = (int)(csprng_u64() % (uint64_t)pk.prm.B);
        int j;

        do {
            j = (int)(csprng_u64() % (uint64_t)pk.prm.B);
        } while (j == i);

        int k;

        do {
            k = (int)(csprng_u64() % (uint64_t)pk.prm.B);
        } while (k == i || k == j);

        Fp a   = rand_fp_nonzero();
        Fp b   = rand_fp_nonzero();
        Fp sum = fp_add(fp_mul(a, pk.powg_B[i]), fp_mul(b, pk.powg_B[j]));
        Fp c   = fp_mul(fp_neg(sum), fp_inv(pk.powg_B[k]));

        Edge e1 {
            0,
            (uint16_t)i,
            SGN_P,
            fp_mul(a, R),
            sigma_from_H(pk, L.seed.ztag, L.seed.nonce, (uint16_t)i, SGN_P, csprng_u64())
        };

        Edge e2 {
            0,
            (uint16_t)j,
            SGN_P,
            fp_mul(b, R),
            sigma_from_H(pk, L.seed.ztag, L.seed.nonce, (uint16_t)j, SGN_P, csprng_u64())
        };

        Edge e3 {
            0,
            (uint16_t)k,
            SGN_P,
            fp_mul(c, R),
            sigma_from_H(pk, L.seed.ztag, L.seed.nonce, (uint16_t)k, SGN_P, csprng_u64())
        };

        Z.E.push_back(std::move(e1));
        Z.E.push_back(std::move(e2));
        Z.E.push_back(std::move(e3));
    }

    return Z;
}

}
