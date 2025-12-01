#pragma once

#include <cstdint>
#include <vector>

#include "../core/types.hpp"
#include "encrypt.hpp"

namespace pvac {

inline Cipher ct_add(const PubKey & pk, const Cipher & A, const Cipher & B) {
    Cipher C;

    C.L.reserve(A.L.size() + B.L.size());

    for (const auto & L : A.L) {
        C.L.push_back(L);
    }

    uint32_t offB = (uint32_t)A.L.size();

    for (const auto & Lb : B.L) {
        Layer L = Lb;

        if (L.rule == RRule::PROD) {
            L.pa += offB;
            L.pb += offB;
        }

        C.L.push_back(L);
    }

    C.E.reserve(A.E.size() + B.E.size());

    for (const auto & e : A.E) {
        C.E.push_back(e);
    }

    for (auto e : B.E) {
        e.layer_id += offB;
        C.E.push_back(std::move(e));
    }

    guard_budget(pk, C, "add");

    return C;
}

inline Cipher ct_scale(const PubKey & pk, const Cipher & A, const Fp & s) {
    (void)pk;

    Cipher C = A;

    for (auto & e : C.E) {
        e.w = fp_mul(e.w, s);
    }
    return C;
}

inline Cipher ct_neg(const PubKey & pk, const Cipher & A) {
    return ct_scale(pk, A, fp_neg(fp_from_u64(1)));
}

inline Cipher ct_sub(const PubKey & pk, const Cipher & A, const Cipher & B) {
    return ct_add(pk, A, ct_neg(pk, B));
}

inline Cipher ct_mul(const PubKey & pk, const Cipher & A, const Cipher & B) {
    Cipher C;

    for (const auto & La : A.L) {
        C.L.push_back(La);
    }

    uint32_t offB = (uint32_t)C.L.size();

    for (const auto & Lb : B.L) {
        Layer L = Lb;

        if (L.rule == RRule::PROD) {
            L.pa += offB;
            L.pb += offB;
        }

        C.L.push_back(L);
    }

    uint32_t LA = (uint32_t)A.L.size();
    uint32_t LB = (uint32_t)B.L.size();

    for (uint32_t la = 0; la < LA; la++) {
        for (uint32_t lb = 0; lb < LB; lb++) {
            Layer L;
            L.rule = RRule::PROD;
            L.pa = la;
            L.pb = (uint32_t)(offB + lb);
            C.L.push_back(L);
        }
    }

    int    Bn     = pk.prm.B;
    size_t L_prod = (size_t)LA * LB;

    struct Agg {
        bool hp;
        bool hm;
        Fp wp;
        Fp wm;
        BitVec sp;
        BitVec sm;

        Agg() : hp(false), hm(false) {}
    };

    std::vector<Agg> acc(L_prod * (size_t)Bn);

    for (const auto & ea : A.E) {
        for (const auto & eb : B.E) {
            size_t lid  = (size_t)ea.layer_id * LB + eb.layer_id;
            int idx  = (ea.idx + eb.idx) % Bn;
            bool outP = (ea.ch == eb.ch);

            Agg & a = acc[lid * (size_t)Bn + (size_t)idx];

            if (outP) {
                if (!a.hp) {
                    a.wp = fp_from_u64(0);
                    a.sp = BitVec::make(pk.prm.m_bits);
                    a.hp = true;
                }

                a.wp = fp_add(a.wp, fp_mul(ea.w, eb.w));
                a.sp.xor_with(ea.s);
                a.sp.xor_with(eb.s);
            } else {
                if (!a.hm) {
                    a.wm = fp_from_u64(0);
                    a.sm = BitVec::make(pk.prm.m_bits);
                    a.hm = true;
                }

                a.wm = fp_add(a.wm, fp_mul(ea.w, eb.w));
                a.sm.xor_with(ea.s);
                a.sm.xor_with(eb.s);
            }
        }
    }

    uint32_t base_count = (uint32_t)C.L.size() - (uint32_t)L_prod;

    for (size_t lid = 0; lid < L_prod; lid++) {
        uint32_t real_lid = base_count + (uint32_t)lid;

        for (int k = 0; k < Bn; k++) {
            Agg & a = acc[lid * (size_t)Bn + (size_t)k];

            if (a.hp) {
                Edge e;
                e.layer_id = real_lid;
                e.idx = (uint16_t)k;
                e.ch = SGN_P;
                e.w = a.wp;
                e.s = a.sp;
                C.E.push_back(std::move(e));
            }

            if (a.hm) {
                Edge e;
                e.layer_id = real_lid;
                e.idx = (uint16_t)k;
                e.ch = SGN_M;
                e.w = a.wm;
                e.s = a.sm;
                C.E.push_back(std::move(e));
            }
        }
    }

    guard_budget(pk, C, "mul");

    return C;
}

inline Cipher ct_div_const(const PubKey & pk, const Cipher & A, const Fp & k) {
    Fp inv = fp_inv(k);
    return ct_scale(pk, A, inv);
}


}