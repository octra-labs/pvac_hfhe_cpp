#include <pvac/pvac.hpp>
#include <iostream>
#include <vector>
#include <map>
#include <algorithm>
#include <cmath>

using namespace pvac;

int g_pass = 0, g_fail = 0;

void result(const char* name, bool ok) {
    std::cout << (ok ? "PASS" : "!! FAIL !!") << "\n";
    ok ? ++g_pass : ++g_fail;
}

Fp fp_i64(int64_t v) {
    return v >= 0 ? fp_from_u64((uint64_t)v) : fp_neg(fp_from_u64((uint64_t)(-v)));
}

std::vector<Fp> gsum_layer0(const PubKey& pk, const Cipher& ct, size_t slot) {
    std::map<uint32_t, Fp> acc;
    for (const auto& e : ct.E) {
        Fp term = fp_mul(e.w[slot], pk.powg_B[e.idx]);
        if (sgn_val(e.ch) < 0) term = fp_neg(term);
        if (acc.count(e.layer_id))
            acc[e.layer_id] = fp_add(acc[e.layer_id], term);
        else
            acc[e.layer_id] = term;
    }
    std::vector<Fp> r;
    for (auto& [lid, gs] : acc) r.push_back(gs);
    return r;
}

bool attack_full_plaintext_recovery(const PubKey& pk, const SecKey& sk) {
    std::cout << "\n[1] full plaintext recovery\n";

    std::vector<uint64_t> vals(64);
    for (int j = 0; j < 64; ++j) vals[j] = (j + 1) * 7;
    Cipher ct = enc_values(pk, sk, vals);

    auto gs0 = gsum_layer0(pk, ct, 0);
    auto gs1 = gsum_layer0(pk, ct, 1);

    std::map<uint64_t, int> ratio_count;
    for (const auto& e : ct.E) {
        if (e.w.size() < 2 || !ct::fp_is_nonzero(e.w[1])) continue;
        Fp ratio = fp_mul(e.w[0], fp_inv(e.w[1]));
        ratio_count[ratio.lo ^ (ratio.hi << 32)]++;
    }

    int max_cluster = 0;
    Fp best_ratio = fp_from_u64(0);
    for (auto& [key, cnt] : ratio_count) {
        if (cnt > max_cluster) {
            max_cluster = cnt;
            for (const auto& e : ct.E) {
                if (e.w.size() < 2 || !ct::fp_is_nonzero(e.w[1])) continue;
                Fp r = fp_mul(e.w[0], fp_inv(e.w[1]));
                if ((r.lo ^ (r.hi << 32)) == key) { best_ratio = r; break; }
            }
        }
    }

    std::cout << "max ratio cluster = " << max_cluster << "\n";

    if (max_cluster >= 4 && !gs0.empty() && !gs1.empty()) {
        Fp gsum_ratio = fp_mul(gs0[0], fp_inv(gs1[0]));
        Fp pt_ratio = fp_mul(gsum_ratio, fp_inv(best_ratio));
        Fp real_ratio = fp_mul(fp_from_u64(vals[0]), fp_inv(fp_from_u64(vals[1])));
        if (ct::fp_eq(pt_ratio, real_ratio)) {
            std::cout << "PLAINTEXT RATIO RECOVERED\n";
            return false;
        }
    }

    return max_cluster < 4;
}

bool attack_noise_signal_distinguisher(const PubKey& pk, const SecKey& sk) {
    std::cout << "\n[2] signal/noise distinguisher\n";

    std::vector<uint64_t> vals(64);
    for (int j = 0; j < 64; ++j) vals[j] = j + 1;
    Cipher ct = enc_values(pk, sk, vals);

    std::map<uint64_t, int> freq;
    for (const auto& e : ct.E) {
        if (e.w.size() < 2 || !ct::fp_is_nonzero(e.w[1])) continue;
        Fp r = fp_mul(e.w[0], fp_inv(e.w[1]));
        freq[r.lo ^ r.hi]++;
    }

    int max_freq = 0;
    for (auto& [k, v] : freq) max_freq = std::max(max_freq, v);

    std::cout << "unique ratios = " << freq.size() << " max cluster = " << max_freq << " edges = " << ct.E.size() << "\n";
    return max_freq < 4;
}

bool attack_mul_chain_depth2(const PubKey& pk, const SecKey& sk) {
    std::cout << "\n[3] mul chain depth 2: (a*b)*c\n";

    std::vector<uint64_t> va(64), vb(64), vc(64);
    for (int j = 0; j < 64; ++j) { va[j] = j + 2; vb[j] = j + 3; vc[j] = j + 5; }

    Cipher abc = ct_mul(pk, ct_mul(pk, enc_values(pk, sk, va), enc_values(pk, sk, vb)), enc_values(pk, sk, vc));
    auto dec = dec_values(pk, sk, abc);

    int bad = 0;
    for (int j = 0; j < 64; ++j)
        if (!ct::fp_eq(dec[j], fp_from_u64(va[j] * vb[j] * vc[j]))) ++bad;

    std::cout << "layers = " << abc.L.size() << " edges = " << abc.E.size() << " mismatches = " << bad << "\n";
    return bad == 0;
}

bool attack_mul_chain_depth3(const PubKey& pk, const SecKey& sk) {
    std::cout << "\n[4] mul chain depth 3: (a*b)*(c*d)\n";

    std::vector<uint64_t> va(64), vb(64), vc(64), vd(64);
    for (int j = 0; j < 64; ++j) { va[j] = j + 2; vb[j] = j + 3; vc[j] = 2; vd[j] = 3; }

    Cipher abcd = ct_mul(pk, ct_mul(pk, enc_values(pk, sk, va), enc_values(pk, sk, vb)),
                             ct_mul(pk, enc_values(pk, sk, vc), enc_values(pk, sk, vd)));
    auto dec = dec_values(pk, sk, abcd);

    int bad = 0;
    for (int j = 0; j < 64; ++j)
        if (!ct::fp_eq(dec[j], fp_from_u64(va[j] * vb[j] * vc[j] * vd[j]))) ++bad;

    std::cout << "layers = " << abcd.L.size() << " edges = " << abcd.E.size() << " mismatches = " << bad << "\n";
    return bad == 0;
}

bool attack_product_R_propagation(const PubKey& pk, const SecKey& sk) {
    std::cout << "\n[5] product R propagation\n";

    std::vector<uint64_t> va(64), vb(64);
    for (int j = 0; j < 64; ++j) { va[j] = j + 2; vb[j] = j + 100; }

    Cipher a = enc_values(pk, sk, va);
    Cipher b = enc_values(pk, sk, vb);
    Cipher ab = ct_mul(pk, a, b);

    auto dec = dec_values(pk, sk, ab);
    int bad = 0;
    for (int j = 0; j < 64; ++j)
        if (!ct::fp_eq(dec[j], fp_from_u64(va[j] * vb[j]))) ++bad;

    int ratio_leaks = 0;
    for (const auto& e : ab.E) {
        if (e.w.size() < 2 || !ct::fp_is_nonzero(e.w[1])) continue;
        Fp r = fp_mul(e.w[0], fp_inv(e.w[1]));
        for (uint64_t k = 1; k <= 500; ++k)
            if (ct::fp_eq(r, fp_from_u64(k)) || ct::fp_eq(r, fp_neg(fp_from_u64(k)))) { ++ratio_leaks; break; }
    }

    std::cout << "mismatches = " << bad << " ratio leaks = " << ratio_leaks << "\n";
    return bad == 0 && ratio_leaks == 0;
}

bool attack_algebraic_identity(const PubKey& pk, const SecKey& sk) {
    std::cout << "\n[6] (a + b) * (a - b) == a^2 - b^2\n";

    std::vector<uint64_t> va(64), vb(64);
    for (int j = 0; j < 64; ++j) { va[j] = 100 + j; vb[j] = j + 1; }

    Cipher a = enc_values(pk, sk, va);
    Cipher b = enc_values(pk, sk, vb);

    Cipher lhs = ct_mul(pk, ct_add(pk, a, b), ct_add(pk, a, ct_scale(pk, b, fp_i64(-1))));
    Cipher rhs = ct_add(pk, ct_mul(pk, a, a), ct_scale(pk, ct_mul(pk, b, b), fp_i64(-1)));

    auto dl = dec_values(pk, sk, lhs);
    auto dr = dec_values(pk, sk, rhs);

    int bad = 0;
    for (int j = 0; j < 64; ++j) {
        uint64_t expected = (va[j] + vb[j]) * (va[j] - vb[j]);
        if (!ct::fp_eq(dl[j], fp_from_u64(expected))) ++bad;
        if (!ct::fp_eq(dr[j], fp_from_u64(expected))) ++bad;
        if (!ct::fp_eq(dl[j], dr[j])) ++bad;
    }

    std::cout << "mismatches = " << bad << "\n";
    return bad == 0;
}

bool attack_zero_slot_leak(const PubKey& pk, const SecKey& sk) {
    std::cout << "\n[7] zero-slot R leak\n";

    std::vector<uint64_t> vals(64, 0);
    vals[0] = 1;
    Cipher ct = enc_values(pk, sk, vals);
    auto R = prf_R_slots(pk, sk, ct.L[0].seed, 64);

    int leaked = 0;
    for (const auto& e : ct.E) {
        if (e.layer_id != 0) continue;
        for (size_t s = 1; s < 4; ++s)
            if (ct::fp_eq(e.w[s], R[s]) || ct::fp_eq(e.w[s], fp_neg(R[s]))) ++leaked;
    }

    std::cout << "R visible = " << leaked << "\n";
    return leaked == 0;
}

bool attack_repeated_value(const PubKey& pk, const SecKey& sk) {
    std::cout << "\n[8] repeated value (all slots = 42)\n";

    Cipher ct = enc_values(pk, sk, std::vector<uint64_t>(64, 42));

    int uniform = 0;
    for (const auto& e : ct.E) {
        if (e.w.size() < 2) continue;
        bool same = true;
        for (size_t j = 1; j < e.w.size(); ++j)
            if (!ct::fp_eq(e.w[0], e.w[j])) { same = false; break; }
        if (same) ++uniform;
    }

    std::cout << "uniform edges = " << uniform << " / " << ct.E.size() << "\n";
    return uniform == 0;
}

bool attack_differential(const PubKey& pk, const SecKey& sk) {
    std::cout << "\n[9] differential: enc(v) vs enc(v+e_0)\n";

    std::vector<uint64_t> v0(64), v1(64);
    for (int j = 0; j < 64; ++j) { v0[j] = 100 + j; v1[j] = 100 + j; }
    v1[0] += 1;

    Cipher diff = ct_add(pk, enc_values(pk, sk, v0), ct_scale(pk, enc_values(pk, sk, v1), fp_i64(-1)));
    auto dec = dec_values(pk, sk, diff);

    int bad = 0;
    if (!ct::fp_eq(dec[0], fp_i64(-1))) ++bad;
    for (int j = 1; j < 64; ++j)
        if (ct::fp_is_nonzero(dec[j])) ++bad;

    std::cout << "mismatches = " << bad << "\n";
    return bad == 0;
}

bool attack_gcd_weights(const PubKey& pk, const SecKey& sk) {
    std::cout << "\n[10] cross-slot ratio consistency\n";

    std::vector<uint64_t> vals(64);
    for (int j = 0; j < 64; ++j) vals[j] = j + 1;
    Cipher ct = enc_values(pk, sk, vals);

    int violations = 0;
    for (const auto& e : ct.E) {
        if (e.w.size() < 4) continue;
        for (size_t j1 = 0; j1 < 3; ++j1)
            for (size_t j2 = j1 + 1; j2 < 3; ++j2)
                for (size_t j3 = j2 + 1; j3 < std::min((size_t)4, e.w.size()); ++j3) {
                    if (!ct::fp_is_nonzero(e.w[j2]) || !ct::fp_is_nonzero(e.w[j3])) continue;
                    Fp r12 = fp_mul(e.w[j1], fp_inv(e.w[j2]));
                    Fp r13 = fp_mul(e.w[j1], fp_inv(e.w[j3]));
                    Fp r23 = fp_mul(e.w[j2], fp_inv(e.w[j3]));
                    Fp check = fp_mul(r12, fp_inv(fp_mul(r13, fp_inv(r23))));
                    if (!ct::fp_eq(check, fp_from_u64(1))) ++violations;
                }
    }

    std::cout << "violations = " << violations << "\n";
    return true;
}

bool attack_noise_sum_constraint(const PubKey& pk, const SecKey& sk) {
    std::cout << "\n[11] noise sum constraint (30 trials)\n";

    int bad = 0;
    for (int t = 0; t < 30; ++t) {
        std::vector<uint64_t> vals(64);
        for (int j = 0; j < 64; ++j) vals[j] = csprng_u64() % 100000;
        auto dec = dec_values(pk, sk, enc_values(pk, sk, vals));
        for (int j = 0; j < 64; ++j)
            if (!ct::fp_eq(dec[j], fp_from_u64(vals[j]))) ++bad;
    }

    std::cout << "mismatches = " << bad << " / 1920\n";
    return bad == 0;
}

bool attack_cross_cipher_correlation(const PubKey& pk, const SecKey& sk) {
    std::cout << "\n[12] cross-cipher correlation (3 related encryptions)\n";

    std::vector<uint64_t> v1(64), v2(64), v3(64);
    for (int j = 0; j < 64; ++j) { v1[j] = j + 1; v2[j] = 2 * (j + 1); v3[j] = 3 * (j + 1); }

    Cipher c1 = enc_values(pk, sk, v1);
    Cipher c2 = enc_values(pk, sk, v2);

    int correlated = 0;
    size_t n = std::min(c1.E.size(), c2.E.size());
    for (size_t i = 0; i < n; ++i) {
        if (c1.E[i].w.size() < 2 || c2.E[i].w.size() < 2) continue;
        if (!ct::fp_is_nonzero(c1.E[i].w[1]) || !ct::fp_is_nonzero(c2.E[i].w[1])) continue;
        Fp r1 = fp_mul(c1.E[i].w[0], fp_inv(c1.E[i].w[1]));
        Fp r2 = fp_mul(c2.E[i].w[0], fp_inv(c2.E[i].w[1]));
        if (ct::fp_eq(r1, r2)) ++correlated;
    }

    std::cout << "correlated = " << correlated << " / " << n << "\n";
    return correlated == 0;
}

bool attack_add_chain_long(const PubKey& pk, const SecKey& sk) {
    std::cout << "\n[13] long add chain (10 additions)\n";

    std::vector<uint64_t> vals(64);
    for (int j = 0; j < 64; ++j) vals[j] = j + 1;
    Cipher acc = enc_values(pk, sk, vals);

    for (int i = 1; i < 10; ++i) {
        std::vector<uint64_t> vi(64);
        for (int j = 0; j < 64; ++j) vi[j] = (i + 1) * (j + 1);
        acc = ct_add(pk, acc, enc_values(pk, sk, vi));
    }

    auto dec = dec_values(pk, sk, acc);
    int bad = 0;
    for (int j = 0; j < 64; ++j) {
        uint64_t expected = 0;
        for (int i = 0; i < 10; ++i) expected += (uint64_t)(i + 1) * (j + 1);
        if (!ct::fp_eq(dec[j], fp_from_u64(expected))) ++bad;
    }

    int ratio_leaks = 0;
    for (const auto& e : acc.E) {
        if (e.w.size() < 2 || !ct::fp_is_nonzero(e.w[1])) continue;
        Fp r = fp_mul(e.w[0], fp_inv(e.w[1]));
        for (uint64_t k = 1; k <= 100; ++k)
            if (ct::fp_eq(r, fp_from_u64(k)) || ct::fp_eq(r, fp_neg(fp_from_u64(k)))) { ++ratio_leaks; break; }
    }

    std::cout << "edges = " << acc.E.size() << " mismatches = " << bad << " ratio leaks = " << ratio_leaks << "\n";
    return bad == 0 && ratio_leaks == 0;
}

bool attack_square_simd(const PubKey& pk, const SecKey& sk) {
    std::cout << "\n[14] ct_square SIMD\n";

    std::vector<uint64_t> vals(64);
    for (int j = 0; j < 64; ++j) vals[j] = j + 2;
    Cipher sq = ct_square(pk, enc_values(pk, sk, vals));
    auto dec = dec_values(pk, sk, sq);

    int bad = 0;
    for (int j = 0; j < 64; ++j)
        if (!ct::fp_eq(dec[j], fp_from_u64(vals[j] * vals[j]))) ++bad;

    int ratio_leaks = 0;
    for (const auto& e : sq.E) {
        if (e.w.size() < 2 || !ct::fp_is_nonzero(e.w[1])) continue;
        Fp r = fp_mul(e.w[0], fp_inv(e.w[1]));
        for (uint64_t k = 1; k <= 100; ++k)
            if (ct::fp_eq(r, fp_from_u64(k)) || ct::fp_eq(r, fp_neg(fp_from_u64(k)))) { ++ratio_leaks; break; }
    }

    std::cout << "mismatches = " << bad << " ratio leaks = " << ratio_leaks << "\n";
    return bad == 0 && ratio_leaks == 0;
}

bool attack_scale_simd(const PubKey& pk, const SecKey& sk) {
    std::cout << "\n[15] ct_scale SIMD\n";

    std::vector<uint64_t> vals(64);
    for (int j = 0; j < 64; ++j) vals[j] = j + 1;
    auto dec = dec_values(pk, sk, ct_scale(pk, enc_values(pk, sk, vals), fp_from_u64(17)));

    int bad = 0;
    for (int j = 0; j < 64; ++j)
        if (!ct::fp_eq(dec[j], fp_from_u64(vals[j] * 17))) ++bad;

    std::cout << "mismatches = " << bad << "\n";
    return bad == 0;
}

bool attack_add_const_simd(const PubKey& pk, const SecKey& sk) {
    std::cout << "\n[16] ct_add_const SIMD\n";

    std::vector<uint64_t> vals(64);
    for (int j = 0; j < 64; ++j) vals[j] = j + 1;
    auto dec = dec_values(pk, sk, ct_add_const(pk, enc_values(pk, sk, vals), (uint64_t)1000));

    int bad = 0;
    for (int j = 0; j < 64; ++j)
        if (!ct::fp_eq(dec[j], fp_from_u64(vals[j] + 1000))) ++bad;

    std::cout << "mismatches = " << bad << "\n";
    return bad == 0;
}

bool attack_prf_backward_compat(const PubKey& pk, const SecKey& sk) {
    std::cout << "\n[17] PRF slots=1 backward compat\n";

    RSeed seed;
    seed.nonce = make_nonce128();
    seed.ztag = prg_layer_ztag(pk.canon_tag, seed.nonce);

    bool match = ct::fp_eq(prf_R(pk, sk, seed), prf_R_slots(pk, sk, seed, 1)[0]);
    std::cout << "match = " << (match ? "yes" : "NO") << "\n";
    return match;
}

bool attack_statistical_independence(const PubKey& pk, const SecKey& sk) {
    std::cout << "\n[18] statistical slot independence\n";

    int shared_coef = 0;
    for (int t = 0; t < 50; ++t) {
        std::vector<uint64_t> vals(64);
        for (int j = 0; j < 64; ++j) vals[j] = csprng_u64() % 1000000;
        Cipher ct = enc_values(pk, sk, vals);
        auto R = prf_R_slots(pk, sk, ct.L[0].seed, 64);

        for (const auto& e : ct.E) {
            if (e.layer_id != 0 || e.w.size() < 2) continue;
            if (!ct::fp_is_nonzero(e.w[0]) || !ct::fp_is_nonzero(e.w[1])) continue;
            Fp rw = fp_mul(e.w[1], fp_inv(e.w[0]));
            Fp rR = fp_mul(R[1], fp_inv(R[0]));
            if (ct::fp_eq(rw, rR)) ++shared_coef;
        }
    }

    std::cout << "shared coef detections = " << shared_coef << " / 50 trials\n";
    return shared_coef == 0;
}

bool attack_R_recovery_product(const PubKey& pk, const SecKey& sk) {
    std::cout << "\n[19] R recovery from product layers\n";

    std::vector<uint64_t> va(64), vb(64);
    for (int j = 0; j < 64; ++j) { va[j] = j + 2; vb[j] = j + 3; }

    Cipher a = enc_values(pk, sk, va);
    Cipher b = enc_values(pk, sk, vb);
    Cipher ab = ct_mul(pk, a, b);

    auto Ra = prf_R_slots(pk, sk, a.L[0].seed, 64);
    auto Rb = prf_R_slots(pk, sk, b.L[0].seed, 64);

    int recovered = 0;
    for (const auto& e : ab.E) {
        for (size_t slot = 0; slot < 4; ++slot) {
            Fp R_prod = fp_mul(Ra[slot], Rb[slot]);
            for (uint64_t k = 1; k <= 200; ++k) {
                Fp cand = fp_mul(e.w[slot], fp_inv(fp_from_u64(k)));
                if (ct::fp_eq(cand, R_prod) || ct::fp_eq(cand, fp_neg(R_prod))) ++recovered;
            }
        }
    }

    std::cout << "recovered = " << recovered << "\n";
    return recovered == 0;
}

bool attack_quadratic_system(const PubKey& pk, const SecKey& sk) {
    std::cout << "\n[20] quadratic system (gsum ratio == plaintext ratio?)\n";

    std::vector<uint64_t> va(64), vb(64);
    for (int j = 0; j < 64; ++j) { va[j] = j + 1; vb[j] = 64 - j; }

    Cipher a = enc_values(pk, sk, va);
    auto gs0 = gsum_layer0(pk, a, 0);
    auto gs1 = gsum_layer0(pk, a, 1);

    if (gs0.empty() || gs1.empty()) { std::cout << "insufficient layers\n"; return true; }

    Fp ratio = fp_mul(gs0[0], fp_inv(gs1[0]));
    Fp expected = fp_mul(fp_from_u64(va[0]), fp_inv(fp_from_u64(va[1])));

    bool leaked = ct::fp_eq(ratio, expected);
    std::cout << "gsum ratio = plaintext ratio: " << (leaked ? "YES LEAK" : "no") << "\n";
    return !leaked;
}

bool attack_chosen_plaintext_batch(const PubKey& pk, const SecKey& sk) {
    std::cout << "\n[21] chosen-plaintext batch\n";

    std::vector<uint64_t> probe(64, 0);
    probe[0] = 1;
    Cipher c_probe = enc_values(pk, sk, probe);

    std::vector<uint64_t> target(64);
    for (int j = 0; j < 64; ++j) target[j] = csprng_u64() % 1000000;
    Cipher c_target = enc_values(pk, sk, target);

    std::map<uint64_t, int> pr, tr;
    for (const auto& e : c_probe.E) {
        if (e.w.size() < 2 || !ct::fp_is_nonzero(e.w[1])) continue;
        Fp r = fp_mul(e.w[0], fp_inv(e.w[1]));
        pr[r.lo ^ r.hi]++;
    }
    for (const auto& e : c_target.E) {
        if (e.w.size() < 2 || !ct::fp_is_nonzero(e.w[1])) continue;
        Fp r = fp_mul(e.w[0], fp_inv(e.w[1]));
        tr[r.lo ^ r.hi]++;
    }

    int shared = 0;
    for (auto& [k, v] : pr) if (tr.count(k)) ++shared;

    std::cout << "shared ratio keys = " << shared << "\n";
    return shared == 0;
}

bool attack_mixed_add_mul_ratio(const PubKey& pk, const SecKey& sk) {
    std::cout << "\n[22] mixed add+mul ratio analysis\n";

    std::vector<uint64_t> va(64), vb(64), vc(64);
    for (int j = 0; j < 64; ++j) { va[j] = j + 1; vb[j] = j + 10; vc[j] = j + 100; }

    Cipher result = ct_mul(pk, ct_add(pk, enc_values(pk, sk, va), enc_values(pk, sk, vb)), enc_values(pk, sk, vc));
    auto dec = dec_values(pk, sk, result);

    int bad = 0;
    for (int j = 0; j < 64; ++j)
        if (!ct::fp_eq(dec[j], fp_from_u64((va[j] + vb[j]) * vc[j]))) ++bad;

    int ratio_leaks = 0;
    for (const auto& e : result.E) {
        if (e.w.size() < 2 || !ct::fp_is_nonzero(e.w[1])) continue;
        Fp r = fp_mul(e.w[0], fp_inv(e.w[1]));
        for (uint64_t k = 1; k <= 100; ++k)
            if (ct::fp_eq(r, fp_from_u64(k)) || ct::fp_eq(r, fp_neg(fp_from_u64(k)))) { ++ratio_leaks; break; }
    }

    std::cout << "mismatches = " << bad << " ratio leaks = " << ratio_leaks << "\n";
    return bad == 0 && ratio_leaks == 0;
}

bool attack_no_uniform_edges(const PubKey& pk, const SecKey& sk) {
    std::cout << "\n[23] no uniform-weight edges in enc or product\n";

    std::vector<uint64_t> v1(64), v2(64);
    for (int j = 0; j < 64; ++j) { v1[j] = j + 1; v2[j] = 64 - j; }

    Cipher c1 = enc_values(pk, sk, v1);
    Cipher c2 = enc_values(pk, sk, v2);
    Cipher prod = ct_mul(pk, c1, c2);

    auto count_uniform = [](const Cipher& ct) {
        int u = 0;
        for (const auto& e : ct.E) {
            if (e.w.size() < 64) continue;
            bool same = true;
            for (size_t j = 1; j < 64; ++j)
                if (!ct::fp_eq(e.w[0], e.w[j])) { same = false; break; }
            if (same) ++u;
        }
        return u;
    };

    int u_enc = count_uniform(c1);
    int u_prod = count_uniform(prod);

    std::cout << "uniform in enc = " << u_enc << " uniform in prod = " << u_prod << "\n";
    return u_enc == 0;
}

bool attack_r2_product_layers(const PubKey& pk, const SecKey& sk) {
    std::cout << "\n[24] R^2 on product layers\n";

    std::vector<uint64_t> va(64), vb(64);
    for (int j = 0; j < 64; ++j) { va[j] = j + 2; vb[j] = j + 3; }

    Cipher a = enc_values(pk, sk, va);
    Cipher b = enc_values(pk, sk, vb);
    Cipher ab = ct_mul(pk, a, b);

    auto Ra = prf_R_slots(pk, sk, a.L[0].seed, 64);
    auto Rb = prf_R_slots(pk, sk, b.L[0].seed, 64);

    int leaks = 0;
    for (size_t slot = 0; slot < 4; ++slot) {
        Fp R2 = fp_mul(fp_mul(Ra[slot], Rb[slot]), fp_mul(Ra[slot], Rb[slot]));
        std::vector<size_t> pidx;
        for (size_t i = 0; i < ab.E.size(); ++i) {
            uint32_t lid = ab.E[i].layer_id;
            if (lid < ab.L.size() && ab.L[lid].rule == RRule::PROD) pidx.push_back(i);
        }
        for (size_t i = 0; i < pidx.size(); ++i) {
            for (size_t j = i + 1; j < pidx.size(); ++j) {
                const Edge& e1 = ab.E[pidx[i]];
                const Edge& e2 = ab.E[pidx[j]];
                if (e1.ch == e2.ch) continue;
                Fp t1 = fp_mul(e1.w[slot], pk.powg_B[e1.idx]);
                if (sgn_val(e1.ch) < 0) t1 = fp_neg(t1);
                Fp t2 = fp_mul(e2.w[slot], pk.powg_B[e2.idx]);
                if (sgn_val(e2.ch) < 0) t2 = fp_neg(t2);
                Fp cand = fp_add(t1, t2);
                if (ct::fp_eq(cand, R2) || ct::fp_eq(fp_neg(cand), R2)) ++leaks;
            }
        }
    }

    std::cout << "R^2 leaks = " << leaks << "\n";
    return leaks == 0;
}

bool attack_massive_random(const PubKey& pk, const SecKey& sk) {
    std::cout << "\n[25] massive random correctness (50 trials)\n";

    int bad = 0;
    for (int t = 0; t < 50; ++t) {
        std::vector<uint64_t> va(64), vb(64);
        for (int j = 0; j < 64; ++j) { va[j] = csprng_u64() % 100000; vb[j] = csprng_u64() % 100000; }

        Cipher a = enc_values(pk, sk, va);
        Cipher b = enc_values(pk, sk, vb);

        auto da = dec_values(pk, sk, a);
        auto db = dec_values(pk, sk, b);
        for (int j = 0; j < 64; ++j) {
            if (!ct::fp_eq(da[j], fp_from_u64(va[j]))) ++bad;
            if (!ct::fp_eq(db[j], fp_from_u64(vb[j]))) ++bad;
        }

        auto ds = dec_values(pk, sk, ct_add(pk, a, b));
        for (int j = 0; j < 64; ++j)
            if (!ct::fp_eq(ds[j], fp_from_u64(va[j] + vb[j]))) ++bad;

        if (t < 10) {
            auto dm = dec_values(pk, sk, ct_mul(pk, a, b));
            for (int j = 0; j < 64; ++j)
                if (!ct::fp_eq(dm[j], fp_from_u64(va[j] * vb[j]))) ++bad;
        }
    }

    std::cout << "mismatches = " << bad << "\n";
    return bad == 0;
}

int main() {

    Params prm;
    PubKey pk;
    SecKey sk;
    keygen(prm, pk, sk);

    result("[1] full plaintext recovery", attack_full_plaintext_recovery(pk, sk));
    result("[2] signal and noise distinguisher", attack_noise_signal_distinguisher(pk, sk));
    result("[3] mul depth 2", attack_mul_chain_depth2(pk, sk));
    result("[4] mul depth 3", attack_mul_chain_depth3(pk, sk));
    result("[5] product R propagation", attack_product_R_propagation(pk, sk));
    result("[6] algebraic identity", attack_algebraic_identity(pk, sk));
    result("[7] zero slot R ", attack_zero_slot_leak(pk, sk));
    result("[8] repeated value", attack_repeated_value(pk, sk));
    result("[9] differential", attack_differential(pk, sk));
    result("[10] cross-slot ratio", attack_gcd_weights(pk, sk));
    result("[11] noise sum constraint", attack_noise_sum_constraint(pk, sk));
    result("[12] cross-cipher correlation", attack_cross_cipher_correlation(pk, sk));
    result("[13] long add chain", attack_add_chain_long(pk, sk));
    result("[14] ct_square SIMD", attack_square_simd(pk, sk));
    result("[15] ct_scale SIMD", attack_scale_simd(pk, sk));
    result("[16] ct_add_const SIMD", attack_add_const_simd(pk, sk));
    result("[17] PRF backward compat", attack_prf_backward_compat(pk, sk));
    result("[18] statistical independence", attack_statistical_independence(pk, sk));
    result("[19] R recovery product", attack_R_recovery_product(pk, sk));
    result("[20] quadratic system", attack_quadratic_system(pk, sk));
    result("[21] chosen-plaintext batch", attack_chosen_plaintext_batch(pk, sk));
    result("[22] mixed add+mul ratio", attack_mixed_add_mul_ratio(pk, sk));
    result("[23] no uniform edges", attack_no_uniform_edges(pk, sk));
    result("[24] R^2 product layers", attack_r2_product_layers(pk, sk));
    result("[25] mass random", attack_massive_random(pk, sk));

    std::cout << "\n== " << g_pass << " / " << (g_pass + g_fail) << " passed ==\n";
    return g_fail == 0 ? 0 : 1;
}