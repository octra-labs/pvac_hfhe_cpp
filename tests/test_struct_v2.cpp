#include <pvac/pvac.hpp>
#include <iostream>
#include <vector>
#include <unordered_map>
#include <cstdint>

using namespace pvac;

bool test_signal_noise(const PubKey& pk, const std::vector<Edge>& E0) {
    std::cout << "\n[1] signal/noise separation\n";

    int n = (int)E0.size();
    if (n < 8 || n > 40) {
        std::cout << "skip (n = " << n << ")\n";
        return true;
    }

    Fp total = fp_from_u64(0);
    std::vector<Fp> terms(n);
    for (int i = 0; i < n; ++i) {
        Fp t = fp_mul(E0[i].w[0], pk.powg_B[E0[i].idx]);
        terms[i] = (sgn_val(E0[i].ch) > 0) ? t : fp_neg(t);
        total = fp_add(total, terms[i]);
    }

    constexpr int k = 8;
    std::vector<int> comb(k);
    for (int i = 0; i < k; ++i) comb[i] = i;

    uint64_t hits = 0;
    do {
        Fp acc = fp_from_u64(0);
        for (int i = 0; i < k; ++i)
            acc = fp_add(acc, terms[comb[i]]);
        if (ct::fp_eq(acc, total)) ++hits;

        int i = k - 1;
        while (i >= 0 && comb[i] == i + n - k) --i;
        if (i < 0) break;
        ++comb[i];
        for (int j = i + 1; j < k; ++j) comb[j] = comb[j-1] + 1;
    } while (true);

    std::cout << "hits = " << hits << "\n";
    return hits == 0;
}

bool test_weight_zero(const std::vector<Edge>& E0) {
    std::cout << "\n[2] weight zero-sum\n";

    int n = (int)E0.size();
    if (n < 8 || n > 40) {
        std::cout << "skip\n";
        return true;
    }

    constexpr int k = 8;
    std::vector<int> comb(k);
    for (int i = 0; i < k; ++i) comb[i] = i;

    uint64_t zeros = 0;
    do {
        Fp acc = fp_from_u64(0);
        for (int i = 0; i < k; ++i) {
            const auto& e = E0[comb[i]];
            acc = (sgn_val(e.ch) > 0) ? fp_add(acc, e.w[0]) : fp_sub(acc, e.w[0]);
        }
        if (!ct::fp_is_nonzero(acc)) ++zeros;

        int i = k - 1;
        while (i >= 0 && comb[i] == i + n - k) --i;
        if (i < 0) break;
        ++comb[i];
        for (int j = i + 1; j < k; ++j) comb[j] = comb[j-1] + 1;
    } while (true);

    std::cout << "zeros = " << zeros << "\n";
    return zeros == 0;
}

bool test_gcd(const std::vector<Edge>& E0) {
    std::cout << "\n[3] gcd attack\n";

    int n = (int)E0.size();
    if (n < 2) {
        std::cout << "skip\n";
        return true;
    }

    std::vector<Fp> W;
    for (const auto& e : E0) W.push_back(e.w[0]);

    int suspicious = 0;
    for (size_t i = 0; i < W.size(); ++i) {
        for (size_t j = i + 1; j < W.size(); ++j) {
            Fp ratio = fp_mul(W[i], fp_inv(W[j]));

            for (uint64_t k = 1; k <= 100; ++k) {
                if (ct::fp_eq(ratio, fp_from_u64(k)) ||
                    ct::fp_eq(ratio, fp_neg(fp_from_u64(k)))) {
                    std::cout << "w[" << i << "] / w[" << j << "] = " << k << "\n";
                    ++suspicious;
                }
                Fp inv = fp_inv(ratio);
                if (ct::fp_eq(inv, fp_from_u64(k)) ||
                    ct::fp_eq(inv, fp_neg(fp_from_u64(k)))) {
                    std::cout << "w[" << j << "] / w[" << i << "] = " << k << "\n";
                    ++suspicious;
                }
            }
        }
    }

    std::cout << "suspicious = " << suspicious << "\n";
    return suspicious == 0;
}

bool test_linear(const std::vector<Edge>& E0) {
    std::cout << "\n[4] linear relations\n";

    int n = (int)E0.size();
    if (n < 3) {
        std::cout << "skip\n";
        return true;
    }

    std::vector<Fp> W;
    for (const auto& e : E0) W.push_back(e.w[0]);

    int relations = 0;
    constexpr int M = 10;

    for (int i = 0; i < n && i < 15; ++i) {
        for (int j = i + 1; j < n && j < 15; ++j) {
            for (int k = j + 1; k < n && k < 15; ++k) {
                for (int a = -M; a <= M; ++a) {
                    if (a == 0) continue;
                    for (int b = -M; b <= M; ++b) {
                        if (b == 0) continue;
                        for (int c = -M; c <= M; ++c) {
                            if (c == 0) continue;

                            Fp sum = fp_from_u64(0);
                            Fp ta = (a > 0) ? fp_from_u64(a) : fp_neg(fp_from_u64(-a));
                            Fp tb = (b > 0) ? fp_from_u64(b) : fp_neg(fp_from_u64(-b));
                            Fp tc = (c > 0) ? fp_from_u64(c) : fp_neg(fp_from_u64(-c));

                            sum = fp_add(sum, fp_mul(ta, W[i]));
                            sum = fp_add(sum, fp_mul(tb, W[j]));
                            sum = fp_add(sum, fp_mul(tc, W[k]));

                            if (!ct::fp_is_nonzero(sum)) {
                                std::cout << a << "*w[" << i << "] + " << b << "*w[" << j << "] + " << c << "*w[" << k << "] = 0\n";
                                ++relations;
                            }
                        }
                    }
                }
            }
        }
    }

    std::cout << "relations = " << relations << "\n";
    return relations == 0;
}

bool test_idx_dist(const std::vector<Edge>& E0) {
    std::cout << "\n[5] index distribution\n";

    std::unordered_map<int, int> cnt;
    for (const auto& e : E0) cnt[e.idx]++;

    int max_reuse = 0;
    for (const auto& kv : cnt) {
        if (kv.second > max_reuse) max_reuse = kv.second;
    }

    std::cout << "unique = " << cnt.size() << " / " << E0.size() << ", max = " << max_reuse << "\n";
    return max_reuse <= 2;
}

bool test_cross_layer(const Cipher& ct) {
    std::cout << "\n[6] cross-layer r\n";

    if (ct.L.size() < 2) {
        std::cout << "skip\n";
        return true;
    }

    std::vector<std::vector<Edge>> by_layer(ct.L.size());
    for (const auto& e : ct.E) {
        if (e.layer_id < ct.L.size())
            by_layer[e.layer_id].push_back(e);
    }

    int suspicious = 0;
    for (size_t l1 = 0; l1 < ct.L.size(); ++l1) {
        for (size_t l2 = l1 + 1; l2 < ct.L.size(); ++l2) {
            if (by_layer[l1].empty() || by_layer[l2].empty()) continue;

            Fp w1 = by_layer[l1][0].w[0];
            Fp w2 = by_layer[l2][0].w[0];
            Fp ratio = fp_mul(w1, fp_inv(w2));

            for (uint64_t k = 1; k <= 1000; ++k) {
                if (ct::fp_eq(ratio, fp_from_u64(k)) ||
                    ct::fp_eq(ratio, fp_neg(fp_from_u64(k))) ||
                    ct::fp_eq(fp_inv(ratio), fp_from_u64(k)) ||
                    ct::fp_eq(fp_inv(ratio), fp_neg(fp_from_u64(k)))) {
                    std::cout << "r[" << l1 << "] / r[" << l2 << "] ~ " << k << "\n";
                    ++suspicious;
                }
            }
        }
    }

    std::cout << "suspicious = " << suspicious << "\n";
    return suspicious == 0;
}

bool test_prf_unique(const PubKey& pk, const SecKey& sk) {
    std::cout << "\n[7] prf uniqueness\n";

    std::vector<Cipher> cts;
    for (int i = 0; i < 10; ++i)
        cts.push_back(enc_value(pk, sk, 42));

    std::vector<Fp> W;
    for (const auto& c : cts) {
        if (!c.E.empty()) W.push_back(c.E[0].w[0]);
    }

    int collisions = 0;
    for (size_t i = 0; i < W.size(); ++i) {
        for (size_t j = i + 1; j < W.size(); ++j) {
            if (ct::fp_eq(W[i], W[j])) {
                std::cout << "collision ct[" << i << "] = ct[" << j << "]\n";
                ++collisions;
            }
        }
    }

    std::cout << "collisions = " << collisions << "\n";
    return collisions == 0;
}

bool test_r_recovery(const PubKey& pk, const SecKey& sk, const Cipher& ct) {
    std::cout << "\n[8] r recovery\n";

    std::vector<Edge> E0;
    for (const auto& e : ct.E) {
        if (e.layer_id == 0) E0.push_back(e);
    }

    if (E0.size() < 2) {
        std::cout << "skip\n";
        return true;
    }

    Fp real_R = prf_R(pk, sk, ct.L[0].seed);

    int recovered = 0;
    for (size_t i = 0; i < E0.size() && i < 10; ++i) {
        for (uint64_t k = 1; k <= 100; ++k) {
            Fp cand = fp_mul(E0[i].w[0], fp_inv(fp_from_u64(k)));
            if (ct::fp_eq(cand, real_R)) {
                std::cout << "recovered via w[" << i << "] / " << k << "\n";
                ++recovered;
            }
            cand = fp_mul(E0[i].w[0], fp_inv(fp_neg(fp_from_u64(k))));
            if (ct::fp_eq(cand, real_R)) {
                std::cout << "recovered via w[" << i << "] / (-" << k << ")\n";
                ++recovered;
            }
        }
    }

    std::cout << "recovered = " << recovered << "\n";
    return recovered == 0;
}

bool test_delta_neq_r(const PubKey& pk, const SecKey& sk) {
    std::cout << "\n[9] delta != r (regression)\n";

    int collisions = 0;
    constexpr int N = 100;
    constexpr int G = 32;

    for (int t = 0; t < N; ++t) {
        RSeed seed;
        seed.nonce = make_nonce128();
        seed.ztag = prg_layer_ztag(pk.canon_tag, seed.nonce);

        Fp R = prf_R(pk, sk, seed);

        for (int gid = 0; gid < G; ++gid) {
            for (uint8_t kind = 0; kind < 2; ++kind) {
                Fp delta = prf_noise_delta(pk, sk, seed, (uint32_t)gid, kind);
                if (ct::fp_eq(delta, R)) {
                    std::cout << "delta(" << gid << "," << (int)kind << ") = R at trial " << t << "\n";
                    ++collisions;
                }
                if (ct::fp_eq(delta, fp_neg(R))) {
                    std::cout << "delta(" << gid << "," << (int)kind << ") = -R at trial " << t << "\n";
                    ++collisions;
                }
            }
        }
    }

    std::cout << "collisions = " << collisions << " / " << (N * G * 2) << "\n";
    return collisions == 0;
}

bool test_noise_sum_nonzero(const PubKey& pk, const SecKey& sk) {
    std::cout << "\n[10] noise sum != 0 (structure regression)\n";

    int zeros = 0;
    constexpr int N = 100;

    for (int t = 0; t < N; ++t) {
        RSeed seed;
        seed.nonce = make_nonce128();
        seed.ztag = prg_layer_ztag(pk.canon_tag, seed.nonce);

        auto [Z2, Z3] = plan_noise(pk, 0);
        int total = Z2 + Z3;

        Fp delta_sum = fp_from_u64(0);
        for (int gid = 0; gid < total; ++gid) {
            uint8_t kind = (gid < Z2) ? 0 : 1;
            Fp d = prf_noise_delta(pk, sk, seed, (uint32_t)gid, kind);
            delta_sum = fp_add(delta_sum, d);
        }

        if (!ct::fp_is_nonzero(delta_sum)) {
            std::cout << "delta_sum = 0 at trial " << t << "\n";
            ++zeros;
        }
    }

    std::cout << "zeros = " << zeros << " / " << N << "\n";
    return zeros == 0;
}

bool test_multi_enc_struct(const PubKey& pk, const SecKey& sk) {
    std::cout << "\n[11] multi-enc structure (n = 50)\n";

    int fail_count = 0;
    constexpr int RUNS = 50;

    for (int run = 0; run < RUNS; ++run) {
        Cipher ct = enc_value(pk, sk, 123456789 + run);

        std::vector<Edge> E0;
        for (const auto& e : ct.E) {
            if (e.layer_id == 0) E0.push_back(e);
        }

        int n = (int)E0.size();
        if (n < 8 || n > 40) continue;

        Fp total = fp_from_u64(0);
        std::vector<Fp> terms(n);
        for (int i = 0; i < n; ++i) {
            Fp t = fp_mul(E0[i].w[0], pk.powg_B[E0[i].idx]);
            terms[i] = (sgn_val(E0[i].ch) > 0) ? t : fp_neg(t);
            total = fp_add(total, terms[i]);
        }

        constexpr int k = 8;
        std::vector<int> comb(k);
        for (int i = 0; i < k; ++i) comb[i] = i;

        bool found_hit = false;
        do {
            Fp acc = fp_from_u64(0);
            for (int i = 0; i < k; ++i)
                acc = fp_add(acc, terms[comb[i]]);
            if (ct::fp_eq(acc, total)) {
                found_hit = true;
                break;
            }

            int i = k - 1;
            while (i >= 0 && comb[i] == i + n - k) --i;
            if (i < 0) break;
            ++comb[i];
            for (int j = i + 1; j < k; ++j) comb[j] = comb[j-1] + 1;
        } while (true);

        if (found_hit) {
            std::cout << "hit at run " << run << "\n";
            ++fail_count;
        }
    }

    std::cout << "failures = " << fail_count << " / " << RUNS << "\n";
    return fail_count == 0;
}

bool test_delta_domain_separation(const PubKey& pk, const SecKey& sk) {
    std::cout << "\n[12] delta domain separation\n";

    RSeed seed;
    seed.nonce = make_nonce128();
    seed.ztag = prg_layer_ztag(pk.canon_tag, seed.nonce);

    constexpr int G = 256;
    std::vector<Fp> kind0(G), kind1(G);

    for (int gid = 0; gid < G; ++gid) {
        kind0[gid] = prf_noise_delta(pk, sk, seed, (uint32_t)gid, 0);
        kind1[gid] = prf_noise_delta(pk, sk, seed, (uint32_t)gid, 1);
    }

    int dup_k0 = 0, dup_k1 = 0, cross = 0;

    for (int i = 0; i < G; ++i) {
        for (int j = i + 1; j < G; ++j) {
            if (ct::fp_eq(kind0[i], kind0[j])) ++dup_k0;
            if (ct::fp_eq(kind1[i], kind1[j])) ++dup_k1;
        }
        for (int j = 0; j < G; ++j) {
            if (ct::fp_eq(kind0[i], kind1[j])) ++cross;
        }
    }

    std::cout << "dup kind0 = " << dup_k0 << ", dup kind1 = " << dup_k1 << ", cross = " << cross << "\n";
    return (dup_k0 == 0) && (dup_k1 == 0) && (cross == 0);
}

int main() {
    Params prm;
    PubKey pk;
    SecKey sk;
    keygen(prm, pk, sk);

    Cipher ct = enc_value(pk, sk, 123456789);

    std::vector<Edge> E0;
    for (const auto& e : ct.E) {
        if (e.layer_id == 0) E0.push_back(e);
    }

    std::cout << "layers = " << ct.L.size() << ", edges = " << ct.E.size() << ", l0 = " << E0.size() << "\n";

    int pass = 0, fail = 0;

    auto run = [&](bool ok) {
        std::cout << (ok ? "pass" : "FAIL") << "\n";
        ok ? ++pass : ++fail;
    };

    run(test_signal_noise(pk, E0));
    run(test_weight_zero(E0));
    run(test_gcd(E0));
    run(test_linear(E0));
    run(test_idx_dist(E0));
    run(test_cross_layer(ct));
    run(test_prf_unique(pk, sk));
    run(test_r_recovery(pk, sk, ct));
    run(test_delta_neq_r(pk, sk));
    run(test_noise_sum_nonzero(pk, sk));
    run(test_multi_enc_struct(pk, sk));
    run(test_delta_domain_separation(pk, sk));

    std::cout << "\n== " << pass << " / " << (pass + fail) << " passed ==\n";
    return (fail == 0) ? 0 : 1;
}