#include <iostream>
#include <iomanip>
#include <vector>
#include <cmath>
#include <map>
#include <chrono>
#include <random>

#include <pvac/pvac.hpp>

using namespace pvac;

static std::mt19937_64 g_rng(42);

static void must(bool cond, const char* msg, const PubKey* pk = nullptr, const Cipher* C = nullptr) {
    if (!cond) {
        std::cerr << "[fail] " << msg << "\n";

        if (pk && C) 
        {std::cerr << " e = " << C->E.size() << " L = " << C->L.size()
                      << " dens = " << sigma_density(*pk, *C) << "\n";
        }

        std::abort();
    }
}

inline int hw64(uint64_t x) { return __builtin_popcountll(x); }

int hw_bv(const BitVec& v) {
    int s = 0;
    for (auto w : v.w) s += hw64(w);
    return s;
}

double shannon(const std::map<uint64_t, int>& freq, int total) {
    if (total == 0) return 0.0;
    double H = 0.0;
    for (auto& [val, cnt] : freq) 
    {
        if (cnt > 0) {
            double p = (double)cnt / total;
            H -= p * std::log2(p);
        }
    }
    return H;
}

double w_ent(const Cipher& c) {
    std::map<uint64_t, int> freq;
    for (const auto& e : c.E) freq[e.w.lo & 0xFFFF]++;
    return shannon(freq, (int)c.E.size());
}

double s_byte_ent(const Cipher& c) {
    std::map<uint64_t, int> freq;
    int total = 0;
    for (const auto& e : c.E) {
        for (auto w : e.s.w) {
            for (int i = 0; i < 8; i++) {
                freq[(w >> (i * 8)) & 0xFF]++;
                total++;
            }
        }
    }
    return shannon(freq, total);
}




/// @brief 
/// @param c 
/// @return 
double avg_s_hw(const Cipher& c) {
    if (c.E.empty()) return 0.0;
    double sum = 0.0;
    for (const auto& e : c.E) sum += hw_bv(e.s);
    return sum / c.E.size();
}

double bit_bal(const Cipher& c) 
{
    uint64_t ones = 0, total = 0;

    for (const auto& e : c.E) {
        for (auto w : e.s.w) {
            ones += hw64(w);
            total += 64;
        }
    }
    return total > 0 ? (double)ones / total : 0.5;
}

double ct_corr(const Cipher& c1, const Cipher& c2) {
    size_t n = std::min(c1.E.size(), c2.E.size());
    if (n == 0) return 0.0;
    double sum = 0.0;
    for (size_t i = 0; i < n; i++) {
        const auto& s1 = c1.E[i].s;
        const auto& s2 = c2.E[i].s;
        size_t m = std::min(s1.w.size(), s2.w.size());
        int xor_hw = 0;
        for (size_t j = 0; j < m; j++) xor_hw += hw64(s1.w[j] ^ s2.w[j]);
        sum += xor_hw;
    }
    return sum / n;
}

std::map<uint32_t, int> layer_dist(const Cipher& c) {
    std::map<uint32_t, int> d;
    for (const auto& e : c.E) d[e.layer_id]++;
    return d;
}

double lpn_sec(int n, double tau) {
    double H_tau = -tau * std::log2(tau) - (1 - tau) * std::log2(1 - tau);
    return n * H_tau;
}

size_t ct_mem(const Cipher& c) {
    size_t sz = sizeof(Cipher);
    sz += c.L.size() * sizeof(Layer);
    for (const auto& e : c.E) {
        sz += sizeof(Edge);
        sz += e.s.w.size() * sizeof(uint64_t);
    }
    return sz;
}




void pr_analysis(const std::string& name, const Cipher& c) {
    std::cout << "   " << name << ": e = " << c.E.size() << " L = " << c.L.size() 

              << " bal = " << std::fixed << std::setprecision(2) << bit_bal(c)
              << " s_ent = " << s_byte_ent(c) << " mem = " << ct_mem(c) << " b\n";
}

template<typename F>
double bench_us(F&& f, int iters = 1) {
    auto t0 = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < iters; i++) f();
    auto t1 = std::chrono::high_resolution_clock::now();
    return std::chrono::duration<double, std::micro>(t1 - t0).count() / iters;
}

int main() {
    std::cout << std::dec << std::fixed << std::setprecision(4);

    Params prm;
    PubKey pk;
    SecKey sk;
    
    keygen(prm, pk, sk);

    std::cout << "- pvac_hfhe test  -\n\n";

    
    double tau = (double)pk.prm.lpn_tau_num / pk.prm.lpn_tau_den;
    std::cout << "lpn: n = " << pk.prm.lpn_n << " t = " << pk.prm.lpn_t << " tau = " << tau;
        std::cout << " sec ~ " << lpn_sec(pk.prm.lpn_n, tau) << " b\n";

        std::cout << "H = 0x" << hex8(pk.H_digest.data(), 8) << " m = " << pk.prm.m_bits 
                << " n = " << pk.prm.n_bits << " B = " << pk.prm.B << "\n\n";

    EvalKey ek = make_evalkey(pk, sk, 32, 3);

    uint64_t x = 2016733, y = 7083881, z = 13579;

    Cipher X = enc_value(pk, sk, x);
    Cipher Y = enc_value(pk, sk, y);
    Cipher Zc = enc_value(pk, sk, z);

    std::cout << "- basic -\n";
    must(dec_value(pk, sk, X).lo == x, "dec(X)", &pk, &X);
        must(dec_value(pk, sk, Y).lo == y, "dec(Y)", &pk, &Y);
        must(dec_value(pk, sk, Zc).lo == z, "dec(Z)", &pk, &Zc);
    std::cout << "   dec ok\n";

    Cipher S = ct_add(pk, X, Y);
    must(dec_value(pk, sk, S).lo == x + y, "add", &pk, &S);

    Cipher D = ct_sub(pk, X, Y);
    must(fp_eq(dec_value(pk, sk, D), fp_sub(fp_from_u64(x), fp_from_u64(y))), "sub", &pk, &D);

    Cipher P = ct_mul(pk, X, Y);
    u128 prod = (u128)x * (u128)y;
    Fp expP = fp_from_words((uint64_t)prod, (uint64_t)(prod >> 64) & MASK63);
    must(fp_eq(dec_value(pk, sk, P), expP), "mul", &pk, &P);
    std::cout << "   add / sub / mul ok\n";

    std::cout << "\n- edge cases -\n";
    Cipher C0 = enc_value(pk, sk, 0);
    Cipher C1 = enc_value(pk, sk, 1);
    must(dec_value(pk, sk, C0).lo == 0, "enc(0)", &pk, &C0);
    must(dec_value(pk, sk, C1).lo == 1, "enc(1)", &pk, &C1);

    must(dec_value(pk, sk, ct_add(pk, X, C0)).lo == x, "x + 0 = x", &pk, &X);
    must(dec_value(pk, sk, ct_mul(pk, X, C1)).lo == x, "x * 1 = x", &pk, &X);





    must(dec_value(pk, sk, ct_mul(pk, X, C0)).lo == 0, "x * 0 = 0", &pk, &X);
    must(dec_value(pk, sk, ct_sub(pk, X, X)).lo == 0, "x - x = 0", &pk, &X);
    std::cout << "   0 / 1 identities ok\n";

    Cipher neg_one = ct_sub(pk, C0, C1);
    Fp dec_neg = dec_value(pk, sk, neg_one);
    Fp exp_neg = fp_sub(fp_from_u64(0), fp_from_u64(1));
    must(fp_eq(dec_neg, exp_neg), "0 - 1 = p - 1", &pk, &neg_one);

    Cipher wrap = ct_add(pk, neg_one, C1);
    must(dec_value(pk, sk, wrap).lo == 0, "(p - 1) + 1 = 0", &pk, &wrap);
    std::cout << "   modular wrap ok\n";
    std::cout << "\n- extra : 30 random ops \n";
    std::vector<Cipher> pool;
    pool.push_back(enc_value(pk, sk, g_rng() % 100 + 1));
    pool.push_back(enc_value(pk, sk, g_rng() % 100 + 1));
    pool.push_back(enc_value(pk, sk, g_rng() % 100 + 1));





    // new ? 

    int add_cnt = 0, sub_cnt = 0, mul_cnt = 0;
    for (int i = 0; i < 30; i++) {
        size_t a = g_rng() % pool.size();
        size_t b = g_rng() % pool.size();
        
        bool can_mul = (pool[a].E.size() < 50 && pool[b].E.size() < 50);
        int op = g_rng() % (can_mul ? 3 : 2);
        
        Cipher res;
        if (op == 0) { res = ct_add(pk, pool[a], pool[b]); add_cnt++; }
        else if (op == 1) { res = ct_sub(pk, pool[a], pool[b]); sub_cnt++; }
        else { res = ct_mul(pk, pool[a], pool[b]); mul_cnt++; }
        
        pool.push_back(res);
        if (pool.size() > 10) pool.erase(pool.begin());
    }
    std::cout << "   ops: add = " << add_cnt << " sub = " << sub_cnt << " mul = " << mul_cnt << "\n";
    std::cout << "   pool size = " << pool.size() << " ok\n";
    std::cout << "\n- algebra -\n";
    must(fp_eq(dec_value(pk, sk, ct_mul(pk, X, Y)), dec_value(pk, sk, ct_mul(pk, Y, X))), "commut", &pk, &P);
    
    Cipher A1 = ct_mul(pk, ct_mul(pk, X, Y), Zc);
    Cipher A2 = ct_mul(pk, X, ct_mul(pk, Y, Zc));
    must(fp_eq(dec_value(pk, sk, A1), dec_value(pk, sk, A2)), "assoc", &pk, &A1);

    Cipher L1 = ct_mul(pk, X, ct_add(pk, Y, Zc));
    Cipher L2 = ct_add(pk, ct_mul(pk, X, Y), ct_mul(pk, X, Zc));
    must(fp_eq(dec_value(pk, sk, L1), dec_value(pk, sk, L2)), "distrib", &pk, &L1);
    std::cout << "commut / assoc / distrib ok\n";

    std::cout << "\n- linear combo: 3x + 5y - 2z -\n";
    Fp c3 = fp_from_u64(3), c5 = fp_from_u64(5), c2 = fp_from_u64(2);
    Cipher lin = ct_sub(pk, ct_add(pk, ct_scale(pk, X, c3), ct_scale(pk, Y, c5)), ct_scale(pk, Zc, c2));

    Fp exp_lin = fp_sub(fp_add(fp_mul(fp_from_u64(x), c3), fp_mul(fp_from_u64(y), c5)), fp_mul(fp_from_u64(z), c2));
    must(fp_eq(dec_value(pk, sk, lin), exp_lin), "linear", &pk, &lin);
    std::cout << "   3 * " << x << " + 5 * " << y << " - 2 * " << z << " = " << exp_lin.lo << " ok\n";

    std::cout << "\n- poly: f(x) = x^3 - 2x^2 + 5x - 7 -\n";
    uint64_t v = 10;
    Cipher Cv = enc_value(pk, sk, v);
    Cipher Cv2 = ct_mul(pk, Cv, Cv);
    Cipher Cv3 = ct_mul(pk, Cv2, Cv);
    Cipher poly = ct_sub(pk, 
        ct_add(pk, Cv3, ct_scale(pk, Cv, fp_from_u64(5))),
        ct_add(pk, ct_scale(pk, Cv2, fp_from_u64(2)), enc_value(pk, sk, 7))
    );
    uint64_t exp_poly = v * v * v - 2 * v * v + 5 * v - 7;
    must(dec_value(pk, sk, poly).lo == exp_poly, "poly", &pk, &poly);
    std::cout << "   f(10) = " << exp_poly << " ok\n";

    std::cout << "\n- quadratic: (a + b)^2 = a^2 + 2ab + b^2 -\n";
    Cipher sum_sq = ct_mul(pk, ct_add(pk, X, Y), ct_add(pk, X, Y));
    Cipher X2 = ct_mul(pk, X, X);
    Cipher Y2 = ct_mul(pk, Y, Y);
    Cipher XY2 = ct_scale(pk, ct_mul(pk, X, Y), fp_from_u64(2));
    Cipher expand = ct_add(pk, ct_add(pk, X2, XY2), Y2);
    must(fp_eq(dec_value(pk, sk, sum_sq), dec_value(pk, sk, expand)), "quad", &pk, &sum_sq);
    std::cout << "   (a + b)^2 expansion ok\n";

    std::cout << "\n- corr test -\n";
    Cipher X_copy = enc_value(pk, sk, x);
    double corr = ct_corr(X, X_copy);
    std::cout << "   corr(enc(x), enc(x)) = " << corr << " (exp ~ " << pk.prm.m_bits / 2 << ")\n";
    must(X.E[0].w.lo != X_copy.E[0].w.lo, "diff rnd", &pk, &X_copy);

    std::cout << "\n- recrypt -\n";
    Cipher X3 = ct_mul(pk, ct_mul(pk, X, X), X);
    std::cout << "   before: bal = " << bit_bal(X3) << " s_ent = " << s_byte_ent(X3) << " L = " << X3.L.size() << "\n";
    Cipher U = ct_recrypt(pk, ek, X3);
    std::cout << "   after:  bal = " << bit_bal(U) << " s_ent = " << s_byte_ent(U) << " L = " << U.L.size() << "\n";
    must(fp_eq(dec_value(pk, sk, U), dec_value(pk, sk, X3)), "recrypt", &pk, &U);

    std::cout << "\n- chain 2^10 -\n";
    const int N = 10;
    Cipher chain = enc_value(pk, sk, 2);
    for (int i = 1; i < N; i++) chain = ct_mul(pk, chain, enc_value(pk, sk, 2));
    must(dec_value(pk, sk, chain).lo == (1ULL << N), "2^10", &pk, &chain);
    std::cout << "   2^10 = " << (1ULL << N) << " ok\n";
    pr_analysis("chain", chain);

    std::cout << "\n- chain with recrypt -\n";
    const int REC_INT = 3;
    int rec_cnt = 0;
    Cipher chain_r = enc_value(pk, sk, 2);
    for (int i = 1; i < N; i++) {
        chain_r = ct_mul(pk, chain_r, enc_value(pk, sk, 2));
        if (i % REC_INT == 0) { chain_r = ct_recrypt(pk, ek, chain_r); rec_cnt++; }
    }
    must(dec_value(pk, sk, chain_r).lo == (1ULL << N), "2^10 rec", &pk, &chain_r);
    std::cout << "   recrypt calls = " << rec_cnt << "\n";
    pr_analysis("chain_r", chain_r);

    std::cout << "\n- 10! -\n";
    Cipher fact = enc_value(pk, sk, 1);
    for (uint64_t i = 2; i <= 10; i++) fact = ct_mul(pk, fact, enc_value(pk, sk, i));
    must(dec_value(pk, sk, fact).lo == 3628800, "10!", &pk, &fact);
    std::cout << "   10! = 3628800 ok\n";

    std::cout << "\n- commit -\n";
    auto cX = commit_ct(pk, X);
    auto cX2 = commit_ct(pk, X_copy);
    auto cY = commit_ct(pk, Y);
    must(cX != cX2, "commit diff enc", &pk, &X);
    must(cX != cY, "commit diff val", &pk, &Y);
    std::cout << " commit unqueness ok\n";

    std::cout << "\n- ubk -\n";
    Cipher P_ubk = P;
    ubk_apply(pk, P_ubk);
    must(fp_eq(dec_value(pk, sk, P_ubk), dec_value(pk, sk, P)), "ubk stable", &pk, &P_ubk);
    std::cout << "   ubk preserves value ok\n";


    std::cout << "\n- weight dist -\n";
    std::map<int, int> w_dist;
    for (const auto& e : P.E) w_dist[hw64(e.w.lo) / 8]++;
    std::cout << "   hw buckets (0-7, 8-15, ...): ";
    for (auto& [bucket, cnt] : w_dist) std::cout << bucket * 8 << "-" << (bucket * 8 + 7) << ":" << cnt << " ";
    std::cout << "\n";

    std::cout << "\n- timing -\n";



    double t_enc = bench_us([&]{ enc_value(pk, sk, 42); }, 10);
    double t_add = bench_us([&]{ ct_add(pk, X, Y); }, 100);
    double t_mul = bench_us([&]{ ct_mul(pk, X, Y); }, 10);
    double t_dec = bench_us([&]{ dec_value(pk, sk, P); }, 10);
    double t_rec = bench_us([&]{ ct_recrypt(pk, ek, X3); }, 3);



    std::cout << " enc: " << std::setw(8) << t_enc << " us\n";

    
    std::cout << " add: " << std::setw(8) << t_add << " us\n";
    
    std::cout << " mul: " << std::setw(8) << t_mul << " us\n";
    
    std::cout << " dec: " << std::setw(8) << t_dec << " us\n";
    
    std::cout << " recrypt: " << std::setw(8) << t_rec << " us\n";

    std::cout << "\n- analysis -\n";
    
    
    // analysis
    
    pr_analysis("X (fresh)", X);
    pr_analysis("P (X * Y)", P);
    pr_analysis("X3 (X^3)", X3);
    pr_analysis("fact (10!)", fact);
    ///





    std::cout << "\n- text -\n";

        std::string msg = "test_test_test data dadfs98324134;'!//.d,d''d,mm";

    auto tcts = enc_text(pk, sk, msg);
    std::string msg2 = dec_text(pk, sk, tcts);
    must(msg == msg2, "text", &pk, &tcts[0]);
    std::cout << "  \"" << msg << "\" roundtrip ok\n";

    dump_metrics(pk, "X", X, dec_value(pk, sk, X));
    dump_metrics(pk, "P", P, dec_value(pk, sk, P));


    std::cout << "\n- all ok -\n";
    return 0;
}