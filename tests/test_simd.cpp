#include <pvac/pvac.hpp>
#include <iostream>
#include <chrono>
#include <vector>
#include <cassert>

using namespace pvac;
using clk = std::chrono::high_resolution_clock;

inline double us(clk::time_point a, clk::time_point b) {
    return std::chrono::duration<double, std::micro>(b - a).count();
}

int main() {
    Params prm;
    PubKey pk;
    SecKey sk;
    keygen(prm, pk, sk);

    constexpr int S = 64;
    std::vector<uint64_t> vals(S);
    for (int j = 0; j < S; ++j) vals[j] = (uint64_t)(j + 1);

    std::cout << "--- scalar (slots = 1) x" << S << " ---\n";

    auto t0 = clk::now();
    std::vector<Cipher> sc(S);
    for (int i = 0; i < S; ++i) sc[i] = enc_value(pk, sk, vals[i]);
    auto t1 = clk::now();
    double sc_enc = us(t0, t1);

    t0 = clk::now();
    for (int i = 0; i < S; ++i) {
        Fp d = dec_value(pk, sk, sc[i]);
        if (!ct::fp_eq(d, fp_from_u64(vals[i]))) { std::cout << "FAIL scalar dec[" << i << "]\n"; return 1; }
    }
    t1 = clk::now();
    double sc_dec = us(t0, t1);
    std::cout << "enc/dec ok\n";

    t0 = clk::now();
    std::vector<Cipher> sc_a(S);
    for (int i = 0; i < S; ++i) sc_a[i] = ct_add(pk, sc[i], sc[i]);
    t1 = clk::now();
    double sc_add = us(t0, t1);

    for (int i = 0; i < S; ++i) {
        Fp d = dec_value(pk, sk, sc_a[i]);
        if (!ct::fp_eq(d, fp_from_u64(vals[i] * 2))) { std::cout << "FAIL scalar add[" << i << "]\n"; return 1; }
    }
    std::cout << "add ok\n";

    t0 = clk::now();
    std::vector<Cipher> sc_m(S);
    for (int i = 0; i < S; ++i) sc_m[i] = ct_mul(pk, sc[i], sc[i]);
    t1 = clk::now();
    double sc_mul = us(t0, t1);

    for (int i = 0; i < S; ++i) {
        Fp d = dec_value(pk, sk, sc_m[i]);
        if (!ct::fp_eq(d, fp_from_u64(vals[i] * vals[i]))) { std::cout << "FAIL scalar mul[" << i << "]\n"; return 1; }
    }
    std::cout << "mul ok\n";

    std::cout << "\n--- simd (slots = " << S << ") x1 ---\n";

    t0 = clk::now();
    Cipher batch = enc_values(pk, sk, vals);
    t1 = clk::now();
    double si_enc = us(t0, t1);

    t0 = clk::now();
    auto dec_all = dec_values(pk, sk, batch);
    t1 = clk::now();
    double si_dec = us(t0, t1);

    for (int j = 0; j < S; ++j) {
        if (!ct::fp_eq(dec_all[j], fp_from_u64(vals[j]))) { std::cout << "FAIL simd dec[" << j << "]\n"; return 1; }
    }
    std::cout << "enc/dec ok\n";

    t0 = clk::now();
    Cipher batch_add = ct_add(pk, batch, batch);
    t1 = clk::now();
    double si_add = us(t0, t1);

    auto dec_a = dec_values(pk, sk, batch_add);
    for (int j = 0; j < S; ++j) {
        if (!ct::fp_eq(dec_a[j], fp_from_u64(vals[j] * 2))) { std::cout << "FAIL simd add[" << j << "]\n"; return 1; }
    }
    std::cout << "add ok\n";

    t0 = clk::now();
    Cipher batch_mul = ct_mul(pk, batch, batch);
    t1 = clk::now();
    double si_mul = us(t0, t1);

    auto dec_m = dec_values(pk, sk, batch_mul);
    for (int j = 0; j < S; ++j) {
        if (!ct::fp_eq(dec_m[j], fp_from_u64(vals[j] * vals[j]))) { std::cout << "FAIL simd mul[" << j << "]\n"; return 1; }
    }
    std::cout << "mul ok\n";

    std::cout << "\n--- results ---\n";

    auto row = [](const char* label, double a, double b) {
        printf("%s %.0f us %.0f us %.1fx\n", label, a, b, a / b);
    };

    row("enc", sc_enc, si_enc);
    row("dec", sc_dec, si_dec);
    row("add", sc_add, si_add);
    row("mul", sc_mul, si_mul);
    row("TOTAL", sc_enc + sc_dec + sc_add + sc_mul, si_enc + si_dec + si_add + si_mul);

    size_t sc_edges = 0, sc_layers = 0;
    for (int i = 0; i < S; ++i) { sc_edges += sc[i].E.size(); sc_layers += sc[i].L.size(); }

    std::cout << "\n--- memory ---\n";
    std::cout << "scalar: " << S << " ciphers, " << sc_edges << " edges, " << sc_layers << " layers\n";
    std::cout << "simd: 1 cipher, " << batch.E.size() << " edges, " << batch.L.size() << " layers\n";

    size_t sc_mem = 0;
    for (int i = 0; i < S; ++i) {
        for (const auto& e : sc[i].E) sc_mem += e.w.size() * sizeof(Fp) + e.s.w.size() * sizeof(uint64_t);
        sc_mem += sc[i].c0.size() * sizeof(Fp);
    }
    size_t si_mem = 0;
    for (const auto& e : batch.E) si_mem += e.w.size() * sizeof(Fp) + e.s.w.size() * sizeof(uint64_t);
    si_mem += batch.c0.size() * sizeof(Fp);

    printf("scalar: %.1f KB\nsimd: %.1f KB\n", sc_mem / 1024.0, si_mem / 1024.0);

    std::cout << "\n== all ok ==\n";
    return 0;
}