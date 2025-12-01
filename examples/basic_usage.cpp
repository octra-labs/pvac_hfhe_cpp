#include <iostream>
#include <iomanip>
#include <chrono>
#include <random>
#include <pvac/pvac.hpp>

using namespace pvac;

int g_test_num = 0;
int g_pass = 0;
int g_fail = 0;

#define TEST(name) std::cout << "\n - " << ++g_test_num << ". " << name << " - \n"
#define CHECK(cond, msg) do { \
    if (!(cond)) { std::cout << "   FAIL: " << msg << "\n"; g_fail++; } \
    else { std::cout << "   ok: " << msg << "\n"; g_pass++; } \
} while(0)

void print_hex64(const uint64_t* data, size_t count) {
    for (size_t i = 0; i < count; i++) {
        std::cout << std::hex << std::setw(16) << std::setfill('0') << data[i];
        if (i + 1 < count) std::cout << " ";
    }
    std::cout << std::dec << "\n";
}

void print_seckey(const SecKey& sk) {
    std::cout << "prf_k[4]: ";
    print_hex64(sk.prf_k.data(), 4);
    std::cout << "lpn_s: " << sk.lpn_s_bits.size() * 64 << " bits\n";
    std::cout << "first 4w: ";

    if (sk.lpn_s_bits.size() >= 4) print_hex64(sk.lpn_s_bits.data(), 4);
}

void print_cipher(const Cipher& c, const std::string& name, size_t max_edges = 3) {
    std::cout << "   " << name << ": " << c.E.size() << " edges, " << c.L.size() << " layers\n";
    size_t show = std::min(c.E.size(), max_edges);
    for (size_t i = 0; i < show; i++) {
        const auto& e = c.E[i];
        std::cout << "      [" << i << "] L = " << e.layer_id 

                  << " i = " << e.idx << " w = 0x" << std::hex << e.w.lo << std::dec << "\n";
    }
    if (c.E.size() > max_edges) std::cout << "      --- (" << c.E.size() - max_edges << " + )\n";
}

int main() {
    std::cout << "pvac_hfhe " << VERSION_STRING << "\n";
    
    TEST("keygen");
    Params prm; PubKey pk; SecKey sk;
    keygen(prm, pk, sk);
    std::cout << "   H = 0x" << hex8(pk.H_digest.data(), 8) << "\n";
    std::cout << "   m = " << prm.m_bits << ", n = " << prm.n_bits << ", B = " << prm.B << "\n";
    print_seckey(sk);
    
    TEST("enc / dec");
    uint64_t a = 42, b = 17;
    Cipher ca = enc_value(pk, sk, a);
    Cipher cb = enc_value(pk, sk, b);
    CHECK(dec_value(pk, sk, ca).lo == a, "dec(42) = 42");
    CHECK(dec_value(pk, sk, cb).lo == b, "dec(17) = 17");

    
    TEST("zero / one");
    Cipher c0 = enc_value(pk, sk, 0);
    Cipher c1 = enc_value(pk, sk, 1);
    CHECK(dec_value(pk, sk, c0).lo == 0, "dec(0) = 0");
    CHECK(dec_value(pk, sk, c1).lo == 1, "dec(1) = 1");
    
    TEST("x + 0 = x");
    CHECK(dec_value(pk, sk, ct_add(pk, ca, c0)).lo == a, "42 + 0 = 42");
    
    TEST("x * 1 = x");
    CHECK(dec_value(pk, sk, ct_mul(pk, ca, c1)).lo == a, "42 * 1 = 42");
    
    TEST("x * 0 = 0");
    CHECK(dec_value(pk, sk, ct_mul(pk, ca, c0)).lo == 0, "42 * 0 = 0");
    
    TEST("x - x = 0");
    CHECK(dec_value(pk, sk, ct_sub(pk, ca, ca)).lo == 0, "42 - 42 = 0");
    
    TEST("commut");
    Cipher c_ab = ct_add(pk, ca, cb);
    Cipher c_ba = ct_add(pk, cb, ca);
    CHECK(dec_value(pk, sk, c_ab).lo == dec_value(pk, sk, c_ba).lo, "a + b = b + a");
    CHECK(dec_value(pk, sk, ct_mul(pk, ca, cb)).lo == dec_value(pk, sk, ct_mul(pk, cb, ca)).lo, "a * b = b * a");
    
    TEST("assoc");
    uint64_t c = 7;
    Cipher cc = enc_value(pk, sk, c);
    Cipher c_ab_c = ct_add(pk, ct_add(pk, ca, cb), cc);
    Cipher c_a_bc = ct_add(pk, ca, ct_add(pk, cb, cc));
    CHECK(dec_value(pk, sk, c_ab_c).lo == dec_value(pk, sk, c_a_bc).lo, "(a + b) + c = a + (b + c)");
    Cipher c_ab_c_mul = ct_mul(pk, ct_mul(pk, ca, cb), cc);
    Cipher c_a_bc_mul = ct_mul(pk, ca, ct_mul(pk, cb, cc));
    CHECK(dec_value(pk, sk, c_ab_c_mul).lo == dec_value(pk, sk, c_a_bc_mul).lo, "(a * b) * c = a * (b * c)");
    
    TEST("distrib");
    Cipher c_bpc = ct_add(pk, cb, cc);
    Cipher c_a_bpc = ct_mul(pk, ca, c_bpc);
    Cipher c_ab_ac = ct_add(pk, ct_mul(pk, ca, cb), ct_mul(pk, ca, cc));
    uint64_t left = dec_value(pk, sk, c_a_bpc).lo;
    uint64_t right = dec_value(pk, sk, c_ab_ac).lo;
    CHECK(left == right, "a * (b + c) = a*b + a*c = " + std::to_string(left));
    
    TEST("(a + b)^2 = a^2 + 2ab + b^2");
    Cipher c_apb = ct_add(pk, ca, cb);
    Cipher c_apb_sq = ct_mul(pk, c_apb, c_apb);
    Cipher c_a_sq = ct_mul(pk, ca, ca);
    Cipher c_b_sq = ct_mul(pk, cb, cb);
    Cipher c_ab_prod = ct_mul(pk, ca, cb);
    Cipher c_2ab = ct_add(pk, c_ab_prod, c_ab_prod);
    Cipher c_rhs = ct_add(pk, ct_add(pk, c_a_sq, c_2ab), c_b_sq);
    uint64_t lhs_val = dec_value(pk, sk, c_apb_sq).lo;
    uint64_t rhs_val = dec_value(pk, sk, c_rhs).lo;
    CHECK(lhs_val == rhs_val, std::to_string(lhs_val) + " = " + std::to_string(rhs_val));
    
    TEST("(a - b)(a + b) = a^2 - b^2");
    Cipher c_amb = ct_sub(pk, ca, cb);
    Cipher c_diff_prod = ct_mul(pk, c_amb, c_apb);
    Cipher c_sq_diff = ct_sub(pk, c_a_sq, c_b_sq);
    uint64_t dp = dec_value(pk, sk, c_diff_prod).lo;
    uint64_t sd = dec_value(pk, sk, c_sq_diff).lo;



    CHECK(dp == sd, std::to_string(dp) + " = " + std::to_string(sd));
    






    TEST("poly f(x) = x^3 + 2x^2 + 3x + 4");
    uint64_t x = 5;
    Cipher cx = enc_value(pk, sk, x);
    Cipher c2 = enc_value(pk, sk, 2);
    Cipher c3 = enc_value(pk, sk, 3);
    Cipher c4 = enc_value(pk, sk, 4);
    Cipher cx2 = ct_mul(pk, cx, cx);
    Cipher cx3 = ct_mul(pk, cx2, cx);
    Cipher c_poly = ct_add(pk, ct_add(pk, ct_add(pk, cx3, ct_mul(pk, c2, cx2)), ct_mul(pk, c3, cx)), c4);
    uint64_t poly_r = dec_value(pk, sk, c_poly).lo;
    uint64_t poly_e = x*x*x + 2*x*x + 3*x + 4;
    CHECK(poly_r == poly_e, "f(5) = " + std::to_string(poly_e));
    
    TEST("depth x^8");
    Cipher cx_1 = enc_value(pk, sk, 2);
    Cipher cx_2 = ct_mul(pk, cx_1, cx_1);
    Cipher cx_4 = ct_mul(pk, cx_2, cx_2);
    Cipher cx_8 = ct_mul(pk, cx_4, cx_4);
    CHECK(dec_value(pk, sk, cx_8).lo == 256, "2^8 = 256");
    std::cout << "   edges: x^1 = " << cx_1.E.size() << ", x^2 = " << cx_2.E.size() 
              << ", x^4 = " << cx_4.E.size() << ", x^8 = " << cx_8.E.size() << "\n";
    
    TEST("depth x^16");
    Cipher cx_16 = ct_mul(pk, cx_8, cx_8);
    CHECK(dec_value(pk, sk, cx_16).lo == 65536, "2^16 = 65536");
    std::cout << "   edges = " << cx_16.E.size() << ", layers = " << cx_16.L.size() << "\n";
    
    TEST("rand 10 pairs");
    std::mt19937_64 rng(12345);
    for (int i = 0; i < 10; i++) {
        uint64_t r1 = rng() % 1000, r2 = rng() % 1000;
        Cipher cr1 = enc_value(pk, sk, r1);
        Cipher cr2 = enc_value(pk, sk, r2);
        uint64_t sum_d = dec_value(pk, sk, ct_add(pk, cr1, cr2)).lo;
        uint64_t prod_d = dec_value(pk, sk, ct_mul(pk, cr1, cr2)).lo;
        bool ok = (sum_d == r1 + r2) && (prod_d == r1 * r2);
        if (ok) g_pass++; else g_fail++;
        std::cout << "   [" << i << "] " << r1 << " + " << r2 << " = " << sum_d 
                  << ", " << r1 << " * " << r2 << " = " << prod_d << (ok ? " ok" : " FAIL") << "\n";
    }
    
    TEST("fib(10)");
    Cipher fib_p = enc_value(pk, sk, 0);
    Cipher fib_c = enc_value(pk, sk, 1);
    for (int i = 2; i <= 10; i++) {
        Cipher fib_n = ct_add(pk, fib_p, fib_c);
        fib_p = fib_c;
        fib_c = fib_n;
    }
    CHECK(dec_value(pk, sk, fib_c).lo == 55, "fib(10) = 55");
    std::cout << "   edges = " << fib_c.E.size() << ", layers = " << fib_c.L.size() << "\n";
    
    TEST("6!");
    Cipher fact = enc_value(pk, sk, 1);
    for (uint64_t i = 2; i <= 6; i++) 
    {
            fact = ct_mul(pk, fact, enc_value(pk, sk, i));
        }
        CHECK(dec_value(pk, sk, fact).lo == 720, "6! = 720");
    std::cout << "   edges = " << fact.E.size() << ", layers = " << fact.L.size() << "\n";
    
    TEST("sum of sq 1..5");
    Cipher sum_sq = enc_value(pk, sk, 0);
    for (uint64_t i = 1; i <= 5; i++) {
        Cipher ci = enc_value(pk, sk, i);
        sum_sq = ct_add(pk, sum_sq, ct_mul(pk, ci, ci));
    }
    CHECK(dec_value(pk, sk, sum_sq).lo == 55, "1 + 4 + 9 + 16 + 25 = 55");
    
    TEST("nested ((a + b) * c - a) * b");
    uint64_t va = 3, vb = 5, vc = 7;
    Cipher cva = enc_value(pk, sk, va);
    Cipher cvb = enc_value(pk, sk, vb);
    Cipher cvc = enc_value(pk, sk, vc);
    Cipher c_nest = ct_mul(pk, ct_sub(pk, ct_mul(pk, ct_add(pk, cva, cvb), cvc), cva), cvb);
    uint64_t nest_r = dec_value(pk, sk, c_nest).lo;
    uint64_t nest_e = ((va + vb) * vc - va) * vb;
    CHECK(nest_r == nest_e, "((3 + 5) * 7 - 3) * 5 = " + std::to_string(nest_e));
    
    TEST("diff ct same val");
    Cipher ca1 = enc_value(pk, sk, 100);
    Cipher ca2 = enc_value(pk, sk, 100);
    CHECK(dec_value(pk, sk, ca1).lo == dec_value(pk, sk, ca2).lo, "both = 100");
    CHECK(ca1.E[0].w.lo != ca2.E[0].w.lo, "diff rnd");
    std::cout << "   w1 = 0x" << std::hex << ca1.E[0].w.lo << ", w2 = 0x" << ca2.E[0].w.lo << std::dec << "\n";
    
    TEST("commit uniq");
    auto cm1 = commit_ct(pk, ca1);
    auto cm2 = commit_ct(pk, ca2);
    CHECK(cm1 != cm2, "diff ct -> diff commit");
    std::cout << "   c1 = 0x" << hex8(cm1.data(), 8) << "\n";
    std::cout << "   c2 = 0x" << hex8(cm2.data(), 8) << "\n";
    
    TEST("text ascii");
    std::string ascii = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    CHECK(dec_text(pk, sk, enc_text(pk, sk, ascii)) == ascii, "ascii roundtrip");
    
    TEST("text special");
    std::string special = "!@#$%^&*()_+-=[]{}|;':\",./<>?`~";
    CHECK(dec_text(pk, sk, enc_text(pk, sk, special)) == special, "special roundtrip");
    
    TEST("text utf8");
    std::string utf8 = "hello world 123";
    CHECK(dec_text(pk, sk, enc_text(pk, sk, utf8)) == utf8, "utf8 roundtrip");
    
    TEST("text empty");
    std::string empty = "";
    CHECK(dec_text(pk, sk, enc_text(pk, sk, empty)) == empty, "empty roundtrip");
    
    TEST("perf 100 adds");
    auto t1 = std::chrono::high_resolution_clock::now();
    Cipher perf_sum = enc_value(pk, sk, 0);
    for (int i = 0; i < 100; i++) perf_sum = ct_add(pk, perf_sum, enc_value(pk, sk, i));
    //
    auto t2 = std::chrono::high_resolution_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(t2 - t1).count();

    CHECK(dec_value(pk, sk, perf_sum).lo == 4950, "sum(0..99) = 4950");
    std::cout << "   time = " << ms << " ms, edges = " << perf_sum.E.size() << "\n";
    
    TEST("perf 10 muls");
    t1 = std::chrono::high_resolution_clock::now();
    Cipher perf_prod = enc_value(pk, sk, 1);
    for (int i = 0; i < 10; i++) perf_prod = ct_mul(pk, perf_prod, enc_value(pk, sk, 2));
    t2 = std::chrono::high_resolution_clock::now();
    ms = std::chrono::duration_cast<std::chrono::milliseconds>(t2 - t1).count();
    //
    CHECK(dec_value(pk, sk, perf_prod).lo == 1024, "2^10 = 1024");
    std::cout << "   time = " << ms << " ms, edges = " << perf_prod.E.size() << ", layers = " << perf_prod.L.size() << "\n";
    
    TEST("large val");
    uint64_t large = 123456789;
    CHECK(dec_value(pk, sk, enc_value(pk, sk, large)).lo == large, "enc / dec 123456789");
    
    TEST("ct dump");
    print_cipher(cx_8, "2^8");
    print_cipher(fact, "6!");
    
    std::cout << "\n___________________\n";
    std::cout << "results: " << g_pass << " passed, " << g_fail << " failed\n";
    std::cout << "\n___________________\n";
    
    return g_fail > 0 ? 1 : 0;
}