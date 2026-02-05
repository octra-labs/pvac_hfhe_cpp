#include <iostream>
#include <vector>
#include <pvac/pvac.hpp>

using namespace pvac;

static size_t ct_mem(const Cipher& C) {
    size_t n = sizeof(Cipher) + C.L.capacity() * sizeof(Layer) + C.E.capacity() * sizeof(Edge);
    for (const auto& e : C.E) n += e.s.w.capacity() * sizeof(uint64_t);
    return n;
}

static size_t edges_in_layer(const Cipher& C, uint32_t lid) {
    size_t n = 0;
    for (const auto& e : C.E) if (e.layer_id == lid) n++;
    return n;
}

static size_t tri_off(uint32_t L, uint32_t a, uint32_t b) {
    return (size_t)a * L - (size_t)a * (a + 1) / 2 + b;
}

static bool check_square_gsum(const PubKey& pk, const Cipher& A, const Cipher& C) {
    uint32_t L = (uint32_t)A.L.size();
    if (C.L.size() != L + L * (L + 1) / 2) return false;

    std::vector<std::vector<Fp>> gA(L);
    for (uint32_t i = 0; i < L; ++i) gA[i] = agg_layer_gsum(pk, A, i);

    for (uint32_t la = 0; la < L; ++la) {
        for (uint32_t lb = la; lb < L; ++lb) {
            uint32_t lid = L + (uint32_t)tri_off(L, la, lb);
            auto got = agg_layer_gsum(pk, C, lid);
            auto exp = field::Op::mul(gA[la], gA[lb]);
            if (la != lb) exp = field::Op::add(exp, exp);
            if (got.size() != exp.size()) return false;
            for (size_t j = 0; j < got.size(); ++j)
                if (!ct::fp_eq(got[j], exp[j])) return false;
        }
    }
    return true;
}

static void must(bool ok, const char* msg) {
    if (!ok) { std::cout << "FAIL: " << msg << "\n"; std::exit(1); }
}

int main() {
    std::cout << "- ct_mul / ct_square formula test -\n";

    Params prm; PubKey pk; SecKey sk;
    keygen(prm, pk, sk);

    constexpr size_t S = 8;

    Cipher X = enc_value(pk, sk, 7);
    Cipher Y = enc_value(pk, sk, 11);
    Cipher P = ct_mul(pk, X, Y, S);

    must(ct::fp_eq(dec_value(pk, sk, P), fp_mul(fp_from_u64(7), fp_from_u64(11))), "mul decrypt");

    uint32_t LA = (uint32_t)X.L.size(), LB = (uint32_t)Y.L.size();
    size_t exp_L = LA + LB + (size_t)LA * LB;
    size_t exp_E = (size_t)LA * LB * S;

    must(P.L.size() == exp_L, "mul layers");
    must(P.E.size() == exp_E, "mul edges");
    must(check_mul_gsum_all(pk, X, Y, P), "mul gsum");

    uint32_t base = LA + LB;
    for (uint32_t la = 0; la < LA; ++la)
        for (uint32_t lb = 0; lb < LB; ++lb)
            must(edges_in_layer(P, base + la * LB + lb) == S, "mul edges/layer");

    Cipher X3 = ct_mul(pk, P, X, S);
    Cipher Sq_mul = ct_mul(pk, X3, X3, S);
    Cipher Sq_sq = ct_square(pk, X3, S);

    must(ct::fp_eq(dec_value(pk, sk, Sq_mul), dec_value(pk, sk, Sq_sq)), "square == mul(A,A)");

    uint32_t L0 = (uint32_t)X3.L.size();
    size_t tri = L0 * (L0 + 1) / 2;

    must(Sq_sq.L.size() == L0 + tri, "square layers");
    must(Sq_sq.E.size() == tri * S, "square edges");
    must(check_square_gsum(pk, X3, Sq_sq), "square gsum");

    for (uint32_t la = 0; la < L0; ++la)
        for (uint32_t lb = la; lb < L0; ++lb)
            must(edges_in_layer(Sq_sq, L0 + (uint32_t)tri_off(L0, la, lb)) == S, "square edges/layer");

    std::cout << "X: E = " << X.E.size() << " L = " << X.L.size() << " mem = " << ct_mem(X) << "B\n";
    std::cout << "Y: E = " << Y.E.size() << " L = " << Y.L.size() << " mem = " << ct_mem(Y) << "B\n";
    std::cout << "P = X * Y: E = " << P.E.size() << " L = " << P.L.size() << " mem = " << ct_mem(P) << "B\n";
    std::cout << "X3: E = " << X3.E.size() << " L = " << X3.L.size() << " mem = " << ct_mem(X3) << "B\n";
    std::cout << "Sq_mul: E = " << Sq_mul.E.size() << " L = " << Sq_mul.L.size() << " mem = " << ct_mem(Sq_mul) << "B\n";
    std::cout << "Sq_sq: E = " << Sq_sq.E.size() << " L = " << Sq_sq.L.size() << " mem = " << ct_mem(Sq_sq) << "B\n";

    std::cout << "PASS\n";
    return 0;
}