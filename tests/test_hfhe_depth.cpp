#include <cstdlib>
#include <iostream>
#include <pvac/crypto/keygen.hpp>
#include <pvac/pvac_native.hpp>

using namespace pvac;

static void must(bool ok, const char* msg) {
    if (ok) {
        return;
    }
    std::cerr << "FAIL: " << msg << "\n";
    std::exit(1);
}

static Params small_params() {
    Params p;
    p.m_bits = 512;
    p.n_bits = 1024;
    p.h_col_wt = 24;
    p.x_col_wt = 16;
    p.err_wt = 16;
    p.lpn_n = 64;
    p.lpn_t = 256;
    p.edge_budget = 2000000;
    return p;
}

static Fp fp(uint64_t x) {
    return fp_from_u64(x);
}

static size_t env_rounds() {
    auto raw = std::getenv("PVAC_HFHE_DEPTH_ROUNDS");
    if (!raw) {
        return 16;
    }
    auto n = std::strtoull(raw, nullptr, 10);
    if (n == 0 || n > 63) {
        return 16;
    }
    return static_cast<size_t>(n);
}

static void need_step(const NatAdm& adm, const NatStep& step, size_t terms, const char* msg) {
    must(nat_terms(step) == terms, msg);
    const auto& h = nat_carrier(step);
    must(native_runtime_carrier_ok(h), "carrier ok");
    must(h.hidden_coeffs, "hidden coeffs");
    must(h.no_basis_oracle, "no basis oracle");
    must(h.native_backend, "native backend");
    must(h.out.hidden_coeffs, "hidden output coeffs");
    must(!h.out.visible_beta, "no visible beta");
    must(!h.materialized_cipher, "no materialized cipher");
    must(h.out.target_terms <= adm.max_terms, "admitted terms");
}

int main() {
    PubKey pk;
    SecKey sk;
    keygen(small_params(), pk, sk);
    auto adm = recrypt_prod_adm();
    auto rk = make_recrypt_key(pk, sk, adm.max_query, recrypt_prod_budget());
    must(recrypt_key_safe(pk, rk), "recrypt key safe");
    must(recrypt_prod_gate(pk, rk, adm).admitted, "production gate admitted");
    auto a = nat_in(pk, enc(pk, sk, 2ULL), adm);
    auto b = nat_in(pk, enc(pk, sk, 3ULL), adm);
    auto base = nat_add(adm, a, b);
    auto step = base;
    size_t max_stage_terms = nat_terms(step);
    size_t max_reset_terms = 0;
    auto rounds = env_rounds();
    for (size_t i = 0; i < rounds; ++i) {
        auto shifted = nat_add_const(adm, base, fp(7 + i));
        auto expanded = nat_mul(adm, step, shifted);
        if (nat_terms(expanded) > max_stage_terms) {
            max_stage_terms = nat_terms(expanded);
        }
        must(nat_terms(expanded) > adm.out_terms, "stage expands support");
        auto clean = recrypt_prod_reset(pk, rk, adm, expanded);
        must(nat_prod_verify(pk, rk, adm, expanded, clean), "reset verifies");
        need_step(adm, clean, adm.out_terms, "reset terms");
        if (nat_terms(clean) > max_reset_terms) {
            max_reset_terms = nat_terms(clean);
        }
        step = clean;
    }
    std::cout << "hfhe_depth rounds = " << rounds << " ";
    std::cout << "query_budget = " << adm.max_query << " ";
    std::cout << "max_stage_terms = " << max_stage_terms << " ";
    std::cout << "max_reset_terms = " << max_reset_terms << " ";
    std::cout << "out_terms = " << adm.out_terms << " ";
    std::cout << "ok = 1\n";
    std::cout << "PASS\n";
    return 0;
}
