#include <cstdlib>
#include <iostream>
#include <pvac/pvac_native.hpp>

using namespace pvac;

static void must(bool ok, const char* msg) {
    if (ok) {
        return;
    }
    std::cerr << "fail = " << msg << "\n";
    std::exit(1);
}

template <class F>
static bool dies(F f) {
    try {
        f();
        return false;
    } catch (...) {
        return true;
    }
}

int main() {
    Params prm;
    prm.m_bits = 512;
    prm.n_bits = 1024;
    prm.h_col_wt = 24;
    prm.x_col_wt = 16;
    prm.err_wt = 16;
    prm.lpn_n = 64;
    prm.lpn_t = 256;
    prm.edge_budget = 2000000;
    PubKey pk;
    SecKey sk;
    keygen(prm, pk, sk);
    auto key = make_recrypt_key(pk, sk, 64);
    must(recrypt_key_safe(pk, key), "canonical recrypt key safe");
    auto a = enc(pk, sk, 7);
    auto b = enc(pk, sk, 11);
    auto ab = ct_mul(pk, a, b);
    must(ct::fp_eq(dec1(pk, sk, ab), fp_from_u64(77)), "canonical cipher decrypts");
    must(dies([&]() { auto bad = recrypt(pk, key, ab); (void)bad; }), "canonical direct refresh rejected");
    auto adm = nat_chain();
    auto compact = recrypt_compact(pk, key, ab, adm);
    must(recrypt_compact_verify(pk, key, ab, compact), "canonical compact refresh verifies");
    must(recrypt_compact_terms(compact) == adm.out_terms, "canonical compact refresh cuts support");
    must(!compact.materialized_cipher, "canonical compact refresh stays hidden");
    must(compact.hidden_coeffs && compact.no_basis_oracle && compact.native_backend, "canonical compact refresh is basis closed");
    auto reusable = decide_native_runtime_reusable(compact, key.budget);
    must(reusable.admitted, "canonical compact refresh reusable gate admits");
    auto compact_tamper = compact;
    compact_tamper.out.output_digest[0] ^= 1;
    must(!recrypt_compact_verify(pk, key, ab, compact_tamper, adm), "canonical compact refresh rejects tamper");
    must(dies([&]() { auto bad = recrypt_compact_step(pk, key, ab, adm, adm.max_query - 1); (void)bad; }), "canonical compact step rejects terminal query");
    must(dies([&]() { auto bad = recrypt_result(pk, key, ab, adm, adm.max_query - 1, true); (void)bad; }), "canonical refresh result rejects terminal query");
    must(dies([&]() { auto bad = recrypt_result(pk, key, ab, adm, 0, true); (void)bad; }), "canonical refresh direct mode rejected");
    auto compact_step = recrypt_compact_step(pk, key, ab, adm);
    must(nat_terms(compact_step) == adm.out_terms, "canonical compact step enters hidden pipeline");
    auto refresh = recrypt_result(pk, key, ab, adm, 0, false);
    must(recrypt_verify(pk, key, ab, refresh), "canonical refresh result verifies");
    must(refresh.has_compact && !refresh.has_cipher, "canonical refresh result stays compact");
    must(recrypt_compact_terms(refresh.compact) == adm.out_terms, "canonical refresh result stays compact");
    auto refresh_step = recrypt_step(refresh);
    must(nat_terms(refresh_step) == adm.out_terms, "canonical refresh result continues compactly");
    auto hb = nat_in(pk, b, adm);
    auto follow = nat_mul(adm, refresh_step, hb);
    auto follow_reset = recrypt_reset(pk, key, adm, follow);
    must(nat_terms(follow_reset) == adm.out_terms, "canonical compact continuation resets support");
    must(recrypt_verify(pk, key, follow.carrier(), adm, adm.out_terms, follow_reset.query(), follow_reset.carrier()), "canonical compact continuation verifies");
    auto prod_key = make_recrypt_key(pk, sk, adm.max_query, recrypt_prod_budget());
    auto gate = recrypt_prod_gate(pk, prod_key, adm);
    must(gate.admitted, "canonical production gate admits");
    auto hx = nat_in(pk, a, adm);
    auto hy = nat_in(pk, b, adm);
    auto stage = nat_mul(adm, hx, hy);
    auto reset = recrypt_prod_reset(pk, prod_key, adm, stage);
    must(nat_terms(reset) < nat_terms(stage), "canonical hidden reset reduces support");
    must(nat_prod_verify(pk, prod_key, adm, stage, reset), "canonical hidden reset verifies");
    std::cout << "canonical recrypt api = 1\n";
    std::cout << "PASS\n";
    return 0;
}