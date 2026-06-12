#include <cstdlib>
#include <iostream>
#include <pvac/pvac_native.hpp>

using namespace pvac;

static void must(bool ok, const char* msg) {
    if (ok) {
        return;
    }
    std::cerr << "FAIL: " << msg << "\n";
    std::exit(1);
}

int main() {
    Params prm;
    prm.edge_budget = 2000000;
    PubKey pk;
    SecKey sk;
    keygen(prm, pk, sk);
    auto adm = recrypt_prod_adm();
    auto rk = make_recrypt_key(pk, sk, adm.max_query, recrypt_prod_budget());
    auto income = enc(pk, sk, 120);
    auto balance = enc(pk, sk, 80);
    auto h_income = nat_in(pk, income, adm);
    auto h_balance = nat_in(pk, balance, adm);
    auto left = nat_add(adm, h_income, h_balance);
    auto right = nat_add_const(adm, left, fp_from_u64(7));
    auto stage = nat_mul(adm, left, right);
    auto clean = recrypt_prod_reset(pk, rk, adm, stage);
    must(recrypt_prod_gate(pk, rk, adm).admitted, "native gate admits");
    must(nat_prod_verify(pk, rk, adm, stage, clean), "hidden reset verifies");
    must(nat_terms(clean) < nat_terms(stage), "hidden reset reduces support");
    std::cout << "recryt usage = 1\n";
    std::cout << "PASs\n";
    return 0;
}
