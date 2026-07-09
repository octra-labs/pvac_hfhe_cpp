#include <cstdlib>
#include <iostream>
#include <pvac/pvac.hpp>
#include <pvac/ops/recrypt_fold.hpp>

using namespace pvac;

static void must(bool ok, const char* msg) {
    if (ok) {
        return;
    }
    std::cerr << "fail = " << msg << "\n";
    std::exit(1);
}

static void clear_rcom(Cipher& ct) {
    for (auto& layer : ct.L) {
        layer.R_com = {};
    }
}

int main() {
    Params prm;
    prm.noise_entropy_bits = 128.0;
    PubKey pk;
    SecKey sk;
    keygen(prm, pk, sk);

    const std::string msg = "123";
    auto cts = enc_text(pk, sk, msg);
    for (auto& ct : cts) {
        clear_rcom(ct);
    }

    size_t before_layers = 0;
    for (const auto& ct : cts) {
        before_layers += ct.L.size();
    }

    must(dec_text(pk, sk, cts) == msg, "rcomless decrypt");

    for (auto& ct : cts) {
        fold_cipher(pk, ct);
    }

    size_t after_layers = 0;
    for (const auto& ct : cts) {
        after_layers += ct.L.size();
    }

    bool layer_safe = before_layers == after_layers;
    bool decrypt_safe = dec_text(pk, sk, cts) == msg;

    std::cout << "rcomless_fold_layers = " << layer_safe << "\n";
    std::cout << "rcomless_fold_decrypt = " << decrypt_safe << "\n";

    return layer_safe && decrypt_safe ? 0 : 1;
}