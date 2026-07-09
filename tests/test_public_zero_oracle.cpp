#include <pvac/pvac.hpp>
#include <pvac/utils/text.hpp>
#include <iostream>

using namespace pvac;

static Fp public_layer_slot0(const PubKey& pk, const Cipher& c, uint32_t layer_id) {
    Fp acc = layer_id == 0 && !c.c0.empty() ? c.c0[0] : fp_from_u64(0);
    for (const auto& e : c.E) {
        if (e.layer_id != layer_id) continue;
        Fp term = fp_mul(e.w[0], pk.powg_B[e.idx]);
        acc = sgn_val(e.ch) > 0 ? fp_add(acc, term) : fp_sub(acc, term);
    }
    return acc;
}

static bool fp_zero(const Fp& x) {
    return x.lo == 0 && x.hi == 0;
}

static bool base_layers_public_nonzero(const PubKey& pk, const Cipher& c) {
    for (size_t i = 0; i < c.L.size(); ++i) {
        if (c.L[i].rule != RRule::BASE) continue;
        if (fp_zero(public_layer_slot0(pk, c, static_cast<uint32_t>(i)))) return false;
    }
    return true;
}

static bool roundtrip_text(const PubKey& pk, const SecKey& sk, const std::string& msg) {
    auto cts = enc_text(pk, sk, msg);
    return dec_text(pk, sk, cts) == msg;
}

int main() {
    Params prm;
    prm.noise_entropy_bits = 128.0;
    PubKey pk;
    SecKey sk;
    keygen(prm, pk, sk);

    Cipher raw_zero = enc_fp_raw_depth(pk, sk, fp_from_u64(0), 2);
    Cipher raw_one = enc_fp_raw_depth(pk, sk, fp_from_u64(1), 2);
    Cipher wrapped_zero = enc_fp_wrapped_depth(pk, sk, fp_from_u64(0), 2);
    std::string zero_block(15, '\0');
    auto text_zero = enc_text(pk, sk, zero_block);

    bool raw_zero_leaks = fp_zero(public_layer_slot0(pk, raw_zero, 0));
    bool raw_one_leaks = fp_zero(public_layer_slot0(pk, raw_one, 0));
    bool wrapped_zero_safe = base_layers_public_nonzero(pk, wrapped_zero);
    bool text_zero_safe = text_zero.size() == 2 && base_layers_public_nonzero(pk, text_zero[1]);
    bool text_roundtrip = roundtrip_text(pk, sk, zero_block);

    std::cout << "raw_zero_leaks = " << raw_zero_leaks << "\n";
    std::cout << "raw_one_leaks = " << raw_one_leaks << "\n";
    std::cout << "wrapped_zero_safe = " << wrapped_zero_safe << "\n";
    std::cout << "text_zero_safe = " << text_zero_safe << "\n";
    std::cout << "text_roundtrip = " << text_roundtrip << "\n";

    return raw_zero_leaks && !raw_one_leaks && wrapped_zero_safe && text_zero_safe && text_roundtrip ? 0 : 1;
}