/*
 * octra labs
 * lambda0xe, denis cmix, J.
 */





#pragma once

#include <array>
#include <cstring>
#include <stdexcept>
#include <vector>

#include "recrypt_eval.hpp"

namespace pvac {

inline std::array<uint8_t, 32> recrypt_seed(SeedableRng& rng) {
    std::array<uint8_t, 32> seed{};
    for (size_t i = 0; i < 4; ++i) {
        auto x = rng.u64();
        std::memcpy(seed.data() + i * sizeof(x), &x, sizeof(x));
    }
    return seed;
}

inline Cipher enc(const PubKey& pk, const SecKey& sk, const std::vector<Fp>& v) {
    if (v.empty())
        throw std::runtime_error("pvac: encrypt value rejected");
    std::array<uint8_t, 32> seed{};
    csprng_bytes(seed.data(), seed.size());
    SeedableRng rng = make_seeded_rng(seed.data());
    std::vector<Fp> mask(v.size());
    for (size_t j = 0; j < v.size(); ++j) {
        mask[j] = rng.fp_nonzero();
    }
    auto left_seed = recrypt_seed(rng);
    auto right_seed = recrypt_seed(rng);
    return combine_ciphers(
        pk,
        enc_nat_fp_seeded(pk, sk, field::Op::add(v, mask), left_seed.data()),
        enc_nat_fp_seeded(pk, sk, field::Op::neg(mask), right_seed.data())
    );
}

inline Cipher enc(const PubKey& pk, const SecKey& sk, const Fp& v) {
    return enc(pk, sk, std::vector<Fp>{v});
}

inline Cipher enc(const PubKey& pk, const SecKey& sk, const std::vector<uint64_t>& v) {
    std::vector<Fp> xs;
    xs.reserve(v.size());
    for (auto x : v) {
        xs.push_back(fp_from_u64(x));
    }
    return enc(pk, sk, xs);
}

inline Cipher enc(const PubKey& pk, const SecKey& sk, uint64_t v) {
    return enc(pk, sk, fp_from_u64(v));
}

inline std::vector<Fp> dec(const PubKey& pk, const SecKey& sk, const Cipher& ct) {
    return dec_values(pk, sk, ct, DecPolicy::NATIVE_LOCAL);
}

inline Fp dec1(const PubKey& pk, const SecKey& sk, const Cipher& ct) {
    return dec_value(pk, sk, ct, DecPolicy::NATIVE_LOCAL);
}

inline bool recrypt_key_safe(const PubKey& pk, const NatKey& key) {
    return nat_key_safe(pk, key);
}

inline NatKey make_recrypt_key(const PubKey& pk, const SecKey& sk, size_t queries = 64, const NativeRuntimeReusableBudget& budget = NativeRuntimeReusableBudget{}) {
    return make_nat_key(pk, sk, queries, budget);
}

inline NatAdm recrypt_adm() {
    return nat_adm();
}

inline NatAdm recrypt_prod_adm() {
    return nat_prod_adm();
}

inline NativeRuntimeReusableBudget recrypt_prod_budget() {
    return nat_prod_budget();
}

struct RecryptResult {
    NativeRuntimeHiddenCarrier compact;
    Cipher cipher;
    NatAdm adm;
    size_t query = 0;
    bool has_compact = false;
    bool has_cipher = false;
};

inline NativeRuntimeHiddenCarrier recrypt_compact(const PubKey& pk, const NatKey& key, const Cipher& ct, const NatAdm& adm = nat_chain(), size_t query = 0) {
    auto source = make_native_runtime_source_carrier(pk, ct);
    auto req = rku_req(pk, key, source, adm, adm.out_terms, query);
    return rku_recrypt_unsafe(pk, key, source, {req});
}

inline bool recrypt_compact_verify(const PubKey& pk, const NatKey& key, const Cipher& ct, const NativeRuntimeHiddenCarrier& clean, const NatAdm& adm = nat_chain(), size_t query = 0) {
    try {
        auto expected = recrypt_compact(pk, key, ct, adm, query);
        return native_recrypt_carrier_eq(expected, clean);
    } catch (...) {
        return false;
    }
}

inline size_t recrypt_compact_terms(const NativeRuntimeHiddenCarrier& clean) {
    return clean.out.target_terms;
}

inline bool recrypt_query_can_emit_step(const NatAdm& adm, size_t query) {
    return adm.max_query != 0 && query < adm.max_query - 1;
}

inline NatStep recrypt_compact_step(const PubKey& pk, const NatKey& key, const Cipher& ct, const NatAdm& adm = nat_chain(), size_t query = 0) {
    if (!recrypt_query_can_emit_step(adm, query))
        throw std::runtime_error("pvac: compact refresh query rejected");
    return nat_step(adm, recrypt_compact(pk, key, ct, adm, query), query + 1);
}

inline RecryptResult recrypt_result(const PubKey& pk, const NatKey& key, const Cipher& ct, const NatAdm& adm = nat_chain(), size_t query = 0, bool delivery = false) {
    if (!recrypt_query_can_emit_step(adm, query))
        throw std::runtime_error("pvac: refresh query rejected");
    RecryptResult out;
    out.adm = adm;
    out.query = query + 1;
    out.compact = recrypt_compact(pk, key, ct, adm, query);
    out.has_compact = true;
    if (delivery) {
        throw std::runtime_error("pvac: recrypt mode rejected");
    }
    return out;
}

inline bool recrypt_verify(const PubKey& pk, const NatKey& key, const Cipher& ct, const RecryptResult& out) {
    if (!out.has_compact)
        return false;
    if (!recrypt_compact_verify(pk, key, ct, out.compact, out.adm, out.query ? out.query - 1 : 0))
        return false;
    if (!out.has_cipher)
        return true;
    return recrypt_verify(pk, key, ct, out.cipher);
}

inline NatStep recrypt_step(const RecryptResult& out) {
    if (!out.has_compact || out.query == 0)
        throw std::runtime_error("pvac: refresh result step rejected");
    return nat_step(out.adm, out.compact, out.query);
}

inline NatProdGate recrypt_prod_gate(const PubKey& pk, const NatKey& key, const NatAdm& adm) {
    return nat_prod_gate(pk, key, adm);
}

inline NatStep recrypt_reset(const PubKey& pk, const NatKey& key, const NatAdm& adm, const NatStep& x) {
    return nat_recrypt(pk, key, adm, x);
}

inline NatStep recrypt_prod_reset(const PubKey& pk, const NatKey& key, const NatAdm& adm, const NatStep& x) {
    return nat_prod_recrypt(pk, key, adm, x);
}

}