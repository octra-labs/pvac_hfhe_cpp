#include <pvac/pvac.hpp>
#include <iostream>

using namespace pvac;

static std::array<uint8_t, 32> old_r_com_base(
    uint64_t canon_tag,
    uint64_t ztag,
    uint64_t nonce_lo,
    uint64_t nonce_hi,
    const std::vector<Fp>& r_slots
) {
    Sha256 s;
    s.init();
    s.update("pvac.dom.r_com", 14);
    sha256_acc_u64(s, canon_tag);
    sha256_acc_u64(s, ztag);
    sha256_acc_u64(s, nonce_lo);
    sha256_acc_u64(s, nonce_hi);
    sha256_acc_u64(s, static_cast<uint64_t>(r_slots.size()));
    for (const auto& r : r_slots) {
        sha256_acc_u64(s, r.lo);
        sha256_acc_u64(s, r.hi & MASK63);
    }
    std::array<uint8_t, 32> out{};
    s.finish(out.data());
    return out;
}

static Fp public_numerator_slot0(const PubKey& pk, const Cipher& c) {
    Fp acc = c.c0.empty() ? fp_from_u64(0) : c.c0[0];
    for (const auto& e : c.E) {
        if (e.layer_id != 0) continue;
        if (e.w.empty()) return fp_from_u64(0);
        Fp term = fp_mul(e.w[0], pk.powg_B[e.idx]);
        acc = sgn_val(e.ch) > 0 ? fp_add(acc, term) : fp_sub(acc, term);
    }
    return acc;
}

static Fp candidate_r(const PubKey& pk, const Cipher& c, const Fp& candidate) {
    Fp n = public_numerator_slot0(pk, c);
    return fp_mul(n, fp_inv(candidate));
}

static bool candidate_matches_r_com(const PubKey& pk, const Cipher& c, const Fp& candidate) {
    Fp r = candidate_r(pk, c, candidate);
    auto d = compute_R_com_base(pk.canon_tag, c.L[0].seed.ztag, c.L[0].seed.nonce.lo, c.L[0].seed.nonce.hi, { r });
    return d == c.L[0].R_com;
}

static bool old_candidate_matches_r_com(const PubKey& pk, const Cipher& c, const Fp& candidate, const Fp& real_r) {
    Fp r = candidate_r(pk, c, candidate);
    auto old_public = old_r_com_base(pk.canon_tag, c.L[0].seed.ztag, c.L[0].seed.nonce.lo, c.L[0].seed.nonce.hi, { real_r });
    auto old_candidate = old_r_com_base(pk.canon_tag, c.L[0].seed.ztag, c.L[0].seed.nonce.lo, c.L[0].seed.nonce.hi, { r });
    return old_public == old_candidate;
}

int main() {
    Params p;
    p.noise_entropy_bits = 128.0;
    PubKey pk;
    SecKey sk;
    keygen(p, pk, sk);

    Fp m = fp_from_u64(1234567);
    Fp wrong = fp_from_u64(7654321);
    Cipher c = enc_fp_raw_depth(pk, sk, m, 2);
    std::vector<uint8_t> st(c.L.size(), 0);
    std::vector<std::vector<Fp>> cache(c.L.size());
    Fp real_r = layer_R_cached(pk, sk, c, 0, st, cache)[0];
    bool old_right = old_candidate_matches_r_com(pk, c, m, real_r);
    bool old_bad = old_candidate_matches_r_com(pk, c, wrong, real_r);
    bool right = candidate_matches_r_com(pk, c, m);
    bool bad = candidate_matches_r_com(pk, c, wrong);
    bool roundtrip = dec_value(pk, sk, c).lo == m.lo && dec_value(pk, sk, c).hi == m.hi;

    std::cout << "old_oracle_right = " << old_right << "\n";
    std::cout << "old_oracle_wrong = " << old_bad << "\n";
    std::cout << "oracle_right = " << right << "\n";
    std::cout << "oracle_wrong = " << bad << "\n";
    std::cout << "roundtrip = " << roundtrip << "\n";

    return (old_right && !old_bad && right && bad && roundtrip) ? 0 : 1;
}