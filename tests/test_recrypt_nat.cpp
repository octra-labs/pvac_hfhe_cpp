#include <array>
#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>
#include <pvac/pvac_native.hpp>

using namespace pvac;

static void must(bool ok, const std::string& msg) {
    if (ok) {
        return;
    }
    std::cerr << "fail = " << msg << "\n";
    std::exit(1);
}

static std::array<uint8_t, 32> tag(uint64_t x) {
    std::array<uint8_t, 32> out{};
    for (size_t i = 0; i < out.size(); ++i) {
        out[i] = static_cast<uint8_t>((x + i * 31) & 255);
    }
    return out;
}

static Params prm() {
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

static Cipher enc(const PubKey& pk, const SecKey& sk, uint64_t v, uint64_t t) {
    auto s = tag(t);
    return enc_nat_value_seeded(pk, sk, v, s.data(), 2);
}

static Cipher enc_vec(const PubKey& pk, const SecKey& sk, const std::vector<uint64_t>& xs, uint64_t t) {
    auto s = tag(t);
    std::vector<Fp> v;
    v.reserve(xs.size());
    for (auto x : xs) {
        v.push_back(fp_from_u64(x));
    }
    return enc_nat_fp_seeded(pk, sk, v, s.data(), 2);
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

static bool branch_seen_all(const std::array<uint8_t, 3>& seen) {
    return seen[0] && seen[1] && seen[2];
}

static std::array<uint8_t, 32> selector_challenge(size_t seed) {
    std::array<uint8_t, 32> challenge{};
    for (size_t i = 0; i < challenge.size(); ++i) {
        challenge[i] = static_cast<uint8_t>((seed * 29 + i * 37 + 11) & 255);
    }
    return challenge;
}

static void run_branch_selector_regression() {
    auto proof_params = make_native_reset_proof_params();
    auto arith_params = native_reset_arith_params_from_proof(proof_params);
    std::array<uint8_t, 3> proof_seen{};
    std::array<uint8_t, 3> arith_seen{};
    for (size_t seed = 0; seed < 4096 && (!branch_seen_all(proof_seen) || !branch_seen_all(arith_seen)); ++seed) {
        auto challenge = selector_challenge(seed);
        auto proof_branch = native_reset_proof_opened_branch(proof_params, challenge, seed, 0);
        auto arith_branch = native_reset_arith_opened_branch(arith_params, challenge, seed, 0);
        if (proof_branch < proof_seen.size())
            proof_seen[proof_branch] = 1;
        if (arith_branch < arith_seen.size())
            arith_seen[arith_branch] = 1;
    }
    must(branch_seen_all(proof_seen), "native reset proof branch selector reaches all openings");
    must(branch_seen_all(arith_seen), "native reset arithmetic branch selector reaches all openings");
    auto bad_proof_params = proof_params;
    bad_proof_params.opened_branches = 2;
    auto challenge = selector_challenge(0);
    must(native_reset_proof_opened_branch(bad_proof_params, challenge, 0, 0) == bad_proof_params.branches, "native reset proof selector rejects unsupported opening count");
    auto bad_arith_params = arith_params;
    bad_arith_params.opened_branches = 2;
    must(native_reset_arith_opened_branch(bad_arith_params, challenge, 0, 0) == bad_arith_params.branches, "native reset arithmetic selector rejects unsupported opening count");
    std::cout << "native_reset_branch_selector = 1\n";
}


// pums 2.

static Layer test_base_layer(const PubKey& pk, const SecKey& sk, uint64_t lo, uint64_t hi, size_t slots, std::vector<Fp>& r) {
    Layer layer{};
    layer.rule = RRule::BASE;
    layer.seed.nonce = Nonce128{lo, hi};
    layer.seed.ztag = prg_layer_ztag(pk.canon_tag, layer.seed.nonce);
    r = prf_R_slots(pk, sk, layer.seed, slots);
    layer.R_com = compute_R_com_base(pk.canon_tag, layer.seed.ztag, layer.seed.nonce.lo, layer.seed.nonce.hi, r);
    compute_layer_PC(layer, sk, r, slots);
    return layer;
}

static void run_layer_binding_policy(const PubKey& pk, const SecKey& sk) {
    NativeResetStmt stmt;
    stmt.c = {fp(9)};
    stmt.alpha = {{fp(1)}};
    stmt.target_terms = 1;
    stmt.bound = HiddenCoeffBound{1, 8, 8};
    NativeResetOutput out;
    out.c = {fp(9)};
    out.beta = {{fp(1)}};
    NativeResetLayerWitness wit;
    wit.canon_tag = pk.canon_tag;
    std::vector<Fp> old_r;
    std::vector<Fp> new_r;
    wit.old_layers.push_back(test_base_layer(pk, sk, 101, 202, 1, old_r));
    wit.new_layers.push_back(test_base_layer(pk, sk, 303, 404, 1, new_r));
    wit.old_r = {old_r};
    wit.new_r = {new_r};
    NativeResetSecrets sec;
    sec.old_x = {{fp_inv(old_r[0])}};
    sec.new_y = {{fp_inv(new_r[0])}};
    auto params = make_native_reset_proof_params();
    auto seed = tag(5151);
    auto old_digest = native_reset_layer_stack_digest(wit.old_layers);
    auto new_digest = native_reset_layer_stack_digest(wit.new_layers);
    auto sha_trace = make_native_reset_sha_compat_trace_boundary(wit, params, seed);
    auto field_trace = make_native_reset_field_layer_trace_boundary(wit, params, seed);
    must(!decide_native_reset_layer_trace(sha_trace, old_digest, new_digest).admitted, "native reset rejects sha trace");
    must(decide_native_reset_field_proof(field_trace.field_proof, old_digest, new_digest).admitted, "native reset field subproof checks product stack");
    must(!decide_native_reset_layer_trace(field_trace, old_digest, new_digest).admitted, "native reset rejects unbound field trace");
    auto sha_layer = make_native_reset_layer_sha_compat_proof(stmt, out, wit, sec, params, seed);
    auto field_layer = make_native_reset_layer_field_proof(stmt, out, wit, sec, params, seed);
    must(!decide_native_reset_layer_proof(stmt, out, sha_layer).admitted, "native reset rejects sha layer proof");
    must(!decide_native_reset_layer_proof(stmt, out, field_layer).admitted, "native reset rejects unbound field layer proof");
    std::cout << "native_reset_layer_binding = 1\n";
}

static void need(const NatStep& s, size_t terms, const std::string& msg) {
    auto& h = nat_carrier(s);
    must(native_runtime_carrier_ok(h), msg + " ok");
    must(h.out.target_terms == terms, msg + " terms");
    must(!h.materialized_cipher, msg + " hidden");
    must(h.hidden_coeffs, msg + " hidden coeffs");
    must(h.no_basis_oracle, msg + " no basis oracle");
    must(h.native_backend, msg + " native");
    must(h.out.hidden_coeffs, msg + " out hidden coeffs");
    must(!h.out.visible_beta, msg + " no visible beta");
}

static bool has_native_source(const PubKey& pk, const Cipher& ct) {
    for (const auto& layer : ct.L) {
        if (layer.rule == RRule::BASE && ru_src(pk, layer)) {
            return true;
        }
    }
    return false;
}

static size_t base_layer_count(const Cipher& ct) {
    size_t n = 0;
    for (const auto& layer : ct.L) {
        if (layer.rule == RRule::BASE) {
            ++n;
        }
    }
    return n;
}

static void run_key_material(const PubKey& pk, const SecKey& sk, const NatKey& rk) {
    must(nat_key_safe(pk, rk), "nat key safe");
    must(rk.sec.size() == sk.prf_k.size(), "nat key material count");
    for (size_t i = 0; i < rk.sec.size(); ++i) {
        must(!has_native_source(pk, rk.sec[i]), "nat key material avoids native source");
        must(base_layer_count(rk.sec[i]) == 2, "nat key material wrapped");
        must(ct::fp_eq(dec_value_native_local(pk, sk, rk.sec[i]), fp_from_u64(sk.prf_k[i])), "nat key material decrypts");
    }
    auto seed = tag(9001);



    auto safe = enc_nat_value_seeded(pk, sk, sk.prf_k[0], seed.data(), 4);
    must(!has_native_source(pk, safe), "nat public material avoids native source");
    must(base_layer_count(safe) == 1, "nat public material uses standard source");
    must(ct::fp_eq(dec_value_native_local(pk, sk, safe), fp_from_u64(sk.prf_k[0])), "nat public material decrypts");
    auto compat = enc_ru_value_seeded(pk, sk, sk.prf_k[0], seed.data(), 4);
    must(!has_native_source(pk, compat), "ru compat material avoids native source");
    must(base_layer_count(compat) == 1, "ru compat material uses standard source");
    must(ct::fp_eq(dec_value_native_local(pk, sk, compat), fp_from_u64(sk.prf_k[0])), "ru compat material decrypts");



    
    auto legacy = rk;
    legacy.sec[0].L[0].PC.clear();
    legacy.view = rku_view(pk, legacy);
    must(!nat_key_safe(pk, legacy), "nat key rejects unbound material");
    std::cout << "nat_key_material = 1\n";
}

static void reset_ok(const PubKey& pk, const NatKey& rk, const NatAdm& adm, const NatStep& src, const NatStep& out, size_t q, const std::string& msg) {
    need(out, adm.out_terms, msg);
    must(nat_query(out) == q, msg + " query");
    must(recrypt_verify(pk, rk, nat_carrier(src), adm, adm.out_terms, q, nat_carrier(out)), msg + " verify");
}

static void reject_carrier(const NatAdm& adm, const NatStep& src, const std::string& name) {
    auto h = nat_carrier(src);
    if (name == "materialized") {
        h.materialized_cipher = true;
    }
    if (name == "visible") {
        h.out.visible_beta = true;
        h.out.output_digest = native_chosen_output_digest(h.out);
    }
    if (name == "basis") {
        h.no_basis_oracle = false;
    }
    if (name == "backend") {
        h.native_backend = false;
    }
    must(dies([&]() { auto bad = nat_step(adm, h, nat_query(src)); (void)bad; }), "nat rejects " + name);
}

static void run_negative(const PubKey& pk, const NatKey& rk, const Cipher& x, const Cipher& y) {
    auto adm = nat_chain();
    auto hx = nat_in(pk, x, adm);
    auto hy = nat_in(pk, y, adm);
    auto s = nat_mul(adm, hx, hy);
    auto r = nat_recrypt(pk, rk, adm, s);
    reject_carrier(adm, r, "materialized");
    reject_carrier(adm, r, "visible");
    reject_carrier(adm, r, "basis");
    reject_carrier(adm, r, "backend");
    auto other = nat_wide();
    must(dies([&]() { auto bad = nat_mul(other, r, nat_in(pk, x, other)); (void)bad; }), "nat rejects profile mismatch");
    NativeResetStageRequest req;
    req.alpha.assign(nat_carrier(s).out.target_terms, fp(3));
    req.next_terms = adm.out_terms;
    req.alpha_bits = adm.alpha_bits;
    req.row_bits = adm.row_bits;
    req.query = 7;
    std::vector<NativeResetStageRequest> bad_requests = {req};
    must(!nat_recrypt_verify_unsafe(pk, rk, nat_carrier(s), bad_requests, nat_carrier(r)), "nat unsafe chosen alpha excluded");
    std::cout << "nat_negative = 1\n";
}

static void run_lin(const PubKey& pk, const NatKey& rk, const Cipher& x, const Cipher& y, const Cipher& z) {
    auto adm = nat_lin();
    auto hx = nat_in(pk, x, adm);
    auto hy = nat_in(pk, y, adm);
    auto hz = nat_in(pk, z, adm);
    auto xy = nat_add(adm, nat_scale(adm, hx, fp(3)), nat_scale(adm, hy, fp(5)));
    auto zc = nat_add_const(adm, hz, fp(9));
    auto t = nat_add(adm, xy, zc);
    need(t, 3, "nat lin stage");
    auto r = nat_recrypt(pk, rk, adm, t);
    reset_ok(pk, rk, adm, t, r, 1, "nat lin reset");
    std::cout << "nat_lin = 1\n";
}

static void run_quad(const PubKey& pk, const NatKey& rk, const Cipher& x, const Cipher& y, const Cipher& z, const Cipher& w) {
    auto adm = nat_quad();
    auto hx = nat_in(pk, x, adm);
    auto hy = nat_in(pk, y, adm);
    auto hz = nat_in(pk, z, adm);
    auto hw = nat_in(pk, w, adm);
    auto a = nat_add(adm, nat_add(adm, hx, hy), hz);
    auto b = nat_add_const(adm, nat_add(adm, hx, hw), fp(4));
    auto t = nat_mul(adm, a, b);
    need(t, 6, "nat quad stage");
    auto r = nat_recrypt(pk, rk, adm, t);
    reset_ok(pk, rk, adm, t, r, 1, "nat quad reset");
    std::cout << "nat_quad = 1\n";
}

static void run_chain(const PubKey& pk, const NatKey& rk, const Cipher& x, const Cipher& y, const Cipher& z, const Cipher& w) {
    auto adm = nat_chain();
    auto hx = nat_in(pk, x, adm);
    auto hy = nat_in(pk, y, adm);
    auto hz = nat_in(pk, z, adm);
    auto hw = nat_in(pk, w, adm);
    auto s = nat_add(adm, hx, hy);
    auto t = nat_mul(adm, s, nat_add_const(adm, s, fp(9)));
    need(t, 4, "nat chain stage 1");
    auto r1 = nat_recrypt(pk, rk, adm, t);
    reset_ok(pk, rk, adm, t, r1, 1, "nat chain reset 1");
    auto u = nat_mul(adm, r1, hz);
    need(u, 2, "nat chain stage 2");
    auto r2 = nat_recrypt(pk, rk, adm, u);
    reset_ok(pk, rk, adm, u, r2, 2, "nat chain reset 2");
    auto v = nat_mul(adm, r2, hw);
    need(v, 2, "nat chain stage 3");
    auto r3 = nat_recrypt(pk, rk, adm, v);
    reset_ok(pk, rk, adm, v, r3, 3, "nat chain reset 3");
    std::cout << "nat_chain = 1\n";
}

static void run_wide(const PubKey& pk, const NatKey& rk, const Cipher& x, const Cipher& y, const Cipher& z, const Cipher& w) {
    auto adm = nat_wide();
    auto hx = nat_in(pk, x, adm);
    auto hy = nat_in(pk, y, adm);
    auto hz = nat_in(pk, z, adm);
    auto hw = nat_in(pk, w, adm);
    auto a = nat_add(adm, nat_add(adm, nat_add(adm, hx, hy), hz), hw);
    auto bx = nat_scale(adm, hx, fp(2));
    auto by = nat_scale(adm, hy, fp(3));
    auto bz = nat_scale(adm, hz, fp(5));
    auto bw = nat_add_const(adm, nat_scale(adm, hw, fp(7)), fp(11));
    auto b = nat_add(adm, nat_add(adm, nat_add(adm, bx, by), bz), bw);
    need(a, 4, "nat wide left");
    need(b, 4, "nat wide right");
    auto t = nat_mul(adm, a, b);
    need(t, 16, "nat wide stage 1");
    auto r1 = nat_recrypt(pk, rk, adm, t);
    reset_ok(pk, rk, adm, t, r1, 1, "nat wide reset 1");
    auto u = nat_mul(adm, r1, a);
    need(u, 16, "nat wide stage 2");
    auto r2 = nat_recrypt(pk, rk, adm, u);
    reset_ok(pk, rk, adm, u, r2, 2, "nat wide reset 2");
    must(dies([&]() { auto bad = nat_mul(adm, t, a); (void)bad; }), "nat wide overflow rejected");
    std::cout << "nat_wide = 1\n";
}

static void run_vec(const PubKey& pk, const SecKey& sk, const NatKey& rk, const NatAdm& adm, const std::vector<uint64_t>& a0, const std::vector<uint64_t>& b0, const std::vector<uint64_t>& c0, const std::string& label) {
    auto a = enc_vec(pk, sk, a0, 31);
    auto b = enc_vec(pk, sk, b0, 32);
    auto c = enc_vec(pk, sk, c0, 33);
    auto ha = nat_in(pk, a, adm);
    auto hb = nat_in(pk, b, adm);
    auto hc = nat_in(pk, c, adm);
    auto left = nat_add(adm, ha, hb);
    auto right = nat_add_const(adm, hc, fp(3));
    auto t = nat_mul(adm, left, right);
    need(t, 2, label + " stage");
    auto r = nat_recrypt(pk, rk, adm, t);
    reset_ok(pk, rk, adm, t, r, 1, label + " reset");
    must(nat_carrier(r).out.slots == a0.size(), label + " slots");
    std::cout << label << " = 1\n";
}

static void run_vec4(const PubKey& pk, const SecKey& sk, const NatKey& rk) {
    run_vec(pk, sk, rk, nat_vec4(), {1, 2, 3, 4}, {5, 6, 7, 8}, {9, 10, 11, 12}, "nat_vec4");
}

static void run_vec8(const PubKey& pk, const SecKey& sk, const NatKey& rk) {
    run_vec(pk, sk, rk, nat_vec8(), {1, 2, 3, 4, 5, 6, 7, 8}, {9, 10, 11, 12, 13, 14, 15, 16}, {17, 18, 19, 20, 21, 22, 23, 24}, "nat_vec8");
}

static void prod_gate_ok(const PubKey& pk, const NatKey& rk, const NatAdm& adm, const std::string& msg) {
    auto gate = nat_prod_gate(pk, rk, adm);
    must(gate.admitted, msg + " admitted");
    must(gate.key, msg + " key");
    must(gate.profile, msg + " profile");
    must(gate.budget, msg + " budget");
}

static void run_prod_gate(const PubKey& pk, const SecKey& sk, const Cipher& x, const Cipher& y, const Cipher& z, const Cipher& w) {
    auto rk = make_nat_key(pk, sk, nat_prod_adm().max_query, nat_prod_budget());
    prod_gate_ok(pk, rk, nat_lin(), "nat prod lin");
    prod_gate_ok(pk, rk, nat_quad(), "nat prod quad");
    prod_gate_ok(pk, rk, nat_chain(), "nat prod chain");
    prod_gate_ok(pk, rk, nat_wide(), "nat prod wide");
    prod_gate_ok(pk, rk, nat_vec4(), "nat prod vec4");
    prod_gate_ok(pk, rk, nat_vec8(), "nat prod vec8");
    auto adm = nat_prod_adm();
    auto hx = nat_in(pk, x, adm);
    auto hy = nat_in(pk, y, adm);
    auto hz = nat_in(pk, z, adm);
    auto hw = nat_in(pk, w, adm);
    auto left = nat_add(adm, nat_add(adm, hx, hy), nat_add(adm, hz, hw));
    auto right = nat_add_const(adm, left, fp(17));
    auto stage = nat_mul(adm, left, right);
    need(stage, 16, "nat prod stage");
    auto clean = nat_prod_recrypt(pk, rk, adm, stage);
    reset_ok(pk, rk, adm, stage, clean, 1, "nat prod reset");
    must(nat_prod_verify(pk, rk, adm, stage, clean), "nat prod verify");
    must(!nat_prod_verify(pk, rk, adm, left, clean), "nat prod rejects wrong source");
    auto too_terms = nat_prod_adm();
    too_terms.max_terms += 1;
    must(nat_prod_gate(pk, rk, too_terms).rejects_profile, "nat prod rejects max terms");
    auto too_out = nat_prod_adm();
    too_out.out_terms += 1;
    must(nat_prod_gate(pk, rk, too_out).rejects_profile, "nat prod rejects out terms");
    auto too_slots = nat_prod_adm();
    too_slots.max_slots += 1;
    must(nat_prod_gate(pk, rk, too_slots).rejects_profile, "nat prod rejects slots");
    auto too_query = nat_prod_adm();
    too_query.max_query += 1;
    must(nat_prod_gate(pk, rk, too_query).rejects_profile, "nat prod rejects query");
    auto too_alpha = nat_prod_adm();
    too_alpha.alpha_bits += 1;
    must(nat_prod_gate(pk, rk, too_alpha).rejects_profile, "nat prod rejects alpha bits");
    auto too_row = nat_prod_adm();
    too_row.row_bits += 1;
    must(nat_prod_gate(pk, rk, too_row).rejects_profile, "nat prod rejects row bits");
    auto sha_key = rk;
    sha_key.budget.proof = NativeResetProofProfileKind::SHA_COMPAT;
    sha_key.view = rku_view(pk, sha_key);
    auto sha_gate = nat_prod_gate(pk, sha_key, nat_prod_adm());
    must(!sha_gate.admitted && sha_gate.rejects_sha_compat, "nat prod rejects sha compat");
    auto weak_key = rk;
    weak_key.budget.target_bits = 64;
    weak_key.view = rku_view(pk, weak_key);
    auto weak_gate = nat_prod_gate(pk, weak_key, nat_prod_adm());
    must(!weak_gate.admitted && weak_gate.rejects_underbudget, "nat prod rejects underbudget");
    auto output_key = rk;
    output_key.budget.max_output_tags = nat_prod_budget().max_output_tags + 1;
    output_key.view = rku_view(pk, output_key);
    auto output_gate = nat_prod_gate(pk, output_key, nat_prod_adm());
    must(!output_gate.admitted && output_gate.rejects_output_wide, "nat prod rejects output wide");
    auto query_key = make_nat_key(pk, sk, nat_prod_adm().max_query + 1, nat_prod_budget());
    auto query_gate = nat_prod_gate(pk, query_key, nat_prod_adm());
    must(!query_gate.admitted && query_gate.rejects_key, "nat prod rejects key query");
    std::cout << "nat_prod_gate = 1\n";
}

int main() {
    run_branch_selector_regression();
    PubKey pk;
    SecKey sk;
    keygen(prm(), pk, sk);
    run_layer_binding_policy(pk, sk);
    auto rk = make_nat_key(pk, sk, 128);
    auto x = enc(pk, sk, 5, 11);
    auto y = enc(pk, sk, 7, 12);
    auto z = enc(pk, sk, 11, 13);
    auto w = enc(pk, sk, 13, 14);
    run_key_material(pk, sk, rk);
    run_lin(pk, rk, x, y, z);
    run_quad(pk, rk, x, y, z, w);
    run_chain(pk, rk, x, y, z, w);
    run_wide(pk, rk, x, y, z, w);
    run_vec4(pk, sk, rk);
    run_vec8(pk, sk, rk);
    run_negative(pk, rk, x, y);
    run_prod_gate(pk, sk, x, y, z, w);
    return 0;
}