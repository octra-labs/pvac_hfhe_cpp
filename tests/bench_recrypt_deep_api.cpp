#include <chrono>
#include <cstdlib>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <pvac/pvac_native.hpp>

using namespace pvac;

using Clock = std::chrono::steady_clock;

struct Case {
    std::string name;
    Params prm;
};

struct Run {
    size_t cadence = 0;
    size_t depth = 0;
    size_t resets = 0;
    size_t fail_depth = 0;
    size_t peak_l = 0;
    size_t peak_e = 0;
    size_t peak_bytes = 0;
    size_t final_l = 0;
    size_t final_e = 0;
    size_t final_bytes = 0;
    std::string fail_stage = "none";
    uint64_t total_us = 0;
    uint64_t mul_us = 0;
    uint64_t reset_us = 0;
    uint64_t verify_us = 0;
    bool survived = false;
    bool correct = false;
};

static void must(bool ok, const std::string& msg) {
    if (ok) {
        return;
    }
    std::cerr << "FAIL: " << msg << "\n";
    std::exit(1);
}

static uint64_t env_u64(const char* key, uint64_t fallback, uint64_t cap) {
    auto raw = std::getenv(key);
    if (!raw) {
        return fallback;
    }
    auto n = std::strtoull(raw, nullptr, 10);
    if (n == 0 || n > cap) {
        return fallback;
    }
    return n;
}

static std::string env_text(const char* key, const std::string& fallback) {
    auto raw = std::getenv(key);
    if (!raw || raw[0] == 0) {
        return fallback;
    }
    return raw;
}

static uint64_t us(Clock::time_point a, Clock::time_point b) {
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(b - a).count());
}

static Params small_prm() {
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

static Params mid_prm() {
    Params p;
    p.m_bits = 2048;
    p.n_bits = 4096;
    p.h_col_wt = 64;
    p.x_col_wt = 48;
    p.err_wt = 48;
    p.lpn_n = 512;
    p.lpn_t = 2048;
    p.edge_budget = 2000000;
    return p;
}

static Case pick_case() {
    auto name = env_text("PVAC_DEEP_PROFILE", "small");
    if (name == "small") {
        return {name, small_prm()};
    }
    if (name == "mid") {
        return {name, mid_prm()};
    }
    if (name == "base") {
        return {name, Params{}};
    }
    return {"small", small_prm()};
}

static std::vector<size_t> cadences() {
    std::vector<size_t> out;
    std::stringstream ss(env_text("PVAC_DEEP_CADENCES", "1,2"));
    std::string item;
    while (std::getline(ss, item, ',')) {
        auto n = std::strtoull(item.c_str(), nullptr, 10);
        if (n > 0 && n <= 1000000) {
            out.push_back(static_cast<size_t>(n));
        }
    }
    if (out.empty()) {
        out.push_back(1);
    }
    return out;
}

static size_t bit_bytes(const BitVec& v) {
    return (v.nbits + 7) / 8;
}

static size_t layer_bytes(const Layer& l) {
    return 1 + 16 + 8 + l.R_com.size() + l.PC.size() * 32;
}

static size_t edge_bytes(const Edge& e) {
    return 4 + 2 + 1 + e.w.size() * sizeof(Fp) + bit_bytes(e.s);
}

static size_t ct_bytes(const Cipher& ct) {
    size_t n = sizeof(size_t) + ct.c0.size() * sizeof(Fp);
    for (const auto& l : ct.L) {
        n += layer_bytes(l);
    }
    for (const auto& e : ct.E) {
        n += edge_bytes(e);
    }
    return n;
}

static size_t pk_bytes(const PubKey& pk) {
    size_t n = sizeof(pk.canon_tag) + pk.H_digest.size() + sizeof(Fp);
    n += pk.powg_B.size() * sizeof(Fp);
    for (const auto& h : pk.H) {
        n += bit_bytes(h);
    }
    n += pk.ubk.perm.size() * sizeof(int);
    n += pk.ubk.inv.size() * sizeof(int);
    return n;
}

static void add_peak(Run& run, const Cipher& ct) {
    auto bytes = ct_bytes(ct);
    if (ct.L.size() > run.peak_l) {
        run.peak_l = ct.L.size();
    }
    if (ct.E.size() > run.peak_e) {
        run.peak_e = ct.E.size();
    }
    if (bytes > run.peak_bytes) {
        run.peak_bytes = bytes;
    }
}

static void show_micro(const Case& c, const PubKey& pk, const SecKey& sk) {
    auto t0 = Clock::now();
    auto scalar = enc(pk, sk, 123456789ULL);
    auto t1 = Clock::now();
    std::vector<uint64_t> xs;
    xs.reserve(64);
    for (uint64_t i = 0; i < 64; ++i) {
        xs.push_back(1000 + i);
    }
    auto simd = enc(pk, sk, xs);
    auto t2 = Clock::now();
    std::cout << "profile = " << c.name << " ";
    std::cout << "experiment = micro ";
    std::cout << "scalar_enc_us = " << us(t0, t1) << " ";
    std::cout << "simd64_enc_us = " << us(t1, t2) << " ";
    std::cout << "pk_bytes = " << pk_bytes(pk) << " ";
    std::cout << "ct_scalar_bytes = " << ct_bytes(scalar) << " ";
    std::cout << "ct_simd64_bytes = " << ct_bytes(simd) << " ";
    std::cout << "bytes_per_value = " << (ct_bytes(simd) / 64) << " ";
    std::cout << "ok = 1\n" << std::flush;
}

static void show_reset_depth(const Case& c, const PubKey& pk, const SecKey& sk, const NatKey& rk) {
    auto max_depth = env_u64("PVAC_RESET_DEPTH_MAX", 2, 128);
    auto two = enc(pk, sk, 2ULL);
    for (uint64_t d = 0; d <= max_depth; ++d) {
        auto acc = enc(pk, sk, 2ULL);
        auto expected = fp_from_u64(2);
        for (uint64_t i = 0; i < d; ++i) {
            acc = ct_mul(pk, acc, two);
            expected = fp_mul(expected, fp_from_u64(2));
        }
        auto in_l = acc.L.size();
        auto in_e = acc.E.size();
        auto in_bytes = ct_bytes(acc);
        bool survived = false;
        bool correct = false;
        bool verified = false;
        size_t out_l = 0;
        size_t out_e = 0;
        size_t out_bytes = 0;
        uint64_t reset_us = 0;
        uint64_t verify_us = 0;
        try {
            auto r0 = Clock::now();
            auto clean = recrypt(pk, rk, acc);
            auto r1 = Clock::now();
            verified = recrypt_verify(pk, rk, acc, clean);
            auto r2 = Clock::now();
            survived = verified;
            correct = verified && ct::fp_eq(dec1(pk, sk, clean), expected);
            out_l = clean.L.size();
            out_e = clean.E.size();
            out_bytes = ct_bytes(clean);
            reset_us = us(r0, r1);
            verify_us = us(r1, r2);
        } catch (...) {
            survived = false;
        }
        std::cout << "profile = " << c.name << " ";
        std::cout << "experiment = reset_depth ";
        std::cout << "depth = " << d << " ";
        std::cout << "in_l = " << in_l << " ";
        std::cout << "in_e = " << in_e << " ";
        std::cout << "in_bytes = " << in_bytes << " ";
        std::cout << "reset_us = " << reset_us << " ";
        std::cout << "verify_us = " << verify_us << " ";
        std::cout << "out_l = " << out_l << " ";
        std::cout << "out_e = " << out_e << " ";
        std::cout << "out_bytes = " << out_bytes << " ";
        std::cout << "verified = " << (verified ? 1 : 0) << " ";
        std::cout << "correct = " << (correct ? 1 : 0) << " ";
        std::cout << "survived = " << (survived ? 1 : 0) << "\n" << std::flush;
    }
}

static Run run_deep(const PubKey& pk, const SecKey& sk, const NatKey& rk, size_t depth, size_t cadence) {
    Run run;
    run.depth = depth;
    run.cadence = cadence;
    auto start = Clock::now();
    size_t current = 0;
    try {
        auto acc = enc(pk, sk, 2ULL);
        auto two = enc(pk, sk, 2ULL);
        auto expected = fp_from_u64(2);
        add_peak(run, acc);
        for (size_t d = 1; d <= depth; ++d) {
            current = d;
            run.fail_stage = "mul";
            auto m0 = Clock::now();
            acc = ct_mul(pk, acc, two);
            auto m1 = Clock::now();
            run.mul_us += us(m0, m1);
            expected = fp_mul(expected, fp_from_u64(2));
            add_peak(run, acc);
            if (d % cadence == 0) {
                run.fail_stage = "reset";
                auto r0 = Clock::now();
                auto clean = recrypt(pk, rk, acc);
                auto r1 = Clock::now();
                run.fail_stage = "verify";
                auto ok = recrypt_verify(pk, rk, acc, clean);
                auto r2 = Clock::now();
                run.reset_us += us(r0, r1);
                run.verify_us += us(r1, r2);
                run.resets += 1;
                if (!ok) {
                    run.fail_depth = d;
                    run.survived = false;
                    run.total_us = us(start, Clock::now());
                    return run;
                }
                acc = clean;
                run.fail_stage = "none";
                add_peak(run, acc);
            }
        }
        run.final_l = acc.L.size();
        run.final_e = acc.E.size();
        run.final_bytes = ct_bytes(acc);
        run.fail_stage = "final";
        run.correct = ct::fp_eq(dec1(pk, sk, acc), expected);
        run.survived = run.correct;
        run.fail_stage = run.survived ? "none" : "final";
        run.total_us = us(start, Clock::now());
        return run;
    } catch (...) {
        run.fail_depth = current;
        run.survived = false;
        run.total_us = us(start, Clock::now());
        return run;
    }
}

static void show_deep(const Case& c, const Run& r) {
    std::cout << "profile = " << c.name << " ";
    std::cout << "experiment = deepchain ";
    std::cout << "depth = " << r.depth << " ";
    std::cout << "cadence = " << r.cadence << " ";
    std::cout << "total_us = " << r.total_us << " ";
    std::cout << "mul_us = " << r.mul_us << " ";
    std::cout << "reset_us = " << r.reset_us << " ";
    std::cout << "verify_us = " << r.verify_us << " ";
    std::cout << "resets = " << r.resets << " ";
    std::cout << "peak_l = " << r.peak_l << " ";
    std::cout << "peak_e = " << r.peak_e << " ";
    std::cout << "peak_bytes = " << r.peak_bytes << " ";
    std::cout << "final_l = " << r.final_l << " ";
    std::cout << "final_e = " << r.final_e << " ";
    std::cout << "final_bytes = " << r.final_bytes << " ";
    std::cout << "fail_depth = " << r.fail_depth << " ";
    std::cout << "fail_stage = " << r.fail_stage << " ";
    std::cout << "correct = " << (r.correct ? 1 : 0) << " ";
    std::cout << "survived = " << (r.survived ? 1 : 0) << "\n" << std::flush;
}

static void show_compact_chain(const Case& c, const PubKey& pk, const SecKey& sk, const NatKey& rk) {
    auto adm = nat_chain();
    auto a = enc(pk, sk, 2ULL);
    auto b = enc(pk, sk, 3ULL);
    auto ab = ct_mul(pk, a, b);
    auto t0 = Clock::now();
    auto refresh = recrypt_result(pk, rk, ab, adm, 0, true);
    auto t1 = Clock::now();
    auto ok = recrypt_verify(pk, rk, ab, refresh);
    auto step = recrypt_step(refresh);
    auto hb = nat_in(pk, b, adm);
    auto next = nat_mul(adm, step, hb);
    auto reset = recrypt_reset(pk, rk, adm, next);
    auto t2 = Clock::now();
    auto next_ok = recrypt_verify(pk, rk, next.carrier(), adm, adm.out_terms, reset.query(), reset.carrier());
    auto t3 = Clock::now();
    std::cout << "profile = " << c.name << " ";
    std::cout << "experiment = deepchain_compact ";
    std::cout << "refresh_us = " << us(t0, t1) << " ";
    std::cout << "continue_us = " << us(t1, t2) << " ";
    std::cout << "verify_us = " << us(t2, t3) << " ";
    std::cout << "compact_terms = " << recrypt_compact_terms(refresh.compact) << " ";
    std::cout << "next_terms = " << nat_terms(next) << " ";
    std::cout << "reset_terms = " << nat_terms(reset) << " ";
    std::cout << "delivery_l = " << refresh.cipher.L.size() << " ";
    std::cout << "delivery_e = " << refresh.cipher.E.size() << " ";
    std::cout << "ok = " << (ok && next_ok ? 1 : 0) << "\n" << std::flush;
}

int main() {
    auto c = pick_case();
    auto depth = static_cast<size_t>(env_u64("PVAC_DEEP_DEPTH", 2, 100000));
    auto t0 = Clock::now();
    PubKey pk;
    SecKey sk;
    keygen(c.prm, pk, sk);
    auto t1 = Clock::now();
    auto rk = make_recrypt_key(pk, sk);
    auto t2 = Clock::now();
    must(recrypt_key_safe(pk, rk), "recrypt key safe");
    std::cout << "profile = " << c.name << " ";
    std::cout << "experiment = setup ";
    std::cout << "depth = " << depth << " ";
    std::cout << "keygen_us = " << us(t0, t1) << " ";
    std::cout << "rk_us = " << us(t1, t2) << " ";
    std::cout << "m_bits = " << pk.prm.m_bits << " ";
    std::cout << "n_bits = " << pk.prm.n_bits << " ";
    std::cout << "slots = 1 ";
    std::cout << "ok = 1\n" << std::flush;
    show_micro(c, pk, sk);
    show_reset_depth(c, pk, sk, rk);
    for (auto cadence : cadences()) {
        show_deep(c, run_deep(pk, sk, rk, depth, cadence));
    }
    show_compact_chain(c, pk, sk, rk);
    std::cout << "pass \n" << std::flush;
    return 0;
}