// Regression test for the native-reset statement-digest oracle.
//
// Before the fix, hidden_coeff_stmt_digest() hashed the SECRET coefficient vector
// `alpha` under a public-only salt. Since the digest is published in the transcript
// and the bound advertises alpha_bits, an observer could brute-force low-entropy
// coefficients out of the published digest (same class as the R_com plaintext oracle).
//
// After the fix, statement_digest is independent of the secret alpha values, so the
// oracle is closed, while honest transcripts still verify.
//
// Build: g++ -std=c++17 -O2 -march=native -I./include tests/test_hidden_coeff_leak.cpp -o build/test_hidden_coeff_leak

#include <pvac/pvac.hpp>
#include <pvac/ops/recrypt_hidden_coeff.hpp>
#include <array>
#include <cstring>
#include <iostream>
#include <vector>

using namespace pvac;

// The vulnerable pre-fix digest, kept here only to demonstrate the oracle it enabled.
static std::array<uint8_t, 32> old_hidden_coeff_stmt_digest(const HiddenCoeffStmt& stmt) {
    Sha256 h;
    h.init();
    h.update("pvac.native.reset.statement", std::strlen("pvac.native.reset.statement"));
    hidden_coeff_acc_bound(h, stmt.bound);
    sha256_acc_u64(h, stmt.alpha.size());
    for (const auto& alpha : stmt.alpha) {
        hidden_coeff_acc_fp(h, alpha);
    }
    std::array<uint8_t, 32> out{};
    h.finish(out.data());
    return out;
}

int main() {
    int fail = 0;

    HiddenCoeffBound bound{ /*terms*/1, /*alpha_bits*/20, /*row_bits*/40 };
    std::vector<std::array<uint8_t, 32>> tags(1);
    tags[0].fill(0x11);
    auto material = make_hidden_coeff_material(tags, bound);

    // A secret, low-entropy (20-bit) coefficient.
    uint64_t secret = 0xC0FFE & ((1u << 20) - 1);
    auto stmt = make_hidden_coeff_stmt({ fp_from_u64(secret) }, bound);

    // 1) The OLD digest is a brute-force oracle: recover the secret from the published digest.
    auto old_pub = old_hidden_coeff_stmt_digest(stmt);
    uint64_t recovered = 0;
    bool old_leaks = false;
    for (uint64_t cand = 0; cand < (1u << 20); ++cand) {
        auto g = make_hidden_coeff_stmt({ fp_from_u64(cand) }, bound);
        if (std::memcmp(old_hidden_coeff_stmt_digest(g).data(), old_pub.data(), 32) == 0) {
            recovered = cand; old_leaks = true; break;
        }
    }
    std::cout << "[pre-fix] secret recovered from published digest: "
              << (old_leaks ? "yes" : "no")
              << " (value=0x" << std::hex << recovered << std::dec << ")\n";
    if (!old_leaks || recovered != secret) {
        std::cout << "  (could not reproduce the historical oracle; test setup issue)\n";
    }

    // 2) The CURRENT digest must NOT depend on the secret alpha values.
    auto d_secret = hidden_coeff_stmt_digest(stmt);
    auto other = make_hidden_coeff_stmt({ fp_from_u64((secret ^ 0xABCDE) & ((1u << 20) - 1)) }, bound);
    auto d_other = hidden_coeff_stmt_digest(other);
    bool current_leaks = std::memcmp(d_secret.data(), d_other.data(), 32) != 0;
    std::cout << "[post-fix] statement_digest depends on secret alpha: "
              << (current_leaks ? "YES (still an oracle)" : "no (oracle closed)") << "\n";
    if (current_leaks) { std::cout << "FAIL: statement_digest still leaks alpha\n"; ++fail; }

    // 3) Honest transcripts must still verify (functionality preserved).
    auto transcript = make_native_hidden_coeff_transcript(material, stmt);
    bool ok = verify_native_hidden_coeff_transcript(material, stmt, transcript);
    std::cout << "[post-fix] honest transcript round-trips: " << (ok ? "yes" : "no") << "\n";
    if (!ok) { std::cout << "FAIL: fix broke honest transcript verification\n"; ++fail; }

    std::cout << (fail == 0 ? "\nPASS\n" : "\nFAIL\n");
    return fail == 0 ? 0 : 1;
}
