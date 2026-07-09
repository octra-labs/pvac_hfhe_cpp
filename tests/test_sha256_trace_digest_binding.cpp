// Security regression test: verify_sha256_hidden_trace_branch_proof does NOT bind
// proof.digest to the circuit output.
//
// The branch verifier checks gate consistency of the two opened branches, the commits,
// the challenge, and the response digest -- but never checks that the traced computation
// actually produces proof.digest. proof.digest is only hashed into the Fiat-Shamir
// challenge (committed), never verified against the reconstructed output. So an attacker
// can assert ANY digest with valid branches.
//
// This test forges a proof whose circuit hashes "honest message" but that asserts an
// attacker-chosen digest, and shows verify accepts it. In recrypt_native_cert.hpp this
// forges `sha.digest == layer.R_com` for an arbitrary R_com (a fake recryption).
//
// EXPECTED SECURE BEHAVIOR: verify must reject a proof whose branches do not compute the
// claimed digest. This test returns non-zero until that binding is added (see PR body).
//
// Build: g++ -std=c++17 -O2 -march=native -I./include tests/test_sha256_trace_digest_binding.cpp -o build/test_sha256_trace_digest_binding

#include <pvac/pvac.hpp>
#include <pvac/ops/sha256_trace.hpp>
#include <pvac/ops/sha256_hidden_trace.hpp>
#include <array>
#include <cstring>
#include <iostream>
#include <vector>

using namespace pvac;

int main() {
    std::vector<uint8_t> real_msg = { 'h','o','n','e','s','t',' ','m','e','s','s','a','g','e' };
    Sha256Trace trace = make_sha256_trace(real_msg);

    std::array<uint8_t, 32> fake_digest;
    for (int i = 0; i < 32; ++i) fake_digest[i] = static_cast<uint8_t>(0xA0 + i);  // attacker-chosen

    std::cout << "real digest   : ";
    for (int i = 0; i < 8; ++i) printf("%02x", trace.digest[i]);
    std::cout << "...\nforged digest : ";
    for (int i = 0; i < 8; ++i) printf("%02x", fake_digest[i]);
    std::cout << "...  (attacker chosen)\n";

    bool accepted = false;
    for (uint64_t seed = 1; seed < 64 && !accepted; ++seed) {
        Fp a = fp_from_words(0x9e3779b97f4a7c15ULL * seed, 0x123456789ULL * seed);
        Fp b = fp_from_words(0xc2b2ae3d27d4eb4fULL * seed, 0x987654321ULL * seed);
        auto hidden = make_sha256_hidden_trace_proof(trace, a, b);
        auto P = make_sha256_hidden_trace_branch_proof(hidden);
        size_t closed = static_cast<size_t>(P.challenge[0]) % 3;

        P.digest = fake_digest;                                       // assert a false digest
        P.challenge = sha256_hidden_trace_branch_challenge(P);
        if (static_cast<size_t>(P.challenge[0]) % 3 != closed) continue;
        P.response_digest = sha256_hidden_trace_branch_response(P);

        if (verify_sha256_hidden_trace_branch_proof(P)) accepted = true;
    }

    if (accepted) {
        std::cout << "\nVULNERABLE: verify_sha256_hidden_trace_branch_proof accepted a proof for a\n"
                     "false digest (branches compute the real hash, proof asserts the fake one).\n"
                     "FAIL (expected until proof.digest is bound to the reconstructed output)\n";
        return 1;
    }
    std::cout << "\nverify rejected the forged digest -- output binding present. PASS\n";
    return 0;
}
