#include <pvac/pvac.hpp>
#include <pvac/utils/text.hpp>
#include <iostream>
#include <vector>

using namespace pvac;

inline bool is_printable_block(const uint8_t* data, size_t len) {
    int printable = 0;
    for (size_t i = 0; i < len; ++i) {
        if (data[i] >= 32 && data[i] < 127) ++printable;
    }
    return (printable * 100 / len) > 80;
}

inline void fp_to_bytes(const Fp& f, uint8_t out[15]) {
    uint64_t lo = f.lo;
    uint64_t hi = f.hi;
    for (int j = 0; j < 15; ++j) {
        size_t sh = j * 8;
        out[j] = (sh < 64) ? (uint8_t)(lo >> sh) : (uint8_t)(hi >> (sh - 64));
    }
}

inline Fp try_decrypt_layer(const PubKey& pk, const Cipher& ct, size_t layer_id, const Fp& R_cand) {
    Fp R_inv = fp_inv(R_cand);
    Fp sum = fp_from_u64(0);
    for (const auto& e : ct.E) {
        if (e.layer_id != layer_id) continue;
        Fp r = fp_mul(e.w[0], R_inv);
        Fp term = fp_mul(r, pk.powg_B[e.idx]);
        if (e.ch == SGN_P) sum = fp_add(sum, term);
        else sum = fp_sub(sum, term);
    }
    return sum;
}

int main() {
    std::cout << "- R^2 attack regression test -\n\n";
    
    Params prm;
    PubKey pk;
    SecKey sk;
    keygen(prm, pk, sk);
    
    std::string test_phrase = "test test2 test3 test4";
    std::cout << "plaintext: \"" << test_phrase << "\"\n";
    std::cout << "len: " << test_phrase.size() << " bytes\n\n";
    
    auto cts = enc_text(pk, sk, test_phrase);
    std::cout << "encrypted: " << cts.size() << " ciphertexts\n\n";
    
    int total_pairs = 0;
    int r2_leaks = 0;
    
    for (size_t ct_idx = 0; ct_idx < cts.size(); ++ct_idx) {
        const Cipher& ct = cts[ct_idx];
        
        Fp R_real = prf_R_slots(pk, sk, ct.L[0].seed, 1)[0];
        Fp R2_real = fp_mul(R_real, R_real);
        
        std::vector<size_t> layer0_edges;
        for (size_t i = 0; i < ct.E.size(); ++i) {
            if (ct.E[i].layer_id == 0) layer0_edges.push_back(i);
        }
        
        for (size_t i = 0; i < layer0_edges.size(); ++i) {
            for (size_t j = i + 1; j < layer0_edges.size(); ++j) {
                const Edge& e1 = ct.E[layer0_edges[i]];
                const Edge& e2 = ct.E[layer0_edges[j]];
                
                if (e1.ch == e2.ch) continue;
                
                ++total_pairs;
                
                Fp g1 = pk.powg_B[e1.idx];
                Fp g2 = pk.powg_B[e2.idx];
                
                int s1 = sgn_val(e1.ch);
                int s2 = sgn_val(e2.ch);
                
                Fp t1 = fp_mul(e1.w[0], g1);
                if (s1 < 0) t1 = fp_neg(t1);
                
                Fp t2 = fp_mul(e2.w[0], g2);
                if (s2 < 0) t2 = fp_neg(t2);
                
                Fp cand = fp_add(t1, t2);
                Fp cand_neg = fp_neg(cand);
                
                bool match = (cand.lo == R2_real.lo && cand.hi == R2_real.hi) ||
                             (cand_neg.lo == R2_real.lo && cand_neg.hi == R2_real.hi);
                
                if (match) {
                    ++r2_leaks;
                    std::cout << "ct[" << ct_idx << "] pair (" << i << "," << j << ")\n";
                }
            }
        }
    }
    
    std::cout << "\ntotal pairs tested: " << total_pairs << "\n";
    std::cout << "R^2 leaks found: " << r2_leaks << "\n\n";
    
    if (r2_leaks == 0) {
        std::cout << "PASS\n";
        return 0;
    } else {
        std::cout << "FAIL\n";
        return 1;
    }
}