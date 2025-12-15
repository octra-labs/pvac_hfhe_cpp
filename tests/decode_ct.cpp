

// lambda0xe 15 Dec 2025
// a simple ciphertext decoder for hypothesis testing (if any)
// personally, always find it helpful to look at the raw data and analyze it for audit purposes
// if you have any questions, comments, or tech issues you'd like to discuss, please dm:
// email: dev [at] octra.org 
// tg: @lambda0xE


#include <pvac/pvac.hpp>
#include <pvac/utils/text.hpp>

#include <cstdint>
#include <string>
#include <vector>
#include <iostream>
#include <fstream>
#include <filesystem>
#include <iomanip>

using namespace pvac;
namespace fs = std::filesystem;

namespace Magic {
    constexpr uint32_t CT  = 0x66699666;
    constexpr uint32_t SK  = 0x66666999;
    constexpr uint32_t PK  = 0x06660666;
    constexpr uint32_t VER = 1;
}

namespace io {
    auto get32 = [](std::istream& i) -> uint32_t {
        uint32_t x = 0;
        i.read(reinterpret_cast<char*>(&x), 4);
        return x;
    };

    auto get64 = [](std::istream& i) -> uint64_t {
        uint64_t x = 0;
        i.read(reinterpret_cast<char*>(&x), 8);
        return x;
    };

    auto getBv = [](std::istream& i) -> BitVec {
        auto b = BitVec::make((int)get32(i));
        for (size_t j = 0; j < (b.nbits + 63) / 64; ++j) b.w[j] = get64(i);
        return b;
    };

    auto getFp = [](std::istream& i) -> Fp {
        return { get64(i), get64(i) };
    };
}

namespace ser {
    using namespace io;

    auto getLayer = [](std::istream& i) -> Layer {
        Layer L{};
        L.rule = (RRule)i.get();
        if (L.rule == RRule::BASE) {
            L.seed.ztag = get64(i);
            L.seed.nonce.lo = get64(i);
             L.seed.nonce.hi = get64(i);
        } else if (L.rule == RRule::PROD) {
            L.pa = get32(i);
            L.pb = get32(i);
        }
        return L;
    };

    auto getEdge = [](std::istream& i) -> Edge {
        Edge e{};
        e.layer_id = get32(i);
        i.read(reinterpret_cast<char*>(&e.idx), 2);
        e.ch = i.get();
        i.get();
        e.w = getFp(i);
        e.s = getBv(i);
        return e;
    };

    auto getCipher = [](std::istream& i) -> Cipher {
        Cipher C;
        auto nL = get32(i), nE = get32(i);
        C.L.resize(nL);
        C.E.resize(nE);
        for (auto& L : C.L) L = getLayer(i);
        for (auto& e : C.E) e = getEdge(i);
        return C;
    };
}

auto loadCts = [](const std::string& path) -> std::vector<Cipher> {
    std::ifstream i(path, std::ios::binary);
    if (!i) throw std::runtime_error("cannot open " + path);
    auto magic = io::get32(i);
    auto ver = io::get32(i);
    if (magic != Magic::CT || ver != Magic::VER)
        throw std::runtime_error("bad ct header");
    std::vector<Cipher> cts(io::get64(i));
    for (auto& c : cts) c = ser::getCipher(i);
    return cts;
};

auto loadSk = [](const std::string& path) -> SecKey {
    std::ifstream i(path, std::ios::binary);
    if (!i) throw std::runtime_error("cannot open " + path);
    auto magic = io::get32(i);
     auto ver = io::get32(i);
    if (magic != Magic::SK || ver != Magic::VER)
        throw std::runtime_error("bad sk header");
    SecKey sk;
    for (int j = 0; j < 4; ++j) sk.prf_k[j] = io::get64(i);
    sk.lpn_s_bits.resize(io::get64(i));
    for (auto& w : sk.lpn_s_bits) w = io::get64(i);
    return sk;
};

auto loadPk = [](const std::string& path) -> PubKey {
    std::ifstream i(path, std::ios::binary);
    if (!i) throw std::runtime_error("cannot open " + path);
    auto magic = io::get32(i);
     auto ver = io::get32(i);
    if (magic != Magic::PK || ver != Magic::VER)
        throw std::runtime_error("bad pk header");



    PubKey pk;

    pk.prm.m_bits = io::get32(i);
    pk.prm.B = io::get32(i);
    pk.prm.lpn_t = io::get32(i);
    pk.prm.lpn_n = io::get32(i);
    pk.prm.lpn_tau_num = io::get32(i);
    pk.prm.lpn_tau_den = io::get32(i);
    pk.prm.noise_entropy_bits = io::get32(i);
    pk.prm.depth_slope_bits = io::get32(i);
    pk.prm.tuple2_fraction = io::get64(i);
    pk.prm.edge_budget = io::get32(i);
    pk.canon_tag = io::get64(i);

    i.read(reinterpret_cast<char*>(pk.H_digest.data()), 32);
    pk.H.resize(io::get64(i));

    for (auto& h : pk.H) h = io::getBv(i);
    pk.ubk.perm.resize(io::get64(i));

    for (auto& v : pk.ubk.perm) v = io::get32(i);
    pk.ubk.inv.resize(io::get64(i));

    for (auto& v : pk.ubk.inv) v = io::get32(i);
    pk.omega_B = io::getFp(i);

    pk.powg_B.resize(io::get64(i));
    for (auto& f : pk.powg_B) f = io::getFp(i);


    return pk;
};

void hexdump(const uint8_t* data, size_t len, size_t max = 64) {
    for (size_t i = 0; i < std::min(len, max); ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
        if ((i + 1) % 16 == 0) std::cout << "\n";
        else if ((i + 1) % 8 == 0) std::cout << "  ";
        else std::cout << " ";
    }
    if (len > max) std::cout << "... [" << std::dec << len << " bytes total]";
    std::cout << std::dec << "\n";
}

void printable(const std::string& s) {
    for (char c : s) {

        if (c >= 32 && c < 127) std::cout << c;
        else std::cout << '.';
    }
    std::cout << "\n";
}

int main(int argc, char** argv) {
    std::string dir = (argc > 1) ? argv[1] : "bounty_data";

    std::cout << "- decode_ct -\n";
    std::cout << "dir: " << dir << "\n\n";

    if (!fs::exists(dir)) {
        std::cout << "dir not found\n";
        return 1;
    }

    auto ct_path = dir + "/seed.ct";
    auto pk_path = dir + "/pk.bin";
    auto sk_path = dir + "/sk.bin";

    bool has_ct = fs::exists(ct_path);
    bool has_pk = fs::exists(pk_path);
    bool has_sk = fs::exists(sk_path);

    std::cout << "seed.ct: " << (has_ct ? "yes" : "no") << "\n";
    std::cout << "pk.bin:  " << (has_pk ? "yes" : "no") << "\n";
    std::cout << "sk.bin:  " << (has_sk ? "yes" : "no") << "\n\n";

    if (!has_ct) {
        std::cout << "no ciphertext\n";
        return 1;
    }

    std::vector<Cipher> cts;
    try {
        cts = loadCts(ct_path);
        std::cout << "loaded " << cts.size() << " CTs\n";
    } catch (const std::exception& e) {
        std::cout << "ct load failed: " << e.what() << "\n";
        return 1;
    }

    if (!has_pk) {
        std::cout << "no pk - cannot dec\n";
        return 1;
    }

    PubKey pk;
    try {
        pk = loadPk(pk_path);
        std::cout << "pk.B = " << pk.prm.B << " pk.H=" << pk.H.size() << "\n";
    } catch (const std::exception& e) {
        std::cout << "pk load failed: " << e.what() << "\n";
        return 1;
    }

    if (!has_sk) {
        std::cout << "\nno sk - cannot dec\n";
        std::cout << "ct info:\n";
        for (size_t i = 0; i < std::min(cts.size(), (size_t)5); ++i) {
            std::cout << "  ct[" << i << "]: L=" << cts[i].L.size() 
                      << " E=" << cts[i].E.size() << "\n";
        }
        return 0;
    }

    SecKey sk;
    try {
        sk = loadSk(sk_path);
        std::cout << "sk.s = " << sk.lpn_s_bits.size() << "\n\n";
    } catch (const std::exception& e) {
        std::cout << "sk load failed: " << e.what() << "\n";
        return 1;
    }

    std::cout << "- decode -\n\n";

    std::vector<uint8_t> raw_bytes;
    std::vector<Fp> raw_fps;

    for (size_t i = 0; i < cts.size(); ++i) {
        Fp val;
        try {
            val = dec_value(pk, sk, cts[i]);
        } catch (...) {
            std::cout << "ct[" << i << "]: dec exception\n";
            val = {0, 0};
        }

        raw_fps.push_back(val);

        if (i == 0) {
            std::cout << "ct[0]: lo = " << val.lo << " hi = " << val.hi << "\n";
        } else {
            uint8_t block[15];
            uint64_t lo = val.lo;
            uint64_t hi = val.hi;
            for (int j = 0; j < 15; ++j) {
                size_t sh = j * 8;
                block[j] = (sh < 64) ? (uint8_t)(lo >> sh) : (uint8_t)(hi >> (sh - 64));
            }
            for (int j = 0; j < 15; ++j) raw_bytes.push_back(block[j]);
        }
    }

    std::cout << "\nraw Fp values:\n";





    for (size_t i = 0; i < std::min(raw_fps.size(), (size_t)8); ++i) {
        std::cout << "[" << i << "] lo = " << std::hex << raw_fps[i].lo 
                  << "hi = " << raw_fps[i].hi << std::dec << "\n";
    }

    uint64_t expected_len = raw_fps.empty() ? 0 : raw_fps[0].lo;
    size_t actual_len = std::min((size_t)expected_len, raw_bytes.size());

    std::cout << "\nexpected len: " << expected_len << "\n";
    std::cout << "raw bytes: " << raw_bytes.size() << "\n";

      std::cout << "using len: " << actual_len << "\n\n";
      
    std::cout << "hex dump:\n";
    hexdump(raw_bytes.data(), actual_len);

    std::cout << "\nprintable:\n";
    std::string result(raw_bytes.begin(), raw_bytes.begin() + actual_len);
    printable(result);

    std::cout << "\nraw string:\n\"" << result << "\"\n";

    return 0;
}