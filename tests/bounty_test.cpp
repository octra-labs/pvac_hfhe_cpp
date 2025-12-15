#include <pvac/pvac.hpp>

#include <pvac/utils/text.hpp>

#include <cstdint>
#include <string>
#include <vector>
#include <iostream>

#include <fstream>
#include <filesystem>



#include <cassert>

using namespace pvac;

namespace fs = std::filesystem;


// format signatures
namespace Magic {
    constexpr uint32_t CT  = 0x66699666; // 666-99-666 ciphertext
    constexpr uint32_t SK  = 0x66666999; // 6666-999 secret key
    constexpr uint32_t PK  = 0x06660666; // 0666-0666 public key
    constexpr uint32_t VER = 1; // format ver
}

namespace io {
    auto put32 = [](std::ostream& o, uint32_t x) -> std::ostream& {
        return o.write(reinterpret_cast<const char*>(&x), 4);
    };

    auto put64 = [](std::ostream& o, uint64_t x) -> std::ostream& {
        return o.write(reinterpret_cast<const char*>(&x), 8);
    };

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

    auto putBv = [](std::ostream& o, const BitVec& b) -> std::ostream& {
        put32(o, (uint32_t)b.nbits);
        for (size_t i = 0; i < (b.nbits + 63) / 64; ++i) put64(o, b.w[i]);
        return o;
    };

    auto getBv = [](std::istream& i) -> BitVec {
        auto b = BitVec::make((int)get32(i));
        for (size_t j = 0; j < (b.nbits + 63) / 64; ++j) b.w[j] = get64(i);
        return b;
    };

    auto putFp = [](std::ostream& o, const Fp& f) -> std::ostream& {
        put64(o, f.lo);
        return put64(o, f.hi);
    };

    auto getFp = [](std::istream& i) -> Fp {
        return { get64(i), get64(i) };
    };
}

namespace ser {
    using namespace io;

    auto putLayer = [](std::ostream& o, const Layer& L) {
        o.put((uint8_t)L.rule);
        if (L.rule == RRule::BASE) {
            put64(o, L.seed.ztag);
            put64(o, L.seed.nonce.lo);
            put64(o, L.seed.nonce.hi);
        } else if (L.rule == RRule::PROD) {
            put32(o, L.pa);

            put32(o, L.pb);
        } else {
            put64(o, 0); put64(o, 0); put64(o, 0);
        }
    };

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

    auto putEdge = [](std::ostream& o, const Edge& e) {
        put32(o, e.layer_id);
        o.write(reinterpret_cast<const char*>(&e.idx), 2);
        o.put(e.ch);
        o.put(0);
        putFp(o, e.w);
        putBv(o, e.s);
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

    auto putCipher = [](std::ostream& o, const Cipher& C) {
        put32(o, (uint32_t)C.L.size());
        put32(o, (uint32_t)C.E.size());
        for (const auto& L : C.L) putLayer(o, L);

        for (const auto& e : C.E) putEdge(o, e);
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

auto saveCts = [](const std::vector<Cipher>& cts, const std::string& path) {
    std::ofstream o(path, std::ios::binary);

    io::put32(o, Magic::CT);
    io::put32(o, Magic::VER);
    io::put64(o, cts.size());
    for (const auto& c : cts) ser::putCipher(o, c);
};

auto loadCts = [](const std::string& path) -> std::vector<Cipher> {
    std::ifstream i(path, std::ios::binary);
    if (io::get32(i) != Magic::CT || io::get32(i) != Magic::VER)
        throw std::runtime_error("bad ct header");
    std::vector<Cipher> cts(io::get64(i));
    for (auto& c : cts) c = ser::getCipher(i);
    return cts;
};

auto saveSk = [](const SecKey& sk, const std::string& path) {
    std::ofstream o(path, std::ios::binary);
    io::put32(o, Magic::SK);
    io::put32(o, Magic::VER);
    
    for (int j = 0; j < 4; ++j) io::put64(o, sk.prf_k[j]);
    io::put64(o, sk.lpn_s_bits.size());

    for (auto w : sk.lpn_s_bits) io::put64(o, w);
};

auto loadSk = [](const std::string& path) -> SecKey {
    std::ifstream i(path, std::ios::binary);




    if (io::get32(i) != Magic::SK || io::get32(i) != Magic::VER)
        throw std::runtime_error("bad sk header");

    SecKey sk;
        for (int j = 0; j < 4; ++j) sk.prf_k[j] = io::get64(i);
        sk.lpn_s_bits.resize(io::get64(i));
        for (auto& w : sk.lpn_s_bits) w = io::get64(i);
    return sk;
};

auto savePk = [](const PubKey& pk, const std::string& path) {




    std::ofstream o(path, std::ios::binary);
    io::put32(o, Magic::PK);
    io::put32(o, Magic::VER);
    io::put32(o, pk.prm.m_bits);
    io::put32(o, pk.prm.B);
    io::put32(o, pk.prm.lpn_t);
    io::put32(o, pk.prm.lpn_n);
    io::put32(o, pk.prm.lpn_tau_num);
    io::put32(o, pk.prm.lpn_tau_den);
    io::put32(o, (uint32_t)pk.prm.noise_entropy_bits);
    io::put32(o, (uint32_t)pk.prm.depth_slope_bits);
    io::put64(o, pk.prm.tuple2_fraction);
    io::put32(o, pk.prm.edge_budget);
    io::put64(o, pk.canon_tag);


    o.write(reinterpret_cast<const char*>(pk.H_digest.data()), 32);
    io::put64(o, pk.H.size());

    for (const auto& h : pk.H) io::putBv(o, h);
    io::put64(o, pk.ubk.perm.size());

    for (auto v : pk.ubk.perm) io::put32(o, v);
    io::put64(o, pk.ubk.inv.size());
    
    for (auto v : pk.ubk.inv) io::put32(o, v);
    io::putFp(o, pk.omega_B);

    io::put64(o, pk.powg_B.size());

    for (const auto& f : pk.powg_B) io::putFp(o, f);
};

auto loadPk = [](const std::string& path) -> PubKey {
    std::ifstream i(path, std::ios::binary);
    if (io::get32(i) != Magic::PK || io::get32(i) != Magic::VER)
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




//
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



auto saveParams = [](const Params& p, const std::string& path) {
    std::ofstream o(path);
    o << "{\n"
      << "  \"m_bits\": " << p.m_bits << ",\n"
      << "  \"B\": " << p.B << ",\n"
      << "  \"lpn_t\": " << p.lpn_t << ",\n"
      << "  \"lpn_n\": " << p.lpn_n << ",\n"
      << "  \"lpn_tau_num\": " << p.lpn_tau_num << ",\n"
      << "  \"lpn_tau_den\": " << p.lpn_tau_den << ",\n"
      << "  \"noise_entropy_bits\": " << p.noise_entropy_bits << ",\n"
      << "  \"depth_slope_bits\": " << p.depth_slope_bits << ",\n"
      << "  \"tuple2_fraction\": " << p.tuple2_fraction << ",\n"
      << "  \"edge_budget\": " << p.edge_budget << "\n"
      << "}\n";
};

int main() {
    std::cout << "- bounty generator -\n";




    // you have to attack this string, it is in the ciphertext file after enc is performed
    const std::string seed = "word1 word2 etc......XXX...>XXX> word12"; 
    //




    const std::string dir = "bounty_data";

    Params prm;
    PubKey pk;
    SecKey sk;
    keygen(prm, pk, sk);

    std::cout << "enc seed [" << seed.size() << " bytes]\n";

    auto cts = enc_text(pk, sk, seed);

    fs::create_directories(dir);

        saveCts(cts, dir + "/seed.ct");
        savePk(pk, dir + "/pk.bin");
        saveSk(sk, dir + "/sk.bin");
        saveParams(prm, dir + "/params.json");

    std::cout << "wrote " << dir << "/\n\n";
    std::cout << "- roundtrip -\n";

    auto pk2 = loadPk(dir + "/pk.bin");
     auto sk2 = loadSk(dir + "/sk.bin");
    auto cts2 = loadCts(dir + "/seed.ct");

    std::cout << "pk.B = " << pk2.prm.B
              << "pk.H = " << pk2.H.size()
              << "sk.s = " << sk2.lpn_s_bits.size() << "\n";

    auto dec = dec_text(pk2, sk2, cts2);

     std::cout << "dec: \"" << dec << "\"\n";
    assert(dec == seed);


 std::cout << "\n- bit flip test -\n";

SecKey sk_bad = sk2;
sk_bad.lpn_s_bits[0] ^= 1;  //  1 bit to check things 
try {auto dec_bad = dec_text(pk2, sk_bad, cts2);
std::cout << "dec_bad: \"" << dec_bad << "\"\n";
} catch (...) {
    std::cout << "decode failed\n";
}


    std::cout << "ok\n\nREADY\n";
}