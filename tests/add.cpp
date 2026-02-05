#include <pvac/pvac.hpp>
#include <pvac/utils/text.hpp>

#include <cstdint>
#include <string>
#include <vector>
#include <iostream>
#include <fstream>
#include <filesystem>
#include <cstring>

using namespace pvac;
namespace fs = std::filesystem;

namespace Magic {
    constexpr uint32_t CT = 0x66699666;
    constexpr uint32_t SK = 0x66666999;
    constexpr uint32_t PK = 0x06660666;
    constexpr uint32_t VER = 1;
}

namespace io {
    auto put32 = [](std::ostream& o, uint32_t x) -> std::ostream& {
        return o.write(reinterpret_cast<const char*>(&x), 4);
    };
    auto put64 = [](std::ostream& o, uint64_t x) -> std::ostream& {
        return o.write(reinterpret_cast<const char*>(&x), 8);
    };
    auto get32 = [](std::istream& i) -> uint32_t {
        uint32_t x = 0; i.read(reinterpret_cast<char*>(&x), 4); return x;
    };
    auto get64 = [](std::istream& i) -> uint64_t {
        uint64_t x = 0; i.read(reinterpret_cast<char*>(&x), 8); return x;
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
        put64(o, f.lo); return put64(o, f.hi);
    };
    auto getFp = [](std::istream& i) -> Fp {
        return {get64(i), get64(i)};
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
        } else {
            (void)get64(i); (void)get64(i); (void)get64(i);
        }
        return L;
    };


    auto putEdge = [](std::ostream& o, const Edge& e) {
        put32(o, e.layer_id);
        o.write(reinterpret_cast<const char*>(&e.idx), 2);
        o.put(e.ch);
        o.put(0);
        for (size_t j = 0; j < SLOTS; ++j) putFp(o, e.w[j]);
        putBv(o, e.s);
    };


    auto getEdge = [](std::istream& i) -> Edge {
        Edge e{};
        e.layer_id = get32(i);
        i.read(reinterpret_cast<char*>(&e.idx), 2);
        e.ch = (uint8_t)i.get();
        i.get();
        for (size_t j = 0; j < SLOTS; ++j) e.w[j] = getFp(i);
        e.s = getBv(i);
        return e;
    };



    auto putCipher = [](std::ostream& o, const Cipher& C) {
        for (size_t j = 0; j < SLOTS; ++j) putFp(o, C.c0[j]);
        put32(o, (uint32_t)C.L.size());
        put32(o, (uint32_t)C.E.size());
        for (const auto& L : C.L) putLayer(o, L);
        for (const auto& e : C.E) putEdge(o, e);
    };




    auto getCipher = [](std::istream& i) -> Cipher {
        Cipher C;
        for (size_t j = 0; j < SLOTS; ++j) C.c0[j] = getFp(i);
        auto nL = get32(i), nE = get32(i);
        C.L.resize(nL); C.E.resize(nE);
        for (auto& L : C.L) L = getLayer(i);
        for (auto& e : C.E) e = getEdge(i);
        return C;
    };
}

auto loadCts = [](const std::string& path) -> std::vector<Cipher> {
    std::ifstream i(path, std::ios::binary);
    if (!i || io::get32(i) != Magic::CT || io::get32(i) != Magic::VER)
        throw std::runtime_error("bad CT: " + path);



    std::vector<Cipher> cts(io::get64(i));
    for (auto& c : cts) c = ser::getCipher(i);
    return cts;
};

auto saveCts = [](const std::vector<Cipher>& cts, const std::string& path) {
    std::ofstream o(path, std::ios::binary);


    io::put32(o, Magic::CT);
    io::put32(o, Magic::VER);
    io::put64(o, cts.size());


    
    for (const auto& c : cts) ser::putCipher(o, c);
};

auto loadSk = [](const std::string& path) -> SecKey {
    std::ifstream i(path, std::ios::binary);
    if (!i || io::get32(i) != Magic::SK || io::get32(i) != Magic::VER)
        throw std::runtime_error("bad SK: " + path);
    SecKey sk;
    for (int j = 0; j < 4; ++j) sk.prf_k[j] = io::get64(i);
    sk.lpn_s_bits.resize(io::get64(i));
    for (auto& w : sk.lpn_s_bits) w = io::get64(i);
    return sk;
};

auto loadPk = [](const std::string& path) -> PubKey {
    std::ifstream i(path, std::ios::binary);
    if (!i || io::get32(i) != Magic::PK || io::get32(i) != Magic::VER)
        throw std::runtime_error("bad PK: " + path);


    PubKey pk;
    pk.prm.m_bits = io::get32(i);
    pk.prm.B = io::get32(i);
    pk.prm.lpn_t = io::get32(i);
    pk.prm.lpn_n = io::get32(i);
    pk.prm.lpn_tau_num = io::get32(i);
    pk.prm.lpn_tau_den = io::get32(i);
    pk.prm.noise_entropy_bits = io::get32(i);
    pk.prm.depth_slope_bits = io::get32(i);
    uint64_t t2 = io::get64(i);
    std::memcpy(&pk.prm.tuple2_fraction, &t2, 8);
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

int main(int argc, char** argv) {
    std::string dir = (argc > 1) ? argv[1] : "bounty2_data";

    std::cout << "- add test -\n";
    std::cout << "dir: " << dir << "\n";

    if (!fs::exists(dir + "/pk.bin") || !fs::exists(dir + "/sk.bin") ||
        !fs::exists(dir + "/a.ct") || !fs::exists(dir + "/b.ct")) {
        std::cerr << "missing files\n";
        return 1;
    }

    auto pk = loadPk(dir + "/pk.bin");
    auto sk = loadSk(dir + "/sk.bin");
    auto cta = loadCts(dir + "/a.ct")[0];
    auto ctb = loadCts(dir + "/b.ct")[0];

    auto sum_ct = combine_ciphers(pk, cta, ctb);

    auto fa = dec_value(pk, sk, cta);
    auto fb = dec_value(pk, sk, ctb);
    auto fsum = dec_value(pk, sk, sum_ct);

    std::cout << "dec a = " << fa.lo << " b = " << fb.lo << " a + b = " << fsum.lo << "\n";

    saveCts({sum_ct}, dir + "/sum.ct");
    std::cout << "sum.ct written\n";
}