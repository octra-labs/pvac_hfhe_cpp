 <h1 align="center">pvac-hfhe-cpp</h1>
<p align="center">
  <img src="https://img.shields.io/badge/Version-0.1.0-blue?style=flat-square">
  <img src="https://img.shields.io/badge/C%2B%2B-17-blue?style=flat-square">
  <img src="https://img.shields.io/badge/License-GPL-green?style=flat-square">
<hr/>
proof of concept implementation of pvac-hfhe, which is based on the assumption of binary parity for learning with noise and arithmetic on a 127-bit prime field. 

we rely on a syndrome graph constructed from a dense random k-uniform hypergraph, and the choice of parameters is based on results on threshold behavior and fractional colorability of random hypergraphs from the works of the moscow institute of physics and technology (MIPT), this is the very first implementation of the beginning of 2024 in its original form.

ps: look at the attachments.


## info

### requirements

| requirement | ver |
|-------------|---------|
| c++ stand | C++17 or later |
| compiler | GCC 9+, Clang 10+, MSVC 2019+ |
| cpu | x86-64 with PCLMUL (recommended) |

### installation 

```bash
git clone https://github.com/octra-labs/pvac_hfhe_cpp.git
cd pvac_hfhe_cpp
```
```cpp
#include <pvac/pvac.hpp>
```
build and run:
```bash
make test # 42 tests
make examples # usage examples
make test-prf 
make test-sigma
make test-depth
make test-ct
make test-hg
```

### example
```cpp
#include <iostream>
#include <pvac/pvac.hpp>

using namespace pvac;

int main() {
    // key generation
    Params prm;
    PubKey pk;
    SecKey sk;
    keygen(prm, pk, sk);

    // encrypt values (client-side)
    Cipher a = enc_value(pk, sk, 42);
    Cipher b = enc_value(pk, sk, 17);

    // homo ops (server-side)
    Cipher sum  = ct_add(pk, a, b); // 42 + 17
    Cipher diff = ct_sub(pk, a, b); // 42 - 17
    Cipher prod = ct_mul(pk, a, b); // 42 * 17

    // decrypt results (client-side)
    std::cout << "42 + 17 = " << IsOne(dec_value(pk, sk, sum) == fp_from_u64(59)) << "\n";
    std::cout << "42 - 17 = " << fp_IsOne(dec_value(pk, sk, diff) == fp_from_u64(25)) << "\n";
    std::cout << "42 * 17 = " << fp_IsOne(dec_value(pk, sk, prod) == fp_from_u64(714)) << "\n";

    return 0;
}
```

```bash
g++ -std=c++17 -O2 -march=native -I./include example.cpp -o example
./example
```
