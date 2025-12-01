
# pvac_hfhe_cpp

pvac-hfhe: proof of concept implementation of pvac hfhe, which is based on the assumption of binary parity for learning with noise and arithmetic on a 127-bit prime field. we rely on a syndrome graph constructed from a dense random k-uniform hypergraph, and the choice of parameters is based on results on threshold behavior and fractional colorability of random hypergraphs from the works of the moscow institute of physics and technology (MIPT), this is the very first implementation of the beginning of 2024 in its original form

ps: look at the attachments (they are in russian)

## build
```bash
make # build test bin
make test # build and run tests
make examples # build basic_usage example
make clean # remove build trash
```

## run
```bash
./build/test_main # run tests
./build/basic_usage # run example
```


## usage
```cpp
#include <pvac/pvac.hpp>
using namespace pvac;

int main() {
    // keygen
    Params prm;
    PubKey pk;
    SecKey sk;
    keygen(prm, pk, sk);

    // encrypt
    Cipher a = enc_value(pk, sk, 42);
    Cipher b = enc_value(pk, sk, 17);

    Cipher sum  = ct_add(pk, a, b); // 42 + 17 = 59
    Cipher diff = ct_sub(pk, a, b); // 42 - 17 = 25
    Cipher prod = ct_mul(pk, a, b);           // 42 * 17 = 714

    Cipher scaled = ct_scale(pk, a, fp_from_u64(3)); // 42 * 3 = 126

    Fp result = dec_value(pk, sk, prod);
    std::cout << result.lo << "\n"; // 714

    return 0;
}
```

| op | func | example |
|-----------|----------|---------|
| enc | `enc_value(pk, sk, x)` | `Cipher c = enc_value(pk, sk, 42)` |
| dec | `dec_value(pk, sk, c)` | `Fp x = dec_value(pk, sk, c)` |
| add | `ct_add(pk, a, b)` | `a + b` |
| sub | `ct_sub(pk, a, b)` | `a - b` |
| mul | `ct_mul(pk, a, b)` | `a * b` |
| scale | `ct_scale(pk, c, k)` | `c * k` (k is plaintext) |
| recrypt | `ct_recrypt(pk, ek, c)` | refresh ct |
