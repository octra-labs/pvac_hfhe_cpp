
# mini-bounty challenge 
we're launching a series of bounty programs with rewards in usdt, there will be a series of such challenges, and this is the first of them, your reward (if successful) is $6,666.6666 in usdt (erc20) equivalent at the following ethereum address: [`0x46a8523Db54D674dabE09CA0c2193D5648c98700`](https://etherscan.io/address/0x46a8523Db54D674dabE09CA0c2193D5648c98700)

in the "tests" directory, a `bounty_test.cpp` file has been prepared for you with a complete mechanism for how the `seed.ct` was obtained, for direct decoding of the ciphertext, there is another file nearby, `decode_ct.cpp` (useful for testing and byte dissection)

this bounty challenge ends in a week (but it can be extended if someone can tell us they need more time and they've "found something that needs to be tested")

the amount will vary significantly in the next challenges, this is our first test of the approach itself, and if researchers like it, we'll increase the bounty reward to $100k in the final tests

**a new $25k challenge will be added next monday (approx. same time)**

so, the objective of this challenge can be described simply as: **decrypt `seed.ct` without `sk.bin`**

several files are presented for your audit:
```
bounty_data/
├── seed.ct       # ciphertext (target)
├── pk.bin        # public key
├── params.json   # scheme parameters
```

**key struct:**
you may find this information useful, but for real researchers, none of this matters (if something contains bytes and they can be read, that's enough)
```cpp
SecKey {
    prf_k[4] // 256 bit prf key
    lpn_s_bits[64] // 4096 bit lpn
}

PubKey {
    params, H_graph, g^k table, omega_B
}
```
just in case, a reminder that the build requires: C++17, x86_64 with AES-NI


## rules 
there are actually no rules, it's all very simple:
1.  recover the seed phrase from `seed.ct` using only public data
2.  no rules beyond cryptanalysis  (any valid attack wins)

## verification
```bash
sha256sum bounty_data/*
5d9160d375c1acbc61405a4bbffb6ea4494687e9576cdb5250038f5b155e8a68  params.json
855112061a00ed94a400d5660f5e8d3cae798d044c092e9efd0a9c3ae684eb67  pk.bin
669494845781a684537ee52b856d617702c61e6e4c1ec87e3c7814cbb2eccf73  seed.ct
```

for transparency and clarity, we will always store the secret key with the pre-publication file hash, secret key exists and will be published after bounty ends
```
sha256(sk.bin) = d545589d4ca9a9318229a5f8a84e07124b550e041168f2d51f87fa1ed3c089a1
```