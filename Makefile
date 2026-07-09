CXX := g++
UNAME_M := $(shell uname -m)
ifeq ($(UNAME_M),arm64)
  ARCH_FLAGS := -march=armv8-a+crypto
else
  ARCH_FLAGS := -march=native
endif
CXXFLAGS := -std=c++17 -O2 $(ARCH_FLAGS) -Wall -Wextra -I./include -pthread
DEBUG_FLAGS := -g -O0 -DPVAC_DEBUG
SANITIZE_FLAGS := -fsanitize=address,undefined
BUILD := build
TESTS := tests
EXAMPLES := examples

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
  LIBPVAC := $(BUILD)/libpvac.dylib
  SHARED_FLAGS := -dynamiclib
else
  LIBPVAC := $(BUILD)/libpvac.so
  SHARED_FLAGS := -shared
endif

all: $(BUILD)/test_main

libpvac: $(LIBPVAC)

$(BUILD):
	mkdir -p $(BUILD)

$(LIBPVAC): pvac_c_api.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) -fPIC $(SHARED_FLAGS) -I../lib/pvac_ffi -o $@ $<

$(BUILD)/test_main: $(TESTS)/test_main.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) -o $@ $<

$(BUILD)/test_hg: $(TESTS)/test_hg.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) -o $@ $<

$(BUILD)/test_main_debug: $(TESTS)/test_main.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) $(DEBUG_FLAGS) -o $@ $<

$(BUILD)/test_main_san: $(TESTS)/test_main.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) $(DEBUG_FLAGS) $(SANITIZE_FLAGS) -o $@ $

$(BUILD)/basic_usage: $(EXAMPLES)/basic_usage.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) -o $@ $<

$(BUILD)/recrypt_usage: $(EXAMPLES)/recrypt_usage.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) -o $@ $<

$(BUILD)/ml_credit_scoring: $(EXAMPLES)/ml/credit_scoring.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) -o $@ $<

$(BUILD)/test_prf: $(TESTS)/test_prf.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) -o $@ $<

$(BUILD)/test_ct: $(TESTS)/test_ct.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) -o $@ $<

$(BUILD)/test_depth: $(TESTS)/test_depth.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) -o $@ $<

$(BUILD)/test_sigma: $(TESTS)/test_sigma.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) -o $@ $<

$(BUILD)/test_zero: $(TESTS)/test_zero.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) -o $@ $<

$(BUILD)/test_lpn: $(TESTS)/test_lpn.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) -o $@ $<

$(BUILD)/test_fp_core: $(TESTS)/test_fp_core.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) -o $@ $<

$(BUILD)/test_bitvec: $(TESTS)/test_bitvec.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) -o $@ $<

$(BUILD)/test_prf_ext: $(TESTS)/test_prf_ext.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) -o $@ $<

$(BUILD)/test_sigma_lpn: $(TESTS)/test_sigma_lpn.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) -o $@ $<

$(BUILD)/test_noise_struct: $(TESTS)/test_noise_struct.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) -o $@ $<

$(BUILD)/test_ct_fuzz: $(TESTS)/test_ct_fuzz.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) -o $@ $<

$(BUILD)/test_ct_safe: $(TESTS)/test_ct_safe.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) -o $@ $<

$(BUILD)/test_aes_ctr: $(TESTS)/test_aes_ctr.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) -o $@ $<

$(BUILD)/test_struct: $(TESTS)/test_struct.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) -o $@ $<

$(BUILD)/test_struct_v2: $(TESTS)/test_struct_v2.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) -o $@ $<

$(BUILD)/test_compactness: $(TESTS)/test_compactness.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) -o $@ $<

$(BUILD)/test_zero_sk: $(TESTS)/test_zero_sk.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) -o $@ $<

$(BUILD)/test_private_transfer: $(TESTS)/test_private_transfer.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) -o $@ $<

$(BUILD)/test_ct_geq_sign: $(TESTS)/test_ct_geq_sign.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) -o $@ $<

$(BUILD)/test_verify_zero: $(TESTS)/test_verify_zero.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) -o $@ $<

$(BUILD)/test_range_proof: $(TESTS)/test_range_proof.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) -o $@ $<

$(BUILD)/test_bound_range: $(TESTS)/test_bound_range.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) -I../lib/pvac_ffi -o $@ $<

$(BUILD)/test_recrypt_nat: $(TESTS)/test_recrypt_nat.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) -o $@ $<

$(BUILD)/test_recrypt_api: $(TESTS)/test_recrypt_api.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) -o $@ $<

$(BUILD)/test_hfhe_depth: $(TESTS)/test_hfhe_depth.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) -o $@ $<

$(BUILD)/test_plaintext_oracle: $(TESTS)/test_plaintext_oracle.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) -o $@ $<

$(BUILD)/test_public_zero_oracle: $(TESTS)/test_public_zero_oracle.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) -o $@ $<

$(BUILD)/test_rcomless_fold: $(TESTS)/test_rcomless_fold.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) -o $@ $<

$(BUILD)/test_public_linear_invariants: $(TESTS)/test_public_linear_invariants.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) -o $@ $<

$(BUILD)/bench_recrypt_deep_api: $(TESTS)/bench_recrypt_deep_api.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) -o $@ $<

$(BUILD)/test_ristretto255: $(TESTS)/test_ristretto255.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) -o $@ $<

$(BUILD)/test_zero_proof: $(TESTS)/test_zero_proof.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) -o $@ $<

$(BUILD)/test_bound_zero_proof: $(TESTS)/test_bound_zero_proof.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) -o $@ $<

$(BUILD)/poc_pc_forge_soundness: $(TESTS)/poc_pc_forge_soundness.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) -o $@ $<

$(BUILD)/forge_decrypt_payload: $(TESTS)/forge_decrypt_payload.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) -I../lib/pvac_ffi -o $@ $<

debug: $(BUILD)/test_main_debug
sanitize: $(BUILD)/test_main_san
examples: $(BUILD)/basic_usage $(BUILD)/recrypt_usage $(BUILD)/ml_credit_scoring
test_zero: $(BUILD)/test_zero
test_lpn: $(BUILD)/test_lpn
test_fp_core: $(BUILD)/test_fp_core
test_bitvec: $(BUILD)/test_bitvec
test_prf_ext: $(BUILD)/test_prf_ext
test_sigma_lpn: $(BUILD)/test_sigma_lpn
test_noise_struct: $(BUILD)/test_noise_struct
test_ct_fuzz: $(BUILD)/test_ct_fuzz
test_ct_safe: $(BUILD)/test_ct_safe
test_aes_ctr: $(BUILD)/test_aes_ctr
test_struct: $(BUILD)/test_struct
test_struct_v2: $(BUILD)/test_struct_v2
test_compactness: $(BUILD)/test_compactness
test_zero_sk: $(BUILD)/test_zero_sk
test_private_transfer: $(BUILD)/test_private_transfer


test: $(BUILD)/test_main
	@./$(BUILD)/test_main

test-v: $(BUILD)/test_main
	@PVAC_DBG=2 ./$(BUILD)/test_main

test-q: $(BUILD)/test_main
	@PVAC_DBG=0 ./$(BUILD)/test_main

test-hg: $(BUILD)/test_hg
	@./$(BUILD)/test_hg

test-prf: $(BUILD)/test_prf
	@./$(BUILD)/test_prf

test-ct: $(BUILD)/test_ct
	@./$(BUILD)/test_ct

test-depth: $(BUILD)/test_depth
	@./$(BUILD)/test_depth

test-sigma: $(BUILD)/test_sigma
	@./$(BUILD)/test_sigma

test-zero: $(BUILD)/test_zero
	@./$(BUILD)/test_zero

test-lpn: $(BUILD)/test_lpn
	@./$(BUILD)/test_lpn

test-fp-core: $(BUILD)/test_fp_core
	@./$(BUILD)/test_fp_core

test-bitvec: $(BUILD)/test_bitvec
	@./$(BUILD)/test_bitvec

test-prf-ext: $(BUILD)/test_prf_ext
	@./$(BUILD)/test_prf_ext

test-sigma-lpn: $(BUILD)/test_sigma_lpn
	@./$(BUILD)/test_sigma_lpn

test-noise-struct: $(BUILD)/test_noise_struct
	@./$(BUILD)/test_noise_struct

test-ct-fuzz: $(BUILD)/test_ct_fuzz
	@./$(BUILD)/test_ct_fuzz

test-ct-safe: $(BUILD)/test_ct_safe
	@./$(BUILD)/test_ct_safe

test-aes-ctr: $(BUILD)/test_aes_ctr
	@./$(BUILD)/test_aes_ctr

test-struct: $(BUILD)/test_struct
	@./$(BUILD)/test_struct

test-struct-v2: $(BUILD)/test_struct_v2
	@./$(BUILD)/test_struct_v2

test-compactness: $(BUILD)/test_compactness
	@./$(BUILD)/test_compactness

test-zero-sk: $(BUILD)/test_zero_sk
	@./$(BUILD)/test_zero_sk

test-private-transfer: $(BUILD)/test_private_transfer
	@./$(BUILD)/test_private_transfer

test-ct-geq-sign: $(BUILD)/test_ct_geq_sign
	@./$(BUILD)/test_ct_geq_sign

test-verify-zero: $(BUILD)/test_verify_zero
	@./$(BUILD)/test_verify_zero

test-range-proof: $(BUILD)/test_range_proof
	@./$(BUILD)/test_range_proof

test-recrypt-nat: $(BUILD)/test_recrypt_nat
	@./$(BUILD)/test_recrypt_nat

test-recrypt-api: $(BUILD)/test_recrypt_api
	@./$(BUILD)/test_recrypt_api

test-hfhe-depth: $(BUILD)/test_hfhe_depth
	@./$(BUILD)/test_hfhe_depth

test-plaintext-oracle: $(BUILD)/test_plaintext_oracle
	@./$(BUILD)/test_plaintext_oracle

test-public-zero-oracle: $(BUILD)/test_public_zero_oracle
	@./$(BUILD)/test_public_zero_oracle

test-rcomless-fold: $(BUILD)/test_rcomless_fold
	@./$(BUILD)/test_rcomless_fold

test-public-linear-invariants: $(BUILD)/test_public_linear_invariants
	@./$(BUILD)/test_public_linear_invariants

test-native: test-recrypt-nat test-recrypt-api

test-hfhe-native: test-plaintext-oracle test-public-zero-oracle test-rcomless-fold test-public-linear-invariants test-recrypt-nat test-recrypt-api test-hfhe-depth

test-recrypt-security: test-hfhe-native

test-recrypt-ci: test-recrypt-security

test-security: test-hfhe-native

bench-recrypt-deep-api: $(BUILD)/bench_recrypt_deep_api
	@PVAC_DEEP_DEPTH=2 PVAC_DEEP_CADENCES=1,2 PVAC_RESET_DEPTH_MAX=2 ./$(BUILD)/bench_recrypt_deep_api

bench-recrypt-deep-api-920: $(BUILD)/bench_recrypt_deep_api
	@PVAC_DEEP_DEPTH=920 PVAC_DEEP_CADENCES=1,2 PVAC_RESET_DEPTH_MAX=2 ./$(BUILD)/bench_recrypt_deep_api

bench-recrypt-deep-api-920-full: $(BUILD)/bench_recrypt_deep_api
	@PVAC_DEEP_DEPTH=920 PVAC_DEEP_CADENCES=1,2,4,8 PVAC_RESET_DEPTH_MAX=2 ./$(BUILD)/bench_recrypt_deep_api

test-ristretto255: $(BUILD)/test_ristretto255
	@./$(BUILD)/test_ristretto255

test-zero-proof: $(BUILD)/test_zero_proof
	@./$(BUILD)/test_zero_proof

test-bound-zero-proof: $(BUILD)/test_bound_zero_proof
	@./$(BUILD)/test_bound_zero_proof

poc-pc-forge-soundness: $(BUILD)/poc_pc_forge_soundness
	@./$(BUILD)/poc_pc_forge_soundness

forge-decrypt-payload: $(BUILD)/forge_decrypt_payload

ml: $(BUILD)/ml_credit_scoring
	@./$(BUILD)/ml_credit_scoring


clean:
	rm -rf $(BUILD) pvac_metrics.csv

help:
	@echo "targets: all test test-v test-q test-hg debug sanitize examples clean"
	@echo "env: PVAC_DBG=0|1|2"

.PHONY: all libpvac test test-v test-q test-hg test-private-transfer clean help examples ml test-recrypt-nat test-recrypt-api test-hfhe-depth test-plaintext-oracle test-public-zero-oracle test-rcomless-fold test-public-linear-invariants test-hfhe-native test-recrypt-security test-recrypt-ci bench-recrypt-deep-api bench-recrypt-deep-api-920 bench-recrypt-deep-api-920-full