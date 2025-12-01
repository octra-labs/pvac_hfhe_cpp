CXX      := g++
CXXFLAGS := -std=c++17 -O2 -march=native -Wall -Wextra -I./include

DEBUG_FLAGS := -g -O0 -DPVAC_DEBUG
SANITIZE_FLAGS := -fsanitize=address,undefined

BUILD_DIR := build
TESTS_DIR := tests
EXAMPLES_DIR := examples

all: $(BUILD_DIR)/test_main

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/test_main: $(TESTS_DIR)/test_main.cpp | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -o $@ $<

debug: CXXFLAGS += $(DEBUG_FLAGS)
debug: $(BUILD_DIR)/test_main_debug

$(BUILD_DIR)/test_main_debug: $(TESTS_DIR)/test_main.cpp | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) $(DEBUG_FLAGS) -o $@ $<

sanitize: CXXFLAGS += $(DEBUG_FLAGS) $(SANITIZE_FLAGS)
sanitize: $(BUILD_DIR)/test_main_sanitize

$(BUILD_DIR)/test_main_sanitize: $(TESTS_DIR)/test_main.cpp | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) $(DEBUG_FLAGS) $(SANITIZE_FLAGS) -o $@ $<

test: $(BUILD_DIR)/test_main
	@echo "running tests..."
	@./$(BUILD_DIR)/test_main

test-verbose: $(BUILD_DIR)/test_main
	@echo "running tests (verbose)..."
	@PVAC_DBG=2 ./$(BUILD_DIR)/test_main

test-quiet: $(BUILD_DIR)/test_main
	@PVAC_DBG=0 ./$(BUILD_DIR)/test_main

examples: $(BUILD_DIR)/basic_usage

$(BUILD_DIR)/basic_usage: $(EXAMPLES_DIR)/basic_usage.cpp | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -o $@ $<

clean:
	rm -rf $(BUILD_DIR)
	rm -f pvac_metrics.csv

help:
	@echo "pvac build system"
	@echo ""
	@echo "targets:"
	@echo "  all          - build main test executable (default)"
	@echo "  test         - build and run tests"
	@echo "  test-verbose - run tests with verbose output"
	@echo "  test-quiet   - run tests with no output"
	@echo "  debug        - build with debug symbols"
	@echo "  sanitize     - build with addresssanitizer"
	@echo "  examples     - build example programs"
	@echo "  clean        - remove build artifacts"
	@echo "  help         - show this help message"
	@echo ""
	@echo "environment variables:"
	@echo "  PVAC_DBG=0   - no debug output"
	@echo "  PVAC_DBG=1   - normal debug output (default)"
	@echo "  PVAC_DBG=2   - verbose debug output"