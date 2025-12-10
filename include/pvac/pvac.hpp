#pragma once


#include "pvac/core/config.hpp"
#include "pvac/core/random.hpp"
#include "pvac/core/hash.hpp"
#include "pvac/core/field.hpp"
#include "pvac/core/bitvec.hpp"
#include "pvac/core/types.hpp"

#include "pvac/crypto/toeplitz.hpp"
#include "pvac/crypto/matrix.hpp"
#include "pvac/crypto/lpn.hpp"
#include "pvac/crypto/keygen.hpp"

#include "pvac/ops/encrypt.hpp"
#include "pvac/ops/decrypt.hpp"
#include "pvac/ops/arithmetic.hpp"
#include "pvac/ops/recrypt.hpp"
#include "pvac/ops/commit.hpp"

#include "pvac/utils/text.hpp"
#include "pvac/utils/metrics.hpp"

namespace pvac {

constexpr int VERSION_MAJOR = 0;
constexpr int VERSION_MINOR = 1;
constexpr int VERSION_PATCH = 0;


constexpr const char * DATE = "03.9.2024";

constexpr const char * VERSION_STRING = "0.1.0";

constexpr const char * PROJECT_NAME = "pvac-hfhe";
constexpr const char * PROJECT_FULL = "pvac-hfhe";



}
