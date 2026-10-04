#pragma once

#include <cstdint>

#include "core/ir/ir.hpp"

namespace juice::ir {

// Evaluates the vector-lane and floating point opcodes (is_vector_or_fp()).
uint64_t evaluate_simd(const Inst& inst, uint64_t a, uint64_t b, uint64_t c);

}  // namespace juice::ir
