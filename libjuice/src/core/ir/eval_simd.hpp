#pragma once

#include <cstdint>

#include "core/ir/ir.hpp"

namespace juice::ir {

// Evaluates the vector-lane and floating point opcodes (is_vector_or_fp()).
uint64_t evaluate_simd(const Inst& inst, uint64_t a, uint64_t b, uint64_t c);

// Arm's BFDotAdd: acc + a0 * b0 + a1 * b1 for BFloat16 a and b and a single
// precision accumulator (round to odd, denormals flushed to zero).
uint32_t bf_dot_add(uint32_t acc, uint16_t a0, uint16_t a1, uint16_t b0, uint16_t b1);

}  // namespace juice::ir
