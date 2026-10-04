#pragma once

// Internal helpers shared by the decoder translation units.

#include <cstdint>

#include "core/arm64/decode/instruction.hpp"

namespace juice::arm64::detail {

constexpr uint32_t bits(uint32_t v, unsigned hi, unsigned lo) {
  return (v >> lo) & ((hi - lo == 31) ? 0xFFFFFFFFu : ((1u << (hi - lo + 1)) - 1));
}
constexpr bool bit(uint32_t v, unsigned n) { return (v >> n) & 1; }

// AdvSIMD load/store structure encodings (part of the load/store class).
// Returns false if `w` is not one of them.
bool decode_simd_structure(Instruction& i, uint32_t w);

// Scalar floating point and Advanced SIMD data processing.
void decode_simd_fp(Instruction& i, uint32_t w);

}  // namespace juice::arm64::detail
