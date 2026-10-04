#pragma once

// ARM64 -> JUICE IR lifter.

#include <cstdint>
#include <functional>

#include "core/arm64/decode/instruction.hpp"
#include "core/ir/ir.hpp"

namespace juice::arm64 {

// Reads one 32-bit instruction word from guest memory. Returns false if the
// address is not readable/executable.
using CodeReader = std::function<bool(uint64_t addr, uint32_t& word)>;

struct LiftOptions {
  uint32_t max_insns = 64;  // longest block (guest instructions)
  // If nonzero, 64-bit loads from [X18, #tls_vector_offset] read
  // CpuState::tls_vector instead of memory. On Windows, X18 is the TEB and
  // TEB+0x58 the implicit-TLS vector; giving guest code a vector of its own
  // keeps its TLS slots (the program's is always slot 0) apart from the host's.
  uint32_t tls_vector_offset = 0;
};

// Translate the basic block starting at `pc` into IR.
ir::Block lift_block(uint64_t pc, const CodeReader& read, const LiftOptions& options = {});

// Append the IR for one instruction. Returns true if the instruction ended the
// block (a terminator was set).
bool lift_instruction(const Instruction& insn, ir::Builder& builder);

// Description of CpuState for IR backends.
ir::StateLayout state_layout();

}  // namespace juice::arm64
