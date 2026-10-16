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
  // Forward conditional branches become side exits and the block goes on
  // with the code after them (backward ones, loops, still end it: a loop
  // whose body is one block keeps its registers in host registers).
  bool side_exits = true;
};

// Translate the basic block starting at `pc` into IR.
ir::Block lift_block(uint64_t pc, const CodeReader& read, const LiftOptions& options = {});

// Append the IR for one instruction. Returns true if the instruction ended the
// block (a terminator was set).
bool lift_instruction(const Instruction& insn, ir::Builder& builder);

// Whether the code at `pc` sets the flags (NZCV) before reading them, looking
// at most `max_insns` ahead. Memory accesses are allowed in between (a fault
// there reports the flags of before the block's end; code continuing after it
// still sets them first). The look follows unconditional branches and both
// ways of branches that don't read the flags (CBZ, TBZ, ...); calls and
// returns end it with the flags dead (the procedure call standard doesn't
// preserve them). Anything else that leaves the straight line (B.cond, BR,
// SVC, BRK, ...) counts as reading them.
bool flags_dead_at(uint64_t pc, const CodeReader& read, unsigned max_insns = 16);

// Description of CpuState for IR backends.
ir::StateLayout state_layout();

}  // namespace juice::arm64
