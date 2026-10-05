#pragma once

// IR -> x86-64 code generator.
//
// Generated blocks have the signature
//
//     void block(void* guest_state, uint64_t* scratch);
//
// using the host's native C calling convention. Guest state is addressed
// through RBX and IR values live in the scratch array (addressed through RBP),
// one 64-bit slot per value id. The code is position independent and may be
// copied anywhere.

#include <cstdint>
#include <vector>

#include "core/ir/ir.hpp"

namespace juice::x64 {

using BlockFn = void (*)(void* state, uint64_t* scratch);

// Maximum number of IR values a compiled block may use (size of the scratch
// array the caller must provide).
inline constexpr size_t kMaxBlockValues = 16384;

class Emitter {
 public:
  explicit Emitter(const ir::StateLayout& layout) : layout_(layout) {}

  // Returns an empty vector if the block is too large to compile.
  std::vector<uint8_t> compile(const ir::Block& block) const;

 private:
  ir::StateLayout layout_;
};

}  // namespace juice::x64
