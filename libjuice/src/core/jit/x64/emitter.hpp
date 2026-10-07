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

// The frame of a block: the prologue pushes RBX (the guest state pointer) and
// RBP and reserves kBlockFrameSize bytes, which the body never changes. At a
// fault in the body, [RSP + kBlockFrameSize] holds the caller's RBP,
// [RSP + kBlockFrameSize + 8] its RBX and [RSP + kBlockFrameSize + 16] the
// return address: a fault handler can return from the block by restoring them.
inline constexpr int32_t kBlockFrameSize = 40;

// A host instruction of a block that may fault: code from host_offset on (up
// to the next site) belongs to the guest instruction at block pc + guest_offset.
struct FaultSite {
  uint32_t host_offset;
  uint32_t guest_offset;
};

// Maximum number of IR values a compiled block may use (size of the scratch
// array the caller must provide).
inline constexpr size_t kMaxBlockValues = 16384;

class Emitter {
 public:
  explicit Emitter(const ir::StateLayout& layout) : layout_(layout) {}

  // Returns an empty vector if the block is too large to compile. `faults`, if
  // given, receives the block's fault sites in code order.
  std::vector<uint8_t> compile(const ir::Block& block, std::vector<FaultSite>* faults = nullptr) const;

 private:
  ir::StateLayout layout_;
};

}  // namespace juice::x64
