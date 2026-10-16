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
#include <iterator>
#include <vector>

#include "core/ir/ir.hpp"
#include "core/jit/x64/assembler.hpp"

namespace juice::x64 {

using BlockFn = void (*)(void* state, uint64_t* scratch);

// The frame of a block: the prologue pushes kBlockSavedRegs in order (RBX,
// the guest state pointer; RBP, the scratch array; the callee-saved registers
// that hold IR values) and reserves kBlockFrameSize bytes, which the body never
// changes. At a fault in the body, [RSP + kBlockFrameSize + 8 * k] holds the
// caller's value of kBlockSavedRegs[N - 1 - k], and the return address follows
// them: a fault handler can return from the block by restoring them.
#if defined(_WIN32)
inline constexpr Reg kBlockSavedRegs[] = {RBX, RBP, RSI, RDI, R12, R13, R14, R15};
// Callee-saved XMM registers (Win64), which hold floating point values; the
// prologue saves them at [RSP + kBlockXmmSaveArea + 16 * k] (XMM(first + k)).
inline constexpr unsigned kBlockSavedXmmFirst = 6;
inline constexpr unsigned kBlockSavedXmmCount = 10;
// Caller-saved registers that also hold IR values (the code doesn't use them
// otherwise): saved around the block's helper calls when they hold a value
// that lives on, at [RSP + kBlockVolatileSaveArea + 8 * k] (GPRs, then the
// low halves of the XMM registers).
inline constexpr Reg kBlockVolatileRegs[] = {R10, R11};
inline constexpr unsigned kBlockVolatileXmmFirst = 0;
inline constexpr unsigned kBlockVolatileXmmCount = 0;
#else
inline constexpr Reg kBlockSavedRegs[] = {RBX, RBP, R12, R13, R14, R15};
inline constexpr unsigned kBlockSavedXmmFirst = 0;
inline constexpr unsigned kBlockSavedXmmCount = 0;  // SysV has no callee-saved XMM registers
inline constexpr Reg kBlockVolatileRegs[] = {R9, R10, R11};
inline constexpr unsigned kBlockVolatileXmmFirst = 8;  // (the code uses XMM0-4 as temporaries)
inline constexpr unsigned kBlockVolatileXmmCount = 8;
#endif
inline constexpr int32_t kBlockXmmSaveArea = 40;  // above the helper calls' home space
inline constexpr int32_t kBlockVolatileSaveArea = kBlockXmmSaveArea + 16 * kBlockSavedXmmCount;
inline constexpr int32_t kBlockVolatileSaveEnd =
    kBlockVolatileSaveArea + 8 * static_cast<int32_t>(std::size(kBlockVolatileRegs) + kBlockVolatileXmmCount);
inline constexpr int32_t kBlockFrameSize =
    kBlockVolatileSaveEnd + ((8 + 8 * std::size(kBlockSavedRegs) + kBlockVolatileSaveEnd) % 16 ? 8 : 0);
static_assert((8 + 8 * std::size(kBlockSavedRegs) + kBlockFrameSize) % 16 == 0, "RSP aligned for calls");

// A host instruction of a block that may fault: code from host_offset on (up
// to the next site) belongs to the guest instruction at block pc + guest_offset.
struct FaultSite {
  uint32_t host_offset;
  uint32_t guest_offset;
};

// Calls of the evaluator from translated code (operations the JIT doesn't
// emit inline), counted while enabled: by opcode and, for VLane, lane
// operation (key = opcode | lane op << 8). For --stats.
void count_helper_calls(bool enable);
std::vector<std::pair<uint32_t, uint64_t>> helper_call_counts();

// Maximum number of IR values a compiled block may use (size of the scratch
// array the caller must provide).
inline constexpr size_t kMaxBlockValues = 16384;

// Block chaining. Instead of returning to the dispatcher, a block looks its
// successor up in the thread's pc -> block table and jumps into its body
// (past the prologue: all blocks share one frame). The dispatcher keeps this
// header just below the scratch array (RBP points past it) for the lookup.
struct ChainHeader {
  uint64_t stop_pc;            // return to the dispatcher at this pc (Engine::run's stop_pc)
  const uint64_t* generation;  // the engine's translation generation, which must still be
  uint64_t table_generation;   //   the one the table was filled at
  void* const* table;          // the table: entries are blocks (see ChainLayout), or null
};
inline constexpr size_t kChainHeaderSlots = sizeof(ChainHeader) / 8;

// Where the chaining code finds what it reads (0 table_mask: no chaining).
struct ChainLayout {
  uint32_t table_mask = 0;        // entries - 1; entry index = (pc >> 2) & table_mask
  int32_t entry_guest_pc = 0;     // offset of the block's guest pc in an entry
  int32_t entry_chain_target = 0; // offset of the body address to jump to (null: don't chain)
  uint32_t interrupt_offset = 0;  // in guest state: nonzero means return to the dispatcher
  uint32_t block_pc_offset = 0;   // in guest state: set to the pc of the block entered

  // Direct links (0 link_helper: none). A jump to a constant target is a
  // patchable `jmp rel32` that first goes to a stub in the block; the stub
  // calls link_helper(link_context, site index) (with the stub's return
  // address in the block identifying it), which returns the body to jump to
  // (and may patch the jump to go there directly), or null to return to the
  // dispatcher.
  uint64_t link_helper = 0;
  uint64_t link_context = 0;
};

// A direct link site of a compiled block: the rel32 of its jump (4-byte
// aligned, so it can be patched while other threads run the code), where it
// points while unlinked, and the guest pc it goes to.
struct LinkSite {
  uint32_t rel32_offset;
  uint32_t stub_offset;
  uint64_t target_pc;
};

class Emitter {
 public:
  explicit Emitter(const ir::StateLayout& layout, const ChainLayout& chain = {}) : layout_(layout), chain_(chain) {}

  // Returns an empty vector if the block is too large to compile. `faults`, if
  // given, receives the block's fault sites in code order; `body`, the offset
  // where the block's body starts (the entry point for chained jumps).
  std::vector<uint8_t> compile(const ir::Block& block, std::vector<FaultSite>* faults = nullptr,
                               size_t* body = nullptr, std::vector<LinkSite>* links = nullptr) const;

 private:
  ir::StateLayout layout_;
  ChainLayout chain_;
};

}  // namespace juice::x64
