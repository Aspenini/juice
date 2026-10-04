#pragma once

// Architectural state of one guest ARM64 thread.
//
// The JIT addresses this structure as an array of 64-bit "slots" (see
// juice::arm64::slot). Keep the layout in sync with the static_asserts below.

#include <cstddef>
#include <cstdint>

namespace juice::arm64 {

// Why a translated block stopped before reaching its natural successor.
enum class ExitReason : uint32_t {
  None = 0,
  Svc,          // SVC #imm (exit_info = imm16), pc = next instruction
  Brk,          // BRK #imm (exit_info = imm16), pc = the BRK itself
  Hlt,          // HLT #imm
  Undefined,    // unallocated / undecodable encoding (exit_info = raw word)
  Unsupported,  // valid encoding JUICE cannot translate yet (exit_info = raw word)
  FetchFault,   // instruction fetch from unreadable memory
};

const char* to_string(ExitReason reason);

struct alignas(16) VReg {
  uint64_t lo;
  uint64_t hi;
};

struct CpuState {
  uint64_t x[31];  // X0..X30 (X30 is the link register)
  uint64_t sp;
  uint64_t pc;
  uint64_t nzcv;   // N:Z:C:V in bits 31..28, all other bits zero
  VReg v[32];
  uint64_t fpcr;
  uint64_t fpsr;
  uint64_t tpidr_el0;
  uint64_t tpidrro_el0;
  uint32_t exit_reason;  // ExitReason
  uint32_t exit_info;
  uint64_t block_pc;     // first guest pc of the block currently executing
};

// Slot numbers (byte offset / 8) used by the lifter for GetReg/SetReg.
namespace slot {
constexpr uint16_t X(unsigned n) { return static_cast<uint16_t>(n); }
inline constexpr uint16_t SP = 31;
inline constexpr uint16_t PC = 32;
inline constexpr uint16_t NZCV = 33;
constexpr uint16_t VLo(unsigned n) { return static_cast<uint16_t>(34 + 2 * n); }
constexpr uint16_t VHi(unsigned n) { return static_cast<uint16_t>(35 + 2 * n); }
inline constexpr uint16_t FPCR = 98;
inline constexpr uint16_t FPSR = 99;
inline constexpr uint16_t TPIDR_EL0 = 100;
inline constexpr uint16_t TPIDRRO_EL0 = 101;
inline constexpr uint16_t Exit = 102;  // exit_reason (low half) / exit_info (high half)
inline constexpr uint16_t BlockPc = 103;
inline constexpr uint16_t Count = 104;
}  // namespace slot

static_assert(offsetof(CpuState, sp) == 8 * slot::SP);
static_assert(offsetof(CpuState, pc) == 8 * slot::PC);
static_assert(offsetof(CpuState, nzcv) == 8 * slot::NZCV);
static_assert(offsetof(CpuState, v) == 8 * slot::VLo(0));
static_assert(offsetof(CpuState, fpcr) == 8 * slot::FPCR);
static_assert(offsetof(CpuState, tpidr_el0) == 8 * slot::TPIDR_EL0);
static_assert(offsetof(CpuState, exit_reason) == 8 * slot::Exit);
static_assert(offsetof(CpuState, exit_info) == 8 * slot::Exit + 4);
static_assert(offsetof(CpuState, block_pc) == 8 * slot::BlockPc);
static_assert(sizeof(CpuState) == 8 * slot::Count);

// Name of a state slot, for IR dumps ("x0", "sp", "nzcv", "v3.lo", ...).
const char* slot_name(uint16_t s);

}  // namespace juice::arm64
