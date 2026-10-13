#pragma once

// Converting calls between Apple's ARM64 calling convention (the guest's)
// and the x86-64 System V convention (macOS's native libraries').
//
// Apple ARM64 (AAPCS64 with Apple's changes):
//   - integers and pointers in X0-X7, floating point and vectors in V0-V7,
//     numbered independently; then the stack, where arguments take their
//     natural size and alignment (a char takes one byte) - unlike AAPCS64's
//     8-byte slots - and composites are 8-byte aligned and rounded up to 8;
//   - variadic arguments always on the stack, one 8-byte slot each;
//   - homogeneous floating point aggregates (up to four floats/doubles) in
//     V registers; other composites up to 16 bytes in X registers; larger
//     ones by reference (a pointer to a copy);
//   - results in X0/X1, V0-V3 (aggregates), or memory at X8;
//   - long double is double.
// x86-64 System V:
//   - integers in RDI, RSI, RDX, RCX, R8, R9; floating point in XMM0-7; the
//     rest on the stack in 8-byte slots;
//   - aggregates up to 16 bytes classified per eightbyte (INTEGER: a general
//     register, SSE: an XMM register), larger ones copied onto the stack;
//   - results in RAX/RDX, XMM0/XMM1, ST0 (long double), or memory at a
//     hidden first argument;
//   - AL holds the number of vector registers a variadic callee may read.
// Swift's registers map across: X20 (self) = R13, X21 (error) = R12, X22
// (async context) = R14.

#include <cstdint>
#include <expected>
#include <string>
#include <vector>

#include "core/arm64/state/cpu_state.hpp"
#include "macos/abi/ctype.hpp"

namespace juice::mac {

struct alignas(16) Vec128 {
  uint64_t lo = 0;
  uint64_t hi = 0;
};

// The x86-64 registers and stack of a call (both directions).
struct HostCall {
  uint64_t gpr[6] = {};  // RDI, RSI, RDX, RCX, R8, R9
  Vec128 xmm[8] = {};
  std::vector<uint64_t> stack;  // stack arguments: stack[0] at [RSP] when the call is made
  uint64_t al = 0;              // vector registers used, for variadic callees
  uint64_t r12 = 0, r13 = 0, r14 = 0;  // Swift error, self, async context
  uint64_t rax = 0;                    // Swift indirect result
  alignas(16) uint8_t result_buffer[128] = {};  // for results returned in memory
};

// The x86-64 registers holding a result (Swift returns up to four integer
// and four floating point values: RAX, RDX, RCX, R8 and XMM0-3).
struct HostResult {
  uint64_t rax = 0, rdx = 0, rcx = 0, r8 = 0;
  Vec128 xmm[4];
  uint8_t st0[16] = {};  // x87 80-bit value (long double results)
  uint64_t r12 = 0;      // Swift error
};

// The x86-64 arguments a native caller passed (callbacks into the guest):
// `stack` points at the first stack argument ([RSP + 8] on entry).
struct HostFrame {
  uint64_t gpr[6] = {};
  Vec128 xmm[8] = {};
  const uint64_t* stack = nullptr;
  uint64_t al = 0;
  uint64_t r12 = 0, r13 = 0, r14 = 0, rax = 0;
};

// Guest memory for a guest call's stack arguments and argument copies: the
// caller picks `base` (16-byte aligned, below the guest's SP), the conversion
// fills `bytes` (to be copied to `base`), and the guest runs with SP = base.
struct GuestStackArea {
  uint64_t base = 0;
  std::vector<uint8_t> bytes;
};

// --- Guest calls native -----------------------------------------------------------------

// Fills `out` from the guest's arguments for a native function of type `f`
// (registers, and the stack at s.sp). For a variadic function,
// `variadic_words` 8-byte slots after the fixed arguments are passed as
// integers (the callee reads them as such: pointers, ints).
std::expected<void, std::string> guest_args_to_host(const FunctionType& f, const arm64::CpuState& s, HostCall& out,
                                                    unsigned variadic_words = 0);

// Sets the guest's result registers (or the memory at X8) from a native result.
void host_result_to_guest(const FunctionType& f, const HostCall& call, const HostResult& r, arm64::CpuState& s);

// Without a type: X0-X5 -> RDI..R9, X6-X7 -> the first two stack slots,
// V0-V7 -> XMM0-7, the Swift registers, X8 -> RAX (Swift's indirect result).
// Exact for functions taking up to eight integer and eight floating point
// arguments in any order (not variadic ones: AL isn't set) and returning
// scalars or Swift values in registers.
void generic_args_to_host(const arm64::CpuState& s, HostCall& out);
// RAX, RDX, RCX, R8 -> X0-X3, XMM0-3 -> V0-V3, R12 -> X21.
void generic_result_to_guest(const HostResult& r, arm64::CpuState& s);

// --- Native calls guest -----------------------------------------------------------------

// Sets the guest's argument registers and fills `area` from a native call of type `f`.
std::expected<void, std::string> host_args_to_guest(const FunctionType& f, const HostFrame& in, arm64::CpuState& s,
                                                    GuestStackArea& area);

// The native result from the guest's result registers (or the memory at the
// hidden pointer, `in.gpr[0]` for results returned in memory).
void guest_result_to_host(const FunctionType& f, const HostFrame& in, const arm64::CpuState& s, HostResult& r);

// Without a type: the reverse of generic_args_to_host / generic_result_to_guest.
void generic_args_to_guest(const HostFrame& in, arm64::CpuState& s);
void generic_result_to_host(const arm64::CpuState& s, HostResult& r);

// Does x86-64 return a value of type `t` in memory (through a hidden pointer)?
// (Objective-C then needs the _stret forms of its dispatch functions.)
bool host_returns_in_memory(const CType& t);

// --- x87 extended precision ---------------------------------------------------------------

void double_to_x87(double v, uint8_t out[10]);
double x87_to_double(const uint8_t in[10]);

}  // namespace juice::mac
