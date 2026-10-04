// Generic Windows ARM64 -> Windows x64 call bridge.
//
// Windows ARM64 passes integer arguments in X0-X7 and floating point
// arguments in D0-D7, each numbered independently, with the rest on the stack
// starting at [SP]. Windows x64 assigns arguments by position: the first four
// go to RCX/RDX/R8/R9 or XMM0-XMM3, the rest to the stack after 32 bytes of
// home space.
//
// Without a signature, argument k is passed as both the k-th integer and the
// k-th floating point argument (X_k in the integer slot, D_k in XMM_k). That
// is exact for functions whose arguments are all integers/pointers or all
// floating point, and for variadic functions (Windows ARM64 passes variadic
// floating point values in integer registers; x64 variadic callees read the
// integer slots). Functions mixing both kinds get a signature (signatures.cpp).
//
// Signatures also cover 16-byte structures, which the two conventions treat
// differently: ARM64 passes and returns them in two integer registers, x64
// passes a pointer to a copy and returns them through a hidden pointer.
//
// The callee's result is returned in both RAX and XMM0, since the return type
// is unknown; the guest sees them as X0 and D0.
//
// Not handled yet: structures larger than 16 bytes returned by value (X8).

#include <windows.h>

#include <cstring>
#include <stdexcept>

#include "core/jit/x64/assembler.hpp"
#include "windows/thunk/thunk_table.hpp"

namespace juice::win {
namespace {

// uint64_t trampoline(void* fn, const uint64_t ints[16], const uint64_t fps[4], uint64_t* xmm0_out)
using Trampoline = uint64_t (*)(void* fn, const uint64_t* ints, const uint64_t* fps, uint64_t* xmm0_out);

Trampoline build_trampoline() {
  using namespace juice::x64;
  constexpr int32_t kFrame = 0x80;  // 32 bytes home space + 12 stack arguments
  Assembler a;
  a.push(RBX);
  a.push(RSI);
  a.push(RDI);
  a.alu_imm(Alu::Sub, RSP, kFrame);  // RSP is 16-byte aligned after the pushes and this
  a.mov(RBX, R9);                    // xmm0_out
  a.mov(RAX, RCX);                   // fn
  a.mov(RSI, RDX);                   // ints
  for (int k = 4; k < 16; ++k) {
    a.load(R10, Mem{RSI, 8 * k});
    a.store(Mem{RSP, 0x20 + 8 * (k - 4)}, R10, 8);
  }
  for (unsigned k = 0; k < 4; ++k) a.movsd_load(k, Mem{R8, static_cast<int32_t>(8 * k)});
  a.load(RCX, Mem{RSI, 0});
  a.load(RDX, Mem{RSI, 8});
  a.load(R8, Mem{RSI, 16});
  a.load(R9, Mem{RSI, 24});
  a.call(RAX);
  a.movsd_store(Mem{RBX, 0}, 0);
  a.alu_imm(Alu::Add, RSP, kFrame);
  a.pop(RDI);
  a.pop(RSI);
  a.pop(RBX);
  a.ret();

  void* mem = VirtualAlloc(nullptr, a.size(), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
  if (!mem) throw std::bad_alloc();
  std::memcpy(mem, a.code().data(), a.size());
  DWORD old = 0;
  VirtualProtect(mem, a.size(), PAGE_EXECUTE_READ, &old);
  FlushInstructionCache(GetCurrentProcess(), mem, a.size());
  return reinterpret_cast<Trampoline>(mem);
}

Trampoline trampoline() {
  static const Trampoline t = build_trampoline();
  return t;
}

}  // namespace

NativeResult call_native(void* fn, const arm64::CpuState& s, const char* signature) {
  const auto* stack = reinterpret_cast<const uint64_t*>(s.sp);
  uint64_t ints[16];
  uint64_t fps[4];
  if (!signature) {
    for (int k = 0; k < 16; ++k) ints[k] = k < 8 ? s.x[k] : stack[k - 8];
    for (int k = 0; k < 4; ++k) fps[k] = s.v[k].lo;
  }

  // Copies of 16-byte structures passed by value, and a 16-byte returned structure.
  uint64_t structs[8][2] = {};
  uint64_t returned[2] = {};
  bool struct_return = false;

  if (signature) {
    // Assign guest integer and FP arguments to x64 positions per the signature;
    // positions past its end are integers.
    unsigned next_int = 0, next_fp = 0, next_stack = 0, next_struct = 0, pos = 0;
    auto take_int = [&] { return next_int < 8 ? s.x[next_int++] : stack[next_stack++]; };
    auto take_fp = [&] { return next_fp < 8 ? s.v[next_fp++].lo : stack[next_stack++]; };
    if (*signature == '>') {  // x64 returns 16-byte structures through a hidden first argument
      struct_return = true;
      ints[pos] = reinterpret_cast<uint64_t>(returned);
      fps[pos++] = 0;
      ++signature;
    }
    for (; pos < 16; ++pos) {
      const char kind = *signature ? *signature++ : 'i';
      uint64_t v;
      if (kind == 'f') {
        v = take_fp();
      } else if (kind == 'S') {
        // ARM64 passes it in two consecutive registers (or entirely on the
        // stack once fewer than two remain); x64 passes a pointer to a copy.
        if (next_int == 7) next_int = 8;
        uint64_t* copy = structs[next_struct++ % 8];
        copy[0] = take_int();
        copy[1] = take_int();
        v = reinterpret_cast<uint64_t>(copy);
      } else {
        v = take_int();
      }
      ints[pos] = v;
      if (pos < 4) fps[pos] = kind == 'f' ? v : 0;
    }
  }

  NativeResult r{};
  r.rax = trampoline()(fn, ints, fps, &r.xmm0);
  if (struct_return) {  // ARM64 returns it in X0:X1
    r.rax = returned[0];
    r.x1 = returned[1];
    r.has_x1 = true;
  }
  return r;
}

}  // namespace juice::win
