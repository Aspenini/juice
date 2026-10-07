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
// integer slots). The callee's result is returned in both RAX and XMM0, since
// the return type is unknown; the guest sees them as X0 and D0.
//
// Other functions have a signature (generated from the SDK headers by
// tools/gen_signatures, see signatures.cpp), a string of argument kinds,
// optionally preceded by a return kind and ':':
//
//   i      integer, pointer, or a structure of 1, 2, 4 or 8 bytes (passed alike)
//   f      float or double
//   S<n>   a structure of n bytes (3, 5, 6, 7, 9-16): one or two X registers
//          on ARM64, a pointer to a copy on x64
//   H<c><t> a homogeneous floating point aggregate of c (1-4) floats (t = f)
//          or doubles (t = d): c V registers on ARM64; on x64 an 8-byte or
//          4-byte one is passed by value in an integer slot, others by pointer
//
//   C<n>   a function pointer, I<n> an interface pointer: passed like i, and if
//          they are the guest's own, native calls to them are converted back
//          per their signature (com_signatures.cpp)
//
//   return kinds: S<n> (in X0:X1 on ARM64, through a hidden first argument on
//   x64), L (larger structures: through X8 on ARM64, a hidden first argument on
//   x64), H<c><t> (in V0-V3 on ARM64, by value or through a hidden first
//   argument on x64).

#include <windows.h>

#include <cstring>
#include <stdexcept>
#include <vector>

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

// The guest's arguments, taken in order as the ARM64 convention assigns them.
struct GuestArgs {
  const arm64::CpuState& s;
  const auto* stack_bytes() const { return reinterpret_cast<const uint8_t*>(s.sp); }
  unsigned ngrn = 0, nsrn = 0;  // next general / SIMD&FP register
  size_t nsaa = 0;              // next stacked argument (offset from SP)

  uint64_t stacked() {
    uint64_t v;
    std::memcpy(&v, stack_bytes() + nsaa, 8);
    nsaa += 8;
    return v;
  }
  uint64_t integer() { return ngrn < 8 ? s.x[ngrn++] : stacked(); }
  uint64_t fp() { return nsrn < 8 ? s.v[nsrn++].lo : stacked(); }
  // A structure of `size` bytes in general registers (or on the stack if they ran out).
  void structure(void* out, size_t size) {
    const unsigned regs = static_cast<unsigned>((size + 7) / 8);
    if (ngrn + regs <= 8) {
      std::memcpy(out, &s.x[ngrn], size);
      ngrn += regs;
    } else {
      ngrn = 8;
      std::memcpy(out, stack_bytes() + nsaa, size);
      nsaa += (size + 7) & ~size_t{7};
    }
  }
  // An HFA of `count` elements of `esize` bytes in SIMD&FP registers (or on the stack).
  void hfa(void* out, unsigned count, unsigned esize) {
    auto* bytes = static_cast<uint8_t*>(out);
    if (nsrn + count <= 8) {
      for (unsigned k = 0; k < count; ++k) std::memcpy(bytes + k * esize, &s.v[nsrn + k].lo, esize);
      nsrn += count;
    } else {
      nsrn = 8;
      const size_t size = size_t{count} * esize;
      std::memcpy(out, stack_bytes() + nsaa, size);
      nsaa += (size + 7) & ~size_t{7};
    }
  }
};

unsigned number(const char*& p) {
  unsigned n = 0;
  while (*p >= '0' && *p <= '9') n = n * 10 + static_cast<unsigned>(*p++ - '0');
  return n;
}

}  // namespace

NativeResult call_native(void* fn, const arm64::CpuState& s, const char* signature) {
  uint64_t ints[16];
  uint64_t fps[4];
  NativeResult r{};

  if (!signature) {
    const auto* stack = reinterpret_cast<const uint64_t*>(s.sp);
    for (int k = 0; k < 16; ++k) ints[k] = k < 8 ? s.x[k] : stack[k - 8];
    for (int k = 0; k < 4; ++k) fps[k] = s.v[k].lo;
    r.rax = trampoline()(fn, ints, fps, &r.xmm0);
    return r;
  }

  // Copies of structures passed by value through a pointer on x64, and the
  // buffer for a returned structure.
  alignas(16) uint64_t copies[16][2] = {};
  alignas(16) uint64_t returned[4] = {};
  unsigned next_copy = 0, pos = 0;
  GuestArgs in{s};
  std::memset(fps, 0, sizeof(fps));

  // Return kind
  enum class Ret { Generic, Small, Large, Hfa } ret = Ret::Generic;
  unsigned ret_size = 0, ret_count = 0, ret_esize = 0;
  bool hfa_by_value = false;
  if (const char* colon = std::strchr(signature, ':')) {
    const char* p = signature;
    if (*p == 'S') {
      ++p;
      ret = Ret::Small;
      ret_size = number(p);
    } else if (*p == 'L') {
      ret = Ret::Large;
    } else if (*p == 'H') {
      ++p;
      ret = Ret::Hfa;
      ret_count = number(p);
      ret_esize = *p == 'd' ? 8 : 4;
      ret_size = ret_count * ret_esize;
      hfa_by_value = ret_size == 4 || ret_size == 8;
    }
    signature = colon + 1;
    // x64 returns these through a hidden first argument (and that pointer in RAX).
    if (ret == Ret::Small || (ret == Ret::Hfa && !hfa_by_value)) {
      ints[pos++] = reinterpret_cast<uint64_t>(returned);
    } else if (ret == Ret::Large) {
      ints[pos++] = s.x[8];
    }
  }

  // Arguments; positions past the signature's end are integers.
  for (const char* p = signature; pos < 16; ++pos) {
    uint64_t v = 0;
    bool is_fp = false;
    switch (*p) {
      case 'f':
        ++p;
        v = in.fp();
        is_fp = true;
        break;
      case 'S': {
        ++p;
        const unsigned size = number(p);
        uint64_t* copy = copies[next_copy++ % 16];
        in.structure(copy, size);
        v = reinterpret_cast<uint64_t>(copy);
        break;
      }
      case 'H': {
        ++p;
        const unsigned count = number(p);
        const unsigned esize = *p++ == 'd' ? 8 : 4;
        uint64_t* copy = copies[next_copy++ % 16];
        copy[0] = copy[1] = 0;
        in.hfa(copy, count, esize);
        const unsigned size = count * esize;
        v = (size == 4 || size == 8) ? copy[0] : reinterpret_cast<uint64_t>(copy);
        break;
      }
      case 'C':
      case 'I': {
        const char kind = *p++;
        const unsigned index = number(p);
        v = in.integer();
        note_callback_argument(kind, index, v);
        break;
      }
      case 'i':
        ++p;
        [[fallthrough]];
      default:
        v = in.integer();
        break;
    }
    ints[pos] = v;
    if (pos < 4) fps[pos] = is_fp ? v : 0;
  }

  r.rax = trampoline()(fn, ints, fps, &r.xmm0);
  switch (ret) {
    case Ret::Small:  // ARM64 returns it in X0:X1
      r.rax = returned[0];
      r.x1 = returned[1];
      r.has_x1 = true;
      break;
    case Ret::Hfa: {  // ARM64 returns it in V0..V3
      uint64_t bytes[4] = {};
      if (hfa_by_value) bytes[0] = r.rax;
      else std::memcpy(bytes, returned, ret_size);
      const auto* b = reinterpret_cast<const uint8_t*>(bytes);
      for (unsigned k = 0; k < ret_count; ++k) {
        r.v[k] = 0;
        std::memcpy(&r.v[k], b + k * ret_esize, ret_esize);
      }
      r.v_count = ret_count;
      break;
    }
    default:
      break;
  }
  return r;
}

bool convert_native_args(const char* signature, const uint64_t gpr[4], const uint64_t fpr[4], const uint64_t* stack,
                         uint64_t x[8], uint64_t v[8], std::vector<uint64_t>& stack_words) {
  if (std::strchr(signature, ':')) return false;  // returned structures: not for callbacks
  unsigned ngrn = 0, nsrn = 0;
  auto int_slot = [&](unsigned pos) { return pos < 4 ? gpr[pos] : stack[pos - 4]; };
  auto fp_slot = [&](unsigned pos) { return pos < 4 ? fpr[pos] : stack[pos - 4]; };
  auto push_bytes = [&](const void* bytes, size_t size) {
    const size_t words = (size + 7) / 8;
    const size_t at = stack_words.size();
    stack_words.resize(at + words, 0);
    std::memcpy(&stack_words[at], bytes, size);
  };
  unsigned pos = 0;
  for (const char* p = signature; *p; ++pos) {
    switch (*p) {
      case 'f': {
        ++p;
        const uint64_t value = fp_slot(pos);
        if (nsrn < 8) v[nsrn++] = value;
        else stack_words.push_back(value);
        break;
      }
      case 'S': {
        ++p;
        const unsigned size = number(p);
        uint64_t bytes[2] = {};
        std::memcpy(bytes, reinterpret_cast<const void*>(int_slot(pos)), size);
        const unsigned regs = (size + 7) / 8;
        if (ngrn + regs <= 8) {
          for (unsigned k = 0; k < regs; ++k) x[ngrn++] = bytes[k];
        } else {
          ngrn = 8;
          push_bytes(bytes, size);
        }
        break;
      }
      case 'H': {
        ++p;
        const unsigned count = number(p);
        const unsigned esize = *p++ == 'd' ? 8 : 4;
        const unsigned size = count * esize;
        uint64_t bytes[4] = {};
        if (size == 4 || size == 8) bytes[0] = int_slot(pos);
        else std::memcpy(bytes, reinterpret_cast<const void*>(int_slot(pos)), size);
        if (nsrn + count <= 8) {
          for (unsigned k = 0; k < count; ++k) {
            v[nsrn] = 0;
            std::memcpy(&v[nsrn++], reinterpret_cast<const uint8_t*>(bytes) + k * esize, esize);
          }
        } else {
          nsrn = 8;
          push_bytes(bytes, size);
        }
        break;
      }
      default: {  // i, C<n>, I<n>
        const char kind = *p++;
        if (kind == 'C' || kind == 'I') number(p);
        const uint64_t value = int_slot(pos);
        if (ngrn < 8) x[ngrn++] = value;
        else stack_words.push_back(value);
        break;
      }
    }
  }
  return true;
}

}  // namespace juice::win
