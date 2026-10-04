// Atomic memory operations on host memory, shared by the interpreter and the
// JIT (which calls execute_atomic() for these opcodes).
//
// All of them are sequentially consistent, which is at least as strong as any
// Arm ordering variant (relaxed, acquire, release, acquire-release).

#include <atomic>
#include <cstdint>
#include <type_traits>

#include "core/ir/ir.hpp"

#if defined(_MSC_VER)
#include <intrin.h>
#endif

namespace juice::ir {
namespace {

template <typename T>
T* host_ptr(uint64_t addr) {
  return reinterpret_cast<T*>(static_cast<uintptr_t>(addr));
}

template <typename T>
uint64_t rmw(uint64_t addr, uint64_t operand, AtomicOp op) {
  using S = std::make_signed_t<T>;
  std::atomic_ref<T> ref(*host_ptr<T>(addr));
  const T v = static_cast<T>(operand);
  switch (op) {
    case AtomicOp::Add: return ref.fetch_add(v);
    case AtomicOp::Clr: return ref.fetch_and(static_cast<T>(~v));
    case AtomicOp::Eor: return ref.fetch_xor(v);
    case AtomicOp::Set: return ref.fetch_or(v);
    case AtomicOp::Swap: return ref.exchange(v);
    default: break;
  }
  T old = ref.load();
  for (;;) {
    T desired = old;
    switch (op) {
      case AtomicOp::SMax: desired = static_cast<S>(old) > static_cast<S>(v) ? old : v; break;
      case AtomicOp::SMin: desired = static_cast<S>(old) < static_cast<S>(v) ? old : v; break;
      case AtomicOp::UMax: desired = old > v ? old : v; break;
      default: desired = old < v ? old : v; break;  // UMin
    }
    if (ref.compare_exchange_weak(old, desired)) return old;
  }
}

template <typename T>
uint64_t cas(uint64_t addr, uint64_t expected, uint64_t desired) {
  std::atomic_ref<T> ref(*host_ptr<T>(addr));
  T old = static_cast<T>(expected);
  ref.compare_exchange_strong(old, static_cast<T>(desired));
  return old;  // the value found in memory, whether or not the swap happened
}

// 128-bit compare-and-swap. `operands` = {expected lo, hi, desired lo, hi}.
// Uses CMPXCHG16B (clang/gcc need -mcx16, see xmake.lua).
uint64_t cas_pair(uint64_t addr, uint64_t operands) {
  const auto* op = host_ptr<const uint64_t>(operands);
#if defined(_MSC_VER)
  __int64 comparand[2] = {static_cast<__int64>(op[0]), static_cast<__int64>(op[1])};
  return _InterlockedCompareExchange128(host_ptr<volatile __int64>(addr), static_cast<__int64>(op[3]),
                                        static_cast<__int64>(op[2]), comparand)
             ? 0
             : 1;
#else
  unsigned __int128 expected = (static_cast<unsigned __int128>(op[1]) << 64) | op[0];
  unsigned __int128 desired = (static_cast<unsigned __int128>(op[3]) << 64) | op[2];
  return __atomic_compare_exchange_n(host_ptr<unsigned __int128>(addr), &expected, desired, false, __ATOMIC_SEQ_CST,
                                     __ATOMIC_SEQ_CST)
             ? 0
             : 1;
#endif
}

}  // namespace

uint64_t execute_atomic(const Inst& in, uint64_t a, uint64_t b, uint64_t c) {
  switch (in.op) {
    case Opcode::AtomicRmw: {
      const auto op = static_cast<AtomicOp>(in.aux);
      switch (in.size) {
        case 1: return rmw<uint8_t>(a, b, op);
        case 2: return rmw<uint16_t>(a, b, op);
        case 4: return rmw<uint32_t>(a, b, op);
        default: return rmw<uint64_t>(a, b, op);
      }
    }
    case Opcode::AtomicCas:
      switch (in.size) {
        case 1: return cas<uint8_t>(a, b, c);
        case 2: return cas<uint16_t>(a, b, c);
        case 4: return cas<uint32_t>(a, b, c);
        default: return cas<uint64_t>(a, b, c);
      }
    case Opcode::AtomicCasPair:
      return cas_pair(a, b);
    default:
      return 0;
  }
}

}  // namespace juice::ir
