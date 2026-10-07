// Atomic memory operations on host memory, shared by the interpreter and the
// JIT (which calls execute_atomic() for these opcodes).
//
// All of them are sequentially consistent, which is at least as strong as any
// Arm ordering variant (relaxed, acquire, release, acquire-release).

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
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
// operands: {expected lo, hi, desired lo, hi}; the expected pair receives the
// value memory held (unchanged if the swap happened).
uint64_t cas_pair(uint64_t addr, uint64_t operands) {
  auto* op = host_ptr<uint64_t>(operands);
#if defined(_MSC_VER)
  __int64 comparand[2] = {static_cast<__int64>(op[0]), static_cast<__int64>(op[1])};
  const bool swapped = _InterlockedCompareExchange128(host_ptr<volatile __int64>(addr), static_cast<__int64>(op[3]),
                                                      static_cast<__int64>(op[2]), comparand);
  op[0] = static_cast<uint64_t>(comparand[0]);
  op[1] = static_cast<uint64_t>(comparand[1]);
#else
  unsigned __int128 expected = (static_cast<unsigned __int128>(op[1]) << 64) | op[0];
  unsigned __int128 desired = (static_cast<unsigned __int128>(op[3]) << 64) | op[2];
  const bool swapped = __atomic_compare_exchange_n(host_ptr<unsigned __int128>(addr), &expected, desired, false,
                                                   __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
  op[0] = static_cast<uint64_t>(expected);
  op[1] = static_cast<uint64_t>(expected >> 64);
#endif
  return swapped ? 0 : 1;
}

// 128-bit read-modify-write (LSE128) with a compare-and-swap loop. `operand`
// points to {lo, hi}, which receives the old value.
void rmw_pair(uint64_t addr, uint64_t operand, AtomicOp op) {
  auto* v = host_ptr<uint64_t>(operand);
  uint64_t cell[4];  // {expected lo, hi, desired lo, hi}
  std::memcpy(cell, host_ptr<const void>(addr), 16);  // a first guess; the CAS checks it
  for (;;) {
    switch (op) {
      case AtomicOp::Clr: cell[2] = cell[0] & ~v[0], cell[3] = cell[1] & ~v[1]; break;
      case AtomicOp::Set: cell[2] = cell[0] | v[0], cell[3] = cell[1] | v[1]; break;
      default: cell[2] = v[0], cell[3] = v[1]; break;  // Swap
    }
    if (cas_pair(addr, reinterpret_cast<uint64_t>(cell)) == 0) break;  // cell[0..1] now hold memory's value
  }
  v[0] = cell[0];
  v[1] = cell[1];
}

// MOPS: memory copy (memmove, or the forward-only CPYF copy) and memory set.
void mem_op(uint64_t dst, uint64_t src, uint64_t count, unsigned kind) {
  auto* d = host_ptr<uint8_t>(dst);
  switch (kind) {
    case 0:
      std::memmove(d, host_ptr<const uint8_t>(src), count);
      break;
    case 1: {  // byte by byte, forward: an overlapping destination above the source repeats the pattern
      const auto* s = host_ptr<const uint8_t>(src);
      if (dst > src && dst < src + count) {
        for (uint64_t k = 0; k < count; ++k) d[k] = s[k];
      } else {
        std::memmove(d, s, count);
      }
      break;
    }
    default:
      std::memset(d, static_cast<int>(src & 0xFF), count);
      break;
  }
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
    case Opcode::AtomicRmwPair:
      rmw_pair(a, b, static_cast<AtomicOp>(in.aux));
      return 0;
    case Opcode::MemOp:
      mem_op(a, b, c, in.aux);
      return 0;
    case Opcode::Counter:
      if (in.aux == 1) {  // RNDR: SplitMix64 of a per-thread state seeded from the clock and the stack
        thread_local uint64_t state = static_cast<uint64_t>(
            std::chrono::steady_clock::now().time_since_epoch().count()) ^ reinterpret_cast<uintptr_t>(&state);
        uint64_t z = (state += 0x9E37'79B9'7F4A'7C15ull);
        z = (z ^ (z >> 30)) * 0xBF58'476D'1CE4'E5B9ull;
        z = (z ^ (z >> 27)) * 0x94D0'49BB'1331'11EBull;
        return z ^ (z >> 31);
      }
      return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
                                       std::chrono::steady_clock::now().time_since_epoch())
                                       .count());
    default:
      return 0;
  }
}

}  // namespace juice::ir
