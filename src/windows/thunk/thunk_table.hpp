#pragma once

// Guest-visible addresses for host functions.
//
// Each imported API gets a unique address inside a reserved, inaccessible
// region. Guest code calls it like any ARM64 function (BL/BLR); when the
// dispatcher sees the guest pc inside this region it performs the host call
// with ARM64 -> x64 ABI conversion and returns to the guest's link register.

#include <atomic>
#include <cstdint>
#include <mutex>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "core/arm64/state/cpu_state.hpp"

namespace juice::win {

class GuestProcess;

// A host implementation of an API with direct access to guest state.
// Returns the value for X0.
using BuiltinFn = uint64_t (*)(GuestProcess& process, arm64::CpuState& state);

struct Thunk {
  enum class Kind : uint8_t {
    ReturnSentinel,  // return address used when the host calls guest code
    Native,          // forward to a native x64 function (generic ABI bridge)
    Builtin,         // JUICE's own implementation
    Missing,         // import that could not be resolved; fails when called
  };
  Kind kind = Kind::Missing;
  std::string dll;
  std::string name;
  void* native = nullptr;
  const char* signature = nullptr;  // argument kinds for the native bridge, see call_native()
  BuiltinFn builtin = nullptr;
  uint64_t calls = 0;  // updated with std::atomic_ref
};

// Thread safe: thunks may be added (GetProcAddress) while other threads look
// them up. Storage is allocated once, so thunks never move.
class ThunkTable {
 public:
  static constexpr uint64_t kStride = 16;

  explicit ThunkTable(size_t capacity = 1 << 15);
  ~ThunkTable();
  ThunkTable(const ThunkTable&) = delete;
  ThunkTable& operator=(const ThunkTable&) = delete;

  uint64_t add(Thunk thunk);
  // Native function thunks are shared by function address.
  uint64_t add_native(void* fn, std::string dll, std::string name, const char* signature = nullptr);

  Thunk* find(uint64_t addr) {
    uint64_t off = addr - begin();
    if (off % kStride || off / kStride >= count_.load(std::memory_order_acquire)) return nullptr;
    return &thunks_[off / kStride];
  }

  uint64_t begin() const { return reinterpret_cast<uint64_t>(base_); }
  uint64_t end() const { return begin() + capacity_ * kStride; }
  uint64_t return_sentinel() const { return begin(); }
  std::span<const Thunk> thunks() const { return {thunks_.data(), count_.load(std::memory_order_acquire)}; }

 private:
  uint64_t add_locked(Thunk thunk);

  void* base_ = nullptr;
  size_t capacity_ = 0;
  std::mutex mutex_;                 // serializes additions
  std::vector<Thunk> thunks_;        // reserved to capacity_: never reallocates
  std::atomic<size_t> count_{0};     // published thunks
  std::unordered_map<void*, uint64_t> by_native_;
};

struct NativeResult {
  uint64_t rax;
  uint64_t xmm0;        // low 64 bits
  uint64_t x1 = 0;      // second half of a returned 16-byte structure
  bool has_x1 = false;
};

// Call a native x64 function with arguments taken from guest state following
// the Windows ARM64 calling convention. `signature` optionally describes the
// argument kinds by position for functions the generic rules get wrong: 'i'
// integer/pointer, 'f' floating point, 'S' 16-byte structure by value, and a
// leading '>' for a returned 16-byte structure; see native_call.cpp.
NativeResult call_native(void* fn, const arm64::CpuState& state, const char* signature = nullptr);

// Known signatures of native exports that mix integer and floating point
// arguments (nullptr if none is needed).
const char* native_signature(std::string_view dll, std::string_view name);

}  // namespace juice::win
