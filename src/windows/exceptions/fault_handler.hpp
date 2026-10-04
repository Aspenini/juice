#pragma once

// Host exception handling for the guest.
//
// 1. Native -> guest calls. Guest code is mapped without execute permission,
//    so when native code calls a guest function pointer (a callback such as a
//    window procedure, qsort comparator or atexit handler) the CPU raises an
//    execute access violation at the guest address. The handler runs the guest
//    function through the translator with x64 -> ARM64 argument conversion and
//    resumes the native caller as if the function had returned normally.
//    Native calls to API thunk addresses are redirected the same way.
//
// 2. Guest faults. Faults inside translated code are reported with the guest
//    context. (Delivering them to the guest as structured exceptions is future
//    work.)

#include <cstdint>

namespace juice::runtime {
class CodeArena;
}

namespace juice::win {

class NativeCallbackTarget {
 public:
  virtual ~NativeCallbackTarget() = default;

  struct Args {
    uint64_t gpr[8];   // first eight integer arguments
    uint64_t fpr[4];   // XMM0-XMM3 (low 64 bits)
  };
  struct Result {
    uint64_t x0;
    uint64_t d0;
  };

  // Native code called guest address `target` (guest code or an API thunk).
  // Returns false if the call cannot be serviced.
  virtual bool call_from_native(uint64_t target, const Args& args, Result& result) = 0;
};

struct FaultRegions {
  const runtime::CodeArena* jit_code = nullptr;
  uint64_t thunks_begin = 0, thunks_end = 0;
  uint64_t image_begin = 0, image_end = 0;
  NativeCallbackTarget* callbacks = nullptr;
};

void install_fault_handler(const FaultRegions& regions);

}  // namespace juice::win
