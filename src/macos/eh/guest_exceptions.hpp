#pragma once

// C++ and Objective-C exceptions through guest frames.
//
// Exceptions start in native code: throw, @throw and rethrow are the host's
// libc++abi and libobjc. One that unwinds a native call the guest made
// arrives at the call trampoline's landing pad (call_native() reports it);
// JUICE then handles the guest's frames itself, as the native unwinder
// would ARM64 ones:
//
//   1. search: walk the guest frames of this call level (up to where native
//      code called into it), asking each frame's language-specific data
//      (LSDA) for a handler, as the C++ and Objective-C personalities do
//      (matching through the catch type_info's own can_catch);
//   2. unwind: walk them again, entering cleanups (whose _Unwind_Resume is
//      JUICE's, continuing the walk) and finally the handler, with X0 = the
//      exception and X1 = the handler's selector.
//
// With no handler in this level, its cleanups run and the exception is raised
// again natively from JUICE (NativeSystem::raise_exception): it continues
// through the entry trampoline into the native code that called the guest,
// and so on outward.

#include <cstdint>
#include <unordered_map>

#include "core/arm64/state/cpu_state.hpp"
#include "macos/eh/guest_unwind.hpp"

namespace juice::mac {

class MacProcess;

// Thrown (in JUICE's own code) when the guest's state was changed to continue
// at a landing pad: the call into native code that brought the exception
// doesn't return normally. MacProcess::on_host_address catches it.
struct GuestLanding {};

class GuestExceptions {
 public:
  explicit GuestExceptions(MacProcess& process);

  // An exception unwound a native call the guest made (the guest's state is
  // the active call level's). Lands in the guest or raises the exception again
  // natively; doesn't return.
  [[noreturn]] void native_exception(uint64_t exception);

  // The guest's _Unwind_Resume(exception), at the end of a cleanup.
  [[noreturn]] void resume(arm64::CpuState& s);

 private:
  struct Scan {
    enum Kind { None, Cleanup, Handler } kind = None;
    uint64_t landing_pad = 0;
    int64_t selector = 0;
    uint64_t action_record = 0;
    uint64_t adjusted = 0;
  };

  bool frame_info(uint64_t pc, FrameUnwindInfo& info);
  bool known_personality(uint64_t personality);
  Scan scan(const FrameUnwindInfo& info, uint64_t return_address, uint64_t exception, bool search);
  bool can_catch(uint64_t catch_type, uint64_t exception, uint64_t& adjusted);
  // Phase 2 from `frame`: lands at a cleanup or the handler, or raises natively.
  [[noreturn]] void unwind(GuestFrame frame, uint64_t exception);
  [[noreturn]] void land(const GuestFrame& frame, uint64_t landing_pad, uint64_t exception, int64_t selector);
  [[noreturn]] void raise_natively(uint64_t exception);
  uint64_t frame_cfa(const GuestFrame& frame, const FrameUnwindInfo& info);

  MacProcess& p_;
  MemoryReader read_;
  uint64_t gxx_personality_ = 0, objc_personality_ = 0, gcc_personality_ = 0;
};

}  // namespace juice::mac
