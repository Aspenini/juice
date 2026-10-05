#pragma once

// The AArch64 Linux signal frame (struct rt_sigframe): what a guest signal
// handler receives and what rt_sigreturn restores. Portable: written and read
// through host pointers.
//
//   frame + 0      siginfo_t (128 bytes)
//   frame + 128    struct ucontext: uc_flags, uc_link, uc_stack, uc_sigmask,
//                  then uc_mcontext (struct sigcontext) at +176 within it:
//                  fault_address, regs[31], sp, pc, pstate, __reserved[4096]
//                  holding an fpsimd_context record and a terminator
//   frame + 4688   frame record {x29, x30} (x29 points here in the handler)

#include <cstdint>

#include "core/arm64/state/cpu_state.hpp"

namespace juice::lx {

inline constexpr uint64_t kSigInfoSize = 128;
inline constexpr uint64_t kUcontextOffset = 128;
inline constexpr uint64_t kMcontextOffset = kUcontextOffset + 176;
inline constexpr uint64_t kFrameRecordOffset = kUcontextOffset + 4560;
inline constexpr uint64_t kSignalFrameSize = kFrameRecordOffset + 16;
inline constexpr uint32_t kFpsimdMagic = 0x46508001;

struct SignalDelivery {
  int sig = 0;
  const void* siginfo = nullptr;  // 128 bytes (zeros except si_signo if null)
  uint64_t saved_mask = 0;        // uc_sigmask: the mask to restore on return
  uint64_t altstack_sp = 0;       // uc_stack
  uint64_t altstack_size = 0;
  uint32_t altstack_flags = 0;
  uint64_t handler = 0;
  uint64_t restorer = 0;          // return address: code that calls rt_sigreturn
  uint64_t fault_address = 0;
};

// Push a frame for `d` below `sp` and point the state at the handler:
// x0 = signal, x1 = &siginfo, x2 = &ucontext, sp = frame, x29 = frame record,
// x30 = restorer, pc = handler. Returns the frame address.
uint64_t push_signal_frame(arm64::CpuState& state, uint64_t sp, const SignalDelivery& d);

// rt_sigreturn: restore the state from the frame at state.sp. Returns false if
// the frame is malformed. `mask` receives uc_sigmask.
bool pop_signal_frame(arm64::CpuState& state, uint64_t& mask);

}  // namespace juice::lx
