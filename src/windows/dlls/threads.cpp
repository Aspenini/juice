// kernel32 thread control and fiber builtins (see guest_threads.cpp).

#include <windows.h>

#include "windows/dlls/builtins.hpp"
#include "windows/guest_process.hpp"

namespace juice::win {
namespace {

using arm64::CpuState;

template <typename T>
T* ptr(uint64_t v) {
  return reinterpret_cast<T*>(static_cast<uintptr_t>(v));
}

uint64_t SuspendThread_(GuestProcess& p, CpuState& s) {
  if (std::optional<DWORD> previous = p.suspend_thread(ptr<void>(s.x[0]))) return *previous;
  return SuspendThread(ptr<void>(s.x[0]));
}

// GetThreadContext(thread, context): the ARM64 CONTEXT (the native function
// would write an x64 one). Threads that never ran guest code have none.
uint64_t GetThreadContext_(GuestProcess& p, CpuState& s) {
  if (p.get_thread_context(ptr<void>(s.x[0]), *ptr<arm64eh::Context>(s.x[1]))) return TRUE;
  SetLastError(ERROR_INVALID_PARAMETER);
  return FALSE;
}

uint64_t SetThreadContext_(GuestProcess& p, CpuState& s) {
  if (p.set_thread_context(ptr<void>(s.x[0]), *ptr<const arm64eh::Context>(s.x[1]))) return TRUE;
  SetLastError(ERROR_INVALID_PARAMETER);
  return FALSE;
}

// GetCurrentThreadStackLimits(low, high): the guest stack, not the host thread's.
uint64_t GetCurrentThreadStackLimits_(GuestProcess& p, CpuState& s) {
  const auto [low, high] = p.stack_limits();
  *ptr<ULONG_PTR>(s.x[0]) = low;
  *ptr<ULONG_PTR>(s.x[1]) = high;
  return 0;
}

// CreateFiber(stack_size, start, param)
uint64_t CreateFiber_(GuestProcess& p, CpuState& s) {
  return reinterpret_cast<uint64_t>(p.create_fiber(s.x[0], s.x[1], s.x[2], 0));
}

// CreateFiberEx(commit_size, reserve_size, flags, start, param)
uint64_t CreateFiberEx_(GuestProcess& p, CpuState& s) {
  return reinterpret_cast<uint64_t>(
      p.create_fiber(s.x[1] ? s.x[1] : s.x[0], s.x[3], s.x[4], static_cast<uint32_t>(s.x[2])));
}

uint64_t ConvertThreadToFiber_(GuestProcess& p, CpuState& s) {
  return reinterpret_cast<uint64_t>(p.convert_thread_to_fiber(s.x[0], 0));
}

uint64_t ConvertThreadToFiberEx_(GuestProcess& p, CpuState& s) {
  return reinterpret_cast<uint64_t>(p.convert_thread_to_fiber(s.x[0], static_cast<uint32_t>(s.x[1])));
}

uint64_t ConvertFiberToThread_(GuestProcess& p, CpuState&) { return p.convert_fiber_to_thread(); }

uint64_t SwitchToFiber_(GuestProcess& p, CpuState& s) {
  p.switch_to_fiber(ptr<void>(s.x[0]));
  return 0;
}

uint64_t DeleteFiber_(GuestProcess& p, CpuState& s) {
  p.delete_fiber(ptr<void>(s.x[0]));
  return 0;
}

constexpr BuiltinExport kThreads[] = {
    {"SuspendThread", SuspendThread_},
    {"GetThreadContext", GetThreadContext_},
    {"SetThreadContext", SetThreadContext_},
    {"GetCurrentThreadStackLimits", GetCurrentThreadStackLimits_},
    {"CreateFiber", CreateFiber_},
    {"CreateFiberEx", CreateFiberEx_},
    {"ConvertThreadToFiber", ConvertThreadToFiber_},
    {"ConvertThreadToFiberEx", ConvertThreadToFiberEx_},
    {"ConvertFiberToThread", ConvertFiberToThread_},
    {"SwitchToFiber", SwitchToFiber_},
    {"DeleteFiber", DeleteFiber_},
};

}  // namespace

std::span<const BuiltinExport> thread_builtins() { return kThreads; }

}  // namespace juice::win
