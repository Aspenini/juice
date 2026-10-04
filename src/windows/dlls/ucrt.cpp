// Universal C runtime builtins.
//
// Programs built with /MD import the C runtime from ucrtbase.dll through the
// api-ms-win-crt-* API sets, and almost all of it is forwarded to the native
// x64 ucrtbase. The process-exit functions are wrapped so that JUICE can run
// its exit hooks (statistics) before the native runtime terminates the process.

#include <windows.h>

#include "windows/dlls/builtins.hpp"
#include "windows/guest_process.hpp"

namespace juice::win {
namespace {

using arm64::CpuState;
using ExitFn = void(__cdecl*)(int);

[[noreturn]] void forward_exit(GuestProcess& p, const char* name, int code) {
  p.before_exit(static_cast<uint32_t>(code));
  HMODULE ucrt = GetModuleHandleA("ucrtbase.dll");
  auto fn = ucrt ? reinterpret_cast<ExitFn>(GetProcAddress(ucrt, name)) : nullptr;
  if (fn) fn(code);
  ExitProcess(static_cast<UINT>(code));
}

uint64_t exit_(GuestProcess& p, CpuState& s) { forward_exit(p, "exit", static_cast<int>(s.x[0])); }
uint64_t _exit_(GuestProcess& p, CpuState& s) { forward_exit(p, "_exit", static_cast<int>(s.x[0])); }
uint64_t quick_exit_(GuestProcess& p, CpuState& s) { forward_exit(p, "quick_exit", static_cast<int>(s.x[0])); }

constexpr BuiltinExport kUcrt[] = {
    {"exit", exit_},
    {"_exit", _exit_},
    {"_Exit", _exit_},
    {"quick_exit", quick_exit_},
};

}  // namespace

std::span<const BuiltinExport> ucrt_builtins() { return kUcrt; }

}  // namespace juice::win
