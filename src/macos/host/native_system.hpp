#pragma once

// The host side of the macOS frontend (macOS only): the system's libraries
// through dlopen/dlsym, and the fault handler that turns native calls of
// guest code into calls through MacProcess::entry().

#include <cstdint>
#include <string>

#include "macos/process/mac_process.hpp"

namespace juice::mac {

class MacNativeSystem final : public NativeSystem {
 public:
  void* open_library(const std::string& install_name) override;
  void* find_symbol(void* library, const std::string& name) override;
  bool is_native_code(uint64_t addr) override;
  std::string describe(uint64_t addr) override;
  bool read_memory(uint64_t addr, void* out, size_t size) override;
  void raise_exception(uint64_t exception) override;
};

// Exceptions unwinding native calls the guest made come to JUICE (the call
// trampoline's personality); call before the process makes native calls.
void install_exception_support();

// Installs the SIGBUS/SIGSEGV handler: an instruction fetch from guest code
// (native code calling a guest function) continues at process.entry() with
// R11 = the guest function; other faults go to the previous handler.
void install_fault_handler(MacProcess& process);

// Makes the native libraries see the program's argc, argv and name (for
// NSProcessInfo, getprogname, ...), not JUICE's.
void set_native_arguments(MacProcess& process);

}  // namespace juice::mac
