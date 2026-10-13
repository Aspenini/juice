#include "macos/host/native_system.hpp"

#include <crt_externs.h>
#include <dlfcn.h>
#include <mach-o/loader.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/ucontext.h>
#include <unistd.h>

#include <cstdio>
#include <cstring>
#include <format>
#include <mutex>
#include <unordered_map>

namespace juice::mac {

void* MacNativeSystem::open_library(const std::string& install_name) {
  // (An ARM64-only library fails to open: the caller treats it as missing.)
  return dlopen(install_name.c_str(), RTLD_LAZY | RTLD_GLOBAL);
}

void* MacNativeSystem::find_symbol(void* library, const std::string& name) {
  return dlsym(library ? library : RTLD_DEFAULT, name.c_str());
}

namespace {

// Is `addr` inside an executable segment of the native image whose header is `mh`?
bool in_executable_segment(const mach_header_64* mh, uint64_t addr) {
  if (mh->magic != MH_MAGIC_64) return false;
  const auto* first = reinterpret_cast<const uint8_t*>(mh + 1);
  // Segment addresses are relative to __TEXT's (the header's) vmaddr.
  uint64_t text_vmaddr = 0;
  const uint8_t* p = first;
  for (uint32_t k = 0; k < mh->ncmds; ++k) {
    const auto* lc = reinterpret_cast<const load_command*>(p);
    if (lc->cmd == LC_SEGMENT_64) {
      const auto* seg = reinterpret_cast<const segment_command_64*>(lc);
      if (seg->fileoff == 0 && seg->filesize) text_vmaddr = seg->vmaddr;
    }
    p += lc->cmdsize;
  }
  p = first;
  for (uint32_t k = 0; k < mh->ncmds; ++k) {
    const auto* lc = reinterpret_cast<const load_command*>(p);
    if (lc->cmd == LC_SEGMENT_64) {
      const auto* seg = reinterpret_cast<const segment_command_64*>(lc);
      const uint64_t start = reinterpret_cast<uint64_t>(mh) + (seg->vmaddr - text_vmaddr);
      if ((seg->initprot & VM_PROT_EXECUTE) && addr >= start && addr - start < seg->vmsize) return true;
    }
    p += lc->cmdsize;
  }
  return false;
}

}  // namespace

bool MacNativeSystem::is_native_code(uint64_t addr) {
  Dl_info info{};
  if (!dladdr(reinterpret_cast<const void*>(addr), &info) || !info.dli_fbase) return false;
  return in_executable_segment(static_cast<const mach_header_64*>(info.dli_fbase), addr);
}

std::string MacNativeSystem::describe(uint64_t addr) {
  Dl_info info{};
  if (!dladdr(reinterpret_cast<const void*>(addr), &info) || !info.dli_fname) return {};
  const char* slash = std::strrchr(info.dli_fname, '/');
  const char* library = slash ? slash + 1 : info.dli_fname;
  if (!info.dli_sname) return library;
  const uint64_t offset = addr - reinterpret_cast<uint64_t>(info.dli_saddr);
  return offset ? std::format("{}`{}+{}", library, info.dli_sname, offset) : std::format("{}`{}", library, info.dli_sname);
}

bool MacNativeSystem::read_memory(uint64_t addr, void* out, size_t size) {
  mach_vm_size_t got = 0;
  return mach_vm_read_overwrite(mach_task_self(), addr, size, reinterpret_cast<mach_vm_address_t>(out), &got) ==
             KERN_SUCCESS &&
         got == size;
}

namespace {

MacProcess* g_fault_process = nullptr;
struct sigaction g_previous_segv, g_previous_bus;

void forward(int sig, siginfo_t* info, void* context) {
  const struct sigaction& previous = sig == SIGBUS ? g_previous_bus : g_previous_segv;
  if (previous.sa_flags & SA_SIGINFO) {
    if (previous.sa_sigaction) {
      previous.sa_sigaction(sig, info, context);
      return;
    }
  } else if (previous.sa_handler != SIG_DFL && previous.sa_handler != SIG_IGN) {
    previous.sa_handler(sig);
    return;
  }
  // The default action: crash with this signal.
  signal(sig, SIG_DFL);
}

void on_fault(int sig, siginfo_t* info, void* context) {
  auto* uc = static_cast<ucontext_t*>(context);
  const uint64_t rip = uc->uc_mcontext->__ss.__rip;
  // Native code jumped into guest code (which is never executable for the host).
  if (g_fault_process && reinterpret_cast<uint64_t>(info->si_addr) == rip && g_fault_process->is_guest_code(rip)) {
    uc->uc_mcontext->__ss.__r11 = rip;
    uc->uc_mcontext->__ss.__rip = reinterpret_cast<uint64_t>(g_fault_process->entry());
    return;
  }
  forward(sig, info, context);
}

}  // namespace

void install_fault_handler(MacProcess& process) {
  g_fault_process = &process;
  // An alternate stack, so that faults on a full stack still reach the handler.
  static uint8_t alternate[64 * 1024];
  stack_t ss{};
  ss.ss_sp = alternate;
  ss.ss_size = sizeof(alternate);
  sigaltstack(&ss, nullptr);
  struct sigaction sa{};
  sa.sa_sigaction = on_fault;
  sa.sa_flags = SA_SIGINFO | SA_ONSTACK | SA_NODEFER;
  sigemptyset(&sa.sa_mask);
  sigaction(SIGSEGV, &sa, &g_previous_segv);
  sigaction(SIGBUS, &sa, &g_previous_bus);
}

void set_native_arguments(MacProcess& process) {
  *_NSGetArgc() = process.argc();
  *_NSGetArgv() = process.argv();
  const std::string& path = process.executable_path();
  static std::string name = path.substr(path.find_last_of('/') + 1);
  setprogname(name.c_str());
}

}  // namespace juice::mac
