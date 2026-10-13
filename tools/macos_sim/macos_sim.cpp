// juice-macos-sim: runs macOS ARM64 command-line programs on Windows, with a
// small fake libSystem made of x86-64 System V functions - to test the macOS
// frontend's core (loading, binding, calls both ways, thread-local variables,
// initializers) without a Mac.
//
//   juice-macos-sim [--trace-binds] [--trace-calls] program [arguments...]
//
// Native code calling guest code works as on macOS: guest pages aren't
// executable, so the call faults (here an execute access violation), and the
// fault handler continues the call at MacProcess::entry().

#if defined(_WIN32) && defined(__clang__)

#include <windows.h>

#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <string>
#include <vector>

#include "fake_objc.hpp"
#include "macos/objc/objc_bridge.hpp"
#include "macos/process/mac_process.hpp"

#define SYSV __attribute__((sysv_abi))

namespace {

using juice::mac::MacProcess;

// The x86-64 va_list JUICE passes to va_list functions: everything in the
// overflow area, 8 bytes per argument - the layout of a Windows va_list.
struct SysvVaList {
  uint32_t gp_offset, fp_offset;
  char* overflow_arg_area;
  void* reg_save_area;
};

std::vector<SYSV void (*)()> g_atexit;

SYSV int f_vprintf(const char* format, SysvVaList* va) { return std::vprintf(format, va->overflow_arg_area); }
SYSV int f_vsnprintf(char* out, size_t size, const char* format, SysvVaList* va) {
  return std::vsnprintf(out, size, format, va->overflow_arg_area);
}
SYSV int f_puts(const char* s) { return std::puts(s); }
SYSV int f_putchar(int c) { return std::putchar(c); }
SYSV void* f_malloc(size_t n) { return std::malloc(n); }
SYSV void* f_calloc(size_t n, size_t m) { return std::calloc(n, m); }
SYSV void* f_realloc(void* p, size_t n) { return std::realloc(p, n); }
SYSV void f_free(void* p) { std::free(p); }
SYSV size_t f_strlen(const char* s) { return std::strlen(s); }
SYSV int f_strcmp(const char* a, const char* b) { return std::strcmp(a, b); }
SYSV void* f_memcpy(void* d, const void* s, size_t n) { return std::memcpy(d, s, n); }
SYSV void* f_memset(void* d, int c, size_t n) { return std::memset(d, c, n); }
SYSV double f_sqrt(double v) { return __builtin_sqrt(v); }
SYSV int f_atexit(SYSV void (*fn)()) {
  g_atexit.push_back(fn);
  return 0;
}
SYSV void f_exit(int code) {
  while (!g_atexit.empty()) {
    auto fn = g_atexit.back();
    g_atexit.pop_back();
    fn();  // (guest functions: faults into the guest)
  }
  std::fflush(stdout);
  std::exit(code);
}
SYSV void f_abort() { std::abort(); }
SYSV void f_stack_chk_fail() {
  std::fputs("stack smashing detected\n", stderr);
  std::abort();
}
// qsort with the comparator called the System V way (a guest function: faults into the guest).
SYSV void f_qsort(void* base, size_t count, size_t size, SYSV int (*compare)(const void*, const void*)) {
  auto* b = static_cast<char*>(base);
  std::vector<char> tmp(size);
  for (size_t i = 1; i < count; ++i) {
    for (size_t j = i; j > 0 && compare(b + (j - 1) * size, b + j * size) > 0; --j) {
      std::memcpy(tmp.data(), b + j * size, size);
      std::memcpy(b + j * size, b + (j - 1) * size, size);
      std::memcpy(b + (j - 1) * size, tmp.data(), size);
    }
  }
}

uint64_t g_stack_chk_guard = 0x5A17C0FFEE5EEDull;
char** g_environ;

struct Symbol {
  void* address;
  bool code;
};

std::map<std::string, Symbol> make_symbols() {
  std::map<std::string, Symbol> table = {
      {"vprintf", {reinterpret_cast<void*>(&f_vprintf), true}},
      {"vsnprintf", {reinterpret_cast<void*>(&f_vsnprintf), true}},
      {"puts", {reinterpret_cast<void*>(&f_puts), true}},
      {"putchar", {reinterpret_cast<void*>(&f_putchar), true}},
      {"malloc", {reinterpret_cast<void*>(&f_malloc), true}},
      {"calloc", {reinterpret_cast<void*>(&f_calloc), true}},
      {"realloc", {reinterpret_cast<void*>(&f_realloc), true}},
      {"free", {reinterpret_cast<void*>(&f_free), true}},
      {"strlen", {reinterpret_cast<void*>(&f_strlen), true}},
      {"strcmp", {reinterpret_cast<void*>(&f_strcmp), true}},
      {"memcpy", {reinterpret_cast<void*>(&f_memcpy), true}},
      {"memset", {reinterpret_cast<void*>(&f_memset), true}},
      {"sqrt", {reinterpret_cast<void*>(&f_sqrt), true}},
      {"atexit", {reinterpret_cast<void*>(&f_atexit), true}},
      {"exit", {reinterpret_cast<void*>(&f_exit), true}},
      {"abort", {reinterpret_cast<void*>(&f_abort), true}},
      {"qsort", {reinterpret_cast<void*>(&f_qsort), true}},
      {"__stack_chk_fail", {reinterpret_cast<void*>(&f_stack_chk_fail), true}},
      {"__stack_chk_guard", {&g_stack_chk_guard, false}},
      {"environ", {&g_environ, false}},
  };
  for (const juice::sim::FakeSymbol& s : juice::sim::fake_objc_symbols()) table[s.name] = {s.address, s.code};
  return table;
}

const std::map<std::string, Symbol>& symbols() {
  static const std::map<std::string, Symbol> table = make_symbols();
  return table;
}

class FakeSystem final : public juice::mac::NativeSystem {
 public:
  void* open_library(const std::string& name) override {
    if (name == "/usr/lib/libSystem.B.dylib" || name == "/usr/lib/libc++.1.dylib" ||
        name == "/usr/lib/libobjc.A.dylib")
      return &library_;
    return nullptr;
  }
  bool read_memory(uint64_t addr, void* out, size_t size) override {
    SIZE_T got = 0;
    return ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<const void*>(addr), out, size, &got) && got == size;
  }
  void* find_symbol(void*, const std::string& name) override {
    auto it = symbols().find(name);
    return it == symbols().end() ? nullptr : it->second.address;
  }
  bool is_native_code(uint64_t addr) override {
    for (const auto& [name, s] : symbols())
      if (s.code && reinterpret_cast<uint64_t>(s.address) == addr) return true;
    return false;
  }
  std::string describe(uint64_t addr) override {
    for (const auto& [name, s] : symbols())
      if (reinterpret_cast<uint64_t>(s.address) == addr) return name;
    return {};
  }

 private:
  int library_ = 0;
};

// Native code calling guest code: an execute fault at a guest address.
LONG CALLBACK redirect_calls_into_guest(EXCEPTION_POINTERS* info) {
  const EXCEPTION_RECORD* r = info->ExceptionRecord;
  if (r->ExceptionCode != EXCEPTION_ACCESS_VIOLATION || r->NumberParameters < 2 || r->ExceptionInformation[0] != 8)
    return EXCEPTION_CONTINUE_SEARCH;
  MacProcess* p = MacProcess::instance();
  CONTEXT* c = info->ContextRecord;
  if (!p || !p->is_guest_code(c->Rip)) return EXCEPTION_CONTINUE_SEARCH;
  c->R11 = c->Rip;
  c->Rip = reinterpret_cast<DWORD64>(p->entry());
  return EXCEPTION_CONTINUE_EXECUTION;
}

}  // namespace

int main(int argc, char** argv) {
  juice::mac::MacOptions options;
  int i = 1;
  for (; i < argc && argv[i][0] == '-'; ++i) {
    if (std::strcmp(argv[i], "--trace-binds") == 0) options.trace_binds = true;
    else if (std::strcmp(argv[i], "--trace-calls") == 0) options.trace_calls = true;
    else if (std::strcmp(argv[i], "--interp") == 0) options.engine.interpret = true;
    else break;
  }
  if (i >= argc) {
    std::fputs("usage: juice-macos-sim [--trace-binds] [--trace-calls] program [arguments...]\n", stderr);
    return 2;
  }
  std::vector<std::string> environment;
  for (char** e = _environ; e && *e; ++e) environment.push_back(*e);
  g_environ = _environ;
  AddVectoredExceptionHandler(1, redirect_calls_into_guest);

  FakeSystem system;
  MacProcess process(options, system);
  juice::mac::ObjcBridge objc(process, juice::sim::fake_objc_runtime());
  objc.install();
  if (auto r = process.load(argv[i], std::vector<std::string>(argv + i + 1, argv + argc), environment); !r) {
    std::fprintf(stderr, "juice-macos-sim: %s\n", r.error().c_str());
    return 1;
  }
  const int code = process.run();
  f_exit(code);
}

#else

#include <cstdio>

int main() {
  std::fputs("juice-macos-sim needs Windows and clang (System V functions on Windows)\n", stderr);
  return 2;
}

#endif
