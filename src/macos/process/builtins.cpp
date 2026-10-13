// JUICE's own implementations of functions macOS programs import: those
// that need the guest's state or its images (dlopen and dlsym, the dyld image
// APIs, thread-local variables, setjmp/longjmp, the program's arguments),
// and variadic functions (called through their va_list forms).

#include <algorithm>
#include <cinttypes>
#include <cstdio>
#include <cstring>
#include <format>
#include <mutex>
#include <set>
#include <string>
#include <vector>

#include "macos/process/mac_process.hpp"

namespace juice::mac {

namespace {

template <typename T>
T* ptr(uint64_t v) {
  return reinterpret_cast<T*>(static_cast<uintptr_t>(v));
}

// --- Thread-local variables -----------------------------------------------------------------

// The thunk of every __thread_vars descriptor: X0 = descriptor, returns the
// variable's address in X0. Its callers expect all other registers preserved.
void tlv_bootstrap(MacProcess& p, arm64::CpuState& s) { s.x[0] = p.tlv_address(s.x[0]); }

// _tlv_atexit(destructor, object): thread-local C++ objects' destructors (not run yet).
void tlv_atexit(MacProcess&, arm64::CpuState&) {}

// --- dlopen and friends ------------------------------------------------------------------------

constexpr uint64_t kRtldNext = static_cast<uint64_t>(-1);
constexpr uint64_t kRtldDefault = static_cast<uint64_t>(-2);
constexpr uint64_t kRtldSelf = static_cast<uint64_t>(-3);
constexpr uint64_t kRtldMainOnly = static_cast<uint64_t>(-5);

thread_local std::string t_dlerror;
thread_local bool t_dlerror_set = false;

void set_dlerror(std::string message) {
  t_dlerror = std::move(message);
  t_dlerror_set = true;
}

// A guest library's handle is its header's address.
GuestImage* guest_handle(MacProcess& p, uint64_t handle) {
  GuestImage* i = p.image_at(handle);
  return i && i->header() == handle ? i : nullptr;
}

// Strings handed to the guest that must live as long as the process.
const char* intern(std::string s) {
  static std::mutex mutex;
  static std::set<std::string> strings;
  std::lock_guard lock(mutex);
  return strings.insert(std::move(s)).first->c_str();
}

// dlsym of a library handle searches the library, then what it links (breadth first).
uint64_t image_and_dependencies_symbol(MacProcess& p, GuestImage& image, const std::string& symbol) {
  std::vector<const GuestImage*> queue{&image};
  for (size_t k = 0; k < queue.size(); ++k) {
    const GuestImage& i = *queue[k];
    if (const uint64_t v = p.export_address(i, symbol)) return v;
    for (const Dependency& d : i.dependencies) {
      if (d.kind == Dependency::Kind::Guest) {
        if (std::find(queue.begin(), queue.end(), d.image) == queue.end()) queue.push_back(d.image);
      } else if (d.kind == Dependency::Kind::Native) {
        if (void* f = p.native().find_symbol(d.native, symbol.substr(1))) return reinterpret_cast<uint64_t>(f);
      }
    }
  }
  return 0;
}

// dlopen(path, mode)
void dlopen_(MacProcess& p, arm64::CpuState& s) {
  const char* path = ptr<const char>(s.x[0]);
  if (!path) {
    s.x[0] = p.main_image().header();
    return;
  }
  std::string error;
  if (GuestImage* i = p.open_guest_library(path, p.image_at(s.x[30]), error)) {
    s.x[0] = i->header();
    return;
  }
  if (!error.empty()) {
    set_dlerror(error);
    s.x[0] = 0;
    return;
  }
  void* native = p.native().open_library(path);
  if (!native) set_dlerror(std::format("dlopen({}): image not found", path));
  s.x[0] = reinterpret_cast<uint64_t>(native);
}

// dlsym(handle, name)
void dlsym_(MacProcess& p, arm64::CpuState& s) {
  const uint64_t handle = s.x[0];
  const char* name = ptr<const char>(s.x[1]);
  if (!name) {
    s.x[0] = 0;
    return;
  }
  const std::string symbol = std::string("_") + name;
  uint64_t v = 0;
  if (handle == kRtldDefault || handle == kRtldNext) {
    v = p.global_symbol(symbol);
  } else if (handle == kRtldSelf) {
    GuestImage* caller = p.image_at(s.x[30]);
    v = caller ? p.export_address(*caller, symbol) : 0;
    if (!v) v = p.global_symbol(symbol);
  } else if (handle == kRtldMainOnly) {
    v = p.export_address(p.main_image(), symbol);
  } else if (GuestImage* i = guest_handle(p, handle)) {
    v = image_and_dependencies_symbol(p, *i, symbol);
  } else {
    v = reinterpret_cast<uint64_t>(p.native().find_symbol(ptr<void>(handle), name));
  }
  if (!v) set_dlerror(std::format("dlsym({}): symbol not found", name));
  s.x[0] = v;
}

// dlclose(handle): guest libraries stay loaded.
void dlclose_(MacProcess& p, arm64::CpuState& s) {
  if (guest_handle(p, s.x[0])) {
    s.x[0] = 0;
    return;
  }
  static const uint64_t native = reinterpret_cast<uint64_t>(p.native().find_symbol(nullptr, "dlclose"));
  if (native) p.call_native_function(native, s);
  else s.x[0] = 0;
}

// dlerror()
void dlerror_(MacProcess&, arm64::CpuState& s) {
  if (!t_dlerror_set) {
    s.x[0] = 0;
    return;
  }
  t_dlerror_set = false;
  s.x[0] = reinterpret_cast<uint64_t>(intern(t_dlerror));
}

// dladdr(addr, Dl_info*): for guest addresses, the image and nearest exported symbol.
void dladdr_(MacProcess& p, arm64::CpuState& s) {
  const uint64_t addr = s.x[0];
  auto* info = ptr<uint64_t>(s.x[1]);  // dli_fname, dli_fbase, dli_sname, dli_saddr
  GuestImage* i = p.image_at(addr);
  if (!i) {
    // (the native dladdr, found once)
    static const uint64_t native = reinterpret_cast<uint64_t>(p.native().find_symbol(nullptr, "dladdr"));
    if (native) p.call_native_function(native, s);
    else s.x[0] = 0;
    return;
  }
  info[0] = reinterpret_cast<uint64_t>(i->path.c_str());
  info[1] = i->header();
  info[2] = info[3] = 0;
  uint64_t best = 0;
  for (const Export& e : all_exports(i->exports)) {
    if (e.reexport() || (e.flags & kExportKindMask) != kExportKindRegular) continue;
    const uint64_t a = i->header() + e.address;
    if (a <= addr && a >= best) {
      best = a;
      info[2] = reinterpret_cast<uint64_t>(intern(e.name.substr(e.name.starts_with('_') ? 1 : 0)));
      info[3] = a;
    }
  }
  s.x[0] = 1;
}

// --- dyld's image list (the guest's images) -----------------------------------------------------

std::mutex g_add_image_mutex;
std::vector<uint64_t> g_add_image_callbacks;

void dyld_image_count(MacProcess& p, arm64::CpuState& s) { s.x[0] = p.images().size(); }

void dyld_get_image_header(MacProcess& p, arm64::CpuState& s) {
  const auto images = p.images();
  s.x[0] = s.x[0] < images.size() ? images[s.x[0]]->header() : 0;
}

void dyld_get_image_vmaddr_slide(MacProcess& p, arm64::CpuState& s) {
  const auto images = p.images();
  s.x[0] = s.x[0] < images.size() ? images[s.x[0]]->slide : 0;
}

void dyld_get_image_name(MacProcess& p, arm64::CpuState& s) {
  const auto images = p.images();
  s.x[0] = s.x[0] < images.size() ? reinterpret_cast<uint64_t>(images[s.x[0]]->path.c_str()) : 0;
}

void dyld_get_prog_image_header(MacProcess& p, arm64::CpuState& s) { s.x[0] = p.main_image().header(); }

// _dyld_register_func_for_add_image(void (*)(const mach_header*, intptr_t slide)):
// called for every image now (and, as dyld does, for those loaded later).
void dyld_register_func_for_add_image(MacProcess& p, arm64::CpuState& s) {
  const uint64_t fn = s.x[0];
  {
    std::lock_guard lock(g_add_image_mutex);
    g_add_image_callbacks.push_back(fn);
  }
  for (GuestImage* i : p.images()) p.call_guest(fn, {i->header(), i->slide});
}

void dyld_register_func_for_remove_image(MacProcess&, arm64::CpuState&) {}

// _NSGetExecutablePath(buf, uint32_t* size)
void ns_get_executable_path(MacProcess& p, arm64::CpuState& s) {
  const std::string& path = p.executable_path();
  auto* size = ptr<uint32_t>(s.x[1]);
  if (*size < path.size() + 1) {
    *size = static_cast<uint32_t>(path.size() + 1);
    s.x[0] = static_cast<uint64_t>(-1);
    return;
  }
  std::memcpy(ptr<char>(s.x[0]), path.c_str(), path.size() + 1);
  s.x[0] = 0;
}

// The program's own argc, argv and name (not JUICE's).
int g_argc;
char** g_argv;
const char* g_progname;

void ns_get_argc(MacProcess& p, arm64::CpuState& s) {
  g_argc = p.argc();
  s.x[0] = reinterpret_cast<uint64_t>(&g_argc);
}
void ns_get_argv(MacProcess& p, arm64::CpuState& s) {
  g_argv = p.argv();
  s.x[0] = reinterpret_cast<uint64_t>(&g_argv);
}
void ns_get_progname(MacProcess& p, arm64::CpuState& s) {
  if (!g_progname) {
    const std::string& path = p.executable_path();
    g_progname = intern(path.substr(path.find_last_of('/') + 1));
  }
  s.x[0] = reinterpret_cast<uint64_t>(&g_progname);
}
void ns_get_mach_execute_header(MacProcess& p, arm64::CpuState& s) { s.x[0] = p.main_image().header(); }

// --- setjmp / longjmp ------------------------------------------------------------------------------
//
// The guest's jmp_buf (int[48], 192 bytes on ARM64) holds X19-X30, SP and D8-D15.

void save_context(arm64::CpuState& s) {
  auto* buf = ptr<uint64_t>(s.x[0]);
  for (int k = 0; k < 12; ++k) buf[k] = s.x[19 + k];  // X19..X30 (X30: where setjmp returns)
  buf[12] = s.sp;
  for (int k = 0; k < 8; ++k) buf[13 + k] = s.v[8 + k].lo;
  s.x[0] = 0;
}

void restore_context(arm64::CpuState& s) {
  const auto* buf = ptr<const uint64_t>(s.x[0]);
  const uint64_t value = static_cast<uint32_t>(s.x[1]);
  for (int k = 0; k < 12; ++k) s.x[19 + k] = buf[k];
  s.sp = buf[12];
  for (int k = 0; k < 8; ++k) s.v[8 + k] = {buf[13 + k], 0};
  s.x[0] = value ? value : 1;
  s.pc = s.x[30];
}

void setjmp_(MacProcess&, arm64::CpuState& s) { save_context(s); }
void longjmp_(MacProcess&, arm64::CpuState& s) { restore_context(s); }

// --- Errors --------------------------------------------------------------------------------------

void stub_binder(MacProcess& p, arm64::CpuState& s) { p.fatal("dyld_stub_binder called (lazy binding)", &s); }

}  // namespace

void MacProcess::add_va_builtin(std::string name, const char* va_name, unsigned fixed, bool from_va_list) {
  void* native = native_.find_symbol(nullptr, va_name);
  if (!native) return;  // (not on this system: bound normally)
  Builtin b;
  b.name = name;
  b.native = reinterpret_cast<uint64_t>(native);
  b.fixed = fixed;
  b.from_va_list = from_va_list;
  const uint64_t a = add_builtin_slot(std::move(b));
  std::lock_guard lock(builtins_mutex_);
  builtin_by_name_[std::move(name)] = a;
}

// The x86-64 va_list: a structure whose register parts are used up, so that
// every argument comes from `overflow_arg_area`, 8 bytes each - exactly how
// Apple's ARM64 convention lays out variadic arguments.
struct HostVaList {
  uint32_t gp_offset = 48;   // all six general registers consumed
  uint32_t fp_offset = 176;  // all eight vector registers consumed
  uint64_t overflow_arg_area = 0;
  uint64_t reg_save_area = 0;
};

void MacProcess::call_va_builtin(const Builtin& b, arm64::CpuState& s) {
  HostVaList va;
  // The variadic arguments follow the fixed ones: in registers (fixed < 8), so at SP.
  va.overflow_arg_area = b.from_va_list ? s.x[b.fixed] : s.sp;
  arm64::CpuState call = s;
  call.x[b.fixed] = reinterpret_cast<uint64_t>(&va);
  call_native_function(b.native, call);
  s.x[0] = call.x[0];
  s.x[1] = call.x[1];
  s.v[0] = call.v[0];
}

void MacProcess::register_builtins() {
  add_builtin("__tlv_bootstrap", tlv_bootstrap);
  add_builtin("__tlv_atexit", tlv_atexit);
  add_builtin("_dlopen", dlopen_);
  add_builtin("_dlsym", dlsym_);
  add_builtin("_dlclose", dlclose_);
  add_builtin("_dlerror", dlerror_);
  add_builtin("_dladdr", dladdr_);
  add_builtin("__dyld_image_count", dyld_image_count);
  add_builtin("__dyld_get_image_header", dyld_get_image_header);
  add_builtin("__dyld_get_image_vmaddr_slide", dyld_get_image_vmaddr_slide);
  add_builtin("__dyld_get_image_name", dyld_get_image_name);
  add_builtin("__dyld_get_prog_image_header", dyld_get_prog_image_header);
  add_builtin("__dyld_register_func_for_add_image", dyld_register_func_for_add_image);
  add_builtin("__dyld_register_func_for_remove_image", dyld_register_func_for_remove_image);
  add_builtin("__NSGetExecutablePath", ns_get_executable_path);
  add_builtin("__NSGetArgc", ns_get_argc);
  add_builtin("__NSGetArgv", ns_get_argv);
  add_builtin("__NSGetProgname", ns_get_progname);
  add_builtin("__NSGetMachExecuteHeader", ns_get_mach_execute_header);
  for (const char* name : {"_setjmp", "__setjmp", "_sigsetjmp"}) add_builtin(name, setjmp_);
  for (const char* name : {"_longjmp", "__longjmp", "_siglongjmp"}) add_builtin(name, longjmp_);
  add_builtin("dyld_stub_binder", stub_binder);

  // Variadic functions: name, va_list form, fixed arguments.
  struct Va {
    const char* name;
    const char* va_name;
    unsigned fixed;
  };
  static constexpr Va kVariadic[] = {
      {"_printf", "vprintf", 1},        {"_fprintf", "vfprintf", 2},     {"_sprintf", "vsprintf", 2},
      {"_snprintf", "vsnprintf", 3},    {"_asprintf", "vasprintf", 2},   {"_dprintf", "vdprintf", 2},
      {"_scanf", "vscanf", 1},          {"_fscanf", "vfscanf", 2},       {"_sscanf", "vsscanf", 2},
      {"_syslog", "vsyslog", 2},        {"_err", "verr", 2},             {"_errx", "verrx", 2},
      {"_warn", "vwarn", 1},            {"_warnx", "vwarnx", 1},         {"_wprintf", "vwprintf", 1},
      {"_fwprintf", "vfwprintf", 2},    {"_swprintf", "vswprintf", 3},   {"_NSLog", "NSLogv", 1},
      {"___sprintf_chk", "__vsprintf_chk", 4},
      {"___snprintf_chk", "__vsnprintf_chk", 5},
      {"_CFStringCreateWithFormat", "CFStringCreateWithFormatAndArguments", 3},
      {"_CFStringAppendFormat", "CFStringAppendFormatAndArguments", 3},
  };
  for (const Va& v : kVariadic) {
    add_va_builtin(v.name, v.va_name, v.fixed, false);
    // The va_list forms themselves: the guest's va_list (a pointer to its
    // 8-byte argument slots) becomes a host va_list.
    add_va_builtin(std::string("_") + v.va_name, v.va_name, v.fixed, true);
  }
}

}  // namespace juice::mac
