#include "windows/guest_process.hpp"

#include <windows.h>

#include <algorithm>
#include <cstring>
#include <cwctype>
#include <format>
#include <optional>

#include "core/arm64/decode/instruction.hpp"
#include "windows/dlls/builtins.hpp"
#include "windows/exceptions/fault_handler.hpp"
#include "windows/imports/import_resolver.hpp"

namespace juice::win {
namespace {

constexpr uint32_t kStatusIllegalInstruction = 0xC000001D;
constexpr uint32_t kStatusAccessViolation = 0xC0000005;
constexpr uint32_t kStatusBreakpoint = 0x80000003;
constexpr uint32_t kStatusStackBufferOverrun = 0xC0000409;
constexpr uint32_t kStatusEntryPointNotFound = 0xC0000139;
constexpr uint32_t kStatusNotSupported = 0xC00000BB;

constexpr uint32_t kStatusDllInitFailed = 0xC0000142;

constexpr size_t kTebPeb = 0x60;

// The guest context of the calling host thread.
thread_local GuestThread* t_thread = nullptr;

// The process whose threads release_thread() cleans up (one per juice process).
GuestProcess* g_process = nullptr;

struct ThreadStart {
  GuestProcess* process;
  uint64_t start;
  uint64_t parameter;
  uint64_t stack_size;
};

// Quote one argument so that CommandLineToArgvW reproduces it.
std::wstring quote_argument(const std::wstring& arg) {
  if (!arg.empty() && arg.find_first_of(L" \t\n\v\"") == std::wstring::npos) return arg;
  std::wstring out = L"\"";
  for (size_t i = 0;; ++i) {
    size_t backslashes = 0;
    while (i < arg.size() && arg[i] == L'\\') {
      ++i;
      ++backslashes;
    }
    if (i == arg.size()) {
      out.append(backslashes * 2, L'\\');
      break;
    }
    if (arg[i] == L'"') {
      out.append(backslashes * 2 + 1, L'\\');
      out.push_back(L'"');
    } else {
      out.append(backslashes, L'\\');
      out.push_back(arg[i]);
    }
  }
  out.push_back(L'"');
  return out;
}

std::wstring lower(std::wstring_view s) {
  std::wstring out(s);
  std::transform(out.begin(), out.end(), out.begin(), [](wchar_t c) { return static_cast<wchar_t>(std::towlower(c)); });
  return out;
}

std::string narrow(const std::wstring& s) {
  int n = WideCharToMultiByte(CP_UTF8, 0, s.c_str(), -1, nullptr, 0, nullptr, nullptr);
  std::string out(n > 0 ? n - 1 : 0, '\0');
  if (n > 1) WideCharToMultiByte(CP_UTF8, 0, s.c_str(), -1, out.data(), n, nullptr, nullptr);
  return out;
}

uint8_t* teb() { return reinterpret_cast<uint8_t*>(NtCurrentTeb()); }

}  // namespace

GuestThread* GuestProcess::t_current() { return t_thread; }

GuestProcess::GuestProcess(ProcessOptions options) : options_(std::move(options)) { g_process = this; }

GuestProcess::~GuestProcess() {
  engine_.reset();
  for (auto& m : module_storage_) pe::unmap_image(m->image);
  if (manifest_.context != INVALID_HANDLE_VALUE && !manifest_.process_default) {
    DeactivateActCtx(0, manifest_.cookie);
    ReleaseActCtx(manifest_.context);
  }
  if (g_process == this) g_process = nullptr;
}

std::expected<void, std::string> GuestProcess::load(const std::filesystem::path& exe,
                                                    const std::vector<std::wstring>& args) {
  std::error_code ec;
  std::filesystem::path full = std::filesystem::absolute(exe, ec);
  exe_path_ = (ec ? exe : full).wstring();

  auto file = pe::read_pe_file(exe);
  if (!file) return std::unexpected(file.error());
  if (file->machine != pe::kMachineArm64) {
    return std::unexpected(std::format("'{}' is a {} executable (machine 0x{:04x}); JUICE runs Windows ARM64 programs",
                                       exe.string(), pe::machine_name(file->machine), file->machine));
  }
  if (file->is_dll()) return std::unexpected(std::format("'{}' is a DLL, not an executable", exe.string()));

  auto image = pe::map_image(*file);
  if (!image) return std::unexpected(image.error());
  if (!image->entry) return std::unexpected("image has no entry point");
  auto program = std::make_unique<GuestModule>();
  program->image = std::move(*image);
  program->path = exe_path_;
  program->name = lower(std::filesystem::path(exe_path_).filename().wstring());
  program->is_exe = true;
  GuestModule& exe_module = *register_module(std::move(program));

  // Before binding imports: the manifest can redirect them (common controls v6).
  auto manifest = apply_manifest(exe_path_, exe_module.base(), options_.trace_imports ? stderr : nullptr);
  if (!manifest) return std::unexpected(manifest.error());
  manifest_ = *manifest;

  {
    std::lock_guard lock(loader_mutex_);
    bind_module_imports(exe_module);
    if (exe_module.image.tls) assign_tls_slot(exe_module);
  }

  // argv[0] is the program as the user named it (like a native launch), which
  // also keeps the guest command line no longer than juice's own.
  command_line_w_ = quote_argument(options_.argv0.empty() ? exe.wstring() : options_.argv0);
  for (const std::wstring& a : args) command_line_w_ += L" " + quote_argument(a);
  int n = WideCharToMultiByte(CP_ACP, 0, command_line_w_.c_str(), -1, nullptr, 0, nullptr, nullptr);
  command_line_a_.assign(n > 0 ? n - 1 : 0, '\0');
  if (n > 1) WideCharToMultiByte(CP_ACP, 0, command_line_w_.c_str(), -1, command_line_a_.data(), n, nullptr, nullptr);
  publish_command_line();

  default_stack_size_ = std::clamp<uint64_t>(file->stack_reserve, 1 << 20, 256 << 20);
  thread_fls_slot_ = FlsAlloc(&GuestProcess::release_thread);

  options_.engine.tls_vector_offset = 0x58;  // TEB->ThreadLocalStoragePointer: guest TLS gets a vector of its own
  engine_ = std::make_unique<runtime::Engine>(*this, options_.engine);
  install_fault_handler({&engine_->arena(), thunks_.begin(), thunks_.end(), this});
  return {};
}

// Native code (e.g. the x64 UCRT parsing argv for a /MD program) reads the
// process command line straight from kernelbase/the PEB rather than through
// the guest's imports. Rewrite those buffers in place so that it sees the
// guest's command line instead of juice's.
void GuestProcess::publish_command_line() {
  wchar_t* native_w = GetCommandLineW();
  char* native_a = GetCommandLineA();
  const size_t len_w = std::wcslen(native_w);
  const size_t len_a = std::strlen(native_a);
  if (command_line_w_.size() > len_w || command_line_a_.size() > len_a) {
    std::fprintf(stderr, "[juice] warning: cannot publish the guest command line to native code\n");
    return;
  }
  std::memcpy(native_w, command_line_w_.c_str(), (command_line_w_.size() + 1) * sizeof(wchar_t));
  std::memcpy(native_a, command_line_a_.c_str(), command_line_a_.size() + 1);

  // PEB->ProcessParameters->CommandLine (a UNICODE_STRING sharing the buffer above).
  constexpr size_t kPebProcessParameters = 0x20;
  constexpr size_t kParamsCommandLine = 0x70;
  auto* peb = *reinterpret_cast<uint8_t**>(teb() + kTebPeb);
  auto* params = *reinterpret_cast<uint8_t**>(peb + kPebProcessParameters);
  auto* length = reinterpret_cast<USHORT*>(params + kParamsCommandLine);
  auto* buffer = *reinterpret_cast<wchar_t**>(params + kParamsCommandLine + 8);
  if (buffer == native_w) *length = static_cast<USHORT>(command_line_w_.size() * sizeof(wchar_t));
}

// --- threads ---------------------------------------------------------------------

GuestThread* GuestProcess::allocate_thread(uint64_t stack_size) {
  auto* t = new GuestThread;
  t->stack_size = std::clamp<uint64_t>(stack_size ? stack_size : default_stack_size_, 64 << 10, 256 << 20);
  t->stack_size = (t->stack_size + 0xFFFF) & ~size_t{0xFFFF};
  t->stack_base = static_cast<uint8_t*>(VirtualAlloc(nullptr, t->stack_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
  if (!t->stack_base) throw std::bad_alloc();
  DWORD old = 0;
  VirtualProtect(t->stack_base, 0x1000, PAGE_NOACCESS, &old);  // overflow guard
  // Leave room above the initial SP: host calls read up to 8 stack arguments.
  t->state.sp = (reinterpret_cast<uint64_t>(t->stack_base) + t->stack_size - 0x100) & ~uint64_t{15};
  t->teb = teb();
  t->state.x[18] = reinterpret_cast<uint64_t>(teb());  // Windows ARM64: X18 always points to the TEB
  return t;
}

GuestThread& GuestProcess::attach_thread(uint64_t stack_size) {
  if (t_thread) return *t_thread;
  reclaim_threads();
  GuestThread* t = allocate_thread(stack_size);
  DuplicateHandle(GetCurrentProcess(), GetCurrentThread(), GetCurrentProcess(), &t->host_thread, SYNCHRONIZE, FALSE, 0);
  t_thread = t;
  {
    std::lock_guard lock(threads_mutex_);
    live_threads_.push_back(t);
  }
  activate_manifest_on_thread(manifest_);
  setup_tls_for_thread();
  if (thread_fls_slot_ != FLS_OUT_OF_INDEXES) FlsSetValue(thread_fls_slot_, t);
  threads_started_.fetch_add(1, std::memory_order_relaxed);
  notify_thread(DLL_THREAD_ATTACH);
  return *t;
}

// FLS destructor: runs on a guest thread's host thread as it exits. Other
// thread-exit notifications (such as the guest C runtime's own FLS
// destructors, which are guest code) may still run on this thread afterwards,
// so the context stays attached and is only freed once the host thread has
// terminated.
void WINAPI GuestProcess::release_thread(void* p) {
  if (!g_process || g_process->exiting_.load()) return;
  auto* t = static_cast<GuestThread*>(p);
  // Threads created natively (thread pool, the native UCRT's _beginthreadex)
  // get their guest thread-detach notifications here.
  if (t == t_thread && !t->main && !t->detached) g_process->notify_thread(DLL_THREAD_DETACH);
  {
    std::lock_guard lock(g_process->threads_mutex_);
    std::erase(g_process->live_threads_, t);
  }
  std::lock_guard lock(g_process->exited_mutex_);
  g_process->exited_threads_.push_back(t);
}

void GuestProcess::reclaim_threads() {
  std::lock_guard lock(exited_mutex_);
  std::erase_if(exited_threads_, [](GuestThread* t) {
    if (t->host_thread && WaitForSingleObject(t->host_thread, 0) != WAIT_OBJECT_0) return false;
    if (t->host_thread) CloseHandle(t->host_thread);
    VirtualFree(t->stack_base, 0, MEM_RELEASE);
    for (const auto& [slot, block] : t->tls_blocks) HeapFree(GetProcessHeap(), 0, block);
    delete[] t->tls_vector;
    delete t;
    return true;
  });
}

HANDLE GuestProcess::create_thread(SECURITY_ATTRIBUTES* attributes, uint64_t stack_size, uint64_t start,
                                   uint64_t parameter, uint32_t flags, DWORD* thread_id) {
  reclaim_threads();
  auto* ts = new ThreadStart{this, start, parameter, stack_size};
  // The host thread only runs the translator; the guest gets a stack of its own.
  HANDLE h = CreateThread(attributes, 0, &GuestProcess::thread_main, ts, flags & ~STACK_SIZE_PARAM_IS_A_RESERVATION,
                          thread_id);
  if (!h) delete ts;
  return h;
}

DWORD WINAPI GuestProcess::thread_main(void* p) {
  const ThreadStart ts = *static_cast<ThreadStart*>(p);
  delete static_cast<ThreadStart*>(p);
  GuestProcess& process = *ts.process;
  process.attach_thread(ts.stack_size);
  if (process.options_.trace_calls)
    std::fprintf(stderr, "[juice] thread %lu starts at 0x%llx\n", GetCurrentThreadId(),
                 static_cast<unsigned long long>(ts.start));
  const auto code = static_cast<DWORD>(process.call_guest(ts.start, {ts.parameter}));
  process.notify_thread(DLL_THREAD_DETACH);
  return code;  // the FLS destructor releases the guest context
}

void GuestProcess::exit_thread(uint32_t code) {
  if (t_thread && !t_thread->main) notify_thread(DLL_THREAD_DETACH);
  std::fflush(stdout);
  ExitThread(code);
}

// --- running guest code ------------------------------------------------------------

int GuestProcess::run() {
  GuestThread* main = allocate_thread(0);
  main->main = true;
  t_thread = main;
  {
    std::lock_guard lock(threads_mutex_);
    live_threads_.push_back(main);
  }
  setup_tls_for_thread();
  // DLLs first (DllMain), then the program's own TLS callbacks.
  GuestModule& program = *modules_[0].load(std::memory_order_acquire);
  if (!initialize_module(program)) fatal("a DLL failed to initialize", kStatusDllInitFailed);
  run_started_ = true;
  uint64_t peb = *reinterpret_cast<uint64_t*>(teb() + kTebPeb);
  uint64_t result = call_guest(program.image.entry, {peb});
  exit(static_cast<uint32_t>(result));
}

uint64_t GuestProcess::call_guest(uint64_t fn, std::initializer_list<uint64_t> args) {
  Args full{};
  size_t i = 0;
  for (uint64_t a : args) {
    if (i < 8) full.gpr[i++] = a;
  }
  return call_guest(fn, full).x0;
}

NativeCallbackTarget::Result GuestProcess::call_guest(uint64_t fn, const Args& args, const GuestCall& how) {
  GuestThread& t = attach_thread();
  arm64::CpuState& state = t.state;
  // The callee runs on the guest stack below the caller's frame. Restoring the
  // whole state afterwards gives the caller exactly what the ABI promises.
  const arm64::CpuState saved = state;
  for (int i = 0; i < 8; ++i) state.x[i] = args.gpr[i];
  for (int i = 0; i < 4; ++i) state.v[i] = {args.fpr[i], 0};
  if (how.sp) state.sp = how.sp;
  if (how.nonvolatile) std::memcpy(&state.x[19], how.nonvolatile, 10 * sizeof(uint64_t));
  state.x[30] = thunks_.return_sentinel();
  state.pc = fn;

  t.levels.push_back({state.sp, how.native_frames, how.link});
  struct LevelScope {
    GuestThread& t;
    ~LevelScope() { t.levels.pop_back(); }
  } scope{t};
  // Exception handling continues guest execution in the call level that owns
  // the target frame (a Resume thrown by unwind/restore_context); outer
  // levels rethrow it on.
  std::optional<Resume> pending;
  for (;;) {
    try {
      if (pending) {
        Resume r = *pending;
        pending.reset();
        resume(r);
      }
      engine_->run(state, thunks_.return_sentinel());
      break;
    } catch (Resume& r) {
      if (!(r.context.sp < t.levels.back().entry_sp)) throw;
      pending.emplace(r);
    }
  }
  const Result result{state.x[0], state.v[0].lo};
  state = saved;
  return result;
}

bool GuestProcess::call_from_native(uint64_t target, const Args& args, Result& result) {
  if (target >= thunks_.begin() && target < thunks_.end()) {
    // A native function was handed the address of an API thunk.
    const Thunk* thunk = thunks_.find(target);
    if (!thunk || (thunk->kind != Thunk::Kind::Native && thunk->kind != Thunk::Kind::Builtin)) return false;
    static const uint64_t no_stack_args[8] = {};
    arm64::CpuState tmp = t_thread ? t_thread->state : arm64::CpuState{};
    for (int i = 0; i < 8; ++i) tmp.x[i] = args.gpr[i];
    tmp.sp = reinterpret_cast<uint64_t>(no_stack_args);
    for (int i = 0; i < 4; ++i) tmp.v[i] = {args.fpr[i], 0};
    if (thunk->kind == Thunk::Kind::Native) {
      const NativeResult r = call_native(thunk->native, tmp, thunk->signature);
      result = {r.rax, r.xmm0};
    } else {
      result = {thunk->builtin(*this, tmp), 0};
    }
    return true;
  }

  if (options_.trace_calls) {
    std::fprintf(stderr, "[juice] callback 0x%llx(0x%llx, 0x%llx, 0x%llx, 0x%llx) from native code on thread %lu\n",
                 static_cast<unsigned long long>(target), static_cast<unsigned long long>(args.gpr[0]),
                 static_cast<unsigned long long>(args.gpr[1]), static_cast<unsigned long long>(args.gpr[2]),
                 static_cast<unsigned long long>(args.gpr[3]), GetCurrentThreadId());
  }
  result = call_guest(target, args);
  return true;
}

bool GuestProcess::read_code(uint64_t addr, uint32_t& word) {
  if (const GuestModule* m = module_at(addr); m && m->image.contains(addr + 3)) {
    std::memcpy(&word, reinterpret_cast<const void*>(addr), 4);
    return true;
  }
  // Code outside the image (e.g. generated by the guest at run time).
  MEMORY_BASIC_INFORMATION mbi{};
  if (!VirtualQuery(reinterpret_cast<const void*>(addr), &mbi, sizeof(mbi))) return false;
  if (mbi.State != MEM_COMMIT || (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) || mbi.Protect == 0) return false;
  if (addr + 4 > reinterpret_cast<uint64_t>(mbi.BaseAddress) + mbi.RegionSize) return false;
  std::memcpy(&word, reinterpret_cast<const void*>(addr), 4);
  return true;
}

bool GuestProcess::is_host_code(uint64_t pc) {
  // Executable code of a loaded native module: the guest got a native function
  // pointer that never went through an import or GetProcAddress, typically a
  // method in the vtable of a COM object created by a system DLL.
  if (module_at(pc)) return false;
  MEMORY_BASIC_INFORMATION mbi{};
  if (!VirtualQuery(reinterpret_cast<const void*>(pc), &mbi, sizeof(mbi))) return false;
  constexpr DWORD kExecute = PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
  return mbi.State == MEM_COMMIT && mbi.Type == MEM_IMAGE && (mbi.Protect & kExecute);
}

Thunk* GuestProcess::native_code_thunk(uint64_t pc) {
  HMODULE module = nullptr;
  GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                     reinterpret_cast<LPCWSTR>(pc), &module);
  char path[MAX_PATH] = "native";
  if (module) GetModuleFileNameA(module, path, MAX_PATH);
  std::string dll = path;
  if (size_t slash = dll.find_last_of("\\/"); slash != std::string::npos) dll = dll.substr(slash + 1);
  const std::string name = std::format("0x{:x}", pc - reinterpret_cast<uint64_t>(module));
  return thunks_.find(thunks_.add_native(reinterpret_cast<void*>(pc), std::move(dll), name));
}

runtime::Action GuestProcess::on_host_address(arm64::CpuState& s) {
  const uint64_t pc = s.pc;
  const bool in_thunks = pc >= thunks_.begin() && pc < thunks_.end();
  Thunk* thunk = in_thunks ? thunks_.find(pc) : native_code_thunk(pc);
  if (!thunk) fatal(std::format("guest jumped into the API thunk region at 0x{:x}", pc), kStatusAccessViolation);
  std::atomic_ref<uint64_t>(thunk->calls).fetch_add(1, std::memory_order_relaxed);
  const uint64_t lr = s.x[30];
  auto describe = [&] { return std::format("{}!{}", thunk->dll, thunk->name); };

  if (thunk->kind == Thunk::Kind::ReturnSentinel) fatal("guest returned to the host unexpectedly", kStatusAccessViolation);
  if (thunk->kind == Thunk::Kind::Missing) {
    fatal(std::format("unimplemented API {} called from 0x{:x}", describe(), lr), kStatusEntryPointNotFound);
  }

  if (options_.trace_calls) {
    std::fprintf(stderr, "[juice] call %s(0x%llx, 0x%llx, 0x%llx, 0x%llx) from 0x%llx\n", describe().c_str(),
                 static_cast<unsigned long long>(s.x[0]), static_cast<unsigned long long>(s.x[1]),
                 static_cast<unsigned long long>(s.x[2]), static_cast<unsigned long long>(s.x[3]),
                 static_cast<unsigned long long>(lr));
  }

  uint64_t result;
  if (thunk->kind == Thunk::Kind::Native) {
    const NativeResult r = call_native(thunk->native, s, thunk->signature);
    result = r.rax;
    s.v[0] = {r.xmm0, 0};  // the return type is unknown: provide both X0 and D0
    if (r.has_x1) s.x[1] = r.x1;
  } else {
    result = thunk->builtin(*this, s);
    if (t_thread && t_thread->state_replaced) {
      // The builtin continues somewhere else (exception handling), not at the caller.
      t_thread->state_replaced = false;
      return runtime::Action::Continue;
    }
  }
  s.x[0] = result;
  s.pc = lr;

  if (options_.trace_calls) {
    std::fprintf(stderr, "[juice]   %s -> 0x%llx\n", describe().c_str(), static_cast<unsigned long long>(result));
  }
  return runtime::Action::Continue;
}

runtime::Action GuestProcess::on_exit(arm64::CpuState& s) {
  const auto reason = static_cast<arm64::ExitReason>(s.exit_reason);
  const uint32_t info = s.exit_info;
  switch (reason) {
    case arm64::ExitReason::Brk:
      if (info == 0xF003) fatal(std::format("guest called __fastfail({})", s.x[0]), kStatusStackBufferOverrun);
      if (info == 0xF000) fatal("guest hit a breakpoint (__debugbreak)", kStatusBreakpoint);
      fatal(std::format("guest executed BRK #0x{:x} at 0x{:x}", info, s.pc), kStatusBreakpoint);
    case arm64::ExitReason::Hlt:
      fatal(std::format("guest executed HLT #0x{:x} at 0x{:x}", info, s.pc), kStatusBreakpoint);
    case arm64::ExitReason::Svc:
      fatal(std::format("guest executed SVC #0x{:x} at 0x{:x}; direct system calls are not supported", info,
                        s.pc - 4),
            kStatusNotSupported);
    case arm64::ExitReason::Undefined:
    case arm64::ExitReason::Unsupported: {
      uint32_t word = 0;
      read_code(s.pc, word);
      fatal(std::format("{} at 0x{:x}: {:08x}  {}", arm64::to_string(reason), s.pc, word,
                        arm64::disassemble(arm64::decode(word, s.pc))),
            kStatusIllegalInstruction);
    }
    case arm64::ExitReason::FetchFault:
      fatal(std::format("guest jumped to non-executable address 0x{:x}", s.pc), kStatusAccessViolation);
    case arm64::ExitReason::None:
    case arm64::ExitReason::CodeModified:  // handled by the Engine
      break;
  }
  return runtime::Action::Continue;
}

uint64_t GuestProcess::get_proc_address(uint64_t module, const char* name) {
  const bool by_ordinal = (reinterpret_cast<uint64_t>(name) >> 16) == 0;
  const uint16_t ordinal = static_cast<uint16_t>(reinterpret_cast<uint64_t>(name));

  if (GuestModule* m = module_by_handle(module)) {
    if (uint64_t addr = guest_export(*m, name)) return addr;
    SetLastError(ERROR_PROC_NOT_FOUND);
    return 0;
  }

  HMODULE mod = reinterpret_cast<HMODULE>(module);
  char path[MAX_PATH] = {};
  GetModuleFileNameA(mod, path, MAX_PATH);
  std::string dll = path;
  if (size_t slash = dll.find_last_of("\\/"); slash != std::string::npos) dll = dll.substr(slash + 1);

  if (!by_ordinal) {
    if (BuiltinFn fn = find_builtin(dll, name)) {
      Thunk t;
      t.kind = Thunk::Kind::Builtin;
      t.dll = dll;
      t.name = name;
      t.builtin = fn;
      return thunks_.add(std::move(t));
    }
  }
  FARPROC f = GetProcAddress(mod, name);
  if (!f) return 0;
  return guest_value_for_native_export(reinterpret_cast<void*>(f), thunks_, dll,
                                       by_ordinal ? std::format("#{}", ordinal) : std::string(name));
}

// --- exit and diagnostics -------------------------------------------------------------

void GuestProcess::exit(uint32_t code) {
  if (!exiting_.load()) detach_modules();  // DLL_PROCESS_DETACH, as ExitProcess does natively
  before_exit(code);
  ExitProcess(code);
}

void notify_native_process_exit() {
  if (g_process && !g_process->exiting_.load()) {
    g_process->detach_modules();
    g_process->before_exit(GuestProcess::kExitCodeUnknown);
  }
}

void GuestProcess::before_exit(uint32_t code) {
  if (exiting_.exchange(true)) return;
  std::fflush(stdout);
  if (options_.stats && engine_) {
    engine_->print_stats(stderr);
    std::vector<std::pair<uint64_t, const Thunk*>> called;
    for (const Thunk& t : thunks_.thunks()) {
      const uint64_t calls = std::atomic_ref<uint64_t>(const_cast<uint64_t&>(t.calls)).load();
      if (calls) called.emplace_back(calls, &t);
    }
    std::sort(called.begin(), called.end(), [](const auto& a, const auto& b) { return a.first > b.first; });
    for (const auto& [calls, t] : called)
      std::fprintf(stderr, "[juice]   api %s!%s: %llu calls\n", t->dll.c_str(), t->name.c_str(),
                   static_cast<unsigned long long>(calls));
    std::fprintf(stderr, "[juice] guest threads started: %u\n", threads_started_.load());
    if (code != kExitCodeUnknown) std::fprintf(stderr, "[juice] exit code %u (0x%x)\n", code, code);
  }
  std::fflush(stderr);
}

void GuestProcess::dump_state(std::FILE* out) const {
  if (!t_thread) return;
  const arm64::CpuState& s = t_thread->state;
  std::fprintf(out, "[juice]   thread %lu  pc 0x%016llx  sp 0x%016llx  nzcv %c%c%c%c\n", GetCurrentThreadId(),
               static_cast<unsigned long long>(s.pc), static_cast<unsigned long long>(s.sp),
               (s.nzcv >> 31) & 1 ? 'N' : '-', (s.nzcv >> 30) & 1 ? 'Z' : '-', (s.nzcv >> 29) & 1 ? 'C' : '-',
               (s.nzcv >> 28) & 1 ? 'V' : '-');
  for (int i = 0; i < 31; i += 3) {
    std::string line = "[juice]  ";
    for (int k = i; k < std::min(i + 3, 31); ++k) line += std::format(" x{:<2} 0x{:016x}", k, s.x[k]);
    std::fprintf(out, "%s\n", line.c_str());
  }
}

void GuestProcess::fatal(const std::string& message, uint32_t exit_code) {
  std::fflush(stdout);
  std::fprintf(stderr, "[juice] error: %s\n", message.c_str());
  std::fprintf(stderr, "[juice]   in %s\n", narrow(exe_path_).c_str());
  dump_state(stderr);
  std::fflush(stderr);
  TerminateProcess(GetCurrentProcess(), exit_code);
  ExitProcess(exit_code);
}

}  // namespace juice::win
