#include "windows/guest_process.hpp"

#include <windows.h>

#include <algorithm>
#include <cstring>
#include <cwctype>
#include <format>

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

constexpr size_t kTebPeb = 0x60;
constexpr size_t kTebThreadLocalStoragePointer = 0x58;

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

GuestProcess::GuestProcess(ProcessOptions options) : options_(std::move(options)) {}

GuestProcess::~GuestProcess() {
  engine_.reset();
  pe::unmap_image(image_);
  if (stack_base_) VirtualFree(stack_base_, 0, MEM_RELEASE);
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
  image_ = std::move(*image);
  if (!image_.entry) return std::unexpected("image has no entry point");

  ImportStats imports = resolve_imports(image_, thunks_, options_.trace_imports ? stderr : nullptr);
  if (options_.trace_imports) {
    std::fprintf(stderr, "[juice] imports: %zu builtin, %zu native, %zu data, %zu missing\n", imports.builtin,
                 imports.native, imports.data, imports.missing);
  }

  // argv[0] is the program as the user named it (like a native launch), which
  // also keeps the guest command line no longer than juice's own.
  command_line_w_ = quote_argument(exe.wstring());
  for (const std::wstring& a : args) command_line_w_ += L" " + quote_argument(a);
  int n = WideCharToMultiByte(CP_ACP, 0, command_line_w_.c_str(), -1, nullptr, 0, nullptr, nullptr);
  command_line_a_.assign(n > 0 ? n - 1 : 0, '\0');
  if (n > 1) WideCharToMultiByte(CP_ACP, 0, command_line_w_.c_str(), -1, command_line_a_.data(), n, nullptr, nullptr);
  publish_command_line();

  setup_stack(file->stack_reserve);
  state_.x[18] = reinterpret_cast<uint64_t>(teb());  // Windows ARM64: X18 always points to the TEB

  main_thread_id_ = GetCurrentThreadId();
  engine_ = std::make_unique<runtime::Engine>(*this, options_.engine);
  install_fault_handler({&engine_->arena(), thunks_.begin(), thunks_.end(), image_.address(),
                         image_.address() + image_.size, this});
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

void GuestProcess::setup_stack(uint64_t reserve) {
  stack_size_ = std::clamp<uint64_t>(reserve, 1 << 20, 256 << 20);
  stack_size_ = (stack_size_ + 0xFFFF) & ~size_t{0xFFFF};
  stack_base_ = static_cast<uint8_t*>(VirtualAlloc(nullptr, stack_size_, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
  if (!stack_base_) throw std::bad_alloc();
  DWORD old = 0;
  VirtualProtect(stack_base_, 0x1000, PAGE_NOACCESS, &old);  // overflow guard
  // Leave room above the initial SP: host calls read up to 8 stack arguments.
  state_.sp = (reinterpret_cast<uint64_t>(stack_base_) + stack_size_ - 0x100) & ~uint64_t{15};
}

void GuestProcess::setup_tls() {
  if (!image_.tls) return;
  const pe::TlsInfo& tls = *image_.tls;
  const size_t template_size = tls.raw_end > tls.raw_start ? tls.raw_end - tls.raw_start : 0;
  const size_t total = template_size + tls.zero_fill;

  // Implicit TLS lives in TEB->ThreadLocalStoragePointer[_tls_index]. The
  // native loader does not know about the guest image, so give the guest a
  // slot of its own past any index the host modules can plausibly use, in a
  // copy of the current thread's array. (The array's length is private to
  // ntdll, so the copy is bounded by the readable memory behind it.)
  // Limitation: if a native DLL with implicit TLS is loaded later, ntdll
  // rebuilds the array and the guest slot is lost.
  constexpr size_t kGuestSlot = 64;
  HANDLE heap = GetProcessHeap();
  auto** teb_array = reinterpret_cast<void***>(teb() + kTebThreadLocalStoragePointer);
  auto* data = static_cast<uint8_t*>(HeapAlloc(heap, HEAP_ZERO_MEMORY, std::max<size_t>(total, 16)));
  auto** array = static_cast<void**>(HeapAlloc(heap, HEAP_ZERO_MEMORY, (kGuestSlot + 1) * sizeof(void*)));
  if (!data || !array) throw std::bad_alloc();
  if (template_size && image_.contains(tls.raw_start))
    std::memcpy(data, reinterpret_cast<const void*>(tls.raw_start), template_size);
  if (void** old = *teb_array) {
    MEMORY_BASIC_INFORMATION mbi{};
    if (VirtualQuery(old, &mbi, sizeof(mbi)) && mbi.State == MEM_COMMIT) {
      uint64_t readable = reinterpret_cast<uint64_t>(mbi.BaseAddress) + mbi.RegionSize - reinterpret_cast<uint64_t>(old);
      std::memcpy(array, old, std::min<uint64_t>(readable, kGuestSlot * sizeof(void*)));
    }
  }
  array[kGuestSlot] = data;
  *teb_array = array;  // the old array stays allocated: ntdll still owns it
  if (image_.contains(tls.index_address)) *reinterpret_cast<uint32_t*>(tls.index_address) = kGuestSlot;
}

int GuestProcess::run() {
  setup_tls();
  if (image_.tls) {
    for (uint64_t cb : image_.tls->callbacks) call_guest(cb, {image_.address(), DLL_PROCESS_ATTACH, 0});
  }
  uint64_t peb = *reinterpret_cast<uint64_t*>(teb() + kTebPeb);
  uint64_t result = call_guest(image_.entry, {peb});
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

NativeCallbackTarget::Result GuestProcess::call_guest(uint64_t fn, const Args& args) {
  // The callee runs on the guest stack below the caller's frame. Restoring the
  // whole state afterwards gives the caller exactly what the ABI promises.
  const arm64::CpuState saved = state_;
  for (int i = 0; i < 8; ++i) state_.x[i] = args.gpr[i];
  for (int i = 0; i < 4; ++i) state_.v[i] = {args.fpr[i], 0};
  state_.x[30] = thunks_.return_sentinel();
  state_.pc = fn;
  engine_->run(state_, thunks_.return_sentinel());
  const Result result{state_.x[0], state_.v[0].lo};
  state_ = saved;
  return result;
}

bool GuestProcess::call_from_native(uint64_t target, const Args& args, Result& result) {
  if (GetCurrentThreadId() != main_thread_id_) {
    std::fprintf(stderr, "[juice] native code called guest function 0x%llx on another thread; "
                         "guest threads are not supported yet\n",
                 static_cast<unsigned long long>(target));
    return false;
  }

  if (target >= thunks_.begin() && target < thunks_.end()) {
    // A native function was handed the address of an API thunk.
    const Thunk* thunk = thunks_.find(target);
    if (!thunk || (thunk->kind != Thunk::Kind::Native && thunk->kind != Thunk::Kind::Builtin)) return false;
    static const uint64_t no_stack_args[8] = {};
    arm64::CpuState tmp = state_;
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
    std::fprintf(stderr, "[juice] callback 0x%llx(0x%llx, 0x%llx, 0x%llx, 0x%llx) from native code\n",
                 static_cast<unsigned long long>(target), static_cast<unsigned long long>(args.gpr[0]),
                 static_cast<unsigned long long>(args.gpr[1]), static_cast<unsigned long long>(args.gpr[2]),
                 static_cast<unsigned long long>(args.gpr[3]));
  }
  result = call_guest(target, args);
  return true;
}

bool GuestProcess::read_code(uint64_t addr, uint32_t& word) {
  if (image_.contains(addr) && image_.contains(addr + 3)) {
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

runtime::Action GuestProcess::on_host_address(arm64::CpuState& s) {
  const uint64_t pc = s.pc;
  Thunk* thunk = thunks_.find(pc);
  if (!thunk) fatal(std::format("guest jumped into the API thunk region at 0x{:x}", pc), kStatusAccessViolation);

  // Copy what we need: the thunk table may grow (and move) during the call.
  const Thunk::Kind kind = thunk->kind;
  void* native = thunk->native;
  const char* signature = thunk->signature;
  BuiltinFn builtin = thunk->builtin;
  ++thunk->calls;
  const uint64_t lr = s.x[30];
  const size_t index = (pc - thunks_.begin()) / ThunkTable::kStride;

  auto describe = [&] {
    const Thunk& t = thunks_.thunks()[index];
    return std::format("{}!{}", t.dll, t.name);
  };

  if (kind == Thunk::Kind::ReturnSentinel) fatal("guest returned to the host unexpectedly", kStatusAccessViolation);
  if (kind == Thunk::Kind::Missing) {
    fatal(std::format("unimplemented API {} called from 0x{:x}", describe(), lr), kStatusEntryPointNotFound);
  }

  if (options_.trace_calls) {
    std::fprintf(stderr, "[juice] call %s(0x%llx, 0x%llx, 0x%llx, 0x%llx) from 0x%llx\n", describe().c_str(),
                 static_cast<unsigned long long>(s.x[0]), static_cast<unsigned long long>(s.x[1]),
                 static_cast<unsigned long long>(s.x[2]), static_cast<unsigned long long>(s.x[3]),
                 static_cast<unsigned long long>(lr));
  }

  uint64_t result;
  if (kind == Thunk::Kind::Native) {
    const NativeResult r = call_native(native, s, signature);
    result = r.rax;
    s.v[0] = {r.xmm0, 0};  // the return type is unknown: provide both X0 and D0
  } else {
    result = builtin(*this, s);
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
      break;
  }
  return runtime::Action::Continue;
}

bool GuestProcess::is_guest_module_name(std::wstring_view name) const {
  auto file_part = [](std::wstring_view p) {
    size_t slash = p.find_last_of(L"\\/");
    return slash == std::wstring_view::npos ? p : p.substr(slash + 1);
  };
  return lower(file_part(name)) == lower(file_part(exe_path_));
}

uint64_t GuestProcess::get_proc_address(uint64_t module, const char* name) {
  const bool by_ordinal = (reinterpret_cast<uint64_t>(name) >> 16) == 0;
  const uint16_t ordinal = static_cast<uint16_t>(reinterpret_cast<uint64_t>(name));

  if (module == image_.address()) {
    if (by_ordinal) {
      auto it = image_.exports_by_ordinal.find(ordinal);
      if (it != image_.exports_by_ordinal.end()) return it->second;
    } else {
      auto it = image_.exports_by_name.find(name);
      if (it != image_.exports_by_name.end()) return it->second;
    }
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

void GuestProcess::exit(uint32_t code) {
  before_exit(code);
  ExitProcess(code);
}

void GuestProcess::before_exit(uint32_t code) {
  if (exiting_) return;
  exiting_ = true;
  std::fflush(stdout);
  if (options_.stats && engine_) {
    engine_->print_stats(stderr);
    std::vector<const Thunk*> called;
    for (const Thunk& t : thunks_.thunks())
      if (t.calls) called.push_back(&t);
    std::sort(called.begin(), called.end(), [](const Thunk* a, const Thunk* b) { return a->calls > b->calls; });
    for (const Thunk* t : called)
      std::fprintf(stderr, "[juice]   api %s!%s: %llu calls\n", t->dll.c_str(), t->name.c_str(),
                   static_cast<unsigned long long>(t->calls));
    std::fprintf(stderr, "[juice] exit code %u (0x%x)\n", code, code);
  }
  std::fflush(stderr);
}

void GuestProcess::dump_state(std::FILE* out) const {
  const arm64::CpuState& s = state_;
  std::fprintf(out, "[juice]   pc 0x%016llx  sp 0x%016llx  nzcv %c%c%c%c\n", static_cast<unsigned long long>(s.pc),
               static_cast<unsigned long long>(s.sp), (s.nzcv >> 31) & 1 ? 'N' : '-', (s.nzcv >> 30) & 1 ? 'Z' : '-',
               (s.nzcv >> 29) & 1 ? 'C' : '-', (s.nzcv >> 28) & 1 ? 'V' : '-');
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
