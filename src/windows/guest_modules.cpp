// Guest modules: the program and the ARM64 DLLs it loads.
//
// An imported or LoadLibrary'd DLL becomes a guest module when an ARM64 copy
// of it is found on the DLL search path (find_guest_dll); everything else
// binds to builtins and native x64 DLLs. Guest modules get what the native
// loader would give them: relocation, import binding (including forwarded
// exports), implicit TLS, TLS callbacks and DllMain notifications in
// dependency order, and reference counts: the last FreeLibrary detaches and
// unmaps a DLL, dropping its translations.

#include <windows.h>

#include <algorithm>
#include <cstring>
#include <cwctype>
#include <filesystem>
#include <format>

#include "windows/guest_process.hpp"
#include "windows/imports/import_resolver.hpp"

namespace juice::win {

namespace {

constexpr uint32_t kMaxTlsModules = 64;
constexpr uint32_t kNoTlsSlot = ~0u;

std::wstring lower(std::wstring_view s) {
  std::wstring out(s);
  std::transform(out.begin(), out.end(), out.begin(), [](wchar_t c) { return static_cast<wchar_t>(std::towlower(c)); });
  return out;
}

std::wstring widen(std::string_view s) {
  const int n = MultiByteToWideChar(CP_ACP, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
  std::wstring out(n, L'\0');
  MultiByteToWideChar(CP_ACP, 0, s.data(), static_cast<int>(s.size()), out.data(), n);
  return out;
}

// "name.dll" for a module name given with or without extension or directory.
std::wstring module_file_name(std::wstring_view name) {
  std::wstring file(name);
  if (size_t slash = file.find_last_of(L"\\/"); slash != std::wstring::npos) file = file.substr(slash + 1);
  if (file.find(L'.') == std::wstring::npos) file += L".dll";
  if (!file.empty() && file.back() == L'.') file.pop_back();  // "name." means no extension
  return lower(file);
}

bool is_path(std::wstring_view name) { return name.find_first_of(L"\\/:") != std::wstring_view::npos; }

// msvcrt.dll, the C runtime of Windows itself (used by many of its tools), is
// always the native x64 one. Its exception handling, RTTI and setjmp/longjmp
// are architecture specific: guest code needs ARM64 versions, which the ARM64
// vcruntime140.dll provides under the same names (the data structures are the
// compiler's, the same for both runtimes).
const char* vcruntime_equivalent(std::string_view dll, std::string_view name) {
  std::string d(dll);
  for (char& c : d) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  if (d != "msvcrt.dll" && d != "msvcrt") return nullptr;
  static constexpr const char* kSameName[] = {
      "__CxxFrameHandler", "__CxxFrameHandler2", "__CxxFrameHandler3", "__C_specific_handler",
      "_CxxThrowException", "__CxxDetectRethrow", "__CxxExceptionFilter", "__CxxQueryExceptionSize",
      "__CxxRegisterExceptionObject", "__CxxUnregisterExceptionObject", "__DestructExceptionObject",
      "__uncaught_exception", "__RTCastToVoid", "__RTDynamicCast", "__RTtypeid", "__AdjustPointer",
      "__BuildCatchObject", "__BuildCatchObjectHelper", "__TypeMatch", "_CreateFrameInfo", "_FindAndUnlinkFrame",
      "_IsExceptionObjectToBeDestroyed", "__FrameUnwindFilter", "_local_unwind", "longjmp", "_set_se_translator",
      "set_unexpected", "unexpected", "_is_exception_typeof",
  };
  for (const char* n : kSameName)
    if (name == n) return n;
  if (name == "_setjmp" || name == "setjmp") return "__intrinsic_setjmp";
  if (name == "_setjmpex") return "__intrinsic_setjmpex";
  return nullptr;
}

// API sets and other OS-provided names are never guest modules.
bool is_system_name(std::wstring_view file) { return file.starts_with(L"api-ms-") || file.starts_with(L"ext-ms-"); }

}  // namespace

// --- registry ------------------------------------------------------------------------

GuestModule* GuestProcess::module_at(uint64_t addr) const {
  const size_t n = module_count_.load(std::memory_order_acquire);
  for (size_t i = 0; i < n; ++i) {
    GuestModule* m = modules_[i].load(std::memory_order_acquire);
    if (m->image.contains(addr) && !m->unloaded.load(std::memory_order_acquire)) return m;
  }
  return nullptr;
}

std::vector<GuestModule*> GuestProcess::loaded_modules() const {
  std::vector<GuestModule*> out;
  const size_t n = module_count_.load(std::memory_order_acquire);
  for (size_t i = 0; i < n; ++i) {
    GuestModule* m = modules_[i].load(std::memory_order_acquire);
    if (!m->unloaded.load(std::memory_order_acquire)) out.push_back(m);
  }
  return out;
}

GuestModule* GuestProcess::module_by_handle(uint64_t handle) const {
  GuestModule* m = module_at(handle);
  return m && m->base() == handle ? m : nullptr;
}

GuestModule* GuestProcess::find_loaded_module(std::wstring_view name) const {
  const std::wstring file = module_file_name(name);
  const std::wstring path = lower(name);
  const size_t n = module_count_.load(std::memory_order_acquire);
  for (size_t i = 0; i < n; ++i) {
    GuestModule* m = modules_[i].load(std::memory_order_acquire);
    if (m->unloaded.load(std::memory_order_acquire)) continue;
    if (m->name == file || lower(m->path) == path) return m;
    // The program also answers to its name without extension (GetModuleHandle("app")).
    if (m->is_exe && module_file_name(m->name) == file) return m;
  }
  return nullptr;
}

GuestModule* GuestProcess::register_module(std::unique_ptr<GuestModule> module) {
  const size_t n = module_count_.load(std::memory_order_relaxed);
  if (n == kMaxModules) throw std::runtime_error("too many guest modules");
  GuestModule* m = module.get();
  module_storage_.push_back(std::move(module));
  modules_[n].store(m, std::memory_order_release);
  module_count_.store(n + 1, std::memory_order_release);
  return m;
}

// --- loading -------------------------------------------------------------------------

// The DLL search order (Windows' standard and "safe" orders), for ARM64 DLLs:
// anything else, including every DLL the system directory has, is left to the
// native loader.
std::optional<std::wstring> GuestProcess::find_guest_dll(std::wstring_view name, const DllSearch& search) const {
  const std::wstring file = module_file_name(name);
  if (is_system_name(file)) return std::nullopt;
  auto arm64_dll = [](const std::filesystem::path& path) -> std::optional<std::wstring> {
    std::error_code ec;
    if (!std::filesystem::is_regular_file(path, ec)) return std::nullopt;
    pe::PeHeaderInfo header;
    if (pe::peek_pe_header(path, header) && header.machine == pe::kMachineArm64 && header.is_dll())
      return std::filesystem::absolute(path, ec).wstring();
    return std::nullopt;
  };
  if (is_path(name)) return arm64_dll(std::filesystem::path(name));

  const std::filesystem::path app_dir = std::filesystem::path(exe().path).parent_path();
  auto in = [&](const std::filesystem::path& dir) { return dir.empty() ? std::nullopt : arm64_dll(dir / file); };
  auto system_has = [&] {
    wchar_t system[MAX_PATH];
    const UINT n = GetSystemDirectoryW(system, MAX_PATH);
    std::error_code ec;
    return n && std::filesystem::exists(std::filesystem::path(std::wstring(system, n)) / file, ec);
  };
  constexpr uint32_t kSearchDllLoadDir = 0x100, kSearchApplicationDir = 0x200, kSearchUserDirs = 0x400,
                     kSearchSystem32 = 0x800, kSearchDefaultDirs = 0x1000, kAlteredSearchPath = 0x8;
  constexpr uint32_t kSearchMask = kSearchDllLoadDir | kSearchApplicationDir | kSearchUserDirs | kSearchSystem32 |
                                   kSearchDefaultDirs;
  uint32_t flags = search.flags & kSearchMask;
  if (!flags && !(search.flags & kAlteredSearchPath)) flags = default_search_flags_;
  if (flags & kSearchDefaultDirs) flags |= kSearchApplicationDir | kSearchUserDirs | kSearchSystem32;

  if (flags) {  // the "safe" order: only the directories named
    if (flags & kSearchDllLoadDir)
      if (auto p = in(search.load_dir)) return p;
    if (flags & kSearchApplicationDir)
      if (auto p = in(app_dir)) return p;
    for (const std::wstring& dir : options_.dll_paths)
      if (auto p = in(dir)) return p;
    if (flags & kSearchUserDirs) {
      for (const auto& [cookie, dir] : user_dll_dirs_)
        if (auto p = in(dir)) return p;
    }
    return std::nullopt;
  }
  // The standard order: the loading DLL's directory (altered search path), the
  // program's, SetDllDirectory's, JUICE's own; then the system directories
  // (native DLLs); then the current directory and PATH.
  if (auto p = in(search.load_dir)) return p;
  if (auto p = in(app_dir)) return p;
  if (auto p = in(dll_directory_)) return p;
  for (const std::wstring& dir : options_.dll_paths)
    if (auto p = in(dir)) return p;
  if (system_has()) return std::nullopt;
  if (dll_directory_.empty()) {
    std::error_code ec;
    if (auto p = in(std::filesystem::current_path(ec))) return p;
  }
  if (const DWORD n = GetEnvironmentVariableW(L"PATH", nullptr, 0)) {
    std::wstring path(n, L'\0');
    path.resize(GetEnvironmentVariableW(L"PATH", path.data(), n));
    for (size_t start = 0; start <= path.size();) {
      size_t end = path.find(L';', start);
      if (end == std::wstring::npos) end = path.size();
      if (end > start)
        if (auto p = in(path.substr(start, end - start))) return p;
      start = end + 1;
    }
  }
  return std::nullopt;
}

void GuestProcess::set_dll_directory(const wchar_t* dir) {
  std::lock_guard lock(loader_mutex_);
  dll_directory_ = dir ? dir : L"";
}

void GuestProcess::add_dll_directory(uint64_t cookie, std::wstring dir) {
  std::lock_guard lock(loader_mutex_);
  user_dll_dirs_.emplace_back(cookie, std::move(dir));
}

void GuestProcess::remove_dll_directory(uint64_t cookie) {
  std::lock_guard lock(loader_mutex_);
  std::erase_if(user_dll_dirs_, [&](const auto& e) { return e.first == cookie; });
}

void GuestProcess::set_default_dll_directories(uint32_t flags) {
  std::lock_guard lock(loader_mutex_);
  default_search_flags_ = flags;
}

GuestModule* GuestProcess::load_guest_dll(std::wstring_view name, const DllSearch& search) {
  std::lock_guard lock(loader_mutex_);
  if (GuestModule* m = find_loaded_module(name)) return m;
  const std::optional<std::wstring> path = find_guest_dll(name, search);
  if (!path) return nullptr;
  if (GuestModule* m = find_loaded_module(*path)) return m;

  auto file = pe::read_pe_file(*path);
  if (!file) return nullptr;
  auto image = pe::map_image(*file);
  if (!image) {
    std::fprintf(stderr, "[juice] warning: cannot map %ls: %s\n", path->c_str(), image.error().c_str());
    return nullptr;
  }
  auto module = std::make_unique<GuestModule>();
  module->image = std::move(*image);
  module->path = *path;
  module->name = module_file_name(*path);
  // LOAD_WITH_ALTERED_SEARCH_PATH / LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR: its
  // imports are looked for next to it first.
  if (search.flags & (0x8 | 0x100)) module->dependency_dir = std::filesystem::path(*path).parent_path().wstring();
  GuestModule* m = register_module(std::move(module));
  if (options_.trace_imports)
    std::fprintf(stderr, "[juice] guest module %ls at 0x%llx\n", m->path.c_str(), static_cast<unsigned long long>(m->base()));
  // Registered before binding its imports, so that import cycles resolve.
  bind_module_imports(*m);
  if (m->image.tls) assign_tls_slot(*m);
  return m;
}

void GuestProcess::bind_module_imports(GuestModule& module) {
  ImportStats stats = resolve_imports(module.image, thunks_, options_.trace_imports ? stderr : nullptr,
                                      [&](const pe::Import& imp) { return bind_guest_import(imp, &module); });
  if (options_.trace_imports) {
    std::fprintf(stderr, "[juice] %ls imports: %zu guest, %zu builtin, %zu native, %zu data, %zu missing\n",
                 module.name.c_str(), stats.guest, stats.builtin, stats.native, stats.data, stats.missing);
  }
}

std::optional<uint64_t> GuestProcess::bind_guest_import(const pe::Import& imp, GuestModule* importer) {
  if (const char* target = imp.by_ordinal ? nullptr : vcruntime_equivalent(imp.dll, imp.name)) {
    if (GuestModule* vcruntime = load_guest_dll(L"vcruntime140.dll")) {
      if (importer && std::find(importer->dependencies.begin(), importer->dependencies.end(), vcruntime) ==
                          importer->dependencies.end()) {
        importer->dependencies.push_back(vcruntime);
        ++vcruntime->refs;
      }
      if (uint64_t value = guest_export(*vcruntime, target)) return value;
    }
  }
  DllSearch search;
  if (importer && !importer->dependency_dir.empty()) {
    search.flags = 0x100;  // the importer's directory first, then the standard order
    search.load_dir = importer->dependency_dir;
  }
  GuestModule* dll = load_guest_dll(widen(imp.dll), search);
  if (!dll && !search.load_dir.empty()) dll = load_guest_dll(widen(imp.dll));
  if (!dll) return std::nullopt;
  if (importer && dll != importer &&
      std::find(importer->dependencies.begin(), importer->dependencies.end(), dll) == importer->dependencies.end()) {
    importer->dependencies.push_back(dll);
    ++dll->refs;  // released when the importer unloads
    if (importer->is_exe) dll->pinned = true;  // the program's own imports never unload
  }
  const std::string ordinal_name = std::format("#{}", imp.ordinal);
  const uint64_t value =
      guest_export(*dll, imp.by_ordinal ? reinterpret_cast<const char*>(uintptr_t{imp.ordinal}) : imp.name.c_str());
  return value ? value : missing_import(thunks_, imp.dll, imp.by_ordinal ? ordinal_name : imp.name);
}

uint64_t GuestProcess::guest_export(GuestModule& module, const char* name_or_ordinal) {
  const bool by_ordinal = (reinterpret_cast<uintptr_t>(name_or_ordinal) >> 16) == 0;
  const pe::LoadedImage& image = module.image;
  const std::string* forwarder = nullptr;
  if (by_ordinal) {
    const auto ordinal = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(name_or_ordinal));
    if (auto it = image.exports_by_ordinal.find(ordinal); it != image.exports_by_ordinal.end()) return it->second;
    if (auto it = image.forwarders_by_ordinal.find(ordinal); it != image.forwarders_by_ordinal.end())
      forwarder = &it->second;
  } else {
    if (auto it = image.exports_by_name.find(name_or_ordinal); it != image.exports_by_name.end()) return it->second;
    if (auto it = image.forwarders_by_name.find(name_or_ordinal); it != image.forwarders_by_name.end())
      forwarder = &it->second;
  }
  return forwarder ? bind_forwarder(*forwarder, 0) : 0;
}

// A forwarded export "DLL.Name" or "DLL.#ordinal": bound like an import of DLL.
uint64_t GuestProcess::bind_forwarder(const std::string& target, int depth) {
  const size_t dot = target.find_last_of('.');
  if (dot == std::string::npos || depth > 8) return 0;
  pe::Import imp;
  imp.dll = target.substr(0, dot) + ".dll";
  const std::string symbol = target.substr(dot + 1);
  if (!symbol.empty() && symbol[0] == '#') {
    imp.by_ordinal = true;
    imp.ordinal = static_cast<uint16_t>(std::strtoul(symbol.c_str() + 1, nullptr, 10));
  } else {
    imp.name = symbol;
  }
  if (std::optional<uint64_t> v = bind_guest_import(imp, nullptr)) return *v;
  return resolve_native_import(imp, thunks_);
}

// --- initialization ------------------------------------------------------------------

void GuestProcess::run_tls_callbacks(const GuestModule& module, uint32_t reason) {
  if (!module.image.tls) return;
  for (uint64_t cb : module.image.tls->callbacks) call_guest(cb, {module.base(), reason, 0});
}

bool GuestProcess::initialize_module(GuestModule& module) {
  std::lock_guard lock(loader_mutex_);
  if (module.state == GuestModule::State::Initialized || module.state == GuestModule::State::Initializing) return true;
  if (module.state == GuestModule::State::Failed) return false;
  module.state = GuestModule::State::Initializing;
  for (GuestModule* dep : module.dependencies) {
    if (!initialize_module(*dep)) {
      module.state = GuestModule::State::Failed;
      return false;
    }
  }
  if (module.image.tls) {
    for (GuestThread* t : live_threads_) allocate_tls(*t, module);
  }
  run_tls_callbacks(module, DLL_PROCESS_ATTACH);
  if (module.image.entry && !module.is_exe) {
    if (options_.trace_calls)
      std::fprintf(stderr, "[juice] DllMain(%ls, DLL_PROCESS_ATTACH)\n", module.name.c_str());
    const bool static_load = run_started_ == false;
    if (!static_cast<BOOL>(call_guest(module.image.entry, {module.base(), DLL_PROCESS_ATTACH, static_load ? 1u : 0u}))) {
      module.state = GuestModule::State::Failed;
      return false;
    }
  }
  module.state = GuestModule::State::Initialized;
  if (!module.is_exe) init_order_.push_back(&module);
  return true;
}

uint64_t GuestProcess::load_library(std::wstring_view name, uint32_t flags, bool& guest) {
  std::lock_guard lock(loader_mutex_);
  GuestModule* m = load_guest_dll(name, DllSearch{flags, {}});
  guest = m != nullptr;
  if (!m) return 0;
  ++m->refs;
  // DONT_RESOLVE_DLL_REFERENCES: mapped (and bound), but DllMain does not run.
  if (!(flags & DONT_RESOLVE_DLL_REFERENCES) && !initialize_module(*m)) {
    --m->refs;
    SetLastError(ERROR_DLL_INIT_FAILED);
    return 0;
  }
  return m->base();
}

void GuestProcess::reference_module(GuestModule& module, bool pin) {
  std::lock_guard lock(loader_mutex_);
  if (pin) module.pinned = true;
  ++module.refs;
}

bool GuestProcess::free_library(uint64_t handle) {
  std::lock_guard lock(loader_mutex_);
  GuestModule* m = module_by_handle(handle);
  if (!m) return false;
  if (m->is_exe || m->pinned) return true;
  if (--m->refs <= 0) unload_module(*m);
  return true;
}

// The last reference is gone: DLL_PROCESS_DETACH, then the image goes away
// (its translations with it), and its own imports are released.
void GuestProcess::unload_module(GuestModule& module) {
  if (module.state == GuestModule::State::Initialized) {
    if (module.image.entry) {
      if (options_.trace_calls) std::fprintf(stderr, "[juice] DllMain(%ls, DLL_PROCESS_DETACH)\n", module.name.c_str());
      call_guest(module.image.entry, {module.base(), DLL_PROCESS_DETACH, 0 /* FreeLibrary */});
    }
    run_tls_callbacks(module, DLL_PROCESS_DETACH);
  }
  std::erase(init_order_, &module);
  module.unloaded.store(true, std::memory_order_release);
  engine_->invalidate(module.base(), module.base() + module.image.size);
  if (options_.trace_imports) std::fprintf(stderr, "[juice] guest module %ls unloaded\n", module.path.c_str());
  pe::unmap_image(module.image);
  for (GuestModule* dep : module.dependencies) {
    if (dep->is_exe || dep->pinned || dep->unloaded) continue;
    if (--dep->refs <= 0) unload_module(*dep);
  }
}

bool GuestProcess::disable_thread_library_calls(uint64_t handle) {
  GuestModule* m = module_by_handle(handle);
  if (!m) return false;
  m->thread_calls = false;
  return true;
}

void GuestProcess::notify_thread(uint32_t reason) {
  if (reason == DLL_THREAD_DETACH && t_current()) t_current()->detached = true;
  std::lock_guard lock(loader_mutex_);
  // DLLs in initialization order (reverse for detach), then the program.
  std::vector<GuestModule*> order = init_order_;
  if (reason == DLL_THREAD_DETACH) std::reverse(order.begin(), order.end());
  GuestModule& program = *modules_[0].load(std::memory_order_acquire);
  if (reason == DLL_THREAD_DETACH) {
    order.insert(order.begin(), &program);
  } else {
    order.push_back(&program);
  }
  for (GuestModule* m : order) {
    if (m->state != GuestModule::State::Initialized) continue;
    run_tls_callbacks(*m, reason);
    if (!m->is_exe && m->thread_calls && m->image.entry) call_guest(m->image.entry, {m->base(), reason, 0});
  }
}

void GuestProcess::detach_modules() {
  std::lock_guard lock(loader_mutex_);
  if (modules_detached_) return;
  modules_detached_ = true;
  GuestModule& program = *modules_[0].load(std::memory_order_acquire);
  run_tls_callbacks(program, DLL_PROCESS_DETACH);
  for (auto it = init_order_.rbegin(); it != init_order_.rend(); ++it) {
    GuestModule& m = **it;
    if (m.image.entry) call_guest(m.image.entry, {m.base(), DLL_PROCESS_DETACH, 1 /* process exit */});
    run_tls_callbacks(m, DLL_PROCESS_DETACH);
  }
}

// --- implicit TLS --------------------------------------------------------------------
//
// Compiled code finds its thread-local data through TEB->ThreadLocalStoragePointer
// [_tls_index]; executables often assume index 0 without reading _tls_index.
// The translator hands guest code a vector of JUICE's own instead of the TEB's
// (CpuState::tls_vector), so the program always has slot 0 and its DLLs the
// following ones, without touching ntdll's vector (which belongs to the host
// modules, juice.exe included, and which ntdll rebuilds when native DLLs with
// TLS load).

void GuestProcess::assign_tls_slot(GuestModule& module) {
  if (module.is_exe) {
    module.tls_slot = 0;
  } else if (tls_modules_ + 1 < kMaxTlsModules) {
    module.tls_slot = ++tls_modules_;
  } else {
    std::fprintf(stderr, "[juice] warning: too many guest modules with thread-local data (%ls)\n", module.name.c_str());
    module.tls_slot = kNoTlsSlot;
    return;
  }
  if (module.image.contains(module.image.tls->index_address))
    *reinterpret_cast<uint32_t*>(module.image.tls->index_address) = module.tls_slot;
}

void GuestProcess::ensure_tls_vector(GuestThread& t) {
  if (t.tls_vector) return;
  t.tls_vector = new void*[kMaxTlsModules]();
  t.state.tls_vector = reinterpret_cast<uint64_t>(t.tls_vector);
}

void GuestProcess::allocate_tls(GuestThread& t, const GuestModule& module) {
  ensure_tls_vector(t);
  if (!module.image.tls || module.tls_slot == kNoTlsSlot) return;
  const pe::TlsInfo& tls = *module.image.tls;
  const size_t template_size = tls.raw_end > tls.raw_start ? tls.raw_end - tls.raw_start : 0;
  auto* data = static_cast<uint8_t*>(
      HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, std::max<size_t>(template_size + tls.zero_fill, 16)));
  if (!data) throw std::bad_alloc();
  if (template_size && module.image.contains(tls.raw_start))
    std::memcpy(data, reinterpret_cast<const void*>(tls.raw_start), template_size);
  t.tls_blocks.emplace_back(module.tls_slot, data);
  t.tls_vector[module.tls_slot] = data;
}

void GuestProcess::setup_tls_for_thread() {
  GuestThread* t = t_current();
  if (!t) return;
  std::lock_guard lock(loader_mutex_);
  ensure_tls_vector(*t);
  const size_t n = module_count_.load(std::memory_order_acquire);
  for (size_t i = 0; i < n; ++i) allocate_tls(*t, *modules_[i].load(std::memory_order_acquire));
}

// --- Visual Studio's ARM64 C++ runtime ----------------------------------------------

std::optional<std::wstring> find_visual_studio_arm64_runtime() {
  // <Program Files>\Microsoft Visual Studio\<version>\<edition>\VC\Redist\MSVC\<tools>\arm64\Microsoft.VC*.CRT
  std::optional<std::filesystem::path> best;
  for (const wchar_t* var : {L"ProgramFiles", L"ProgramFiles(x86)"}) {
    wchar_t root[MAX_PATH] = {};
    if (!GetEnvironmentVariableW(var, root, MAX_PATH)) continue;
    std::error_code ec;
    const std::filesystem::path vs = std::filesystem::path(root) / L"Microsoft Visual Studio";
    for (const auto& version : std::filesystem::directory_iterator(vs, ec)) {
      for (const auto& edition : std::filesystem::directory_iterator(version.path(), ec)) {
        const auto redist = edition.path() / L"VC" / L"Redist" / L"MSVC";
        for (const auto& tools : std::filesystem::directory_iterator(redist, ec)) {
          const auto arm64 = tools.path() / L"arm64";
          for (const auto& crt : std::filesystem::directory_iterator(arm64, ec)) {
            const std::wstring name = crt.path().filename().wstring();
            if (!name.starts_with(L"Microsoft.VC") || !name.ends_with(L".CRT")) continue;
            if (!std::filesystem::is_regular_file(crt.path() / L"vcruntime140.dll", ec)) continue;
            if (!best || tools.path().filename() > best->parent_path().parent_path().filename()) best = crt.path();
          }
        }
      }
    }
  }
  if (!best) return std::nullopt;
  return best->wstring();
}

}  // namespace juice::win
