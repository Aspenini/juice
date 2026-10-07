#pragma once

// A Windows ARM64 program running under JUICE: owns the mapped image, the
// API thunks, the guest stack and the translation engine.

#include <windows.h>

#include <array>
#include <atomic>
#include <unordered_map>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <initializer_list>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <span>
#include <vector>

#include "core/arm64/state/cpu_state.hpp"
#include "runtime/engine.hpp"
#include "windows/exceptions/arm64_unwind.hpp"
#include "windows/exceptions/fault_handler.hpp"
#include "windows/manifest.hpp"
#include "windows/pe/pe_loader.hpp"
#include "windows/thunk/thunk_table.hpp"

namespace juice::win {

// One nested run of guest code on a thread (GuestProcess::call_guest).
struct GuestCallLevel {
  uint64_t entry_sp;     // guest SP when the call started; the level's frames are below it
  bool native_frames;    // native code may sit between this call and the guest code that made it
  const arm64eh::Context* link;  // for exception dispatch: the guest frames continue here
  // With native frames: the guest state that called into host code, whose
  // frames continue (past the native ones) at its return address.
  const arm64::CpuState* caller = nullptr;
};

// A guest (ARM64) module: the program or one of its DLLs.
struct GuestModule {
  enum class State { Loaded, Initializing, Initialized, Failed };
  pe::LoadedImage image;
  std::wstring path;
  std::wstring name;  // file name, lower case
  bool is_exe = false;
  bool thread_calls = true;  // DLL_THREAD_ATTACH/DETACH to DllMain (DisableThreadLibraryCalls)
  uint32_t tls_slot = 0;     // index in the guest's implicit-TLS vectors (if image.tls)
  std::vector<GuestModule*> dependencies;  // guest DLLs it imports
  State state = State::Loaded;
  int refs = 0;              // LoadLibrary / GetModuleHandleEx counts plus importers; unloaded at 0
  bool pinned = false;       // never unloaded (GET_MODULE_HANDLE_EX_FLAG_PIN)
  std::atomic<bool> unloaded{false};  // FreeLibrary unmapped it: lookups skip it
  std::wstring dependency_dir;  // searched first for its imports (LOAD_WITH_ALTERED_SEARCH_PATH)

  uint64_t base() const { return image.address(); }
  // The file name as on disk (GetModuleBaseName, toolhelp).
  std::wstring display_name() const {
    const size_t slash = path.find_last_of(L"\\/");
    return slash == std::wstring::npos ? path : path.substr(slash + 1);
  }
};

// Guest execution context of one host thread: ARM64 CPU state and stack.
struct GuestThread {
  arm64::CpuState state{};
  uint8_t* stack_base = nullptr;
  size_t stack_size = 0;
  uint8_t* teb = nullptr;
  void** tls_vector = nullptr;   // the guest's implicit-TLS vector (CpuState::tls_vector)
  // Implicit TLS blocks of guest modules: (slot, block).
  std::vector<std::pair<uint32_t, void*>> tls_blocks;
  HANDLE host_thread = nullptr;  // signaled once the host thread has fully terminated
  bool main = false;
  bool detached = false;         // DLL_THREAD_DETACH notifications have run
  std::vector<GuestCallLevel> levels;  // nested call_guest() runs, innermost last
  bool state_replaced = false;   // a builtin set the whole CPU state (exception handling)
  DWORD thread_id = 0;           // the host thread (for a fiber: the one it last ran on)

  // Thread control (SuspendThread, Get/SetThreadContext from other threads).
  // The state in memory is exact while the thread is in host code (an API
  // call: `in_host`) or parked between blocks (`parked`, on request).
  std::atomic<bool> in_host{false};
  std::atomic<bool> parked{false};
  std::atomic<bool> park_request{false};
  std::atomic<bool> park_release{false};
  bool context_set = false;      // SetThreadContext replaced the state during an API call: keep it

  // Fibers. A thread's own context runs its first fiber; CreateFiber makes a
  // context (and guest stack) per fiber, and `active` names the one running.
  std::atomic<GuestThread*> active{nullptr};  // on a thread's own context: the fiber running (nullptr: itself)
  bool fiber = false;            // a CreateFiber context
  uint64_t fiber_start = 0;
  uint64_t fiber_param = 0;
  void* host_fiber = nullptr;

  bool exact() const { return in_host.load(std::memory_order_acquire) || parked.load(std::memory_order_acquire); }
};

// How call_guest() runs a guest function.
struct GuestCall {
  bool native_frames = true;               // see GuestCallLevel
  const arm64eh::Context* link = nullptr;  // see GuestCallLevel
  uint64_t sp = 0;                         // stack pointer for the callee (0: below the current one)
  const uint64_t* nonvolatile = nullptr;   // x19-x28 for the callee (exception funclets share the parent's)
  const uint64_t* extra_fpr = nullptr;     // V4-V7 (converted callback arguments)
  std::span<const uint64_t> stack_args;    // arguments passed on the guest stack
};

struct ProcessOptions {
  runtime::EngineOptions engine;
  bool trace_calls = false;    // log every API call
  bool trace_imports = false;  // log import resolution
  bool stats = false;          // print engine statistics at exit
  // Directories searched for ARM64 DLLs after the program's own directory.
  std::vector<std::wstring> dll_paths;
  // argv[0] of the program as its parent wrote it (when a guest started it), if
  // different from the path JUICE was given.
  std::wstring argv0;
};

class GuestProcess final : public runtime::Environment, public NativeCallbackTarget {
  friend void notify_native_process_exit();

 public:
  explicit GuestProcess(ProcessOptions options);
  ~GuestProcess() override;

  // Load and bind the executable. `args` excludes the program itself.
  std::expected<void, std::string> load(const std::filesystem::path& exe, const std::vector<std::wstring>& args);

  // Run TLS callbacks and the entry point. Returns the process exit code.
  int run();

  // --- Environment ---------------------------------------------------------------
  bool read_code(uint64_t addr, uint32_t& word) override;
  std::pair<uint64_t, uint64_t> host_range() const override { return {thunks_.begin(), thunks_.end()}; }
  runtime::Action on_host_address(arm64::CpuState& state) override;
  bool is_host_code(uint64_t pc) override;
  runtime::Action on_exit(arm64::CpuState& state) override;

  // --- NativeCallbackTarget ----------------------------------------------------------
  bool call_from_native(uint64_t target, const Args& args, Result& result) override;

  // --- NativeCallbackTarget / fault handler ---------------------------------------
  bool is_guest_address(uint64_t addr) const override { return module_at(addr) != nullptr; }

  // --- Services for builtin API implementations -----------------------------------
  // The program's image.
  const pe::LoadedImage& image() const { return exe().image; }
  const GuestModule& exe() const { return *modules_[0].load(std::memory_order_acquire); }

  // --- Guest modules (guest_modules.cpp) -------------------------------------------
  // The guest module containing `addr`, the module whose base is `handle`, or
  // a loaded module named `name` (a file name, with or without ".dll", or a path).
  GuestModule* module_at(uint64_t addr) const;
  GuestModule* module_by_handle(uint64_t handle) const;
  GuestModule* find_loaded_module(std::wstring_view name) const;
  // LoadLibraryEx for guest DLLs: returns the module handle, or 0 with `guest`
  // false if `name` is not an ARM64 DLL JUICE can find (load it natively then).
  uint64_t load_library(std::wstring_view name, uint32_t flags, bool& guest);
  // FreeLibrary for a guest module: false if `handle` is not one.
  bool free_library(uint64_t handle);
  // GetModuleHandleEx's reference (unless GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT) and pin.
  void reference_module(GuestModule& module, bool pin);
  bool disable_thread_library_calls(uint64_t handle);
  // The loaded guest modules, the program first.
  std::vector<GuestModule*> loaded_modules() const;
  // DLL search directories (SetDllDirectory, AddDllDirectory, SetDefaultDllDirectories).
  void set_dll_directory(const wchar_t* dir);
  void add_dll_directory(uint64_t cookie, std::wstring dir);
  void remove_dll_directory(uint64_t cookie);
  void set_default_dll_directories(uint32_t flags);
  // Guest-visible address of an export of a guest module (0 if none).
  uint64_t guest_export(GuestModule& module, const char* name_or_ordinal);
  ThunkTable& thunks() { return thunks_; }
  const std::wstring& exe_path() const { return exe_path_; }
  const std::wstring& command_line_w() const { return command_line_w_; }
  const std::string& command_line_a() const { return command_line_a_; }
  const ProcessOptions& options() const { return options_; }


  // GetProcAddress as seen by the guest: guest exports, builtins, or thunked
  // native exports. Returns 0 if not found.
  uint64_t get_proc_address(uint64_t module, const char* name_or_ordinal);

  // Start a guest thread (CreateThread). `stack_size` 0 selects the image default.
  HANDLE create_thread(SECURITY_ATTRIBUTES* attributes, uint64_t stack_size, uint64_t start, uint64_t parameter,
                       uint32_t flags, DWORD* thread_id);
  // Guest thread exit (ExitThread): runs thread-detach notifications, then ends the host thread.
  [[noreturn]] void exit_thread(uint32_t code);

  // --- Thread control and fibers (guest_threads.cpp) ---------------------------------
  // SuspendThread of a guest thread, which stops where its state is exact;
  // nullopt if `thread` is not a guest thread (suspend it natively).
  std::optional<DWORD> suspend_thread(HANDLE thread);
  // Get/SetThreadContext with the ARM64 CONTEXT; false if `thread` is unknown.
  bool get_thread_context(HANDLE thread, arm64eh::Context& context);
  bool set_thread_context(HANDLE thread, const arm64eh::Context& context);
  // The guest stack of the calling thread (or fiber): [low, high).
  std::pair<uint64_t, uint64_t> stack_limits();
  void* create_fiber(uint64_t stack_size, uint64_t start, uint64_t param, uint32_t flags);
  void* convert_thread_to_fiber(uint64_t param, uint32_t flags);
  bool convert_fiber_to_thread();
  void switch_to_fiber(void* fiber);
  void delete_fiber(void* fiber);

  // Call a guest function with integer arguments and run it to completion.
  // The calling host thread becomes a guest thread if it isn't one yet.
  uint64_t call_guest(uint64_t fn, std::initializer_list<uint64_t> args);
  // Full form: X0-X7 and D0-D3 arguments; returns X0 and D0.
  Result call_guest(uint64_t fn, const Args& args, const GuestCall& how = {});

  // --- Guest exceptions (exceptions/guest_exceptions.cpp) --------------------------
  // The guest context at a call into a builtin: pc is the return address.
  static arm64eh::Context capture_context(const arm64::CpuState& state);
  // Make the calling builtin return to `context` instead of to its caller.
  void resume_at(const arm64eh::Context& context);
  // Dispatch an exception to the guest's vectored handlers and frame-based
  // handlers. Returns if a handler continued execution (at `context`); a
  // handler that catches the exception unwinds instead, and an unhandled
  // exception ends the process.
  void dispatch_exception(EXCEPTION_RECORD& record, arm64eh::Context& context);
  // A hardware exception (memory fault, breakpoint, illegal instruction) at
  // the guest instruction at s.pc: dispatched to the guest's handlers; if one
  // continues execution, `s` is where it continues.
  void raise_hardware_exception(arm64::CpuState& s, uint32_t code, std::initializer_list<uint64_t> params);
  // An exception that left a native function the guest called (state `s`, at
  // the call): dispatched to the guest's handlers from its call site.
  void raise_native_exception(arm64::CpuState& s, const EXCEPTION_RECORD& record);
  // RtlUnwindEx: unwind the guest frames from `context` to `target_frame`,
  // running termination handlers, and continue at `target_ip`.
  [[noreturn]] void unwind(uint64_t target_frame, uint64_t target_ip, EXCEPTION_RECORD* record, uint64_t return_value,
                           arm64eh::Context context);
  // RtlRestoreContext: continue at `context` (in this or an outer guest call).
  [[noreturn]] void restore_context(arm64eh::Context context, EXCEPTION_RECORD* record);
  // RtlLookupFunctionEntry for guest code; nullptr if `pc` has no unwind information.
  const arm64eh::RuntimeFunction* lookup_function_entry(uint64_t pc, uint64_t* image_base) const;
  uint64_t add_vectored_handler(bool first, uint64_t handler);
  bool remove_vectored_handler(uint64_t handle);
  uint64_t set_unhandled_exception_filter(uint64_t filter) { return unhandled_filter_.exchange(filter); }

  [[noreturn]] void exit(uint32_t code);
  static constexpr uint32_t kExitCodeUnknown = 0xFFFFFFFF;
  // Exit hooks (statistics); idempotent. Called before the process terminates.
  void before_exit(uint32_t code);

  // Print a diagnostic with a guest register dump and terminate.
  [[noreturn]] void fatal(const std::string& message, uint32_t exit_code);

 private:
  void publish_command_line();

  // The guest context of the calling host thread, created on first use
  // (with `stack_size`, 0 = image default) for threads started natively.
  GuestThread& attach_thread(uint64_t stack_size = 0);
  GuestThread* allocate_thread(uint64_t stack_size);
  void setup_tls_for_thread();
  void notify_thread(uint32_t reason);  // guest TLS callbacks
  static DWORD WINAPI thread_main(void* start);
  static void WINAPI release_thread(void* thread);  // FLS destructor
  void reclaim_threads();  // free contexts of host threads that have terminated
  void dump_state(std::FILE* out) const;
  static GuestThread* t_current();  // the calling thread's guest context, if any
  static GuestThread* t_own();      // the calling thread's own context (not a fiber's), if any
  runtime::Action on_interrupt(arm64::CpuState& state) override;
  GuestThread* find_thread(DWORD thread_id);  // the context running on a guest thread
  void enter_fiber(GuestThread& context);     // `context` runs on this thread now
  static void WINAPI fiber_main(void* context);
  // Guest modules (guest_modules.cpp).
  GuestModule* register_module(std::unique_ptr<GuestModule> module);
  // Where to look for a DLL: LoadLibraryEx's search flags and the directory
  // of the module whose imports are being loaded (if it asked for that).
  struct DllSearch {
    uint32_t flags = 0;
    std::wstring load_dir;
  };
  GuestModule* load_guest_dll(std::wstring_view name, const DllSearch& search);
  GuestModule* load_guest_dll(std::wstring_view name) { return load_guest_dll(name, DllSearch{}); }
  std::optional<std::wstring> find_guest_dll(std::wstring_view name, const DllSearch& search) const;
  void unload_module(GuestModule& module);
  std::optional<uint64_t> bind_guest_import(const pe::Import& import, GuestModule* importer);
  uint64_t bind_forwarder(const std::string& target, int depth);
  void bind_module_imports(GuestModule& module);
  bool initialize_module(GuestModule& module);
  void run_tls_callbacks(const GuestModule& module, uint32_t reason);
  void assign_tls_slot(GuestModule& module);
  void allocate_tls(GuestThread& thread, const GuestModule& module);
  void ensure_tls_vector(GuestThread& thread);
  void detach_modules();  // DLL_PROCESS_DETACH at exit

  // Thunk for native code the guest reached directly (is_host_code), named module+offset.
  Thunk* native_code_thunk(uint64_t pc, uint64_t self);
  struct Resume;  // thrown to continue guest execution in an outer call level
  void resume(Resume& r);
  [[noreturn]] void unhandled_exception(EXCEPTION_RECORD& record, arm64eh::Context& context, const char* why);

  ProcessOptions options_;
  ThunkTable thunks_;
  // Guest modules, in load order; [0] is the program. Published lock-free
  // (lookups by address happen on every translation) and never unloaded.
  static constexpr size_t kMaxModules = 256;
  std::array<std::atomic<GuestModule*>, kMaxModules> modules_{};
  std::atomic<size_t> module_count_{0};
  std::vector<std::unique_ptr<GuestModule>> module_storage_;
  std::recursive_mutex loader_mutex_;        // like the native loader lock
  std::vector<GuestModule*> init_order_;     // initialized DLLs
  std::wstring dll_directory_;               // SetDllDirectory
  std::vector<std::pair<uint64_t, std::wstring>> user_dll_dirs_;  // AddDllDirectory: (cookie, directory)
  uint32_t default_search_flags_ = 0;        // SetDefaultDllDirectories
  uint32_t tls_modules_ = 0;
  std::mutex threads_mutex_;
  std::vector<GuestThread*> live_threads_;  // attached, not yet reclaimed
  std::mutex fibers_mutex_;
  std::unordered_map<void*, GuestThread*> fibers_;  // native fiber -> the guest context it runs
  ManifestState manifest_;
  std::unique_ptr<runtime::Engine> engine_;

  uint64_t default_stack_size_ = 1 << 20;
  DWORD thread_fls_slot_ = FLS_OUT_OF_INDEXES;
  std::atomic<uint32_t> threads_started_{0};
  std::mutex exited_mutex_;
  std::vector<GuestThread*> exited_threads_;  // released, waiting for their host thread to end
  std::atomic<bool> exiting_{false};
  bool run_started_ = false;      // the program's entry point has been called
  bool modules_detached_ = false;

  struct VectoredHandler {
    uint64_t handle;
    uint64_t function;
  };
  std::mutex vectored_mutex_;
  std::vector<VectoredHandler> vectored_handlers_;
  uint64_t next_vectored_handle_ = 0x5EB0000;
  std::atomic<uint64_t> unhandled_filter_{0};

  std::wstring exe_path_;
  std::wstring command_line_w_;
  std::string command_line_a_;
};

// Native code ended the process (ExitProcess not called through the guest's
// imports, e.g. by the native C runtime's exit()): run the guest modules'
// DLL_PROCESS_DETACH notifications and the exit hooks. Called from juice.exe's
// TLS callback, which the native loader runs before detaching native DLLs.
void notify_native_process_exit();

// The ARM64 C++ runtime DLLs of a Visual Studio installation (its ARM64
// redistributable directory), if one is installed.
std::optional<std::wstring> find_visual_studio_arm64_runtime();

struct GuestProcess::Resume {
  arm64eh::Context context;
  uint64_t consolidate_record = 0;  // EXCEPTION_RECORD* of a STATUS_UNWIND_CONSOLIDATE unwind
  uint64_t stack = 0;               // guest SP below everything still in use (for the consolidation callback)
};

}  // namespace juice::win
