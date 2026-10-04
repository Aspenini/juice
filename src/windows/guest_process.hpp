#pragma once

// A Windows ARM64 program running under JUICE: owns the mapped image, the
// API thunks, the guest stack and the translation engine.

#include <windows.h>

#include <atomic>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <initializer_list>
#include <memory>
#include <mutex>
#include <string>
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
};

// Guest execution context of one host thread: ARM64 CPU state and stack.
struct GuestThread {
  arm64::CpuState state{};
  uint8_t* stack_base = nullptr;
  size_t stack_size = 0;
  void* tls_data = nullptr;  // the guest image's implicit TLS block for this thread
  HANDLE host_thread = nullptr;  // signaled once the host thread has fully terminated
  bool main = false;
  bool detached = false;         // DLL_THREAD_DETACH notifications have run
  std::vector<GuestCallLevel> levels;  // nested call_guest() runs, innermost last
  bool state_replaced = false;   // a builtin set the whole CPU state (exception handling)
};

// How call_guest() runs a guest function.
struct GuestCall {
  bool native_frames = true;               // see GuestCallLevel
  const arm64eh::Context* link = nullptr;  // see GuestCallLevel
  uint64_t sp = 0;                         // stack pointer for the callee (0: below the current one)
  const uint64_t* nonvolatile = nullptr;   // x19-x28 for the callee (exception funclets share the parent's)
};

struct ProcessOptions {
  runtime::EngineOptions engine;
  bool trace_calls = false;    // log every API call
  bool trace_imports = false;  // log import resolution
  bool stats = false;          // print engine statistics at exit
};

class GuestProcess final : public runtime::Environment, public NativeCallbackTarget {
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

  // --- Services for builtin API implementations -----------------------------------
  const pe::LoadedImage& image() const { return image_; }
  ThunkTable& thunks() { return thunks_; }
  const std::wstring& exe_path() const { return exe_path_; }
  const std::wstring& command_line_w() const { return command_line_w_; }
  const std::string& command_line_a() const { return command_line_a_; }
  const ProcessOptions& options() const { return options_; }

  // Is `name` (a module name or path as passed to GetModuleHandle) the guest executable?
  bool is_guest_module_name(std::wstring_view name) const;

  // GetProcAddress as seen by the guest: guest exports, builtins, or thunked
  // native exports. Returns 0 if not found.
  uint64_t get_proc_address(uint64_t module, const char* name_or_ordinal);

  // Start a guest thread (CreateThread). `stack_size` 0 selects the image default.
  HANDLE create_thread(SECURITY_ATTRIBUTES* attributes, uint64_t stack_size, uint64_t start, uint64_t parameter,
                       uint32_t flags, DWORD* thread_id);
  // Guest thread exit (ExitThread): runs thread-detach notifications, then ends the host thread.
  [[noreturn]] void exit_thread(uint32_t code);

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
  // Thunk for native code the guest reached directly (is_host_code), named module+offset.
  Thunk* native_code_thunk(uint64_t pc);
  struct Resume;  // thrown to continue guest execution in an outer call level
  void resume(Resume& r);
  [[noreturn]] void unhandled_exception(EXCEPTION_RECORD& record, arm64eh::Context& context, const char* why);

  ProcessOptions options_;
  ThunkTable thunks_;
  pe::LoadedImage image_{};
  ManifestState manifest_;
  std::unique_ptr<runtime::Engine> engine_;

  uint64_t default_stack_size_ = 1 << 20;
  DWORD thread_fls_slot_ = FLS_OUT_OF_INDEXES;
  std::atomic<uint32_t> threads_started_{0};
  std::mutex exited_mutex_;
  std::vector<GuestThread*> exited_threads_;  // released, waiting for their host thread to end
  std::atomic<bool> exiting_{false};

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

struct GuestProcess::Resume {
  arm64eh::Context context;
  uint64_t consolidate_record = 0;  // EXCEPTION_RECORD* of a STATUS_UNWIND_CONSOLIDATE unwind
  uint64_t stack = 0;               // guest SP below everything still in use (for the consolidation callback)
};

}  // namespace juice::win
