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
#include "windows/exceptions/fault_handler.hpp"
#include "windows/pe/pe_loader.hpp"
#include "windows/thunk/thunk_table.hpp"

namespace juice::win {

// Guest execution context of one host thread: ARM64 CPU state and stack.
struct GuestThread {
  arm64::CpuState state{};
  uint8_t* stack_base = nullptr;
  size_t stack_size = 0;
  void* tls_data = nullptr;  // the guest image's implicit TLS block for this thread
  HANDLE host_thread = nullptr;  // signaled once the host thread has fully terminated
  bool main = false;
  bool detached = false;         // DLL_THREAD_DETACH notifications have run
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
  Result call_guest(uint64_t fn, const Args& args);

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

  ProcessOptions options_;
  ThunkTable thunks_;
  pe::LoadedImage image_{};
  std::unique_ptr<runtime::Engine> engine_;

  uint64_t default_stack_size_ = 1 << 20;
  DWORD thread_fls_slot_ = FLS_OUT_OF_INDEXES;
  std::atomic<uint32_t> threads_started_{0};
  std::mutex exited_mutex_;
  std::vector<GuestThread*> exited_threads_;  // released, waiting for their host thread to end
  std::atomic<bool> exiting_{false};

  std::wstring exe_path_;
  std::wstring command_line_w_;
  std::string command_line_a_;
};

}  // namespace juice::win
