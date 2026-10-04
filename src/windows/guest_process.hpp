#pragma once

// A Windows ARM64 program running under JUICE: owns the mapped image, the
// API thunks, the guest stack and the translation engine.

#include <cstdint>
#include <expected>
#include <filesystem>
#include <initializer_list>
#include <memory>
#include <string>
#include <vector>

#include "core/arm64/state/cpu_state.hpp"
#include "runtime/engine.hpp"
#include "windows/exceptions/fault_handler.hpp"
#include "windows/pe/pe_loader.hpp"
#include "windows/thunk/thunk_table.hpp"

namespace juice::win {

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
  arm64::CpuState& state() { return state_; }
  const std::wstring& exe_path() const { return exe_path_; }
  const std::wstring& command_line_w() const { return command_line_w_; }
  const std::string& command_line_a() const { return command_line_a_; }
  const ProcessOptions& options() const { return options_; }

  // Is `name` (a module name or path as passed to GetModuleHandle) the guest executable?
  bool is_guest_module_name(std::wstring_view name) const;

  // GetProcAddress as seen by the guest: guest exports, builtins, or thunked
  // native exports. Returns 0 if not found.
  uint64_t get_proc_address(uint64_t module, const char* name_or_ordinal);

  // Call a guest function with integer arguments and run it to completion.
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
  void setup_stack(uint64_t reserve);
  void setup_tls();
  void dump_state(std::FILE* out) const;

  ProcessOptions options_;
  ThunkTable thunks_;
  pe::LoadedImage image_{};
  std::unique_ptr<runtime::Engine> engine_;
  arm64::CpuState state_{};

  uint8_t* stack_base_ = nullptr;
  size_t stack_size_ = 0;
  uint32_t main_thread_id_ = 0;
  bool exiting_ = false;

  std::wstring exe_path_;
  std::wstring command_line_w_;
  std::string command_line_a_;
};

}  // namespace juice::win
