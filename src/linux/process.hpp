#pragma once

// A Linux AArch64 program running under JUICE on Linux x86-64: loads the ELF
// program (and its ELF interpreter, the guest's own ld.so, for dynamically
// linked programs), sets up the initial stack, and serves the guest's system
// calls and signals. Guest and host share the address space: the guest's
// pointers are used directly in host system calls.

#include <signal.h>

#include <array>
#include <atomic>
#include <cstdint>
#include <expected>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "core/arm64/state/cpu_state.hpp"
#include "linux/elf/elf_file.hpp"
#include "runtime/engine.hpp"

namespace juice::lx {

struct Options {
  runtime::EngineOptions engine;
  // Prefix for the guest's absolute paths: where its ld.so, libraries and
  // configuration live when they are not installed on the host itself.
  std::string sysroot;
  std::string argv0;            // argv[0] for the guest (default: the program as named)
  bool trace_syscalls = false;  // log every system call
  bool stats = false;           // print translation statistics at exit
};

// The kernel's struct sigaction for AArch64 (as rt_sigaction passes it).
struct GuestSigaction {
  uint64_t handler = 0;  // 0 = SIG_DFL, 1 = SIG_IGN
  uint64_t flags = 0;
  uint64_t restorer = 0;
  uint64_t mask = 0;
};

// Guest state of one thread (one host thread each).
struct LinuxThread {
  arm64::CpuState state{};
  int tid = 0;
  uint64_t clear_child_tid = 0;  // CLONE_CHILD_CLEARTID / set_tid_address: zeroed and woken at exit
  uint64_t robust_list = 0;      // set_robust_list (recorded, not walked)
  uint64_t blocked = 0;          // the guest's signal mask (bit n-1 = signal n)
  std::atomic<uint64_t> pending{0};  // caught by the host handler, not yet delivered
  std::array<siginfo_t, 65> info{};
  uint64_t altstack_sp = 0, altstack_size = 0;
  uint32_t altstack_flags = 2;  // SS_DISABLE
};

class LinuxProcess final : public runtime::Environment {
 public:
  explicit LinuxProcess(Options options);
  ~LinuxProcess() override;

  // Load `path` (with its interpreter, if any) and build the initial stack.
  std::expected<void, std::string> load(const std::string& path, const std::vector<std::string>& args, char** envp);

  // Run the program on the calling (main) thread. Does not return.
  [[noreturn]] void run();

  // --- runtime::Environment --------------------------------------------------------
  bool read_code(uint64_t addr, uint32_t& word) override;
  runtime::Action on_exit(arm64::CpuState& state) override;
  runtime::Action on_interrupt(arm64::CpuState& state) override;

  static LinuxThread* current_thread();
  static LinuxProcess* instance();

  // Print a diagnostic with the guest registers and end the process with `sig`.
  [[noreturn]] void fatal(const std::string& message, int sig);

  // Host signal handler entry (see signals.cpp).
  void on_host_signal(int sig, siginfo_t* info, void* context);

 private:
  struct Mapped {
    uint64_t base = 0;   // load bias
    uint64_t entry = 0;
    uint64_t phdr = 0;
    uint16_t phnum = 0;
    uint64_t end = 0;    // end of the highest segment
  };
  std::expected<Mapped, std::string> map_elf(const std::string& path, bool main_program, ElfFile& elf);
  std::string find_interpreter(const std::string& interp) const;

  // --- system calls (syscalls.cpp) ---
  // Returns the value for X0, or kNoResult when the call set the state itself.
  static constexpr int64_t kNoResult = INT64_MIN;
  int64_t do_syscall(arm64::CpuState& s);
  int64_t sys_brk(uint64_t addr);
  int64_t sys_clone(arm64::CpuState& s, uint64_t flags, uint64_t newsp, uint64_t ptid, uint64_t tls, uint64_t ctid);
  int64_t sys_execve(uint64_t path, uint64_t argv, uint64_t envp);
  void exit_thread(int status);
  [[noreturn]] void exit_process(int status);
  std::string guest_path(const char* path) const;  // sysroot redirection, /proc/self/exe
  bool is_self_exe(const char* path) const;
  std::vector<std::string> juice_arguments() const;  // options for a juice started by execve
  static void* thread_main(void* start);

  // --- signals (signals.cpp) ---
  enum class Delivery { Pushed, Done, Unhandled };  // frame pushed / ignored or default action / caller reports it
  void init_signals();  // fault handlers; the mask and ignored signals inherited across execve

  int64_t sys_rt_sigaction(int sig, uint64_t act, uint64_t oldact, uint64_t size);
  int64_t sys_rt_sigprocmask(int how, uint64_t set, uint64_t oldset, uint64_t size);
  int64_t sys_sigaltstack(uint64_t ss, uint64_t old_ss);
  int64_t sys_rt_sigreturn(arm64::CpuState& s);
  void set_guest_mask(LinuxThread& t, uint64_t mask);
  // Deliver `sig` to the current thread under its current mask; `saved_mask`
  // is what the handler's rt_sigreturn restores.
  Delivery deliver_signal(arm64::CpuState& s, int sig, const siginfo_t* info, uint64_t saved_mask);
  bool deliver_pending(arm64::CpuState& s, uint64_t saved_mask);  // true if a handler frame was pushed
  bool restart_pending(const LinuxThread& t);  // a pending signal's handler has SA_RESTART

  void dump_state(const arm64::CpuState& s) const;

  Options options_;
  std::unique_ptr<runtime::Engine> engine_;
  std::string exe_path_;  // absolute path of the guest program (what /proc/self/exe shows it)
  LinuxThread main_thread_;
  uint64_t brk_start_ = 0, brk_current_ = 0, brk_limit_ = 0;
  uint64_t sigreturn_trampoline_ = 0;
  uint64_t last_code_page_ = ~0ull;  // last page read_code verified as readable
  std::atomic<int> live_threads_{1};
  std::mutex actions_mutex_;
  std::array<GuestSigaction, 65> actions_{};
};

}  // namespace juice::lx
