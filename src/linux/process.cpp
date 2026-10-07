#include "linux/process.hpp"

#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <format>
#include <random>

#include "core/arm64/decode/instruction.hpp"
#include "linux/abi/initial_stack.hpp"
#include "linux/abi/translate.hpp"

#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif

namespace juice::lx {

namespace {

thread_local LinuxThread* t_thread = nullptr;
LinuxProcess* g_process = nullptr;

constexpr uint64_t kBrkReserve = uint64_t{1} << 30;  // address space reserved for brk()
constexpr uint64_t kDefaultStack = uint64_t{8} << 20;

int host_tid() { return static_cast<int>(::syscall(SYS_gettid)); }

struct ThreadStart {
  LinuxProcess* process;
  LinuxThread* thread;
  uint64_t set_child_tid;  // CLONE_CHILD_SETTID address, or 0
  std::atomic<int> tid{0};
};

}  // namespace

LinuxThread* LinuxProcess::current_thread() { return t_thread; }
LinuxProcess* LinuxProcess::instance() { return g_process; }

LinuxProcess::LinuxProcess(Options options) : options_(std::move(options)) { g_process = this; }

LinuxProcess::~LinuxProcess() {
  if (g_process == this) g_process = nullptr;
}

// --- loading -------------------------------------------------------------------------

std::expected<LinuxProcess::Mapped, std::string> LinuxProcess::map_elf(const std::string& path, bool main_program,
                                                                       ElfFile& elf) {
  const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
  if (fd < 0) return std::unexpected(std::format("cannot open '{}': {}", path, std::strerror(errno)));
  struct Closer {
    int fd;
    ~Closer() { ::close(fd); }
  } closer{fd};

  auto parsed = parse_elf([&](uint64_t off, void* out, size_t n) {
    return ::pread(fd, out, n, static_cast<off_t>(off)) == static_cast<ssize_t>(n);
  });
  if (!parsed) return std::unexpected(std::format("'{}': {}", path, parsed.error()));
  elf = std::move(*parsed);

  // Reserve the whole extent first: position-independent images go wherever
  // the kernel finds room, fixed-address ones exactly where they ask.
  const uint64_t span = elf.max_vaddr - elf.min_vaddr;
  void* hint = elf.is_dynamic() ? nullptr : reinterpret_cast<void*>(elf.min_vaddr);
  const int fixed = elf.is_dynamic() ? 0 : MAP_FIXED_NOREPLACE;
  void* region = ::mmap(hint, span, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE | fixed, -1, 0);
  if (region == MAP_FAILED || (!elf.is_dynamic() && region != hint)) {
    return std::unexpected(std::format("'{}': cannot reserve 0x{:x} bytes at 0x{:x}: {}", path, span, elf.min_vaddr,
                                       region == MAP_FAILED ? std::strerror(errno) : "address in use"));
  }
  const uint64_t bias = reinterpret_cast<uint64_t>(region) - elf.min_vaddr;

  for (const ElfSegment& seg : elf.segments) {
    if (seg.type != kPtLoad || seg.memsz == 0) continue;
    // Guest code is never executed by the host: map without PROT_EXEC, but
    // always readable (execute-only segments must still be translated).
    const int prot = PROT_READ | ((seg.flags & kPfW) ? PROT_WRITE : 0);
    const uint64_t start = page_down(bias + seg.vaddr);
    const uint64_t file_end = bias + seg.vaddr + seg.filesz;
    const uint64_t mem_end = bias + seg.vaddr + seg.memsz;
    if (seg.filesz) {
      void* m = ::mmap(reinterpret_cast<void*>(start), page_up(file_end) - start, prot | PROT_WRITE,
                       MAP_PRIVATE | MAP_FIXED, fd, static_cast<off_t>(page_down(seg.offset)));
      if (m == MAP_FAILED) return std::unexpected(std::format("'{}': cannot map a segment: {}", path, std::strerror(errno)));
      // The rest of the last file page belongs to .bss: zero it.
      if (seg.memsz > seg.filesz && page_up(file_end) > file_end)
        std::memset(reinterpret_cast<void*>(file_end), 0, page_up(file_end) - file_end);
    }
    const uint64_t anon_start = seg.filesz ? page_up(file_end) : start;
    if (page_up(mem_end) > anon_start) {
      void* m = ::mmap(reinterpret_cast<void*>(anon_start), page_up(mem_end) - anon_start, prot,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
      if (m == MAP_FAILED) return std::unexpected(std::format("'{}': cannot map .bss: {}", path, std::strerror(errno)));
    }
    if (seg.filesz) ::mprotect(reinterpret_cast<void*>(start), page_up(file_end) - start, prot);
  }

  Mapped m;
  m.base = bias;
  m.entry = bias + elf.entry;
  m.phnum = elf.phnum;
  m.end = bias + elf.max_vaddr;
  if (elf.phdr_vaddr) {
    m.phdr = bias + elf.phdr_vaddr;
  } else if (main_program) {
    // Headers not in any segment: give the program a copy for AT_PHDR.
    const size_t size = size_t{elf.phnum} * elf.phentsize;
    void* copy = ::mmap(nullptr, page_up(size), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (copy == MAP_FAILED || ::pread(fd, copy, size, static_cast<off_t>(elf.phoff)) != static_cast<ssize_t>(size))
      return std::unexpected("cannot read the program headers");
    m.phdr = reinterpret_cast<uint64_t>(copy);
  }
  return m;
}

// The guest's ELF interpreter: under the sysroot if one is given, on the host
// if it has the file (Debian/Ubuntu multiarch), else in the usual cross
// toolchain sysroots.
std::string LinuxProcess::find_interpreter(const std::string& interp) const {
  auto exists = [](const std::string& p) { return ::access(p.c_str(), R_OK) == 0; };
  if (!options_.sysroot.empty()) return options_.sysroot + interp;
  if (exists(interp)) return interp;
  for (const char* root : {"/usr/aarch64-linux-gnu", "/usr/aarch64-linux-gnu/sys-root", "/usr/aarch64-linux-musl"}) {
    if (exists(root + interp)) return root + interp;
  }
  return interp;
}

std::expected<void, std::string> LinuxProcess::load(const std::string& path, const std::vector<std::string>& args,
                                                    char** envp) {
  std::error_code ec;
  const auto absolute = std::filesystem::absolute(path, ec);
  exe_path_ = ec ? path : absolute.string();

  ElfFile exe;
  auto main = map_elf(path, true, exe);
  if (!main) return std::unexpected(main.error());

  uint64_t entry = main->entry;
  uint64_t interp_base = 0;
  if (!exe.interpreter.empty()) {
    const std::string interp_path = find_interpreter(exe.interpreter);
    // Remember the sysroot the interpreter came from: the guest's ld.so then
    // finds its libraries there too.
    if (options_.sysroot.empty() && interp_path != exe.interpreter)
      options_.sysroot = interp_path.substr(0, interp_path.size() - exe.interpreter.size());
    ElfFile interp;
    auto loaded = map_elf(interp_path, false, interp);
    if (!loaded) {
      return std::unexpected(std::format(
          "{}\n(the program is dynamically linked: install the AArch64 C library, e.g. libc6:arm64 or "
          "libc6-arm64-cross, or name its root with --sysroot)",
          loaded.error()));
    }
    interp_base = loaded->base;
    entry = loaded->entry;
  }

  // brk() heap after the program, as the kernel places it.
  brk_start_ = brk_current_ = page_up(main->end);
  void* heap = ::mmap(reinterpret_cast<void*>(brk_start_), kBrkReserve, PROT_NONE,
                      MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE | MAP_FIXED_NOREPLACE, -1, 0);
  brk_limit_ = heap == reinterpret_cast<void*>(brk_start_) ? brk_start_ + kBrkReserve : brk_start_;

  // The guest stack.
  rlimit limit{};
  uint64_t stack_size = kDefaultStack;
  if (::getrlimit(RLIMIT_STACK, &limit) == 0 && limit.rlim_cur != RLIM_INFINITY)
    stack_size = std::clamp<uint64_t>(limit.rlim_cur, 1 << 20, 256ull << 20);
  void* stack = ::mmap(nullptr, stack_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
  if (stack == MAP_FAILED) return std::unexpected("cannot allocate the guest stack");
  ::mprotect(stack, kPageSize, PROT_NONE);  // guard page
  const uint64_t stack_top = reinterpret_cast<uint64_t>(stack) + stack_size;

  // rt_sigreturn trampoline for signal handlers without SA_RESTORER:
  //   mov x8, #139 (rt_sigreturn); svc #0
  void* tramp = ::mmap(nullptr, kPageSize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (tramp == MAP_FAILED) return std::unexpected("cannot allocate the signal trampoline");
  const uint32_t code[2] = {0xD2801168u, 0xD4000001u};
  std::memcpy(tramp, code, sizeof(code));
  ::mprotect(tramp, kPageSize, PROT_READ);
  sigreturn_trampoline_ = reinterpret_cast<uint64_t>(tramp);

  InitialStackInput in;
  in.argv.push_back(options_.argv0.empty() ? path : options_.argv0);
  in.argv.insert(in.argv.end(), args.begin(), args.end());
  for (char** e = envp; e && *e; ++e) in.envp.emplace_back(*e);
  in.execfn = path;
  std::random_device rd;
  for (auto& b : in.random) b = static_cast<uint8_t>(rd());
  in.auxv = {
      {kAtPhdr, main->phdr},
      {kAtPhent, 56},
      {kAtPhnum, main->phnum},
      {kAtPagesz, kPageSize},
      {kAtBase, interp_base},
      {kAtFlags, 0},
      {kAtEntry, main->entry},
      {kAtUid, ::getuid()},
      {kAtEuid, ::geteuid()},
      {kAtGid, ::getgid()},
      {kAtEgid, ::getegid()},
      {kAtHwcap, kHwcaps},
      {kAtHwcap2, kHwcaps2},
      {kAtClktck, static_cast<uint64_t>(::sysconf(_SC_CLK_TCK))},
      {kAtSecure, 0},
      {kAtMinsigstksz, 8192},
  };
  const uint64_t sp = build_initial_stack(stack_top, reinterpret_cast<uint64_t>(stack) + kPageSize, in);
  if (!sp) return std::unexpected("arguments and environment do not fit on the stack");

  arm64::CpuState& s = main_thread_.state;
  s = {};
  s.sp = sp;
  s.pc = entry;

  options_.engine.tls_vector_offset = 0;  // Linux code addresses TLS through TPIDR_EL0
  engine_ = std::make_unique<runtime::Engine>(*this, options_.engine);
  init_signals();
  return {};
}

// --- running ---------------------------------------------------------------------------

void LinuxProcess::run() {
  main_thread_.tid = host_tid();
  t_thread = &main_thread_;
  engine_->run(main_thread_.state);
  // The main thread called exit(): the process lives on while other threads run.
  ::pthread_exit(nullptr);
}

bool LinuxProcess::read_code(uint64_t addr, uint32_t& word) {
  // Called with the engine's translation lock held: one thread at a time.
  const uint64_t page = page_down(addr);
  if (page != last_code_page_) {
    iovec local{&word, sizeof(word)};
    iovec remote{reinterpret_cast<void*>(addr), sizeof(word)};
    const ssize_t n = ::process_vm_readv(::getpid(), &local, 1, &remote, 1, 0);
    if (n != static_cast<ssize_t>(sizeof(word)) && !(n < 0 && errno == ENOSYS)) return false;
    last_code_page_ = page;
  }
  std::memcpy(&word, reinterpret_cast<const void*>(addr), sizeof(word));
  return true;
}

runtime::Action LinuxProcess::on_exit(arm64::CpuState& s) {
  const auto reason = static_cast<arm64::ExitReason>(s.exit_reason);
  switch (reason) {
    case arm64::ExitReason::Svc: {
      const int64_t r = do_syscall(s);
      if (r != kNoResult) s.x[0] = static_cast<uint64_t>(r);
      // exit() of this thread
      if (t_thread && t_thread->tid == 0) return runtime::Action::Stop;
      return runtime::Action::Continue;
    }
    case arm64::ExitReason::Brk:
    case arm64::ExitReason::Hlt: {
      siginfo_t info{};
      info.si_signo = SIGTRAP;
      info.si_code = 1;  // TRAP_BRKPT
      if (deliver_signal(s, SIGTRAP, &info, t_thread->blocked) != Delivery::Unhandled) return runtime::Action::Continue;
      fatal(std::format("guest executed BRK #0x{:x} at 0x{:x}", s.exit_info, s.pc), SIGTRAP);
    }
    case arm64::ExitReason::Undefined:
    case arm64::ExitReason::Unsupported: {
      siginfo_t info{};
      info.si_signo = SIGILL;
      info.si_code = 1;  // ILL_ILLOPC
      info.si_addr = reinterpret_cast<void*>(s.pc);
      if (reason == arm64::ExitReason::Undefined &&
          deliver_signal(s, SIGILL, &info, t_thread->blocked) != Delivery::Unhandled)
        return runtime::Action::Continue;
      uint32_t word = 0;
      read_code(s.pc, word);
      fatal(std::format("{} at 0x{:x}: {:08x}  {}", arm64::to_string(reason), s.pc, word,
                        arm64::disassemble(arm64::decode(word, s.pc))),
            SIGILL);
    }
    case arm64::ExitReason::FetchFault:
      fatal(std::format("guest jumped to unmapped address 0x{:x}", s.pc), SIGSEGV);
    case arm64::ExitReason::None:
    case arm64::ExitReason::CodeModified:  // handled by the Engine
      break;
  }
  return runtime::Action::Continue;
}

// --- threads and processes ----------------------------------------------------------

void* LinuxProcess::thread_main(void* p) {
  auto* start = static_cast<ThreadStart*>(p);
  LinuxProcess* process = start->process;
  LinuxThread* t = start->thread;
  t->tid = host_tid();
  t_thread = t;
  if (start->set_child_tid) *reinterpret_cast<uint32_t*>(start->set_child_tid) = static_cast<uint32_t>(t->tid);
  start->tid.store(t->tid, std::memory_order_release);
  start->tid.notify_one();  // `start` belongs to the parent from here on
  process->engine_->run(t->state);
  t_thread = nullptr;
  delete t;
  return nullptr;
}

int64_t LinuxProcess::sys_clone(arm64::CpuState& s, uint64_t flags, uint64_t newsp, uint64_t ptid, uint64_t tls,
                                uint64_t ctid) {
  LinuxThread& self = *t_thread;
  if ((flags & CLONE_VM) && (flags & CLONE_THREAD)) {
    // A new thread: a host thread running the engine on a copy of this state.
    auto* t = new LinuxThread;
    t->state = s;
    t->state.x[0] = 0;
    t->state.exit_reason = 0;  // the parent's SVC exit is still recorded in `s`
    t->state.exit_info = 0;
    t->state.interrupt = 0;
    if (newsp) t->state.sp = newsp;
    if (flags & CLONE_SETTLS) t->state.tpidr_el0 = tls;
    t->clear_child_tid = (flags & CLONE_CHILD_CLEARTID) ? ctid : 0;
    t->blocked = self.blocked;
    ThreadStart start{this, t, (flags & CLONE_CHILD_SETTID) ? ctid : 0};
    live_threads_.fetch_add(1);
    pthread_attr_t attr;
    ::pthread_attr_init(&attr);
    ::pthread_attr_setstacksize(&attr, size_t{2} << 20);
    ::pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_t thread;
    const int err = ::pthread_create(&thread, &attr, &LinuxProcess::thread_main, &start);  // inherits our signal mask
    ::pthread_attr_destroy(&attr);
    if (err) {
      live_threads_.fetch_sub(1);
      delete t;
      return -err;
    }
    start.tid.wait(0, std::memory_order_acquire);
    const int tid = start.tid.load(std::memory_order_acquire);
    if (flags & CLONE_PARENT_SETTID) *reinterpret_cast<uint32_t*>(ptid) = static_cast<uint32_t>(tid);
    return tid;
  }

  // A new process (fork, vfork, posix_spawn's CLONE_VM | CLONE_VFORK): fork
  // the whole emulator. A vfork child gets a copy instead of shared memory,
  // which is enough for the child that just calls execve.
  pid_t pid;
  {
    auto lock = engine_->lock_for_fork();
    pid = ::fork();
  }
  if (pid < 0) return -errno;
  if (pid == 0) {
    live_threads_.store(1);  // only this thread survives fork()
    self.tid = host_tid();
    if (newsp) s.sp = newsp;
    if (flags & CLONE_SETTLS) s.tpidr_el0 = tls;
    if (flags & CLONE_CHILD_SETTID) *reinterpret_cast<uint32_t*>(ctid) = static_cast<uint32_t>(self.tid);
    if (flags & CLONE_CHILD_CLEARTID) self.clear_child_tid = ctid;
    return 0;
  }
  if (flags & CLONE_PARENT_SETTID) *reinterpret_cast<uint32_t*>(ptid) = static_cast<uint32_t>(pid);
  return pid;
}

void LinuxProcess::exit_thread(int status) {
  LinuxThread& t = *t_thread;
  // The last thread's exit ends the process with its status.
  if (live_threads_.fetch_sub(1) == 1) exit_process(status);
  if (t.clear_child_tid) {
    std::atomic_ref<uint32_t>(*reinterpret_cast<uint32_t*>(t.clear_child_tid)).store(0);
    ::syscall(SYS_futex, t.clear_child_tid, 1 /* FUTEX_WAKE */, 1, nullptr, nullptr, 0);
  }
  t.tid = 0;  // on_exit stops the engine for this thread
}

void LinuxProcess::exit_process(int status) {
  std::fflush(stdout);
  if (options_.stats && engine_) engine_->print_stats(stderr);
  std::fflush(stderr);
  ::syscall(SYS_exit_group, status);
  __builtin_unreachable();
}

// --- diagnostics -------------------------------------------------------------------------

void LinuxProcess::dump_state(const arm64::CpuState& s) const {
  std::fprintf(stderr, "[juice]   pc 0x%016llx  sp 0x%016llx  nzcv 0x%llx\n", static_cast<unsigned long long>(s.pc),
               static_cast<unsigned long long>(s.sp), static_cast<unsigned long long>(s.nzcv));
  for (int i = 0; i < 31; i += 3) {
    std::string line = "[juice]  ";
    for (int k = i; k < std::min(i + 3, 31); ++k) line += std::format(" x{:<2} 0x{:016x}", k, s.x[k]);
    std::fprintf(stderr, "%s\n", line.c_str());
  }
}

void LinuxProcess::fatal(const std::string& message, int sig) {
  std::fflush(stdout);
  std::fprintf(stderr, "[juice] error: %s\n[juice]   in %s\n", message.c_str(), exe_path_.c_str());
  if (t_thread) dump_state(t_thread->state);
  std::fflush(stderr);
  // End the way the guest would have: by the signal, with its default action.
  struct sigaction dfl{};
  dfl.sa_handler = SIG_DFL;
  ::sigaction(sig, &dfl, nullptr);
  sigset_t set;
  sigemptyset(&set);
  sigaddset(&set, sig);
  ::pthread_sigmask(SIG_UNBLOCK, &set, nullptr);
  ::syscall(SYS_tgkill, ::getpid(), host_tid(), sig);
  ::_exit(128 + sig);
}

}  // namespace juice::lx
