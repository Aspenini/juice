// System calls of Linux AArch64 guests, served by the x86-64 host kernel.
//
// Guest and host share the address space, so most calls go straight to the
// host with the same arguments (only the numbers differ: AArch64 uses the
// asm-generic table). The rest need work:
//   - layouts that differ: struct stat, struct epoll_event;
//   - flag values that differ: O_DIRECTORY, O_NOFOLLOW, O_DIRECT, O_LARGEFILE;
//   - state JUICE emulates: brk, threads, signals, the program's own path;
//   - memory that holds guest code: mmap/munmap/mprotect drop translations;
//   - things that would reach the emulator itself: execve, rseq, seccomp, ptrace.
// Absolute paths the guest looks up are tried under the sysroot first (like
// QEMU_LD_PREFIX), which is how the guest's ld.so finds its libraries.

#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <format>
#include <vector>

#include "linux/abi/syscalls.hpp"
#include "linux/abi/translate.hpp"
#include "linux/process.hpp"

namespace juice::lx {

namespace {

int64_t host(long nr, uint64_t a0 = 0, uint64_t a1 = 0, uint64_t a2 = 0, uint64_t a3 = 0, uint64_t a4 = 0,
             uint64_t a5 = 0) {
  const long r = ::syscall(nr, a0, a1, a2, a3, a4, a5);
  return r == -1 ? -errno : r;
}

template <typename T>
T* ptr(uint64_t addr) {
  return reinterpret_cast<T*>(addr);
}

// AArch64 numbers of the calls that pass straight through, mapped to the host's.
std::array<int16_t, 512> make_passthrough() {
  std::array<int16_t, 512> t;
  t.fill(-1);
#define P(n) t[sys::n] = SYS_##n;
  P(io_setup) P(io_destroy) P(io_submit) P(io_cancel) P(io_getevents) P(setxattr) P(lsetxattr) P(fsetxattr)
  P(getxattr) P(lgetxattr) P(fgetxattr) P(listxattr) P(llistxattr) P(flistxattr) P(removexattr) P(lremovexattr)
  P(fremovexattr) P(getcwd) P(eventfd2) P(epoll_create1) P(dup) P(dup3) P(inotify_init1)
  P(inotify_add_watch) P(inotify_rm_watch) P(ioctl) P(ioprio_set) P(ioprio_get) P(flock) P(mknodat) P(mkdirat)
  P(unlinkat) P(symlinkat) P(linkat) P(renameat) P(umount2) P(mount) P(pivot_root) P(statfs) P(fstatfs)
  P(truncate) P(ftruncate) P(fallocate) P(chdir) P(fchdir) P(chroot) P(fchmod) P(fchmodat) P(fchownat) P(fchown)
  P(close) P(vhangup) P(quotactl) P(getdents64) P(lseek) P(read) P(write) P(readv) P(writev) P(pread64)
  P(pwrite64) P(preadv) P(pwritev) P(sendfile) P(signalfd4) P(vmsplice) P(splice) P(tee) P(sync) P(fsync)
  P(fdatasync) P(sync_file_range) P(timerfd_create) P(timerfd_settime) P(timerfd_gettime) P(utimensat) P(acct)
  P(capget) P(capset) P(personality) P(waitid) P(unshare) P(futex) P(nanosleep) P(getitimer) P(setitimer)
  P(timer_create) P(timer_gettime) P(timer_getoverrun) P(timer_settime) P(timer_delete) P(clock_settime)
  P(clock_gettime) P(clock_getres) P(clock_nanosleep) P(syslog) P(sched_setparam) P(sched_setscheduler)
  P(sched_getscheduler) P(sched_getparam) P(sched_setaffinity) P(sched_getaffinity) P(sched_yield)
  P(sched_get_priority_max) P(sched_get_priority_min) P(sched_rr_get_interval) P(kill) P(tkill) P(tgkill)
  P(rt_sigtimedwait) P(rt_sigqueueinfo) P(setpriority) P(getpriority) P(setregid) P(setgid)
  P(setreuid) P(setuid) P(setresuid) P(getresuid) P(setresgid) P(getresgid) P(setfsuid) P(setfsgid) P(times)
  P(setpgid) P(getpgid) P(getsid) P(setsid) P(getgroups) P(setgroups) P(sethostname) P(setdomainname)
  P(getrlimit) P(setrlimit) P(getrusage) P(umask) P(getcpu) P(gettimeofday) P(settimeofday) P(adjtimex)
  P(getpid) P(getppid) P(getuid) P(geteuid) P(getgid) P(getegid) P(gettid) P(sysinfo) P(mq_open) P(mq_unlink)
  P(mq_timedsend) P(mq_timedreceive) P(mq_notify) P(mq_getsetattr) P(msgget) P(msgctl) P(msgrcv) P(msgsnd)
  P(semget) P(semctl) P(semtimedop) P(semop) P(shmget) P(shmctl) P(shmat) P(shmdt) P(socket) P(socketpair)
  P(bind) P(listen) P(accept) P(connect) P(getsockname) P(getpeername) P(sendto) P(recvfrom) P(setsockopt)
  P(getsockopt) P(shutdown) P(sendmsg) P(recvmsg) P(readahead) P(add_key) P(request_key) P(keyctl)
  P(fadvise64) P(msync) P(mlock) P(munlock) P(mlockall) P(munlockall) P(mincore) P(madvise) P(mbind)
  P(get_mempolicy) P(set_mempolicy) P(migrate_pages) P(move_pages) P(rt_tgsigqueueinfo) P(perf_event_open)
  P(accept4) P(recvmmsg) P(wait4) P(prlimit64) P(fanotify_init) P(fanotify_mark) P(name_to_handle_at)
  P(open_by_handle_at) P(clock_adjtime) P(syncfs) P(setns) P(sendmmsg) P(process_vm_readv) P(process_vm_writev)
  P(kcmp) P(sched_setattr) P(sched_getattr) P(renameat2) P(getrandom) P(memfd_create) P(userfaultfd)
  P(membarrier) P(mlock2) P(copy_file_range) P(preadv2) P(pwritev2) P(pkey_alloc) P(pkey_free)
  // Newer than some host headers.
#ifdef SYS_pidfd_send_signal
  P(pidfd_send_signal)
#endif
#ifdef SYS_pidfd_open
  P(pidfd_open)
#endif
#ifdef SYS_close_range
  P(close_range)
#endif
#ifdef SYS_pidfd_getfd
  P(pidfd_getfd)
#endif
#ifdef SYS_process_madvise
  P(process_madvise)
#endif
#ifdef SYS_futex_waitv
  P(futex_waitv)
#endif
#ifdef SYS_memfd_secret
  P(memfd_secret)
#endif
#ifdef SYS_cachestat
  P(cachestat)
#endif
#ifdef SYS_fchmodat2
  P(fchmodat2)
#endif
#ifdef SYS_futex_wake
  P(futex_wake) P(futex_wait) P(futex_requeue)
#endif
#undef P
  return t;
}

const std::array<int16_t, 512> kPassthrough = make_passthrough();

// mmap/mprotect protection for guest memory. Guest code is only read by the
// translator, never executed by the host: executable means readable.
uint64_t host_prot(uint64_t prot) {
  constexpr uint64_t kProtBti = 0x10, kProtMte = 0x20;  // AArch64-only
  prot &= ~(kProtBti | kProtMte);
  if (prot & PROT_EXEC) prot = (prot & ~uint64_t{PROT_EXEC}) | PROT_READ;
  return prot;
}

// Calls that sleep: with a signal handler run, they fail with EINTR even
// under SA_RESTART (signal(7)).
bool never_restarted(uint64_t nr) {
  switch (nr) {
    case sys::nanosleep: case sys::clock_nanosleep: case sys::rt_sigsuspend: case sys::rt_sigtimedwait:
    case sys::ppoll: case sys::pselect6: case sys::epoll_pwait: case sys::epoll_pwait2: case sys::io_getevents:
    case sys::io_pgetevents: case sys::semtimedop: case sys::semop: case sys::msgrcv: case sys::msgsnd:
      return true;
    default:
      return false;
  }
}

std::vector<std::string> read_string_vector(uint64_t addr) {
  std::vector<std::string> v;
  for (auto* p = ptr<const uint64_t>(addr); p && *p; ++p) v.emplace_back(ptr<const char>(*p));
  return v;
}

// First bytes of a file (for execve), empty if it cannot be read.
std::string read_head(const std::string& path, size_t n) {
  std::string head(n, '\0');
  const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
  if (fd < 0) return {};
  const ssize_t got = ::read(fd, head.data(), n);
  ::close(fd);
  head.resize(got > 0 ? static_cast<size_t>(got) : 0);
  return head;
}

bool is_guest_elf(const std::string& head) {
  return elf_machine(reinterpret_cast<const uint8_t*>(head.data()), head.size()) == kEmAarch64;
}

}  // namespace

// --- paths ----------------------------------------------------------------------------

bool LinuxProcess::is_self_exe(const char* path) const {
  if (!path) return false;
  if (!std::strcmp(path, "/proc/self/exe") || !std::strcmp(path, "/proc/thread-self/exe")) return true;
  return std::format("/proc/{}/exe", ::getpid()) == path;
}

std::string LinuxProcess::guest_path(const char* path) const {
  if (!path) return {};
  if (is_self_exe(path)) return exe_path_;
  if (path[0] != '/' || path[1] == '\0' || options_.sysroot.empty()) return path;
  // The kernel's file systems are the host's.
  for (const char* host_only : {"/proc/", "/sys/", "/dev/", "/tmp/", "/run/"}) {
    if (!std::strncmp(path, host_only, std::strlen(host_only))) return path;
  }
  std::string redirected = options_.sysroot + path;
  struct stat st;
  if (::lstat(redirected.c_str(), &st) == 0) return redirected;
  return path;
}

std::vector<std::string> LinuxProcess::juice_arguments() const {
  std::vector<std::string> a;
  if (!options_.sysroot.empty()) a.push_back("--sysroot=" + options_.sysroot);
  if (options_.trace_syscalls) a.emplace_back("--strace");
  if (!options_.engine.optimize) a.emplace_back("--no-opt");
  if (options_.engine.interpret) a.emplace_back("--interp");
  return a;
}

// --- dispatch -----------------------------------------------------------------------------

int64_t LinuxProcess::do_syscall(arm64::CpuState& s) {
  const uint64_t nr = s.x[8];
  const uint64_t a0 = s.x[0], a1 = s.x[1], a2 = s.x[2], a3 = s.x[3], a4 = s.x[4], a5 = s.x[5];
  LinuxThread& t = *current_thread();
  int64_t r = -ENOSYS;
  // A mask the call installs while it waits (sigsuspend, ppoll, pselect, epoll_pwait).
  uint64_t wait_mask_addr = 0;

  switch (nr) {
    // --- files --------------------------------------------------------------------------
    case sys::openat: {
      const std::string path = guest_path(ptr<const char>(a1));
      r = host(SYS_openat, a0, reinterpret_cast<uint64_t>(path.c_str()), open_flags_to_host(static_cast<uint32_t>(a2)),
               a3);
      break;
    }
    case sys::openat2:
      r = -ENOSYS;  // the C library falls back to openat
      break;
    case sys::faccessat:
    case sys::faccessat2: {
      const std::string path = guest_path(ptr<const char>(a1));
      r = nr == sys::faccessat ? host(SYS_faccessat, a0, reinterpret_cast<uint64_t>(path.c_str()), a2)
#ifdef SYS_faccessat2
                               : host(SYS_faccessat2, a0, reinterpret_cast<uint64_t>(path.c_str()), a2, a3);
#else
                               : -ENOSYS;
#endif
      break;
    }
    case sys::readlinkat: {
      const char* path = ptr<const char>(a1);
      if (is_self_exe(path)) {
        const size_t n = std::min<size_t>(exe_path_.size(), a3);
        std::memcpy(ptr<char>(a2), exe_path_.data(), n);
        r = static_cast<int64_t>(n);
      } else {
        const std::string p = guest_path(path);
        r = host(SYS_readlinkat, a0, reinterpret_cast<uint64_t>(p.c_str()), a2, a3);
      }
      break;
    }
    case sys::newfstatat:
    case sys::fstat: {
      X64Stat st{};
      if (nr == sys::fstat) {
        r = host(SYS_fstat, a0, reinterpret_cast<uint64_t>(&st));
      } else {
        const std::string path = guest_path(ptr<const char>(a1));
        r = host(SYS_newfstatat, a0, reinterpret_cast<uint64_t>(path.c_str()), reinterpret_cast<uint64_t>(&st), a3);
      }
      if (r == 0) {
        const Arm64Stat out = to_arm64(st);
        std::memcpy(ptr<void>(nr == sys::fstat ? a1 : a2), &out, sizeof(out));
      }
      break;
    }
    case sys::statx: {
      const std::string path = guest_path(ptr<const char>(a1));
      r = host(SYS_statx, a0, reinterpret_cast<uint64_t>(path.c_str()), a2, a3, a4);
      break;
    }
    case sys::fcntl:
      if (a1 == F_SETFL) {
        r = host(SYS_fcntl, a0, a1, open_flags_to_host(static_cast<uint32_t>(a2)));
      } else {
        r = host(SYS_fcntl, a0, a1, a2);
        if (a1 == F_GETFL && r >= 0) r = open_flags_to_guest(static_cast<uint32_t>(r));
      }
      break;
    case sys::pipe2:
      r = host(SYS_pipe2, a0, open_flags_to_host(static_cast<uint32_t>(a1)));
      break;

    // --- epoll: 16-byte events on AArch64, packed 12-byte ones on x86-64 ----------
    case sys::epoll_ctl: {
      X64EpollEvent ev{};
      if (a3) {
        Arm64EpollEvent in;
        std::memcpy(&in, ptr<void>(a3), sizeof(in));
        ev.events = in.events;
        ev.data = in.data;
      }
      r = host(SYS_epoll_ctl, a0, a1, a2, a3 ? reinterpret_cast<uint64_t>(&ev) : 0);
      break;
    }
    case sys::epoll_pwait:
    case sys::epoll_pwait2: {
      const int max = static_cast<int>(a2);
      if (max <= 0 || max > (1 << 20)) {
        r = -EINVAL;
        break;
      }
      std::vector<X64EpollEvent> events(static_cast<size_t>(max));
      const uint64_t buf = reinterpret_cast<uint64_t>(events.data());
#ifdef SYS_epoll_pwait2
      r = nr == sys::epoll_pwait ? host(SYS_epoll_pwait, a0, buf, a2, a3, a4, a5)
                                 : host(SYS_epoll_pwait2, a0, buf, a2, a3, a4, a5);
#else
      r = nr == sys::epoll_pwait ? host(SYS_epoll_pwait, a0, buf, a2, a3, a4, a5) : -ENOSYS;
#endif
      for (int64_t i = 0; i < r; ++i) {
        const Arm64EpollEvent out{events[i].events, 0, events[i].data};
        std::memcpy(ptr<Arm64EpollEvent>(a1) + i, &out, sizeof(out));
      }
      wait_mask_addr = a4;
      break;
    }
    case sys::ppoll:
      r = host(SYS_ppoll, a0, a1, a2, a3, a4);
      wait_mask_addr = a3;
      break;
    case sys::pselect6:
      r = host(SYS_pselect6, a0, a1, a2, a3, a4, a5);
      if (a5) wait_mask_addr = *ptr<const uint64_t>(a5);  // { const sigset_t* ss; size_t ss_len; }
      break;

    // --- memory ---------------------------------------------------------------------------
    case sys::brk:
      r = sys_brk(a0);
      break;
    case sys::mmap:
      r = host(SYS_mmap, a0, a1, host_prot(a2), a3, a4, a5);
      // New mappings at fresh addresses hold no translated code (munmap
      // dropped it); a fixed mapping may replace some.
      if (r >= 0 && (a3 & MAP_FIXED)) {
        engine_->invalidate(static_cast<uint64_t>(r), static_cast<uint64_t>(r) + page_up(a1));
        last_code_page_ = ~0ull;
      }
      break;
    case sys::munmap:
      r = host(SYS_munmap, a0, a1);
      if (r == 0) {
        engine_->invalidate(a0, a0 + page_up(a1));
        last_code_page_ = ~0ull;
      }
      break;
    case sys::mremap:
      r = host(SYS_mremap, a0, a1, a2, a3, a4);
      if (r >= 0) {
        engine_->invalidate(a0, a0 + page_up(a1));
        if (static_cast<uint64_t>(r) != a0) engine_->invalidate(static_cast<uint64_t>(r), r + page_up(a2));
        last_code_page_ = ~0ull;
      }
      break;
    case sys::mprotect:
    case sys::pkey_mprotect:
      r = nr == sys::mprotect ? host(SYS_mprotect, a0, a1, host_prot(a2))
                              : host(SYS_pkey_mprotect, a0, a1, host_prot(a2), a3);
      // Made executable: a code generator finished writing (W^X).
      if (r == 0 && (a2 & PROT_EXEC)) engine_->invalidate(a0, a0 + page_up(a1));
      if (r == 0) last_code_page_ = ~0ull;
      break;
    case sys::remap_file_pages:
      r = -ENOSYS;
      break;

    // --- threads and processes -------------------------------------------------------
    case sys::clone:
      r = sys_clone(s, a0, a1, a2, a3, a4);
      break;
    case sys::clone3:
      r = -ENOSYS;  // the C library falls back to clone
      break;
    case sys::execve:
      r = sys_execve(a0, a1, a2);
      break;
    case sys::execveat:
      r = -ENOSYS;
      break;
    case sys::exit:
      exit_thread(static_cast<int>(a0));
      return kNoResult;
    case sys::exit_group:
      exit_process(static_cast<int>(a0));
    case sys::set_tid_address:
      t.clear_child_tid = a0;
      r = t.tid;
      break;
    case sys::set_robust_list:
      // Recorded only: the host C library keeps its own list for this thread.
      if (a1 != 24) {
        r = -EINVAL;
        break;
      }
      t.robust_list = a0;
      r = 0;
      break;
    case sys::get_robust_list:
      if (a0 != 0 && static_cast<int>(a0) != t.tid) {
        r = -EPERM;
        break;
      }
      *ptr<uint64_t>(a1) = t.robust_list;
      *ptr<uint64_t>(a2) = 24;
      r = 0;
      break;
    case sys::rseq:
      r = -ENOSYS;  // the host C library has registered the host thread's
      break;

    // --- signals --------------------------------------------------------------------------
    case sys::rt_sigaction:
      r = sys_rt_sigaction(static_cast<int>(a0), a1, a2, a3);
      break;
    case sys::rt_sigprocmask:
      r = sys_rt_sigprocmask(static_cast<int>(a0), a1, a2, a3);
      break;
    case sys::sigaltstack:
      r = sys_sigaltstack(a0, a1);
      break;
    case sys::rt_sigreturn:
      return sys_rt_sigreturn(s);
    case sys::rt_sigsuspend:
      r = host(SYS_rt_sigsuspend, a0, a1);
      wait_mask_addr = a0;
      break;
    case sys::rt_sigpending:
      r = host(SYS_rt_sigpending, a0, a1);
      // Plus what JUICE caught but holds back because the guest blocks it.
      if (r == 0) *ptr<uint64_t>(a0) |= t.pending.load(std::memory_order_relaxed) & t.blocked;
      break;

    // --- identity and environment ------------------------------------------------------
    case sys::uname:
      r = host(SYS_uname, a0);
      if (r == 0) std::strcpy(ptr<char>(a0) + 4 * 65, "aarch64");  // utsname.machine
      break;
    case sys::prctl:
      switch (a0) {
        case PR_SET_SECCOMP:
          r = -EINVAL;  // a filter for AArch64 system calls would stop the emulator
          break;
        case PR_SET_MM:
          r = -EPERM;
          break;
        case 0x41555856:  // PR_GET_AUXV
        case 50: case 51:  // PR_SVE_SET_VL, PR_SVE_GET_VL
          r = -EINVAL;
          break;
        default:
          r = host(SYS_prctl, a0, a1, a2, a3, a4);
          break;
      }
      break;
    case sys::seccomp:
      r = -EINVAL;
      break;
    case sys::ptrace:
      r = -EPERM;
      break;
    case sys::io_uring_setup:
    case sys::io_uring_enter:
    case sys::io_uring_register:
      r = -ENOSYS;
      break;

    default:
      if (nr < kPassthrough.size() && kPassthrough[nr] >= 0) {
        r = host(kPassthrough[nr], a0, a1, a2, a3, a4, a5);
      } else if (options_.trace_syscalls) {
        std::fprintf(stderr, "[juice] unsupported system call %llu (%s)\n", static_cast<unsigned long long>(nr),
                     sys::name(nr));
      }
      break;
  }

  if (options_.trace_syscalls) {
    std::fprintf(stderr, "[juice %d] %s(0x%llx, 0x%llx, 0x%llx, 0x%llx) = %lld\n", t.tid, sys::name(nr),
                 static_cast<unsigned long long>(a0), static_cast<unsigned long long>(a1),
                 static_cast<unsigned long long>(a2), static_cast<unsigned long long>(a3),
                 static_cast<long long>(r));
  }

  if (r == -EINTR) {
    if (wait_mask_addr) {
      // The signal arrived under the call's temporary mask, which the guest
      // may block otherwise (sigsuspend's purpose): deliver it under that
      // mask now; the handler's return restores the usual one.
      const uint64_t original = t.blocked;
      s.x[0] = static_cast<uint64_t>(r);  // what the handler's frame saves
      t.blocked = *ptr<const uint64_t>(wait_mask_addr);
      if (!deliver_pending(s, original)) set_guest_mask(t, original);
      return kNoResult;
    }
    if (!never_restarted(nr) && restart_pending(t)) {
      // SA_RESTART: run the SVC again once the handler returns.
      s.pc -= 4;
      return kNoResult;
    }
  }
  return r;
}

// --- brk ---------------------------------------------------------------------------------

int64_t LinuxProcess::sys_brk(uint64_t addr) {
  if (addr < brk_start_ || addr > brk_limit_) return static_cast<int64_t>(brk_current_);
  const uint64_t old_end = page_up(brk_current_), new_end = page_up(addr);
  if (new_end > old_end) {
    if (::mprotect(ptr<void>(old_end), new_end - old_end, PROT_READ | PROT_WRITE) != 0)
      return static_cast<int64_t>(brk_current_);
  } else if (new_end < old_end) {
    // Give the memory back; it reads as zero if the heap grows again.
    ::madvise(ptr<void>(new_end), old_end - new_end, MADV_DONTNEED);
    ::mprotect(ptr<void>(new_end), old_end - new_end, PROT_NONE);
  }
  brk_current_ = addr;
  return static_cast<int64_t>(brk_current_);
}

// --- execve ------------------------------------------------------------------------------

// AArch64 programs (and scripts whose interpreter is one) run in a new JUICE:
// /proc/self/exe with this process's options. Anything else is the host's.
int64_t LinuxProcess::sys_execve(uint64_t path_addr, uint64_t argv_addr, uint64_t envp_addr) {
  const char* guest = ptr<const char>(path_addr);
  if (!guest) return -EFAULT;
  const std::string path = guest_path(guest);
  if (::access(path.c_str(), X_OK) != 0) return -errno;

  std::vector<std::string> argv = read_string_vector(argv_addr);
  std::vector<std::string> program;  // what JUICE runs: the program, then its arguments
  std::string argv0;
  const std::string head = read_head(path, 256);
  if (is_guest_elf(head)) {
    program.push_back(path);
    argv0 = argv.empty() ? std::string(guest) : argv[0];
    if (argv.size() > 1) program.insert(program.end(), argv.begin() + 1, argv.end());
  } else if (head.starts_with("#!")) {
    // "#!interpreter [one argument]"
    std::string line = head.substr(2, head.find('\n') == std::string::npos ? std::string::npos : head.find('\n') - 2);
    auto trim = [](std::string& v) {
      const size_t b = v.find_first_not_of(" \t"), e = v.find_last_not_of(" \t\r");
      v = b == std::string::npos ? std::string() : v.substr(b, e - b + 1);
    };
    trim(line);
    const size_t space = line.find_first_of(" \t");
    std::string interp = line.substr(0, space), arg = space == std::string::npos ? "" : line.substr(space + 1);
    trim(arg);
    const std::string interp_path = guest_path(interp.c_str());
    if (interp.empty() || !is_guest_elf(read_head(interp_path, 64))) {
      return host(SYS_execve, reinterpret_cast<uint64_t>(path.c_str()), argv_addr, envp_addr);
    }
    // The kernel's argv for a script: interpreter, its argument, the script, the rest.
    program.push_back(interp_path);
    argv0 = interp;
    if (!arg.empty()) program.push_back(arg);
    program.emplace_back(guest);
    if (argv.size() > 1) program.insert(program.end(), argv.begin() + 1, argv.end());
  } else {
    return host(SYS_execve, reinterpret_cast<uint64_t>(path.c_str()), argv_addr, envp_addr);
  }

  std::vector<std::string> args = {"juice"};
  for (std::string& a : juice_arguments()) args.push_back(std::move(a));
  args.push_back("--argv0=" + argv0);
  args.emplace_back("--");
  args.insert(args.end(), program.begin(), program.end());
  std::vector<char*> host_argv;
  for (std::string& a : args) host_argv.push_back(a.data());
  host_argv.push_back(nullptr);
  std::fflush(stdout);
  std::fflush(stderr);
  return host(SYS_execve, reinterpret_cast<uint64_t>("/proc/self/exe"), reinterpret_cast<uint64_t>(host_argv.data()),
              envp_addr);
}

}  // namespace juice::lx
