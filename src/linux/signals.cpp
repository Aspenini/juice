// Signals for Linux guests.
//
// Guest handlers are never installed on the host. The host handler records
// the signal in the thread and sets CpuState::interrupt; the dispatcher then
// calls on_interrupt between blocks, where the guest state is exact, and the
// signal is delivered by pushing an AArch64 rt_sigframe (abi/signal_frame).
// SIG_DFL and SIG_IGN are passed to the host, so default actions are native.
// AArch64 and x86-64 Linux number their signals the same way.
//
// The guest's signal mask is the host thread's mask, except that the
// synchronous fault signals stay unblocked on the host. Masks and handlers
// are set with the raw system calls: glibc's wrappers refuse its internal
// signals 32 and 33, which the guest's own C library uses the same way.
//
// Synchronous faults (SIGSEGV, SIGBUS, SIGILL, SIGFPE raised by the CPU while
// running translated code) are reported with the guest state and end the
// process with the same signal: the translated code does not yet keep the
// guest state exact at every faulting instruction, which a guest handler
// would need.

#include <signal.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <format>

#include "linux/abi/signal_frame.hpp"
#include "linux/process.hpp"

#if !defined(__x86_64__)
#error "the Linux frontend runs on x86-64 hosts"
#endif

// rt_sigreturn for the host handlers installed with the raw system call
// (glibc's own restorer is not exported).
extern "C" void juice_restore_rt();
asm(R"(
  .text
  .globl juice_restore_rt
  .type juice_restore_rt, @function
juice_restore_rt:
  movq $15, %rax
  syscall
  .size juice_restore_rt, . - juice_restore_rt
  .previous
)");

namespace juice::lx {

namespace {

// Guest sa_flags (the same values as on x86-64).
constexpr uint64_t kSaNocldstop = 0x00000001, kSaNocldwait = 0x00000002;
constexpr uint64_t kSaOnstack = 0x08000000, kSaRestart = 0x10000000, kSaNodefer = 0x40000000;
constexpr uint64_t kSaResethand = 0x80000000, kSaRestorer = 0x04000000;
constexpr uint32_t kSsOnstack = 1, kSsDisable = 2;
constexpr uint64_t kSigDfl = 0, kSigIgn = 1;

uint64_t bit(int sig) { return uint64_t{1} << (sig - 1); }

bool is_fault_signal(int sig) { return sig == SIGSEGV || sig == SIGBUS || sig == SIGILL || sig == SIGFPE; }

constexpr uint64_t kUnblockable = (uint64_t{1} << (SIGKILL - 1)) | (uint64_t{1} << (SIGSTOP - 1));
constexpr uint64_t kFaultSignals = (uint64_t{1} << (SIGSEGV - 1)) | (uint64_t{1} << (SIGBUS - 1)) |
                                   (uint64_t{1} << (SIGILL - 1)) | (uint64_t{1} << (SIGFPE - 1));

// The kernel's struct sigaction for x86-64.
struct HostSigaction {
  uint64_t handler;
  uint64_t flags;
  uint64_t restorer;
  uint64_t mask;
};

void host_handler(int sig, siginfo_t* info, void* context) {
  if (LinuxProcess* p = LinuxProcess::instance()) p->on_host_signal(sig, info, context);
}

int set_host_action(int sig, uint64_t handler, uint64_t flags) {
  HostSigaction a{handler, flags, 0, 0};
  if (handler > kSigIgn) {
    a.flags |= SA_SIGINFO | kSaRestorer;
    a.restorer = reinterpret_cast<uint64_t>(&juice_restore_rt);
    a.mask = ~uint64_t{0};  // nothing interrupts the host handler
  }
  return ::syscall(SYS_rt_sigaction, sig, &a, nullptr, 8) == 0 ? 0 : -errno;
}

void set_host_mask(int how, uint64_t mask) { ::syscall(SYS_rt_sigprocmask, how, &mask, nullptr, 8); }

}  // namespace

void LinuxProcess::init_signals() {
  struct sigaction sa{};
  sa.sa_sigaction = host_handler;
  sa.sa_flags = SA_SIGINFO | SA_NODEFER;
  sigfillset(&sa.sa_mask);
  for (int sig : {SIGSEGV, SIGBUS, SIGILL, SIGFPE}) ::sigaction(sig, &sa, nullptr);

  // What execve() keeps: the mask, and the signals that are ignored.
  uint64_t mask = 0;
  ::syscall(SYS_rt_sigprocmask, SIG_BLOCK, nullptr, &mask, 8);
  for (int sig = 1; sig <= 64; ++sig) {
    HostSigaction old{};
    if (sig != SIGKILL && sig != SIGSTOP && !is_fault_signal(sig) &&
        ::syscall(SYS_rt_sigaction, sig, nullptr, &old, 8) == 0 && old.handler == kSigIgn) {
      actions_[sig].handler = kSigIgn;
    }
  }
  set_guest_mask(main_thread_, mask);
}

void LinuxProcess::on_host_signal(int sig, siginfo_t* info, void* context) {
  (void)context;
  LinuxThread* t = current_thread();
  if (is_fault_signal(sig) && info->si_code > 0) {
    // Raised by the CPU. The state is that of the block's start; block_pc names it.
    std::string where = t ? std::format(" (in the guest block at 0x{:x})", t->state.block_pc) : std::string();
    const char* what = sig == SIGSEGV ? "segmentation fault" : sig == SIGBUS ? "bus error"
                       : sig == SIGILL ? "illegal instruction" : "arithmetic exception";
    fatal(std::format("guest {} at address 0x{:x}{}", what, reinterpret_cast<uint64_t>(info->si_addr), where), sig);
  }
  if (!t) return;  // not a guest thread
  t->info[sig] = *info;
  t->pending.fetch_or(bit(sig), std::memory_order_relaxed);
  std::atomic_ref<uint64_t>(t->state.interrupt).store(1, std::memory_order_relaxed);
}

runtime::Action LinuxProcess::on_interrupt(arm64::CpuState& s) {
  if (LinuxThread* t = current_thread()) deliver_pending(s, t->blocked);
  return runtime::Action::Continue;
}

bool LinuxProcess::deliver_pending(arm64::CpuState& s, uint64_t saved_mask) {
  LinuxThread& t = *current_thread();
  bool pushed = false;
  uint64_t pending = t.pending.exchange(0, std::memory_order_acquire);
  for (int sig = 1; sig <= 64 && pending; ++sig) {
    if (!(pending & bit(sig))) continue;
    pending &= ~bit(sig);
    if (t.blocked & bit(sig)) {  // blocked meanwhile: keep it until unblocked
      t.pending.fetch_or(bit(sig), std::memory_order_relaxed);
      continue;
    }
    // A second handler's frame returns to the first handler, under its mask.
    if (deliver_signal(s, sig, &t.info[sig], saved_mask) == Delivery::Pushed) {
      saved_mask = t.blocked;
      pushed = true;
    }
  }
  return pushed;
}

LinuxProcess::Delivery LinuxProcess::deliver_signal(arm64::CpuState& s, int sig, const siginfo_t* info,
                                                    uint64_t saved_mask) {
  LinuxThread& t = *current_thread();
  // Raised by the guest's own instruction (BRK, UDF): if it cannot be handled,
  // the caller reports it, as the kernel would kill the process.
  const bool synchronous = (is_fault_signal(sig) || sig == SIGTRAP) && info->si_code > 0;
  GuestSigaction act;
  {
    std::lock_guard lock(actions_mutex_);
    act = actions_[sig];
    if (synchronous && (act.handler <= kSigIgn || (t.blocked & bit(sig)))) return Delivery::Unhandled;
    if (act.handler > kSigIgn && (act.flags & kSaResethand)) actions_[sig] = GuestSigaction{};
  }
  if (act.handler == kSigIgn) return Delivery::Done;
  if (act.handler == kSigDfl) {
    // Let the host perform the default action.
    set_host_action(sig, kSigDfl, 0);
    set_host_mask(SIG_UNBLOCK, bit(sig));
    ::syscall(SYS_tgkill, ::getpid(), t.tid, sig);
    return Delivery::Done;  // ignored by default (SIGCHLD, SIGWINCH, ...), or stopped and continued
  }

  // The handler's stack: the alternate stack if requested and not already on it.
  uint64_t sp = s.sp;
  const bool on_alt = t.altstack_size && sp > t.altstack_sp && sp <= t.altstack_sp + t.altstack_size;
  if ((act.flags & kSaOnstack) && !(t.altstack_flags & kSsDisable) && !on_alt) sp = t.altstack_sp + t.altstack_size;

  SignalDelivery d;
  d.sig = sig;
  d.siginfo = info;
  d.saved_mask = saved_mask;
  d.altstack_sp = t.altstack_sp;
  d.altstack_size = t.altstack_size;
  d.altstack_flags = t.altstack_flags;
  d.handler = act.handler;
  d.restorer = (act.flags & kSaRestorer) && act.restorer ? act.restorer : sigreturn_trampoline_;
  if (is_fault_signal(sig) || sig == SIGTRAP) d.fault_address = reinterpret_cast<uint64_t>(info->si_addr);
  push_signal_frame(s, sp, d);
  set_guest_mask(t, t.blocked | act.mask | ((act.flags & kSaNodefer) ? 0 : bit(sig)));
  return Delivery::Pushed;
}

bool LinuxProcess::restart_pending(const LinuxThread& t) {
  const uint64_t pending = t.pending.load(std::memory_order_relaxed) & ~t.blocked;
  std::lock_guard lock(actions_mutex_);
  for (int sig = 1; sig <= 64; ++sig)
    if ((pending & bit(sig)) && actions_[sig].handler > kSigIgn && (actions_[sig].flags & kSaRestart)) return true;
  return false;
}

void LinuxProcess::set_guest_mask(LinuxThread& t, uint64_t mask) {
  t.blocked = mask & ~kUnblockable;
  set_host_mask(SIG_SETMASK, t.blocked & ~kFaultSignals);
  // Signals caught while blocked (only in a race with the change) are due now.
  if (t.pending.load(std::memory_order_relaxed) & ~t.blocked)
    std::atomic_ref<uint64_t>(t.state.interrupt).store(1, std::memory_order_relaxed);
}

int64_t LinuxProcess::sys_rt_sigaction(int sig, uint64_t act, uint64_t oldact, uint64_t size) {
  if (size != 8 || sig < 1 || sig > 64) return -EINVAL;
  if (act && (sig == SIGKILL || sig == SIGSTOP)) return -EINVAL;
  std::lock_guard lock(actions_mutex_);
  GuestSigaction a;
  if (act) std::memcpy(&a, reinterpret_cast<const void*>(act), sizeof(a));
  if (oldact) std::memcpy(reinterpret_cast<void*>(oldact), &actions_[sig], sizeof(GuestSigaction));
  if (!act) return 0;

  // The fault signals keep JUICE's handler, which passes signals sent by
  // kill() on to the guest like any other.
  if (!is_fault_signal(sig)) {
    // Never SA_RESTART on the host: interrupted calls come back to us, and
    // do_syscall restarts them after delivery if the guest asked for it.
    const uint64_t flags = a.flags & (kSaNocldstop | kSaNocldwait);
    const uint64_t handler = a.handler <= kSigIgn ? a.handler : reinterpret_cast<uint64_t>(&host_handler);
    if (const int err = set_host_action(sig, handler, flags)) return err;
  }
  actions_[sig] = a;
  return 0;
}

int64_t LinuxProcess::sys_rt_sigprocmask(int how, uint64_t set, uint64_t oldset, uint64_t size) {
  if (size != 8) return -EINVAL;
  LinuxThread& t = *current_thread();
  const uint64_t old = t.blocked;
  if (set) {
    uint64_t m;
    std::memcpy(&m, reinterpret_cast<const void*>(set), 8);
    switch (how) {
      case SIG_BLOCK: set_guest_mask(t, old | m); break;
      case SIG_UNBLOCK: set_guest_mask(t, old & ~m); break;
      case SIG_SETMASK: set_guest_mask(t, m); break;
      default: return -EINVAL;
    }
  }
  if (oldset) std::memcpy(reinterpret_cast<void*>(oldset), &old, 8);
  return 0;
}

int64_t LinuxProcess::sys_sigaltstack(uint64_t ss, uint64_t old_ss) {
  LinuxThread& t = *current_thread();
  const uint64_t sp = t.state.sp;
  const bool on_alt = t.altstack_size && sp > t.altstack_sp && sp <= t.altstack_sp + t.altstack_size;
  // stack_t: { void* ss_sp; int ss_flags; size_t ss_size; }
  uint64_t new_sp = 0, new_size = 0;
  uint32_t new_flags = 0;
  if (ss) {
    std::memcpy(&new_sp, reinterpret_cast<const void*>(ss), 8);
    std::memcpy(&new_flags, reinterpret_cast<const void*>(ss + 8), 4);
    std::memcpy(&new_size, reinterpret_cast<const void*>(ss + 16), 8);
  }
  if (old_ss) {
    uint8_t out[24] = {};
    const uint32_t flags = (t.altstack_flags & kSsDisable) ? kSsDisable : (on_alt ? kSsOnstack : 0);
    std::memcpy(out, &t.altstack_sp, 8);
    std::memcpy(out + 8, &flags, 4);
    std::memcpy(out + 16, &t.altstack_size, 8);
    std::memcpy(reinterpret_cast<void*>(old_ss), out, sizeof(out));
  }
  if (ss) {
    if (on_alt) return -EPERM;
    if (new_flags & kSsDisable) {
      t.altstack_flags = kSsDisable;
      t.altstack_sp = t.altstack_size = 0;
    } else {
      if (new_flags & ~(kSsOnstack | 0x80000000u /* SS_AUTODISARM */)) return -EINVAL;
      if (new_size < 2048) return -ENOMEM;  // MINSIGSTKSZ
      t.altstack_sp = new_sp;
      t.altstack_size = new_size;
      t.altstack_flags = 0;
    }
  }
  return 0;
}

int64_t LinuxProcess::sys_rt_sigreturn(arm64::CpuState& s) {
  uint64_t mask = 0;
  if (!pop_signal_frame(s, mask)) fatal("rt_sigreturn with a corrupt signal frame", SIGSEGV);
  set_guest_mask(*current_thread(), mask);
  return kNoResult;
}

}  // namespace juice::lx
