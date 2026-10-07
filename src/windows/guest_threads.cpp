// Thread control and fibers for guest threads.
//
// SuspendThread / GetThreadContext / SetThreadContext: a guest thread's
// registers live in its CpuState, which is exact while the thread is in host
// code (an API call) or between two translated blocks. Suspending a thread
// that is running translated code asks it (through CpuState::interrupt) to
// park at the next block boundary, and suspends it natively there.
//
// Fibers: the native fiber functions switch host stacks; each guest fiber
// also needs a CPU state and guest stack of its own, so every CreateFiber
// gets a GuestThread context, and SwitchToFiber makes the target's context
// the thread's current one.

#include <windows.h>

#include <cstring>

#include "windows/guest_process.hpp"

namespace juice::win {
namespace {

using arm64eh::Context;

constexpr uint32_t kContextArm64 = 0x00400000;
constexpr uint32_t kContextControl = kContextArm64 | 0x1;  // Fp, Lr, Sp, Pc, Cpsr
constexpr uint32_t kContextInteger = kContextArm64 | 0x2;  // X0-X28
constexpr uint32_t kContextFloatingPoint = kContextArm64 | 0x4;
constexpr uint32_t kContextDebug = kContextArm64 | 0x8;

bool has(uint32_t flags, uint32_t part) { return (flags & part) == part; }

// The parts of `s` that `flags` asks for (pc given: the state's own, or the
// return address of an API call in progress).
void read_context(const arm64::CpuState& s, uint64_t pc, Context& c) {
  const uint32_t flags = c.flags;
  if (has(flags, kContextControl)) {
    c.cpsr = static_cast<uint32_t>(s.nzcv);
    c.x[29] = s.x[29];
    c.x[30] = s.x[30];
    c.sp = s.sp;
    c.pc = pc;
  }
  if (has(flags, kContextInteger)) std::memcpy(c.x, s.x, 29 * sizeof(uint64_t));
  if (has(flags, kContextFloatingPoint)) {
    for (int i = 0; i < 32; ++i) c.v[i] = {s.v[i].lo, s.v[i].hi};
    c.fpcr = static_cast<uint32_t>(s.fpcr);
    c.fpsr = static_cast<uint32_t>(s.fpsr);
  }
  if (has(flags, kContextDebug)) {  // no hardware breakpoints or watchpoints
    std::memset(c.bcr, 0, sizeof(c.bcr));
    std::memset(c.bvr, 0, sizeof(c.bvr));
    std::memset(c.wcr, 0, sizeof(c.wcr));
    std::memset(c.wvr, 0, sizeof(c.wvr));
  }
}

void write_context(const Context& c, arm64::CpuState& s) {
  const uint32_t flags = c.flags;
  if (has(flags, kContextControl)) {
    s.nzcv = c.cpsr & 0xF0000000u;
    s.x[29] = c.x[29];
    s.x[30] = c.x[30];
    s.sp = c.sp;
    s.pc = c.pc;
  }
  if (has(flags, kContextInteger)) std::memcpy(s.x, c.x, 29 * sizeof(uint64_t));
  if (has(flags, kContextFloatingPoint)) {
    for (int i = 0; i < 32; ++i) s.v[i] = {c.v[i].lo, c.v[i].hi};
    s.fpcr = c.fpcr;
    s.fpsr = c.fpsr;
  }
}

// Where a thread's guest code continues: an API call returns to its caller.
uint64_t resume_pc(const GuestThread& t) { return t.in_host.load(std::memory_order_acquire) ? t.state.x[30] : t.state.pc; }

bool is_current_thread(HANDLE thread) { return GetThreadId(thread) == GetCurrentThreadId(); }

}  // namespace

GuestThread* GuestProcess::find_thread(DWORD thread_id) {
  std::lock_guard lock(threads_mutex_);
  for (GuestThread* t : live_threads_) {
    if (t->thread_id != thread_id) continue;
    GuestThread* active = t->active.load(std::memory_order_acquire);
    return active ? active : t;
  }
  return nullptr;
}

// A thread asked to park (see suspend_thread) waits here, between blocks,
// until the suspender has suspended it natively and it is resumed.
runtime::Action GuestProcess::on_interrupt(arm64::CpuState& state) {
  GuestThread* t = t_current();
  if (t && &t->state == &state && t->park_request.exchange(false, std::memory_order_acq_rel)) {
    t->parked.store(true, std::memory_order_release);
    while (!t->park_release.exchange(false, std::memory_order_acq_rel)) SwitchToThread();
    t->parked.store(false, std::memory_order_release);
  }
  return runtime::Action::Continue;
}

std::optional<DWORD> GuestProcess::suspend_thread(HANDLE thread) {
  if (is_current_thread(thread)) return std::nullopt;
  const DWORD id = GetThreadId(thread);
  for (;;) {
    GuestThread* t = find_thread(id);
    if (!t) return std::nullopt;
    const DWORD previous = SuspendThread(thread);
    if (previous == static_cast<DWORD>(-1)) return previous;
    // SuspendThread is asynchronous: reading the host context waits for it.
    CONTEXT host{};
    host.ContextFlags = CONTEXT_CONTROL;
    GetThreadContext(thread, &host);
    if (previous > 0) return previous;  // already held where its state is exact
    t = find_thread(id);  // it may have switched fibers meanwhile
    if (!t) return previous;
    if (t->exact()) {
      t->park_request.store(false, std::memory_order_release);
      if (t->parked.load(std::memory_order_acquire)) t->park_release.store(true, std::memory_order_release);
      return previous;
    }
    // Running translated code: have it park at the next block boundary.
    ResumeThread(thread);
    t->park_request.store(true, std::memory_order_release);
    std::atomic_ref<uint64_t>(t->state.interrupt).store(1, std::memory_order_release);
    while (!t->exact()) {
      if (WaitForSingleObject(thread, 0) == WAIT_OBJECT_0) return std::nullopt;  // it ended meanwhile
      if (find_thread(id) != t) break;  // switched fibers: start over
      SwitchToThread();
    }
  }
}

bool GuestProcess::get_thread_context(HANDLE thread, Context& context) {
  if (is_current_thread(thread)) {
    // From an API call: the context of its caller.
    GuestThread& t = attach_thread();
    read_context(t.state, t.state.x[30], context);
    return true;
  }
  GuestThread* t = find_thread(GetThreadId(thread));
  if (!t) return false;
  read_context(t->state, resume_pc(*t), context);
  return true;
}

bool GuestProcess::set_thread_context(HANDLE thread, const Context& context) {
  if (is_current_thread(thread)) {
    // From an API call: its caller continues at `context` (the parts not asked for unchanged).
    GuestThread& t = attach_thread();
    arm64::CpuState s = t.state;
    s.pc = s.x[30];
    write_context(context, s);
    Context full = capture_context(s);
    full.pc = s.pc;
    resume_at(full);
    return true;
  }
  GuestThread* t = find_thread(GetThreadId(thread));
  if (!t) return false;
  if (t->in_host.load(std::memory_order_acquire) && !t->parked.load(std::memory_order_acquire)) {
    // In an API call, which would return to x30 with its result in x0. A
    // context equal to the one GetThreadContext reported changes nothing;
    // any other replaces the state, and the call's result is dropped.
    arm64::CpuState s = t->state;
    s.pc = s.x[30];
    Context current{};
    current.flags = context.flags;
    read_context(s, s.pc, current);
    write_context(context, s);
    Context next{};
    next.flags = context.flags;
    read_context(s, s.pc, next);
    if (std::memcmp(&next, &current, sizeof(Context)) == 0) return true;
    t->state = s;
    t->context_set = true;
    return true;
  }
  write_context(context, t->state);
  return true;
}

std::pair<uint64_t, uint64_t> GuestProcess::stack_limits() {
  GuestThread& t = attach_thread();
  const uint64_t low = reinterpret_cast<uint64_t>(t.stack_base);
  return {low, low + t.stack_size};
}

// --- fibers --------------------------------------------------------------------------

void* GuestProcess::create_fiber(uint64_t stack_size, uint64_t start, uint64_t param, uint32_t flags) {
  GuestThread* context = allocate_thread(stack_size);
  context->fiber = true;
  context->fiber_start = start;
  context->fiber_param = param;
  void* fiber = CreateFiberEx(0, 0, flags, &GuestProcess::fiber_main, context);
  if (!fiber) {
    VirtualFree(context->stack_base, 0, MEM_RELEASE);
    delete context;
    return nullptr;
  }
  context->host_fiber = fiber;
  std::lock_guard lock(fibers_mutex_);
  fibers_[fiber] = context;
  return fiber;
}

void* GuestProcess::convert_thread_to_fiber(uint64_t param, uint32_t flags) {
  GuestThread& own = attach_thread();
  void* fiber = ConvertThreadToFiberEx(reinterpret_cast<void*>(param), flags);
  if (fiber) {
    own.host_fiber = fiber;
    std::lock_guard lock(fibers_mutex_);
    fibers_[fiber] = &own;
  }
  return fiber;
}

bool GuestProcess::convert_fiber_to_thread() {
  void* fiber = GetCurrentFiber();
  if (!ConvertFiberToThread()) return false;
  std::lock_guard lock(fibers_mutex_);
  fibers_.erase(fiber);
  return true;
}

void GuestProcess::switch_to_fiber(void* fiber) {
  GuestThread& self = attach_thread();
  SwitchToFiber(fiber);
  enter_fiber(self);  // switched back to (perhaps on another thread)
}

void GuestProcess::delete_fiber(void* fiber) {
  if (fiber == GetCurrentFiber()) exit_thread(0);  // as DeleteFiber does: the thread ends
  GuestThread* context = nullptr;
  {
    std::lock_guard lock(fibers_mutex_);
    if (auto it = fibers_.find(fiber); it != fibers_.end()) {
      context = it->second;
      fibers_.erase(it);
    }
  }
  DeleteFiber(fiber);
  if (context && context->fiber) {
    VirtualFree(context->stack_base, 0, MEM_RELEASE);
    delete context;
  }
}

}  // namespace juice::win
