// Windows exception handling for guest code: the ARM64 counterparts of
// ntdll's RtlDispatchException, RtlUnwindEx and RtlRestoreContext.
//
// Guest frames are walked with the image's ARM64 unwind information and the
// guest's own language handlers (__C_specific_handler, __CxxFrameHandler4,
// ...) are called the way ntdll calls them. Where the dispatcher runs guest
// code (handlers, filters, the C++ catch-block callback), each call is a
// nested call_guest() level whose `link` names the guest frame the walk
// continues at, standing in for ntdll's own frames on a native stack.
//
// Continuing at an unwind target unwinds the host stack too: restore_context
// throws a Resume that the call_guest() level owning the target frame catches.
// Native code between levels (a callback from a native DLL) cannot be unwound
// that way, so exceptions that would cross it are reported instead.

#include <windows.h>

#include <algorithm>
#include <cstring>
#include <format>

#include "windows/guest_process.hpp"

namespace juice::win {

using arm64eh::Context;
using arm64eh::DispatcherContext;
using arm64eh::RuntimeFunction;

namespace {

constexpr uint32_t kExceptionContinueExecution = 0;
constexpr uint32_t kExceptionContinueSearch = 1;
constexpr uint32_t kExceptionNestedException = 2;
constexpr uint32_t kExceptionCollidedUnwind = 3;

constexpr DWORD kUnwinding = 0x2;        // EXCEPTION_UNWINDING
constexpr DWORD kExitUnwind = 0x4;       // EXCEPTION_EXIT_UNWIND
constexpr DWORD kNestedCall = 0x10;      // EXCEPTION_NESTED_CALL
constexpr DWORD kTargetUnwind = 0x20;    // EXCEPTION_TARGET_UNWIND
constexpr DWORD kStatusUnwind = 0xC0000027;
constexpr DWORD kStatusUnwindConsolidate = 0x80000029;
constexpr DWORD kStatusLongjump = 0x80000026;
constexpr DWORD kStatusNoncontinuable = 0xC0000025;
constexpr DWORD kStatusInvalidDisposition = 0xC0000026;
constexpr DWORD kStatusBadStack = 0xC0000028;
constexpr DWORD kStatusInvalidUnwindTarget = 0xC0000029;

// Guest code the dispatcher calls runs this far below the current stack
// pointer, so that its frames are clearly below every frame it may unwind to.
constexpr uint64_t kCallGap = 0x100;

uint64_t below(uint64_t sp) { return (sp - kCallGap) & ~uint64_t{15}; }

void to_state(const Context& c, arm64::CpuState& s) {
  std::memcpy(s.x, c.x, sizeof(s.x));
  s.sp = c.sp;
  s.pc = c.pc;
  s.nzcv = c.cpsr & 0xF0000000u;
  for (int i = 0; i < 32; ++i) s.v[i] = {c.v[i].lo, c.v[i].hi};
  s.fpcr = c.fpcr;
  s.fpsr = c.fpsr;
}

template <typename T>
uint64_t addr(T* p) {
  return reinterpret_cast<uint64_t>(p);
}

}  // namespace

Context GuestProcess::capture_context(const arm64::CpuState& s) {
  Context c{};
  c.flags = arm64eh::kContextFull | arm64eh::kContextUnwoundToCall;
  c.cpsr = static_cast<uint32_t>(s.nzcv);
  std::memcpy(c.x, s.x, sizeof(c.x));
  c.sp = s.sp;
  c.pc = s.x[30];  // the builtin returns to its caller
  for (int i = 0; i < 32; ++i) c.v[i] = {s.v[i].lo, s.v[i].hi};
  c.fpcr = static_cast<uint32_t>(s.fpcr);
  c.fpsr = static_cast<uint32_t>(s.fpsr);
  return c;
}

void GuestProcess::resume_at(const Context& context) {
  GuestThread& t = attach_thread();
  to_state(context, t.state);
  t.state_replaced = true;
}

const RuntimeFunction* GuestProcess::lookup_function_entry(uint64_t pc, uint64_t* image_base) const {
  if (!image_.contains(pc) || !image_.exception_directory.size) return nullptr;
  const auto* begin = image_.at_rva<const RuntimeFunction>(image_.exception_directory.rva);
  const auto* end = begin + image_.exception_directory.size / sizeof(RuntimeFunction);
  const uint32_t rva = static_cast<uint32_t>(pc - image_.address());
  // The last entry starting at or before the pc.
  const auto* it = std::upper_bound(begin, end, rva, [](uint32_t r, const RuntimeFunction& f) { return r < f.begin; });
  if (it == begin) return nullptr;
  --it;
  if (rva >= it->begin + arm64eh::function_length(image_.address(), *it)) return nullptr;
  if (image_base) *image_base = image_.address();
  return it;
}

uint64_t GuestProcess::add_vectored_handler(bool first, uint64_t handler) {
  std::lock_guard lock(vectored_mutex_);
  const VectoredHandler h{++next_vectored_handle_, handler};
  vectored_handlers_.insert(first ? vectored_handlers_.begin() : vectored_handlers_.end(), h);
  return h.handle;
}

bool GuestProcess::remove_vectored_handler(uint64_t handle) {
  std::lock_guard lock(vectored_mutex_);
  return std::erase_if(vectored_handlers_, [&](const VectoredHandler& h) { return h.handle == handle; }) != 0;
}

void GuestProcess::dispatch_exception(EXCEPTION_RECORD& record, Context& context) {
  GuestThread& t = attach_thread();
  const uint64_t sentinel = thunks_.return_sentinel();
  const uint64_t stack = below(t.state.sp);

  // Vectored handlers come first.
  std::vector<VectoredHandler> vectored;
  {
    std::lock_guard lock(vectored_mutex_);
    vectored = vectored_handlers_;
  }
  for (const VectoredHandler& h : vectored) {
    EXCEPTION_POINTERS pointers{&record, reinterpret_cast<CONTEXT*>(&context)};
    const auto r = static_cast<int32_t>(call_guest(h.function, {{addr(&pointers)}}, {false, &context, stack}).x0);
    if (r == EXCEPTION_CONTINUE_EXECUTION) return;
  }

  // Then the frame-based handlers, from the innermost frame outwards.
  Context frame = context;
  size_t level = t.levels.size();
  const char* why = nullptr;
  for (;;) {
    if (frame.pc == sentinel) {
      // The end of a call_guest() level: continue with the frames it links
      // to, or stop at the bottom of the guest stack or a native caller.
      if (level == 0) break;
      const GuestCallLevel& l = t.levels[--level];
      if (l.link) {
        frame = *l.link;
        continue;
      }
      if (level > 0 && l.native_frames) why = "it would propagate into the native code that called the program";
      break;
    }
    const uint64_t pc = frame.pc;
    const bool unwound = frame.flags & arm64eh::kContextUnwoundToCall;
    uint64_t base = 0;
    const RuntimeFunction* f = lookup_function_entry(unwound ? pc - 4 : pc, &base);
    if (!f && !image_.contains(pc)) {
      why = "the guest stack could not be unwound";
      break;
    }
    Context before = frame;  // the frame's own registers, for its handler's funclets
    const arm64eh::UnwindResult u = arm64eh::virtual_unwind(base, pc, f, frame);
    if (frame.sp < before.sp) {
      why = "the guest stack is corrupt";
      break;
    }
    if (!u.handler) continue;

    DispatcherContext dc{};
    dc.control_pc = pc;
    dc.image_base = base;
    dc.function_entry = addr(f);
    dc.establisher_frame = u.establisher_frame;
    dc.context_record = addr(&frame);
    dc.language_handler = u.handler;
    dc.handler_data = u.handler_data;
    dc.control_pc_is_unwound = unwound;
    dc.non_volatile_registers = addr(&before.x[19]);
    const auto disposition = static_cast<uint32_t>(
        call_guest(u.handler, {{addr(&record), u.establisher_frame, addr(&context), addr(&dc)}}, {false, &context, stack})
            .x0);
    switch (disposition) {
      case kExceptionContinueExecution:
        if (record.ExceptionFlags & EXCEPTION_NONCONTINUABLE) {
          EXCEPTION_RECORD nested{};
          nested.ExceptionCode = kStatusNoncontinuable;
          nested.ExceptionFlags = EXCEPTION_NONCONTINUABLE;
          nested.ExceptionRecord = &record;
          nested.ExceptionAddress = record.ExceptionAddress;
          dispatch_exception(nested, context);
          fatal("a handler continued a noncontinuable exception", kStatusNoncontinuable);
        }
        return;
      case kExceptionContinueSearch:
        break;
      case kExceptionNestedException:
        record.ExceptionFlags |= kNestedCall;
        break;
      default: {
        EXCEPTION_RECORD invalid{};
        invalid.ExceptionCode = kStatusInvalidDisposition;
        invalid.ExceptionFlags = EXCEPTION_NONCONTINUABLE;
        invalid.ExceptionRecord = &record;
        dispatch_exception(invalid, context);
        fatal("invalid exception disposition", kStatusInvalidDisposition);
      }
    }
  }
  unhandled_exception(record, context, why);
}

void GuestProcess::unhandled_exception(EXCEPTION_RECORD& record, Context& context, const char* why) {
  // Like kernelbase's UnhandledExceptionFilter: the program's top-level
  // filter (SetUnhandledExceptionFilter) gets a look first.
  if (const uint64_t filter = unhandled_filter_.load(); filter && !why) {
    EXCEPTION_POINTERS pointers{&record, reinterpret_cast<CONTEXT*>(&context)};
    const uint64_t stack = below(attach_thread().state.sp);
    const auto r = static_cast<int32_t>(call_guest(filter, {{addr(&pointers)}}, {false, &context, stack}).x0);
    if (r == EXCEPTION_CONTINUE_EXECUTION) throw Resume{context, 0, 0};
  }
  std::string message = std::format("unhandled exception 0x{:08x} at 0x{:x}", record.ExceptionCode,
                                    reinterpret_cast<uint64_t>(record.ExceptionAddress));
  if (why) message += std::format(" ({})", why);
  fatal(message, record.ExceptionCode);
}

void GuestProcess::unwind(uint64_t target_frame, uint64_t target_ip, EXCEPTION_RECORD* record, uint64_t return_value,
                          Context context) {
  GuestThread& t = attach_thread();
  const uint64_t sentinel = thunks_.return_sentinel();
  const uint64_t stack = below(t.state.sp);

  EXCEPTION_RECORD local{};
  if (!record) {
    local.ExceptionCode = kStatusUnwind;
    local.ExceptionAddress = reinterpret_cast<void*>(context.pc);
    record = &local;
  }
  record->ExceptionFlags |= kUnwinding;
  if (!target_frame) {
    record->ExceptionFlags |= kExitUnwind;
    fatal("exit unwinds (RtlUnwindEx without a target frame) are not supported", kStatusInvalidUnwindTarget);
  }

  Context frame = context;
  size_t level = t.levels.size();
  for (;;) {
    if (frame.pc == sentinel) {
      const GuestCallLevel* l = level ? &t.levels[--level] : nullptr;
      if (!l || !l->link) {
        fatal(std::format("unwind target frame 0x{:x} is not on the guest stack{}", target_frame,
                          l && l->native_frames ? " (unwinding into native code is not supported)" : ""),
              kStatusInvalidUnwindTarget);
      }
      frame = *l->link;
      continue;
    }
    const Context before = frame;
    const bool unwound = frame.flags & arm64eh::kContextUnwoundToCall;
    uint64_t base = 0;
    const RuntimeFunction* f = lookup_function_entry(unwound ? frame.pc - 4 : frame.pc, &base);
    if (!f && !image_.contains(frame.pc)) fatal("the guest stack could not be unwound", kStatusBadStack);
    const arm64eh::UnwindResult u = arm64eh::virtual_unwind(base, before.pc, f, frame);
    if (u.establisher_frame > target_frame)
      fatal(std::format("invalid unwind target frame 0x{:x}", target_frame), kStatusInvalidUnwindTarget);

    if (u.handler) {
      if (u.establisher_frame == target_frame) record->ExceptionFlags |= kTargetUnwind;
      Context current = before;
      DispatcherContext dc{};
      dc.control_pc = before.pc;
      dc.image_base = base;
      dc.function_entry = addr(f);
      dc.establisher_frame = u.establisher_frame;
      dc.target_pc = target_ip;
      dc.context_record = addr(&current);
      dc.language_handler = u.handler;
      dc.handler_data = u.handler_data;
      dc.control_pc_is_unwound = unwound;
      dc.non_volatile_registers = addr(&current.x[19]);
      const auto disposition = static_cast<uint32_t>(
          call_guest(u.handler, {{addr(record), u.establisher_frame, addr(&current), addr(&dc)}},
                     {false, &before, stack})
              .x0);
      if (disposition == kExceptionCollidedUnwind)
        fatal("collided unwinds are not supported", kStatusInvalidDisposition);
      if (disposition != kExceptionContinueSearch)
        fatal("invalid unwind disposition", kStatusInvalidDisposition);
    }
    if (u.establisher_frame == target_frame) {
      frame = before;  // continue inside the target function
      break;
    }
  }

  frame.pc = target_ip;
  frame.x[0] = return_value;
  restore_context(frame, record);
}

void GuestProcess::restore_context(Context context, EXCEPTION_RECORD* record) {
  GuestThread& t = attach_thread();
  Resume r{context, 0, t.state.sp};
  if (record && record->ExceptionCode == kStatusLongjump && record->NumberParameters >= 1) {
    // _JUMP_BUFFER: Frame, Reserved, X19-X28, Fp, Lr, Sp, Fpcr/Fpsr, D8-D15.
    const auto* jmp = reinterpret_cast<const uint64_t*>(record->ExceptionInformation[0]);
    for (int i = 0; i < 10; ++i) r.context.x[19 + i] = jmp[2 + i];
    r.context.x[29] = jmp[12];
    for (int i = 0; i < 8; ++i) r.context.v[8 + i].lo = jmp[16 + i];
  } else if (record && record->ExceptionCode == kStatusUnwindConsolidate && record->NumberParameters >= 1) {
    r.consolidate_record = addr(record);
  }
  // Native code between this level and the one owning the target frame can't be unwound.
  for (size_t i = t.levels.size(); i-- > 0;) {
    const GuestCallLevel& l = t.levels[i];
    if (context.sp < l.entry_sp) break;
    if (l.native_frames && i > 0)
      fatal("an exception handler in the program would unwind native code that called it; not supported yet",
            kStatusInvalidUnwindTarget);
  }
  throw r;
}

// Continue at an unwind target in the current call level. For C++ catch
// blocks the unwind is a consolidation: the callback (__CxxCallCatchBlock)
// runs the catch block first, on the stack below the unwound frames (the
// exception object still lives there), and returns where to continue.
void GuestProcess::resume(Resume& r) {
  GuestThread& t = attach_thread();
  if (r.consolidate_record) {
    auto* record = reinterpret_cast<EXCEPTION_RECORD*>(r.consolidate_record);
    // The target context goes on the guest stack: the callback reads the
    // non-volatile registers through ExceptionInformation[10] and may update them.
    const uint64_t at = (r.stack - sizeof(Context) - 0x40) & ~uint64_t{15};
    auto* target = reinterpret_cast<Context*>(at);
    *target = r.context;
    record->ExceptionInformation[10] = addr(&target->x[19]);
    const uint64_t callback = record->ExceptionInformation[0];
    const uint64_t continuation = call_guest(callback, {{addr(record)}}, {false, target, below(at)}).x0;
    r.context = *target;
    r.context.pc = continuation;
  }
  to_state(r.context, t.state);
}

}  // namespace juice::win
