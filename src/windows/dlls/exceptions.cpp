// Exception handling builtins: raising, dispatching and unwinding guest
// exceptions with ARM64 contexts and unwind information (the native x64
// functions would walk x64 frames with x64 structures).

#include <windows.h>

#include <algorithm>
#include <cstring>
#include <format>

#include "windows/dlls/builtins.hpp"
#include "windows/guest_process.hpp"

namespace juice::win {
namespace {

using arm64::CpuState;
using arm64eh::Context;
using arm64eh::DispatcherContext;

template <typename T>
T* ptr(uint64_t v) {
  return reinterpret_cast<T*>(static_cast<uintptr_t>(v));
}

// The exception record and context of a raised exception live on the guest
// stack below the raising frame, as they would on a native stack: the C++
// runtime keeps pointers to them while a catch block runs (for rethrow and
// std::current_exception), after the dispatcher's own host frames are gone.
struct RaiseFrame {
  Context context;
  EXCEPTION_RECORD record;
};

RaiseFrame& raise_frame(CpuState& s) {
  const uint64_t at = (s.sp - sizeof(RaiseFrame) - 0x40) & ~uint64_t{15};
  auto* frame = ptr<RaiseFrame>(at);
  frame->context = GuestProcess::capture_context(s);
  s.sp = at;  // handlers called by the dispatcher run below it
  return *frame;
}

uint64_t RaiseException_(GuestProcess& p, CpuState& s) {
  RaiseFrame& f = raise_frame(s);
  EXCEPTION_RECORD& record = f.record;
  record = {};
  record.ExceptionCode = static_cast<DWORD>(s.x[0]);
  record.ExceptionFlags = (static_cast<DWORD>(s.x[1]) & EXCEPTION_NONCONTINUABLE) | EXCEPTION_SOFTWARE_ORIGINATE;
  if (const auto* args = ptr<const ULONG_PTR>(s.x[3])) {
    record.NumberParameters = std::min<DWORD>(static_cast<DWORD>(s.x[2]), EXCEPTION_MAXIMUM_PARAMETERS);
    std::memcpy(record.ExceptionInformation, args, record.NumberParameters * sizeof(ULONG_PTR));
  }
  record.ExceptionAddress = reinterpret_cast<void*>(f.context.pc);
  p.dispatch_exception(record, f.context);
  p.resume_at(f.context);  // a handler continued execution
  return 0;
}

uint64_t RtlRaiseException_(GuestProcess& p, CpuState& s) {
  auto* record = ptr<EXCEPTION_RECORD>(s.x[0]);
  RaiseFrame& f = raise_frame(s);
  record->ExceptionAddress = reinterpret_cast<void*>(f.context.pc);
  p.dispatch_exception(*record, f.context);
  p.resume_at(f.context);
  return 0;
}

uint64_t RtlUnwindEx_(GuestProcess& p, CpuState& s) {
  p.unwind(s.x[0], s.x[1], ptr<EXCEPTION_RECORD>(s.x[2]), s.x[3], GuestProcess::capture_context(s));
}

uint64_t RtlUnwind_(GuestProcess& p, CpuState& s) {
  p.unwind(s.x[0], s.x[1], ptr<EXCEPTION_RECORD>(s.x[2]), s.x[3], GuestProcess::capture_context(s));
}

uint64_t RtlRestoreContext_(GuestProcess& p, CpuState& s) {
  p.restore_context(*ptr<const Context>(s.x[0]), ptr<EXCEPTION_RECORD>(s.x[1]));
}

uint64_t RtlLookupFunctionEntry_(GuestProcess& p, CpuState& s) {
  uint64_t base = 0;
  const arm64eh::RuntimeFunction* f = p.lookup_function_entry(s.x[0], &base);
  if (f && s.x[1]) *ptr<uint64_t>(s.x[1]) = base;
  return reinterpret_cast<uint64_t>(f);
}

uint64_t RtlVirtualUnwind_(GuestProcess&, CpuState& s) {
  // (HandlerType, ImageBase, ControlPc, FunctionEntry, ContextRecord, HandlerData, EstablisherFrame, ContextPointers)
  const arm64eh::UnwindResult u = arm64eh::virtual_unwind(s.x[1], s.x[2], ptr<const arm64eh::RuntimeFunction>(s.x[3]),
                                                          *ptr<Context>(s.x[4]));
  if (s.x[5]) *ptr<uint64_t>(s.x[5]) = u.handler_data;
  if (s.x[6]) *ptr<uint64_t>(s.x[6]) = u.establisher_frame;
  return (s.x[0] & 3) ? u.handler : 0;  // UNW_FLAG_EHANDLER / UNW_FLAG_UHANDLER
}

uint64_t RtlPcToFileHeader_(GuestProcess& p, CpuState& s) {
  uint64_t base = 0;
  if (p.image().contains(s.x[0])) {
    base = p.image().address();
  } else {
    PVOID native = nullptr;
    RtlPcToFileHeader(ptr<void>(s.x[0]), &native);
    base = reinterpret_cast<uint64_t>(native);
  }
  *ptr<uint64_t>(s.x[1]) = base;
  return base;
}

uint64_t AddVectoredExceptionHandler_(GuestProcess& p, CpuState& s) { return p.add_vectored_handler(s.x[0] != 0, s.x[1]); }

uint64_t RemoveVectoredExceptionHandler_(GuestProcess& p, CpuState& s) { return p.remove_vectored_handler(s.x[0]); }

uint64_t SetUnhandledExceptionFilter_(GuestProcess& p, CpuState& s) { return p.set_unhandled_exception_filter(s.x[0]); }

// __C_specific_handler, the language handler of C __try blocks, as the ARM64
// C runtime implements it. Programs built with the static C runtime have their
// own copy in guest code; this one replaces vcruntime140.dll's (x64) export.
uint64_t C_specific_handler_(GuestProcess& p, CpuState& s) {
  auto* record = ptr<EXCEPTION_RECORD>(s.x[0]);
  const uint64_t frame = s.x[1];
  auto* context = ptr<CONTEXT>(s.x[2]);
  auto* dc = ptr<DispatcherContext>(s.x[3]);
  struct Scope {
    uint32_t begin, end, handler, target;
  };
  const auto* table = ptr<const uint32_t>(dc->handler_data);
  const uint32_t count = table[0];
  const auto* scopes = reinterpret_cast<const Scope*>(table + 1);
  const uint64_t base = dc->image_base;
  const uint64_t pc = dc->control_pc - (dc->control_pc_is_unwound ? 4 : 0);
  auto in = [&](const Scope& sc, uint64_t a) { return a >= base + sc.begin && a < base + sc.end; };
  const uint64_t stack = (s.sp - 0x100) & ~uint64_t{15};
  // Filters and __finally blocks are funclets of the function with the __try:
  // they run with its non-volatile registers (x19-x28) and get its frame
  // pointer as their second argument, like the C runtime's own version does.
  const auto* nonvolatile = ptr<const uint64_t>(dc->non_volatile_registers);
  const uint64_t parent_fp = nonvolatile ? nonvolatile[10] : frame;
  const GuestCall funclet{false, nullptr, stack, nonvolatile};

  if (record->ExceptionFlags & (EXCEPTION_UNWINDING | EXCEPTION_EXIT_UNWIND)) {
    // Unwinding: run the __finally blocks of the scopes being left.
    for (uint32_t i = dc->scope_index; i < count; ++i) {
      const Scope& sc = scopes[i];
      if (!in(sc, pc) || sc.target) continue;
      if ((record->ExceptionFlags & EXCEPTION_TARGET_UNWIND) && in(sc, dc->target_pc)) break;
      dc->scope_index = i + 1;
      p.call_guest(base + sc.handler, {{1 /* abnormal termination */, parent_fp}}, funclet);
    }
    return ExceptionContinueSearch;
  }

  for (uint32_t i = dc->scope_index; i < count; ++i) {
    const Scope& sc = scopes[i];
    if (!in(sc, pc) || !sc.target) continue;
    if (sc.handler != EXCEPTION_EXECUTE_HANDLER) {
      EXCEPTION_POINTERS pointers{record, context};
      const auto r = static_cast<int32_t>(
          p.call_guest(base + sc.handler, {{reinterpret_cast<uint64_t>(&pointers), parent_fp}}, funclet).x0);
      if (r == EXCEPTION_CONTINUE_SEARCH) continue;
      if (r == EXCEPTION_CONTINUE_EXECUTION) return ExceptionContinueExecution;
    }
    // __except: unwind to the handler block, which receives the exception code in x0.
    p.unwind(frame, base + sc.target, record, record->ExceptionCode, GuestProcess::capture_context(s));
  }
  return ExceptionContinueSearch;
}

// C++ exceptions in programs using the dynamic C runtime: vcruntime140.dll is
// x64 code that can't handle ARM64 frames.
[[noreturn]] void dynamic_cxx_unsupported(GuestProcess& p) {
  p.fatal("C++ exceptions in programs built with the dynamic C runtime (/MD) are not supported yet; "
          "build with /MT",
          0xE06D7363);
}
uint64_t CxxThrowException_(GuestProcess& p, CpuState&) { dynamic_cxx_unsupported(p); }
uint64_t CxxFrameHandler_(GuestProcess& p, CpuState&) { dynamic_cxx_unsupported(p); }

constexpr BuiltinExport kExceptions[] = {
    {"RaiseException", RaiseException_},
    {"RtlRaiseException", RtlRaiseException_},
    {"RtlUnwindEx", RtlUnwindEx_},
    {"RtlUnwind", RtlUnwind_},
    {"RtlRestoreContext", RtlRestoreContext_},
    {"RtlLookupFunctionEntry", RtlLookupFunctionEntry_},
    {"RtlVirtualUnwind", RtlVirtualUnwind_},
    {"RtlPcToFileHeader", RtlPcToFileHeader_},
    {"AddVectoredExceptionHandler", AddVectoredExceptionHandler_},
    {"RtlAddVectoredExceptionHandler", AddVectoredExceptionHandler_},
    {"RemoveVectoredExceptionHandler", RemoveVectoredExceptionHandler_},
    {"RtlRemoveVectoredExceptionHandler", RemoveVectoredExceptionHandler_},
    {"SetUnhandledExceptionFilter", SetUnhandledExceptionFilter_},
    {"__C_specific_handler", C_specific_handler_},
};

constexpr BuiltinExport kVcruntime[] = {
    {"__C_specific_handler", C_specific_handler_},
    {"_CxxThrowException", CxxThrowException_},
    {"__CxxFrameHandler3", CxxFrameHandler_},
    {"__CxxFrameHandler4", CxxFrameHandler_},
};

}  // namespace

std::span<const BuiltinExport> exception_builtins() { return kExceptions; }
std::span<const BuiltinExport> vcruntime_builtins() { return kVcruntime; }

}  // namespace juice::win
