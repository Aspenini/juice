#include "windows/exceptions/fault_handler.hpp"

#include <windows.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <optional>

#include "core/jit/x64/emitter.hpp"
#include "runtime/engine.hpp"
#include "runtime/memory/exec_memory.hpp"

namespace juice::win {
namespace {

FaultRegions g_regions;

const char* access_kind(ULONG_PTR kind) {
  switch (kind) {
    case 0: return "read";
    case 1: return "write";
    case 8: return "execute";
    default: return "access";
  }
}

void dump_guest(const arm64::CpuState& s) {
  std::fprintf(stderr, "[juice]   block pc 0x%016llx  sp 0x%016llx  lr 0x%016llx\n",
               static_cast<unsigned long long>(s.block_pc), static_cast<unsigned long long>(s.sp),
               static_cast<unsigned long long>(s.x[30]));
  for (int i = 0; i < 30; i += 3)
    std::fprintf(stderr, "[juice]   x%-2d 0x%016llx  x%-2d 0x%016llx  x%-2d 0x%016llx\n", i,
                 static_cast<unsigned long long>(s.x[i]), i + 1, static_cast<unsigned long long>(s.x[i + 1]), i + 2,
                 static_cast<unsigned long long>(s.x[i + 2]));
}

void print_location(const char* prefix, uint64_t address);

bool in_jit_code(uint64_t address) {
  return g_regions.jit_code && g_regions.jit_code->contains(reinterpret_cast<void*>(address));
}

// A fault in a host helper that translated code called (atomics, MOPS):
// unwind `c` to the translated code, a few frames up at most. False if it
// isn't there (a fault in JUICE itself, or in native code the guest called).
bool unwind_to_jit_code(CONTEXT& c) {
  for (int depth = 0; depth < 6; ++depth) {
    DWORD64 image_base = 0;
    PRUNTIME_FUNCTION function = RtlLookupFunctionEntry(c.Rip, &image_base, nullptr);
    if (!function) {
      if (depth > 0) return false;  // only the faulting function may be a leaf
      c.Rip = *reinterpret_cast<const DWORD64*>(c.Rsp);
      c.Rsp += 8;
    } else {
      void* handler_data = nullptr;
      DWORD64 establisher = 0;
      RtlVirtualUnwind(UNW_FLAG_NHANDLER, image_base, c.Rip, function, &c, &handler_data, &establisher, nullptr);
    }
    if (in_jit_code(c.Rip)) return true;
  }
  return false;
}

// A guest memory access faulted at host_pc in a translated block whose body
// runs with context `c`: record the fault in the guest state and return from
// the block to the dispatcher, which hands it to the Windows layer as
// ExitReason::MemoryFault (dispatched to the guest's exception handlers).
bool recover_guest_fault(CONTEXT& c, uint64_t host_pc, const EXCEPTION_RECORD* rec) {
  const std::optional<uint64_t> pc = g_regions.engine->fault_pc(host_pc);
  if (!pc) return false;
  auto* s = reinterpret_cast<arm64::CpuState*>(c.Rbx);  // blocks keep the state pointer in RBX
  if (s != runtime::Engine::current_state()) return false;
  s->pc = *pc;
  s->exit_reason = static_cast<uint32_t>(arm64::ExitReason::MemoryFault);
  s->exit_info = rec->NumberParameters >= 1 ? static_cast<uint32_t>(rec->ExceptionInformation[0]) : 0;
  s->fault_address = rec->NumberParameters >= 2 ? rec->ExceptionInformation[1] : 0;
  s->fault_code = rec->ExceptionCode;
  // The block's epilogue (see x64::kBlockFrameSize).
  const auto* frame = reinterpret_cast<const DWORD64*>(c.Rsp + x64::kBlockFrameSize);
  c.Rbp = frame[0];
  c.Rbx = frame[1];
  c.Rip = frame[2];
  c.Rsp += x64::kBlockFrameSize + 24;
  return true;
}

LONG CALLBACK handler(EXCEPTION_POINTERS* info) {
  const EXCEPTION_RECORD* rec = info->ExceptionRecord;
  const DWORD code = rec->ExceptionCode;
  static const bool trace = std::getenv("JUICE_TRACE_EXCEPTIONS") != nullptr;
  if (trace) {  // every host exception, handled or not (debugging aid)
    std::fprintf(stderr, "[juice] exception 0x%08lx on thread %lu ", code, GetCurrentThreadId());
    print_location("at ", info->ContextRecord->Rip);
  }
  if (code != EXCEPTION_ACCESS_VIOLATION && code != EXCEPTION_ILLEGAL_INSTRUCTION &&
      code != EXCEPTION_INT_DIVIDE_BY_ZERO && code != EXCEPTION_STACK_OVERFLOW && code != EXCEPTION_PRIV_INSTRUCTION &&
      code != EXCEPTION_IN_PAGE_ERROR && code != STATUS_GUARD_PAGE_VIOLATION)
    return EXCEPTION_CONTINUE_SEARCH;

  CONTEXT* ctx = info->ContextRecord;
  const uint64_t rip = ctx->Rip;
  const bool in_jit = in_jit_code(rip);

  // Guest memory faults (in translated code, or in a helper it called) go to
  // the guest's exception handlers.
  const bool memory_fault =
      code == EXCEPTION_ACCESS_VIOLATION || code == EXCEPTION_IN_PAGE_ERROR || code == STATUS_GUARD_PAGE_VIOLATION;
  if (memory_fault && g_regions.engine) {
    CONTEXT c = *ctx;
    if (in_jit ? recover_guest_fault(c, rip, rec)
               : unwind_to_jit_code(c) && recover_guest_fault(c, c.Rip - 1, rec)) {
      *ctx = c;
      return EXCEPTION_CONTINUE_EXECUTION;
    }
  }
  const bool in_thunks = rip >= g_regions.thunks_begin && rip < g_regions.thunks_end;
  const bool in_image = g_regions.callbacks && g_regions.callbacks->is_guest_address(rip);
  if (!in_jit && !in_thunks && !in_image) return EXCEPTION_CONTINUE_SEARCH;

  // Native code called into the guest: emulate the call and return to it.
  const bool execute_fault = code == EXCEPTION_ACCESS_VIOLATION && rec->NumberParameters >= 2 &&
                             rec->ExceptionInformation[0] == 8 && rec->ExceptionInformation[1] == rip;
  if (execute_fault && (in_thunks || in_image) && g_regions.callbacks) {
    // x64: RCX, RDX, R8, R9, then the stack after the return address and 32 bytes of home space.
    const auto* stack = reinterpret_cast<const uint64_t*>(ctx->Rsp);
    NativeCallbackTarget::Args args = {
        {ctx->Rcx, ctx->Rdx, ctx->R8, ctx->R9, stack[5], stack[6], stack[7], stack[8]},
        {ctx->Xmm0.Low, ctx->Xmm1.Low, ctx->Xmm2.Low, ctx->Xmm3.Low},
        stack + 5,
    };
    NativeCallbackTarget::Result result{};
    if (g_regions.callbacks->call_from_native(rip, args, result)) {
      // The return type is unknown: provide the result in both RAX and XMM0.
      ctx->Rax = result.x0;
      ctx->Xmm0.Low = result.d0;
      ctx->Xmm0.High = 0;
      ctx->Rip = stack[0];
      ctx->Rsp += 8;
      return EXCEPTION_CONTINUE_EXECUTION;
    }
  }

  std::fflush(stdout);
  if (in_jit) {
    if (code == EXCEPTION_ACCESS_VIOLATION && rec->NumberParameters >= 2) {
      std::fprintf(stderr, "[juice] guest %s access violation at address 0x%llx\n",
                   access_kind(rec->ExceptionInformation[0]),
                   static_cast<unsigned long long>(rec->ExceptionInformation[1]));
    } else {
      std::fprintf(stderr, "[juice] guest fault 0x%08lx in translated code\n", code);
    }
    if (const arm64::CpuState* s = runtime::Engine::current_state()) dump_guest(*s);
  } else {
    std::fprintf(stderr, "[juice] native code called guest address 0x%llx%s, which could not be serviced\n",
                 static_cast<unsigned long long>(rip), in_thunks ? " (an API thunk)" : "");
  }
  std::fflush(stderr);
  TerminateProcess(GetCurrentProcess(), code);
  return EXCEPTION_CONTINUE_SEARCH;
}

// "module+0xoffset" for a host code address, for llvm-symbolizer.
void print_location(const char* prefix, uint64_t address) {
  HMODULE module = nullptr;
  char path[MAX_PATH] = "?";
  if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                         reinterpret_cast<LPCWSTR>(address), &module)) {
    GetModuleFileNameA(module, path, MAX_PATH);
    const char* name = std::strrchr(path, '\\');
    std::fprintf(stderr, "%s%s+0x%llx\n", prefix, name ? name + 1 : path,
                 static_cast<unsigned long long>(address - reinterpret_cast<uint64_t>(module)));
  } else if (g_regions.jit_code && g_regions.jit_code->contains(reinterpret_cast<void*>(address))) {
    std::fprintf(stderr, "%stranslated code at 0x%llx\n", prefix, static_cast<unsigned long long>(address));
  } else {
    std::fprintf(stderr, "%s0x%llx\n", prefix, static_cast<unsigned long long>(address));
  }
}

// A crash in JUICE itself (or in native code it called): report where, with
// a host stack trace and the guest context of this thread.
LONG WINAPI unhandled(EXCEPTION_POINTERS* info) {
  const EXCEPTION_RECORD* rec = info->ExceptionRecord;
  std::fflush(stdout);
  std::fprintf(stderr, "[juice] internal error: exception 0x%08lx on thread %lu\n", rec->ExceptionCode,
               GetCurrentThreadId());
  if (rec->ExceptionCode == EXCEPTION_ACCESS_VIOLATION && rec->NumberParameters >= 2)
    std::fprintf(stderr, "[juice]   %s of address 0x%llx\n", access_kind(rec->ExceptionInformation[0]),
                 static_cast<unsigned long long>(rec->ExceptionInformation[1]));

  CONTEXT ctx = *info->ContextRecord;
  for (int frame = 0; frame < 24 && ctx.Rip; ++frame) {
    print_location("[juice]   at ", ctx.Rip);
    if (g_regions.jit_code && g_regions.jit_code->contains(reinterpret_cast<void*>(ctx.Rip))) break;
    DWORD64 image_base = 0;
    PRUNTIME_FUNCTION function = RtlLookupFunctionEntry(ctx.Rip, &image_base, nullptr);
    if (!function) {  // leaf function
      ctx.Rip = *reinterpret_cast<const DWORD64*>(ctx.Rsp);
      ctx.Rsp += 8;
      continue;
    }
    void* handler_data = nullptr;
    DWORD64 establisher = 0;
    RtlVirtualUnwind(UNW_FLAG_NHANDLER, image_base, ctx.Rip, function, &ctx, &handler_data, &establisher, nullptr);
  }
  if (const arm64::CpuState* s = runtime::Engine::current_state()) dump_guest(*s);
  std::fflush(stderr);
  TerminateProcess(GetCurrentProcess(), rec->ExceptionCode);
  return EXCEPTION_CONTINUE_SEARCH;
}

}  // namespace

void install_fault_handler(const FaultRegions& regions) {
  static bool installed = false;
  g_regions = regions;
  if (!installed) {
    AddVectoredExceptionHandler(1, handler);
    SetUnhandledExceptionFilter(unhandled);
    installed = true;
  }
}

}  // namespace juice::win
