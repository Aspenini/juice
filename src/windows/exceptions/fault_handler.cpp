#include "windows/exceptions/fault_handler.hpp"

#include <windows.h>

#include <cstdio>
#include <cstring>

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

LONG CALLBACK handler(EXCEPTION_POINTERS* info) {
  const EXCEPTION_RECORD* rec = info->ExceptionRecord;
  const DWORD code = rec->ExceptionCode;
  if (code != EXCEPTION_ACCESS_VIOLATION && code != EXCEPTION_ILLEGAL_INSTRUCTION &&
      code != EXCEPTION_INT_DIVIDE_BY_ZERO && code != EXCEPTION_STACK_OVERFLOW && code != EXCEPTION_PRIV_INSTRUCTION)
    return EXCEPTION_CONTINUE_SEARCH;

  CONTEXT* ctx = info->ContextRecord;
  const uint64_t rip = ctx->Rip;
  const bool in_jit = g_regions.jit_code && g_regions.jit_code->contains(reinterpret_cast<void*>(rip));
  const bool in_thunks = rip >= g_regions.thunks_begin && rip < g_regions.thunks_end;
  const bool in_image = rip >= g_regions.image_begin && rip < g_regions.image_end;
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
