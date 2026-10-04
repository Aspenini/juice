/* Structured exception handling with software exceptions (RaiseException):
 * __try/__except with filters, __finally on normal exit and during unwinding,
 * nesting, unwinding through several frames, continuing execution, __leave,
 * exceptions in threads and vectored exception handlers. */
#include <stdio.h>
#include <windows.h>

typedef long long i64;

static void line(const char* label, unsigned long long v) { printf("%s = 0x%llx\n", label, v); }
static void line_i(const char* label, i64 v) { printf("%s = %lld\n", label, v); }
static ULONG_PTR opaque(ULONG_PTR v) {
  volatile ULONG_PTR x = v;
  return x;
}

#define CODE_A 0xE0001234u
#define CODE_B 0xE0005678u

static int log_index;

static void step(const char* what) {
  printf("%d: %s\n", ++log_index, what);
}

static void raise_with_args(DWORD code, DWORD flags) {
  ULONG_PTR args[3] = {11, 22, (ULONG_PTR)opaque(33)};
  RaiseException(code, flags, 3, args);
}

static int filter_details(EXCEPTION_POINTERS* info) {
  const EXCEPTION_RECORD* r = info->ExceptionRecord;
  line("  filter: code", r->ExceptionCode);
  line_i("  filter: flags", (i64)r->ExceptionFlags);
  line_i("  filter: parameters", (i64)r->NumberParameters);
  line_i("  filter: parameter sum",
         (i64)(r->ExceptionInformation[0] + r->ExceptionInformation[1] + r->ExceptionInformation[2]));
  line_i("  filter: has context", info->ContextRecord != NULL);
  return EXCEPTION_EXECUTE_HANDLER;
}

static void basic(void) {
  step("basic");
  __try {
    raise_with_args(CODE_A, 0);
    step("not reached");
  } __except (filter_details(GetExceptionInformation())) {
    line("  handler: code", GetExceptionCode());
  }
  step("after basic");
}

static void finally_normal(void) {
  step("finally on normal exit");
  __try {
    step("  body");
  } __finally {
    line_i("  finally: abnormal", AbnormalTermination());
  }
}

static int ordered_filter(void) {
  step("  outer filter");
  return EXCEPTION_EXECUTE_HANDLER;
}

static void finally_unwind(void) {
  step("finally during unwind");
  __try {
    __try {
      raise_with_args(CODE_B, 0);
    } __finally {
      step("  inner finally");
      line_i("  inner finally: abnormal", AbnormalTermination());
    }
  } __except (ordered_filter()) {
    step("  outer handler");
  }
}

static int search_filter(DWORD code) {
  step("  inner filter: continue search");
  (void)code;
  return EXCEPTION_CONTINUE_SEARCH;
}

static void nested(void) {
  step("nested");
  __try {
    __try {
      raise_with_args(CODE_A, 0);
    } __except (search_filter(GetExceptionCode())) {
      step("  not reached");
    }
  } __except (GetExceptionCode() == CODE_A ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
    step("  outer handler");
  }
}

static volatile int depth_finallies;

static void recurse(int depth) {
  __try {
    if (depth == 0) raise_with_args(CODE_B, 0);
    else recurse(depth - 1);
  } __finally {
    ++depth_finallies;
  }
}

static void deep(void) {
  step("deep unwind");
  volatile int local = 1;
  __try {
    local = 2;
    recurse(20);
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    line_i("  local", local);
    line_i("  finally blocks run", depth_finallies);
  }
}

static int continue_filter(EXCEPTION_POINTERS* info) {
  step("  filter: continue execution");
  return info->ExceptionRecord->ExceptionCode == CODE_A ? EXCEPTION_CONTINUE_EXECUTION : EXCEPTION_CONTINUE_SEARCH;
}

static void continue_execution(void) {
  step("continue execution");
  __try {
    raise_with_args(CODE_A, 0);
    step("  resumed after RaiseException");
  } __except (continue_filter(GetExceptionInformation())) {
    step("  not reached");
  }
}

static void noncontinuable(void) {
  step("noncontinuable");
  __try {
    __try {
      raise_with_args(CODE_A, EXCEPTION_NONCONTINUABLE);
    } __except (continue_filter(GetExceptionInformation())) {
      step("  not reached");
    }
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    line("  outer handler: code", GetExceptionCode());
  }
}

static void leave(void) {
  step("__leave");
  __try {
    if (opaque(1)) __leave;
    step("  not reached");
  } __finally {
    line_i("  finally: abnormal", AbnormalTermination());
  }
}

static void raise_in_handler(void) {
  step("raise in a handler");
  __try {
    __try {
      raise_with_args(CODE_A, 0);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
      step("  inner handler raises");
      raise_with_args(CODE_B, 0);
    }
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    line("  outer handler: code", GetExceptionCode());
  }
}

static DWORD WINAPI thread_proc(void* param) {
  __try {
    raise_with_args(CODE_B, 0);
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    *(DWORD*)param = GetExceptionCode();
  }
  return 0;
}

static void in_thread(void) {
  step("thread");
  DWORD code = 0;
  HANDLE thread = CreateThread(NULL, 0, thread_proc, &code, 0, NULL);
  WaitForSingleObject(thread, INFINITE);
  CloseHandle(thread);
  line("  caught in thread", code);
}

static volatile int veh_calls;

static LONG CALLBACK vectored(EXCEPTION_POINTERS* info) {
  ++veh_calls;
  if (info->ExceptionRecord->ExceptionCode == CODE_B) return EXCEPTION_CONTINUE_EXECUTION;
  return EXCEPTION_CONTINUE_SEARCH;
}

static void vectored_handlers(void) {
  step("vectored handler");
  void* handle = AddVectoredExceptionHandler(1, vectored);
  raise_with_args(CODE_B, 0);
  step("  resumed by the vectored handler");
  __try {
    raise_with_args(CODE_A, 0);
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    step("  frame handler after the vectored handler");
  }
  line_i("  vectored handler calls", veh_calls);
  line_i("  removed", RemoveVectoredExceptionHandler(handle));
  __try {
    raise_with_args(CODE_A, 0);
  } __except (EXCEPTION_EXECUTE_HANDLER) {
  }
  line_i("  calls after removal", veh_calls);
}

int main(void) {
  basic();
  finally_normal();
  finally_unwind();
  nested();
  deep();
  continue_execution();
  noncontinuable();
  leave();
  raise_in_handler();
  in_thread();
  vectored_handlers();
  step("done");
  return 0;
}
