/* Hardware exceptions delivered to the program: access violations (read,
 * write, execute, in nested calls, in atomics), guard-page style recovery
 * that continues execution, vectored handlers, __finally during the unwind,
 * breakpoints, illegal instructions and integer division by zero. Also
 * exceptions across native code: raised or faulting in a native function the
 * program called, and raised in a callback that native code called, caught
 * by the program outside the native call.
 *
 * Every faulting operation is in a function of its own: clang's __try only
 * catches hardware exceptions raised in calls made inside it. */
#include <stdio.h>
#include <string.h>
#include <windows.h>
#include <intrin.h>
#include <rpc.h>

#pragma comment(lib, "rpcrt4.lib")

static DWORD last_code;
static volatile int zero = 0, seven = 7;
static ULONG_PTR last_info[2];
static int context_matches;

static int record(EXCEPTION_POINTERS* e) {
  const EXCEPTION_RECORD* r = e->ExceptionRecord;
  last_code = r->ExceptionCode;
  last_info[0] = r->NumberParameters >= 1 ? r->ExceptionInformation[0] : 99;
  last_info[1] = r->NumberParameters >= 2 ? r->ExceptionInformation[1] : 99;
#if defined(_M_ARM64)
  context_matches = e->ContextRecord->Pc == (DWORD64)r->ExceptionAddress;
#else
  context_matches = e->ContextRecord->Rip == (DWORD64)r->ExceptionAddress;
#endif
  return EXCEPTION_EXECUTE_HANDLER;
}

/* An atomic's fault is a read on ARM64 (the exclusive load of LDAXR/STLXR)
 * and a write on x64 (lock xadd): only the address is compared. */
static void report_address(const char* what) {
  printf("%s: 0x%08lx (0x%llx), context at the fault: %d\n", what, last_code, (unsigned long long)last_info[1],
         context_matches);
  last_code = 0;
}

static void report(const char* what) {
  printf("%s: 0x%08lx", what, last_code);
  if (last_code == EXCEPTION_ACCESS_VIOLATION) printf(" (%s 0x%llx)", last_info[0] == 1 ? "write" : last_info[0] == 8 ? "execute" : "read",
                                                       (unsigned long long)last_info[1]);
  printf(", context at the fault: %d\n", context_matches);
  last_code = 0;
}

__declspec(noinline) static int read_at(volatile int* p) { return *p; }
__declspec(noinline) static void write_at(volatile int* p, int v) { *p = v; }
__declspec(noinline) static void call_at(void* p) { ((void (*)(void))p)(); }
__declspec(noinline) static void increment_at(volatile LONG* p) { InterlockedIncrement(p); }
__declspec(noinline) static void cas_at(volatile LONG64* p) { InterlockedCompareExchange64(p, 1, 0); }
__declspec(noinline) static int write_and_sum(char* p) {
  p[100] = 42;
  return p[100] + p[101];
}
__declspec(noinline) static void write_byte(volatile char* p, char v) { *p = v; }
__declspec(noinline) static void breakpoint(void) { __debugbreak(); }

/* A copy from a bad address: on ARM64 the MOPS instructions (FEAT_MOPS),
 * which JUICE runs in a host helper, so the fault is in host code that the
 * translated code called. */
__declspec(noinline) static void copy_bytes(void* dst, const void* src, size_t n) {
#if defined(_M_ARM64)
  __asm__ volatile("cpyfp [%0]!, [%1]!, %2!\n\tcpyfm [%0]!, [%1]!, %2!\n\tcpyfe [%0]!, [%1]!, %2!"
                   : "+r"(dst), "+r"(src), "+r"(n)
                   :
                   : "memory");
#else
  memcpy(dst, src, n);
#endif
}
__declspec(noinline) static int deeper(volatile int* p, int depth) { return depth ? deeper(p, depth - 1) + 1 : read_at(p); }

static int finally_ran;
__declspec(noinline) static void with_finally(volatile int* p) {
  __try {
    write_at(p, 1);
  } __finally {
    finally_ran = AbnormalTermination();
  }
}

/* A page made accessible by the handler, which then continues execution. */
static char* lazy_page;
static int lazy_faults;

static int commit_lazy(EXCEPTION_POINTERS* e) {
  const EXCEPTION_RECORD* r = e->ExceptionRecord;
  if (r->ExceptionCode != EXCEPTION_ACCESS_VIOLATION || r->ExceptionInformation[1] - (ULONG_PTR)lazy_page >= 4096)
    return EXCEPTION_CONTINUE_SEARCH;
  DWORD old;
  VirtualProtect(lazy_page, 4096, PAGE_READWRITE, &old);
  ++lazy_faults;
  return EXCEPTION_CONTINUE_EXECUTION;
}

static char* vectored_page;
static LONG CALLBACK vectored(EXCEPTION_POINTERS* e) {
  const EXCEPTION_RECORD* r = e->ExceptionRecord;
  if (r->ExceptionCode == EXCEPTION_ACCESS_VIOLATION && r->ExceptionInformation[1] - (ULONG_PTR)vectored_page < 4096) {
    DWORD old;
    VirtualProtect(vectored_page, 4096, PAGE_READWRITE, &old);
    return EXCEPTION_CONTINUE_EXECUTION;
  }
  return EXCEPTION_CONTINUE_SEARCH;
}

__declspec(noinline) static int divide(int a, int b) {
#if defined(_M_ARM64)
  if (b == 0) __asm__ volatile("brk #0xf004");  /* what MSVC emits for the check */
#endif
  return a / b;
}

__declspec(noinline) static void illegal(void) {
#if defined(_M_ARM64)
  __asm__ volatile("udf #0");
#else
  __ud2();
#endif
}

/* --- exceptions across native code -------------------------------------------- */

typedef size_t(__cdecl* StrlenFn)(const char*);

static int callback_finally;

static BOOL CALLBACK raise_in_callback(INIT_ONCE* once, void* param, void** context) {
  (void)once;
  (void)context;
  __try {
    if (*(int*)param == 1) RaiseException(0xE0001234, 0, 0, NULL);
    if (*(int*)param == 2) read_at((volatile int*)0x60);
  } __finally {
    callback_finally = 1;
  }
  return TRUE;
}

static int run_once(int what) {
  INIT_ONCE once = INIT_ONCE_STATIC_INIT;
  return InitOnceExecuteOnce(&once, raise_in_callback, &what, NULL);
}

static void across_native(void) {
  /* A fault in a native function (the x64 C runtime's strlen). */
  HMODULE ucrt = LoadLibraryA("ucrtbase.dll");
  StrlenFn native_strlen = (StrlenFn)GetProcAddress(ucrt, "strlen");
  __try {
    printf("%zu\n", native_strlen((const char*)0x70));
  } __except (record(GetExceptionInformation())) {
    printf("fault in a native function: 0x%08lx (read 0x%llx)\n", last_code, (unsigned long long)last_info[1]);
    last_code = 0;
  }
  /* An exception a native function raises. */
  __try {
    RpcRaiseException(1726);
  } __except (record(GetExceptionInformation())) {
    printf("raised by a native function: %lu\n", last_code);
    last_code = 0;
  }
  /* Raised in a callback, caught outside the native function that called it. */
  callback_finally = 0;
  __try {
    run_once(1);
    printf("not reached\n");
  } __except (record(GetExceptionInformation())) {
    printf("raised in a callback: 0x%08lx, callback's __finally ran: %d\n", last_code, callback_finally);
    last_code = 0;
  }
  callback_finally = 0;
  __try {
    run_once(2);
    printf("not reached\n");
  } __except (record(GetExceptionInformation())) {
    printf("fault in a callback: 0x%08lx (read 0x%llx), callback's __finally ran: %d\n", last_code,
           (unsigned long long)last_info[1], callback_finally);
    last_code = 0;
  }
  printf("after: %d\n", run_once(0) == FALSE || 1);
}

int main(void) {
  __try {
    read_at((volatile int*)16);
  } __except (record(GetExceptionInformation())) {
    report("read of 0x10");
  }
  __try {
    write_at((volatile int*)32, 5);
  } __except (record(GetExceptionInformation())) {
    report("write to 0x20");
  }
  __try {
    deeper((volatile int*)8, 20);
  } __except (record(GetExceptionInformation())) {
    report("read 20 calls deep");
  }
  __try {
    with_finally((volatile int*)24);
  } __except (record(GetExceptionInformation())) {
    report("write under __finally");
  }
  printf("__finally ran abnormally: %d\n", finally_ran);

  /* Execute: a data page (no execute permission). */
  void* data = VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  memset(data, 0, 4096);
  __try {
    call_at(data);
  } __except (record(GetExceptionInformation())) {
    printf("execute data page: 0x%08lx, execute %d, address matches %d\n", last_code, last_info[0] == 8,
           last_info[1] == (ULONG_PTR)data);
    last_code = 0;
  }

  /* Atomics on a bad address. */
  __try {
    increment_at((volatile LONG*)40);
  } __except (record(GetExceptionInformation())) {
    report_address("InterlockedIncrement");
  }
  __try {
    cas_at((volatile LONG64*)48);
  } __except (record(GetExceptionInformation())) {
    report_address("InterlockedCompareExchange64");
  }

  char buffer[64];
  __try {
    copy_bytes(buffer, (const void*)0x50, sizeof(buffer));
  } __except (record(GetExceptionInformation())) {
    printf("copy from a bad address: 0x%08lx, read %d, address in the source %d\n", last_code, last_info[0] == 0,
           last_info[1] >= 0x50 && last_info[1] < 0x90);
    last_code = 0;
  }

  /* Continue execution after making the page accessible. */
  lazy_page = VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_NOACCESS);
  int sum = 0;
  __try {
    sum = write_and_sum(lazy_page);
  } __except (commit_lazy(GetExceptionInformation())) {
    printf("not reached\n");
  }
  printf("continued after commit: sum %d, faults %d\n", sum, lazy_faults);

  /* Many faults in a row: nothing accumulates. */
  int caught = 0;
  for (int i = 0; i < 2000; ++i) {
    __try {
      read_at((volatile int*)(uintptr_t)(i * 8));
    } __except (EXCEPTION_EXECUTE_HANDLER) {
      ++caught;
    }
  }
  printf("caught in a loop: %d\n", caught);

  /* A vectored handler fixes the fault. */
  vectored_page = VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READONLY);
  void* handle = AddVectoredExceptionHandler(1, vectored);
  write_byte(vectored_page + 7, 7);
  printf("vectored handler continued: %d\n", vectored_page[7]);
  RemoveVectoredExceptionHandler(handle);

  __try {
    breakpoint();
  } __except (record(GetExceptionInformation())) {
    report("__debugbreak");
  }
  __try {
    illegal();
  } __except (record(GetExceptionInformation())) {
    report("illegal instruction");
  }
  __try {
    printf("%d\n", divide(seven, zero));
  } __except (record(GetExceptionInformation())) {
    report("division by zero");
  }
  across_native();
  printf("done\n");
  return 0;
}
