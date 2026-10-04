/* Threads: CreateThread workers hammering shared state through Interlocked
 * operations and an SRW lock, per-thread TLS, suspended creation, ExitThread
 * exit codes, events, and thread-pool callbacks (which arrive on threads the
 * program never created). */
#include "juice_test.h"

#define WORKERS 8
#define ITERATIONS 20000

static volatile LONG counter32;
static volatile LONG64 counter64;
static volatile LONG cas_counter;
static SRWLOCK lock = SRWLOCK_INIT;
static u64 locked_counter; /* protected by `lock` */
static DWORD tls_index;
static u64 worker_results[WORKERS];

static DWORD WINAPI worker(LPVOID param) {
  const int id = (int)(ULONG_PTR)param;
  TlsSetValue(tls_index, (LPVOID)(ULONG_PTR)(id * 1000 + 1));
  u64 local = 0;
  for (int i = 0; i < ITERATIONS; ++i) {
    InterlockedIncrement(&counter32);
    InterlockedAdd64(&counter64, id + 1);
    for (;;) {
      LONG seen = cas_counter;
      if (InterlockedCompareExchange(&cas_counter, seen + 2, seen) == seen) break;
    }
    if ((i & 15) == 0) {
      AcquireSRWLockExclusive(&lock);
      locked_counter += 3;
      ReleaseSRWLockExclusive(&lock);
    }
    local += (u64)i * (u64)(id + 1);
    if ((i & 1023) == 0) SwitchToThread();
  }
  /* TLS must still hold this thread's own value. */
  if ((ULONG_PTR)TlsGetValue(tls_index) != (ULONG_PTR)(id * 1000 + 1)) local = 0;
  worker_results[id] = local;
  return (DWORD)(100 + id);
}

static DWORD WINAPI exits_early(LPVOID param) {
  (void)param;
  ExitThread(77);
}

static volatile LONG pool_calls;
static volatile LONG pool_remaining;
static HANDLE pool_done;

static VOID CALLBACK pool_callback(PTP_CALLBACK_INSTANCE instance, PVOID context) {
  (void)instance;
  InterlockedAdd(&pool_calls, (LONG)(ULONG_PTR)context);
  if (InterlockedDecrement(&pool_remaining) == 0) SetEvent(pool_done);
}

void mainCRTStartup(void) {
  tls_index = TlsAlloc();
  TlsSetValue(tls_index, (LPVOID)42);

  HANDLE threads[WORKERS];
  for (int i = 0; i < WORKERS; ++i) {
    DWORD flags = (i % 2) ? CREATE_SUSPENDED : 0;
    threads[i] = CreateThread(NULL, 0, worker, (LPVOID)(ULONG_PTR)i, flags, NULL);
    if (!threads[i]) {
      put_str("CreateThread failed\n");
      finish(1);
    }
  }
  for (int i = 1; i < WORKERS; i += 2) ResumeThread(threads[i]);
  WaitForMultipleObjects(WORKERS, threads, TRUE, INFINITE);

  u64 exit_sum = 0;
  for (int i = 0; i < WORKERS; ++i) {
    DWORD code = 0;
    GetExitCodeThread(threads[i], &code);
    exit_sum += code;
    CloseHandle(threads[i]);
  }
  line_i("counter32", counter32);
  line_i("counter64", counter64);
  line_i("cas counter", cas_counter);
  line_i("locked counter", (i64)locked_counter);
  line_i("exit codes", (i64)exit_sum);
  for (int i = 0; i < WORKERS; ++i) line("worker result", worker_results[i]);
  line_i("main tls", (i64)(ULONG_PTR)TlsGetValue(tls_index));

  HANDLE early = CreateThread(NULL, 0, exits_early, NULL, 0, NULL);
  WaitForSingleObject(early, INFINITE);
  {
    DWORD code = 0;
    GetExitCodeThread(early, &code);
    line_i("ExitThread code", code);
  }
  CloseHandle(early);

  /* Thread-pool callbacks run on native worker threads. */
  pool_done = CreateEventA(NULL, TRUE, FALSE, NULL);
  pool_remaining = 32;
  for (int i = 1; i <= 32; ++i) TrySubmitThreadpoolCallback(pool_callback, (PVOID)(ULONG_PTR)i, NULL);
  WaitForSingleObject(pool_done, INFINITE);
  line_i("pool calls", pool_calls);

  finish(0);
}
