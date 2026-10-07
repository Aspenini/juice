/* Fibers (each with a stack of its own, moving between threads),
 * GetCurrentThreadStackLimits, and thread control: SuspendThread,
 * GetThreadContext and SetThreadContext on another thread, both while it runs
 * code and while it waits in an API call. */
#include <stdio.h>
#include <windows.h>

static __declspec(thread) int tls_marker = 0;

static void* main_fiber;
static void* worker_fiber;
static void* ping_fiber;
static int log_step = 0;

static int in_stack(const void* p) {
  ULONG_PTR low, high;
  GetCurrentThreadStackLimits(&low, &high);
  return (ULONG_PTR)p >= low && (ULONG_PTR)p < high;
}

/* Recursion across fiber switches: the fiber's frames must survive. */
static int deep_sum(int n) {
  volatile int local = n;
  if (n == 0) {
    printf("  %d: ping at the bottom of its recursion\n", ++log_step);
    SwitchToFiber(main_fiber);
    return 0;
  }
  return local + deep_sum(n - 1);
}

static void WINAPI ping(void* param) {
  int local = 0;
  printf("  %d: ping starts, data %d, current fiber %d, own stack %d\n", ++log_step, *(int*)param,
         GetCurrentFiber() == ping_fiber, in_stack(&local));
  printf("  %d: ping sum %d\n", ++log_step, deep_sum(50));
  SwitchToFiber(main_fiber);
  /* Resumed by the worker thread: its thread-local data now. */
  printf("  %d: ping on the worker thread, tls %d, own stack %d\n", ++log_step, tls_marker, in_stack(&local));
  SwitchToFiber(worker_fiber);
  printf("never reached\n");
}

static DWORD WINAPI fiber_worker(void* param) {
  (void)param;
  tls_marker = 2;
  worker_fiber = ConvertThreadToFiber(NULL);
  SwitchToFiber(ping_fiber);
  printf("  %d: worker back, tls %d\n", ++log_step, tls_marker);
  ConvertFiberToThread();
  return 0;
}

static void fibers(void) {
  printf("fibers:\n");
  tls_marker = 1;
  int data = 1234;
  main_fiber = ConvertThreadToFiber(&data);
  printf("  fiber data: %d\n", *(int*)GetFiberData());
  ping_fiber = CreateFiber(256 * 1024, ping, &data);
  SwitchToFiber(ping_fiber);
  printf("  %d: main between, tls %d\n", ++log_step, tls_marker);
  SwitchToFiber(ping_fiber);
  printf("  %d: main again\n", ++log_step);
  HANDLE worker = CreateThread(NULL, 0, fiber_worker, NULL, 0, NULL);
  WaitForSingleObject(worker, INFINITE);
  CloseHandle(worker);
  DeleteFiber(ping_fiber);
  printf("  ConvertFiberToThread: %d\n", ConvertFiberToThread());
}

/* --- thread control ---------------------------------------------------------- */

static volatile LONG64 counter = 0;
static volatile LONG stop = 0;
static volatile LONG hijacked_with = 0;
static ULONG_PTR worker_low, worker_high;

static DWORD WINAPI spinner(void* param) {
  (void)param;
  GetCurrentThreadStackLimits(&worker_low, &worker_high);
  while (!stop) counter = counter + 1;
  return 1;
}

static void hijacked(LONG64 value) {
  hijacked_with = (LONG)value;
  ExitThread(42);
}

static HANDLE event;
static DWORD wait_result = 99;

static DWORD WINAPI waiter(void* param) {
  (void)param;
  GetCurrentThreadStackLimits(&worker_low, &worker_high);
  wait_result = WaitForSingleObject(event, INFINITE);
  return 7;
}

static ULONG_PTR context_sp(const CONTEXT* c) {
#if defined(_M_ARM64)
  return c->Sp;
#else
  return c->Rsp;
#endif
}

static void thread_control(void) {
  printf("thread control:\n");
  HANDLE thread = CreateThread(NULL, 0, spinner, NULL, 0, NULL);
  while (counter < 1000) SwitchToThread();
  printf("  SuspendThread: %lu\n", SuspendThread(thread));
  CONTEXT c;
  c.ContextFlags = CONTEXT_FULL;
  printf("  GetThreadContext: %d\n", GetThreadContext(thread, &c));  /* also waits for the suspension */
  const LONG64 at_suspend = counter;
  Sleep(50);
  printf("  stopped while suspended: %d\n", counter == at_suspend);
  printf("  suspended twice: %lu\n", SuspendThread(thread));
  printf("  ResumeThread: %lu\n", ResumeThread(thread));
  printf("  stack pointer in the thread's stack: %d\n", context_sp(&c) > worker_low && context_sp(&c) <= worker_high);
  printf("  SetThreadContext unchanged: %d\n", SetThreadContext(thread, &c));
  printf("  ResumeThread: %lu\n", ResumeThread(thread));
  Sleep(20);
  printf("  runs again: %d\n", counter != at_suspend);

  /* Redirect it into another function. */
  SuspendThread(thread);
  c.ContextFlags = CONTEXT_FULL;
  GetThreadContext(thread, &c);
#if defined(_M_ARM64)
  c.Pc = (DWORD64)hijacked;
  c.X0 = 314;
  c.Sp = (c.Sp - 0x200) & ~(DWORD64)15;
#else
  c.Rip = (DWORD64)hijacked;
  c.Rcx = 314;
  c.Rsp = ((c.Rsp - 0x200) & ~(DWORD64)15) - 8;
#endif
  printf("  SetThreadContext: %d\n", SetThreadContext(thread, &c));
  ResumeThread(thread);
  WaitForSingleObject(thread, INFINITE);
  DWORD code = 0;
  GetExitCodeThread(thread, &code);
  printf("  hijacked: %ld, exit code %lu\n", hijacked_with, code);
  CloseHandle(thread);

  /* A thread waiting in an API call: its context round trip changes nothing. */
  event = CreateEventA(NULL, TRUE, FALSE, NULL);
  thread = CreateThread(NULL, 0, waiter, NULL, 0, NULL);
  Sleep(50);
  printf("  SuspendThread (waiting): %lu\n", SuspendThread(thread));
  c.ContextFlags = CONTEXT_FULL;
  printf("  GetThreadContext: %d\n", GetThreadContext(thread, &c));
  printf("  stack pointer in the thread's stack: %d\n", context_sp(&c) > worker_low && context_sp(&c) <= worker_high);
  printf("  SetThreadContext unchanged: %d\n", SetThreadContext(thread, &c));
  ResumeThread(thread);
  SetEvent(event);
  WaitForSingleObject(thread, INFINITE);
  GetExitCodeThread(thread, &code);
  printf("  wait result %lu, exit code %lu\n", wait_result, code);
  CloseHandle(thread);
  CloseHandle(event);
}

int main(void) {
  int local;
  printf("main stack limits contain a local: %d\n", in_stack(&local));
  fibers();
  thread_control();
  return 0;
}
