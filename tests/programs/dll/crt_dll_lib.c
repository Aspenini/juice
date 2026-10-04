/* A DLL the test program imports statically: exported functions and data, an
 * export by ordinal only, a forwarder to a native DLL, DllMain notifications,
 * implicit thread-local data and a function that raises an exception. */
#include <windows.h>

#define EXPORT __declspec(dllexport)

/* Notifications DllMain received: process attach (with lpReserved), thread
 * attach and detach. */
EXPORT int lib_process_attach = 0;
EXPORT int lib_static_load = 0;
EXPORT volatile LONG lib_thread_attach = 0;
EXPORT volatile LONG lib_thread_detach = 0;

static __declspec(thread) int tls_value = 1234;

EXPORT int lib_add(int a, int b) { return a + b; }

EXPORT int lib_tls_get(void) { return tls_value; }
EXPORT void lib_tls_set(int v) { tls_value = v; }

/* Exported only by ordinal 42. */
int lib_secret(void) { return 4242; }
#pragma comment(linker, "/export:lib_secret,@42,NONAME")

/* Forwarded to a native DLL. */
#pragma comment(linker, "/export:lib_process_id=kernel32.GetCurrentProcessId")

EXPORT void lib_raise(DWORD code) { RaiseException(code, 0, 0, NULL); }

/* Callback for a native API (InitOnceExecuteOnce). */
EXPORT BOOL CALLBACK lib_init_once(INIT_ONCE* once, void* param, void** context) {
  (void)once;
  (void)context;
  *(int*)param += 100;
  return TRUE;
}

static void write_line(const char* text) {
  DWORD written;
  WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), text, lstrlenA(text), &written, NULL);
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, void* reserved) {
  (void)instance;
  switch (reason) {
    case DLL_PROCESS_ATTACH:
      ++lib_process_attach;
      lib_static_load = reserved != NULL;
      break;
    case DLL_THREAD_ATTACH:
      InterlockedIncrement(&lib_thread_attach);
      break;
    case DLL_THREAD_DETACH:
      InterlockedIncrement(&lib_thread_detach);
      break;
    case DLL_PROCESS_DETACH:
      write_line("lib: process detach\n");
      break;
  }
  return TRUE;
}
