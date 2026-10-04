/* A program with DLLs of its own (crt_dll_lib.dll, imported; crt_dll_plugin.dll,
 * loaded with LoadLibrary): exports, DllMain notifications, thread-local data,
 * module functions, callbacks and exceptions across modules. */
#include <stdio.h>
#include <string.h>
#include <windows.h>

__declspec(dllimport) extern int lib_process_attach;
__declspec(dllimport) extern int lib_static_load;
__declspec(dllimport) extern volatile LONG lib_thread_attach;
__declspec(dllimport) extern volatile LONG lib_thread_detach;
__declspec(dllimport) int lib_add(int a, int b);
__declspec(dllimport) int lib_tls_get(void);
__declspec(dllimport) void lib_tls_set(int v);
__declspec(dllimport) void lib_raise(DWORD code);
__declspec(dllimport) BOOL CALLBACK lib_init_once(INIT_ONCE* once, void* param, void** context);

typedef int (*IntFn)(void);
typedef int (*AddFn)(int, int);
typedef DWORD (*DwordFn)(void);
typedef const char* (*NameFn)(void);

static const char* file_part(const char* path) {
  const char* slash = strrchr(path, '\\');
  return slash ? slash + 1 : path;
}

static HANDLE go, ready;
static int thread_tls, thread_plugin_tls;
static IntFn plugin_tls_get;

static DWORD WINAPI worker(void* param) {
  (void)param;
  lib_tls_set(5);
  thread_tls = lib_tls_get();
  SetEvent(ready);
  WaitForSingleObject(go, INFINITE);  /* the plugin is loaded meanwhile */
  thread_plugin_tls = plugin_tls_get();
  return 0;
}

int main(void) {
  printf("process attach: %d, static load: %d\n", lib_process_attach, lib_static_load);
  printf("lib_add: %d\n", lib_add(40, 2));

  /* Module functions. */
  HMODULE lib = GetModuleHandleA("crt_dll_lib.dll");
  char path[MAX_PATH];
  GetModuleFileNameA(lib, path, MAX_PATH);
  printf("module file: %s\n", file_part(path));
  printf("GetModuleHandle without extension: %d\n", GetModuleHandleA("crt_dll_lib") == lib);
  HMODULE from_address = NULL;
  GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                     (LPCSTR)lib_add, &from_address);
  printf("GetModuleHandleEx from address: %d\n", from_address == lib);
  printf("GetProcAddress(lib_add): %d\n", ((AddFn)GetProcAddress(lib, "lib_add"))(1, 2));
  printf("by ordinal: %d\n", ((IntFn)GetProcAddress(lib, MAKEINTRESOURCEA(42)))());
  printf("forwarded to kernel32: %d\n",
         ((DwordFn)GetProcAddress(lib, "lib_process_id"))() == GetCurrentProcessId());
  printf("missing export: %d\n", GetProcAddress(lib, "no_such_export") == NULL);

  /* A native API calling back into the DLL. */
  INIT_ONCE once = INIT_ONCE_STATIC_INIT;
  int value = 1;
  InitOnceExecuteOnce(&once, lib_init_once, &value, NULL);
  printf("callback into the DLL: %d\n", value);

  /* An exception raised in the DLL, handled here. */
  __try {
    lib_raise(0xE0000042);
    printf("not reached\n");
  } __except (GetExceptionCode() == 0xE0000042 ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
    printf("caught exception from the DLL: 0x%08lx\n", GetExceptionCode());
  }

  /* Thread-local data and thread notifications. */
  lib_tls_set(99);
  go = CreateEventA(NULL, TRUE, FALSE, NULL);
  ready = CreateEventA(NULL, TRUE, FALSE, NULL);
  HANDLE thread = CreateThread(NULL, 0, worker, NULL, 0, NULL);
  WaitForSingleObject(ready, INFINITE);

  /* A DLL with thread-local data loaded while the thread exists. */
  HMODULE plugin = LoadLibraryA("crt_dll_plugin.dll");
  printf("plugin loaded: %d\n", plugin != NULL);
  plugin_tls_get = (IntFn)GetProcAddress(plugin, "plugin_tls_get");
  printf("plugin name: %s\n", ((NameFn)GetProcAddress(plugin, "plugin_name"))());
  printf("plugin forwarder to the other DLL: %d\n", ((AddFn)GetProcAddress(plugin, "plugin_add"))(20, 3));
  printf("loading again returns the same module: %d\n", LoadLibraryA("crt_dll_plugin") == plugin);
  SetEvent(go);
  WaitForSingleObject(thread, INFINITE);
  CloseHandle(thread);

  printf("main thread tls: %d, worker tls: %d\n", lib_tls_get(), thread_tls);
  printf("plugin tls in main: %d, in the older thread: %d\n", plugin_tls_get(), thread_plugin_tls);
  printf("thread attach: %ld, detach: %ld\n", lib_thread_attach, lib_thread_detach);
  printf("plugin thread notifications: %ld\n",
         *(volatile LONG*)GetProcAddress(plugin, "plugin_thread_notifications"));
  printf("FreeLibrary: %d\n", FreeLibrary(plugin));
  fflush(stdout);
  return 0;
}
