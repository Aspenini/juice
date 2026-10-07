/* A program with DLLs of its own (crt_dll_lib.dll, imported; crt_dll_plugin.dll,
 * loaded with LoadLibrary; sub\crt_dll_dep.dll and sub\crt_dll_deplib.dll,
 * found through the search path functions; crt_dll_com.dll, an in-process COM
 * server): exports, DllMain notifications, thread-local data, module functions,
 * reference counts and unloading, module enumeration, callbacks and exceptions
 * across modules. */
#include <stdio.h>
#include <string.h>
#include <windows.h>

#include <objbase.h>
#include <psapi.h>
#include <tlhelp32.h>

#include "crt_dll_com.h"

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "advapi32.lib")

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

static char program_dir[MAX_PATH];

static void sub_path(char* out, const char* file) {
  snprintf(out, MAX_PATH, "%s\\sub%s%s", program_dir, file ? "\\" : "", file ? file : "");
}

static int is_loaded(const char* name) { return GetModuleHandleA(name) != NULL; }

/* FreeLibrary, with the output so far written first (DllMain writes directly). */
static BOOL free_library(HMODULE module) {
  fflush(stdout);
  return FreeLibrary(module);
}

static void search_paths(void) {
  char path[MAX_PATH];
  printf("deplib not on the search path: %d\n", LoadLibraryExA("crt_dll_deplib.dll", NULL, 0) == NULL);

  /* LOAD_WITH_ALTERED_SEARCH_PATH: the DLL's imports are found next to it. */
  sub_path(path, "crt_dll_dep.dll");
  HMODULE dep = LoadLibraryExA(path, NULL, LOAD_WITH_ALTERED_SEARCH_PATH);
  printf("altered search path: %d\n", dep != NULL);
  printf("dep_value: %d\n", dep ? ((IntFn)GetProcAddress(dep, "dep_value"))() : -1);
  printf("deplib loaded with it: %d\n", is_loaded("crt_dll_deplib.dll"));
  printf("FreeLibrary(dep): %d\n", free_library(dep));
  printf("dep and deplib unloaded: %d %d\n", !is_loaded("crt_dll_dep.dll"), !is_loaded("crt_dll_deplib.dll"));

  /* SetDllDirectory. */
  sub_path(path, NULL);
  SetDllDirectoryA(path);
  HMODULE deplib = LoadLibraryA("crt_dll_deplib.dll");
  printf("SetDllDirectory: %d\n", deplib != NULL);
  char dir[MAX_PATH];
  printf("GetDllDirectory: %d\n", GetDllDirectoryA(MAX_PATH, dir) > 0 && strcmp(dir, path) == 0);
  SetDllDirectoryA(NULL);
  free_library(deplib);

  /* AddDllDirectory and the LOAD_LIBRARY_SEARCH_* flags. */
  wchar_t wpath[MAX_PATH];
  MultiByteToWideChar(CP_ACP, 0, path, -1, wpath, MAX_PATH);
  DLL_DIRECTORY_COOKIE cookie = AddDllDirectory(wpath);
  printf("AddDllDirectory: %d\n", cookie != NULL);
  printf("not searched without the flag: %d\n",
         LoadLibraryExA("crt_dll_deplib.dll", NULL, LOAD_LIBRARY_SEARCH_APPLICATION_DIR) == NULL);
  deplib = LoadLibraryExA("crt_dll_deplib.dll", NULL, LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
  printf("LOAD_LIBRARY_SEARCH_DEFAULT_DIRS: %d\n", deplib != NULL);
  printf("deplib attached: %d\n", deplib ? *(int*)GetProcAddress(deplib, "deplib_attached") : -1);
  free_library(deplib);
  printf("RemoveDllDirectory: %d\n", RemoveDllDirectory(cookie));
  printf("removed directory not searched: %d\n",
         LoadLibraryExA("crt_dll_deplib.dll", NULL, LOAD_LIBRARY_SEARCH_DEFAULT_DIRS) == NULL);

  /* DONT_RESOLVE_DLL_REFERENCES: no DllMain. */
  sub_path(path, "crt_dll_deplib.dll");
  deplib = LoadLibraryExA(path, NULL, DONT_RESOLVE_DLL_REFERENCES);
  printf("DONT_RESOLVE_DLL_REFERENCES: %d, attached: %d\n", deplib != NULL,
         deplib ? *(int*)GetProcAddress(deplib, "deplib_attached") : -1);
  free_library(deplib);
  printf("unloaded: %d\n", !is_loaded("crt_dll_deplib.dll"));
}

static int same_name(const char* a, const char* b) { return lstrcmpiA(a, b) == 0; }

static void module_lists(HMODULE lib) {
  HMODULE modules[512];
  DWORD needed = 0;
  int found_lib = 0;
  if (EnumProcessModules(GetCurrentProcess(), modules, sizeof(modules), &needed)) {
    for (DWORD i = 0; i < needed / sizeof(HMODULE) && i < 512; ++i) found_lib |= modules[i] == lib;
    printf("EnumProcessModules: program first: %d, lib: %d\n", modules[0] == GetModuleHandleA(NULL), found_lib);
  }
  char name[MAX_PATH];
  GetModuleBaseNameA(GetCurrentProcess(), lib, name, MAX_PATH);
  printf("GetModuleBaseName: %s\n", name);
  GetModuleBaseNameA(GetCurrentProcess(), NULL, name, MAX_PATH);
  printf("GetModuleBaseName(NULL): %s\n", name);
  GetModuleFileNameExA(GetCurrentProcess(), lib, name, MAX_PATH);
  printf("GetModuleFileNameEx: %s\n", file_part(name));
  MODULEINFO info;
  GetModuleInformation(GetCurrentProcess(), lib, &info, sizeof(info));
  printf("GetModuleInformation: base %d, size %d, entry %d\n", info.lpBaseOfDll == lib, info.SizeOfImage > 0x1000,
         (char*)info.EntryPoint > (char*)lib && (char*)info.EntryPoint < (char*)lib + info.SizeOfImage);

  HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, 0);
  MODULEENTRY32 entry;
  entry.dwSize = sizeof(entry);
  if (Module32First(snapshot, &entry)) {
    printf("Module32First: %s, own process: %d\n", entry.szModule, entry.th32ProcessID == GetCurrentProcessId());
    found_lib = 0;
    int found_kernel32 = 0;
    do {
      if (same_name(entry.szModule, "crt_dll_lib.dll"))
        found_lib = entry.hModule == lib && entry.modBaseAddr == (BYTE*)lib && same_name(file_part(entry.szExePath), "crt_dll_lib.dll");
      found_kernel32 |= same_name(entry.szModule, "kernel32.dll");
    } while (Module32Next(snapshot, &entry));
    printf("Module32Next: lib %d, kernel32 %d\n", found_lib, found_kernel32);
  }
  CloseHandle(snapshot);
}

/* The in-process server, registered (for this run only) under a fresh CLSID. */
static void com_server(void) {
  CLSID clsid;
  CoCreateGuid(&clsid);
  wchar_t clsid_text[64], key[128], dll[MAX_PATH];
  StringFromGUID2(&clsid, clsid_text, 64);
  swprintf(key, 128, L"Software\\Classes\\CLSID\\%ls", clsid_text);
  GetModuleFileNameW(NULL, dll, MAX_PATH);
  lstrcpyW(wcsrchr(dll, L'\\') + 1, L"crt_dll_com.dll");
  HKEY clsid_key, server_key;
  if (RegCreateKeyExW(HKEY_CURRENT_USER, key, 0, NULL, REG_OPTION_VOLATILE, KEY_ALL_ACCESS, NULL, &clsid_key, NULL) ||
      RegCreateKeyExW(clsid_key, L"InprocServer32", 0, NULL, REG_OPTION_VOLATILE, KEY_ALL_ACCESS, NULL, &server_key,
                      NULL)) {
    printf("could not register the COM class\n");
    return;
  }
  RegSetValueExW(server_key, NULL, 0, REG_SZ, (const BYTE*)dll, (DWORD)(wcslen(dll) + 1) * sizeof(wchar_t));
  RegSetValueExW(server_key, L"ThreadingModel", 0, REG_SZ, (const BYTE*)L"Both", sizeof(L"Both"));

  CoInitializeEx(NULL, COINIT_MULTITHREADED);
  IJuiceAdder* adder = NULL;
  HRESULT hr = CoCreateInstance(&clsid, NULL, CLSCTX_INPROC_SERVER, &IID_IJuiceAdder, (void**)&adder);
  int sum = 0;
  if (SUCCEEDED(hr)) adder->lpVtbl->Add(adder, 2, 3, &sum);
  printf("CoCreateInstance: 0x%08lx, sum %d\n", hr, sum);
  if (adder) adder->lpVtbl->Release(adder);

  IClassFactory* factory = NULL;
  hr = CoGetClassObject(&clsid, CLSCTX_INPROC_SERVER, NULL, &IID_IClassFactory, (void**)&factory);
  adder = NULL;
  sum = 0;
  if (SUCCEEDED(hr) && SUCCEEDED(factory->lpVtbl->CreateInstance(factory, NULL, &IID_IJuiceAdder, (void**)&adder)))
    adder->lpVtbl->Add(adder, 30, 12, &sum);
  printf("CoGetClassObject: 0x%08lx, sum %d\n", hr, sum);
  if (adder) adder->lpVtbl->Release(adder);
  if (factory) factory->lpVtbl->Release(factory);

  MULTI_QI qi[3] = {{&IID_IJuiceAdder, NULL, 0}, {&IID_IUnknown, NULL, 0}, {&IID_IClassFactory, NULL, 0}};
  hr = CoCreateInstanceEx(&clsid, NULL, CLSCTX_INPROC_SERVER, NULL, 3, qi);
  printf("CoCreateInstanceEx: 0x%08lx, results 0x%08lx 0x%08lx 0x%08lx, same object %d\n", hr, qi[0].hr, qi[1].hr,
         qi[2].hr, qi[0].pItf == qi[1].pItf);
  for (int i = 0; i < 3; ++i)
    if (qi[i].pItf) qi[i].pItf->lpVtbl->Release(qi[i].pItf);

  CLSID unknown;
  CoCreateGuid(&unknown);
  IUnknown* none = NULL;
  printf("unregistered class: 0x%08lx\n", CoCreateInstance(&unknown, NULL, CLSCTX_INPROC_SERVER, &IID_IUnknown,
                                                          (void**)&none));
  CoUninitialize();
  RegCloseKey(server_key);
  RegCloseKey(clsid_key);
  RegDeleteTreeW(HKEY_CURRENT_USER, key);
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
  GetModuleFileNameA(NULL, program_dir, MAX_PATH);
  *strrchr(program_dir, '\\') = 0;
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
  HMODULE again = LoadLibraryA("crt_dll_plugin");
  printf("loading again returns the same module: %d\n", again == plugin);
  free_library(again);
  SetEvent(go);
  WaitForSingleObject(thread, INFINITE);
  CloseHandle(thread);

  printf("main thread tls: %d, worker tls: %d\n", lib_tls_get(), thread_tls);
  printf("plugin tls in main: %d, in the older thread: %d\n", plugin_tls_get(), thread_plugin_tls);
  printf("thread attach: %ld, detach: %ld\n", lib_thread_attach, lib_thread_detach);
  printf("plugin thread notifications: %ld\n",
         *(volatile LONG*)GetProcAddress(plugin, "plugin_thread_notifications"));

  /* Reference counts: GetModuleHandleEx adds one (unless asked not to). */
  HMODULE extra = NULL;
  GetModuleHandleExA(0, "crt_dll_plugin.dll", &extra);
  printf("FreeLibrary: %d\n", free_library(plugin));
  printf("still loaded: %d\n", is_loaded("crt_dll_plugin.dll"));
  printf("FreeLibrary: %d\n", free_library(extra));
  printf("unloaded: %d\n", !is_loaded("crt_dll_plugin.dll"));
  /* Loaded again: a fresh copy, thread-local data included. */
  plugin = LoadLibraryA("crt_dll_plugin.dll");
  plugin_tls_get = (IntFn)GetProcAddress(plugin, "plugin_tls_get");
  printf("reloaded: %d, tls %d, name %s\n", plugin != NULL, plugin_tls_get(),
         ((NameFn)GetProcAddress(plugin, "plugin_name"))());
  /* The program's own imports stay. */
  printf("FreeLibrary(lib): %d, still loaded: %d\n", free_library(lib), is_loaded("crt_dll_lib.dll"));

  search_paths();
  module_lists(lib);
  com_server();
  fflush(stdout);
  return 0;
}
