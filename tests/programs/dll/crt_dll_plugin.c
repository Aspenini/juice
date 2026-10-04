/* A DLL the test program loads with LoadLibrary: thread-local data that
 * threads which already exist must see too, DisableThreadLibraryCalls, and a
 * forwarder to an export of another DLL of the program. */
#include <windows.h>

#define EXPORT __declspec(dllexport)

EXPORT volatile LONG plugin_thread_notifications = 0;

static __declspec(thread) int plugin_tls = 77;

EXPORT int plugin_tls_get(void) { return plugin_tls; }

EXPORT const char* plugin_name(void) { return "juice plugin"; }

/* Forwarded to the program's other DLL. */
#pragma comment(linker, "/export:plugin_add=crt_dll_lib.lib_add")

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, void* reserved) {
  (void)reserved;
  if (reason == DLL_PROCESS_ATTACH) DisableThreadLibraryCalls(instance);
  if (reason == DLL_THREAD_ATTACH || reason == DLL_THREAD_DETACH) InterlockedIncrement(&plugin_thread_notifications);
  return TRUE;
}
