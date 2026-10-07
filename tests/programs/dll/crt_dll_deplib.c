/* A DLL in a subdirectory of the program's (sub\), found only through the
 * search path functions: SetDllDirectory, AddDllDirectory, or the directory
 * of the DLL that imports it (crt_dll_dep.dll, LOAD_WITH_ALTERED_SEARCH_PATH). */
#include <windows.h>

#define EXPORT __declspec(dllexport)

EXPORT int deplib_attached = 0;

EXPORT int deplib_value(void) { return 7; }

static void write_line(const char* text) {
  DWORD written;
  WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), text, lstrlenA(text), &written, NULL);
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, void* reserved) {
  (void)instance;
  if (reason == DLL_PROCESS_ATTACH) deplib_attached = 1;
  if (reason == DLL_PROCESS_DETACH) write_line(reserved ? "deplib: process detach (exit)\n" : "deplib: process detach\n");
  return TRUE;
}
