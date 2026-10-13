/* A native (x64) DLL next to the program, which loads it with LoadLibrary:
 * under JUICE it is native code working for the guest. It calls a callback of
 * the program inside its own __try, and asks the native loader about the
 * program's module. */
#include <windows.h>

#define EXPORT __declspec(dllexport)

/* Calls fn(arg); an exception 0xE0000777 that leaves it is handled here. */
EXPORT int native_catch(int (*fn)(int), int arg) {
  __try {
    return fn(arg);
  } __except (GetExceptionCode() == 0xE0000777 ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
    return -1;
  }
}

/* The file name of the main module, as native code sees it, and the result of
 * a function the program exports, found through GetModuleHandle(NULL). */
EXPORT int native_main_module(wchar_t* name, int size) {
  wchar_t path[MAX_PATH];
  GetModuleFileNameW(NULL, path, MAX_PATH);
  const wchar_t* file = path;
  for (const wchar_t* p = path; *p; ++p)
    if (*p == L'\\') file = p + 1;
  lstrcpynW(name, file, size);
  int (*fn)(void) = (int (*)(void))GetProcAddress(GetModuleHandleW(NULL), "exported_from_program");
  return fn ? fn() : -1;
}
