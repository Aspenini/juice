/* A program with an application manifest (manifest.manifest, embedded by the
 * linker) that asks for common controls version 6 and per-monitor v2 DPI
 * awareness. The checks only pass if the manifest was applied: without it,
 * the system loads common controls 5.82 and the process is DPI unaware. */
#include "juice_test.h"

#include <commctrl.h>
#include <shlwapi.h>

typedef HRESULT(CALLBACK* DllGetVersionFn)(DLLVERSIONINFO*);

/* Version of the module that implements the window's class, 0 if it has no
 * DllGetVersion (user32's built-in classes). */
static DWORD class_module_version(HWND hwnd) {
  HMODULE module = (HMODULE)GetClassLongPtrW(hwnd, GCLP_HMODULE);
  DllGetVersionFn get_version = (DllGetVersionFn)GetProcAddress(module, "DllGetVersion");
  if (!get_version) return 0;
  DLLVERSIONINFO info = {sizeof(info)};
  get_version(&info);
  return info.dwMajorVersion;
}

static DWORD button_class_version(void) {
  HWND button = CreateWindowExW(0, L"BUTTON", L"juice", WS_CHILD, 0, 0, 10, 10, HWND_MESSAGE, NULL, NULL, NULL);
  DWORD version = class_module_version(button);
  DestroyWindow(button);
  return version;
}

static DWORD WINAPI thread_proc(void* param) {
  *(DWORD*)param = button_class_version();
  return 0;
}

void mainCRTStartup(void) {
  /* A static import of comctl32: bound through the manifest's assembly. */
  INITCOMMONCONTROLSEX icc = {sizeof(icc), ICC_STANDARD_CLASSES | ICC_PROGRESS_CLASS};
  line_i("InitCommonControlsEx", InitCommonControlsEx(&icc));
  DllGetVersionFn get_version = (DllGetVersionFn)GetProcAddress(GetModuleHandleW(L"comctl32.dll"), "DllGetVersion");
  DLLVERSIONINFO info = {sizeof(info)};
  if (get_version) get_version(&info);
  line_i("comctl32 major version", info.dwMajorVersion);

  /* user32's control classes are redirected to comctl32 v6. */
  line_i("BUTTON class version", button_class_version());
  HWND progress = CreateWindowExW(0, PROGRESS_CLASSW, NULL, WS_CHILD, 0, 0, 10, 10, HWND_MESSAGE, NULL, NULL, NULL);
  line_i("progress bar created", progress != NULL);
  line_i("progress bar class version", class_module_version(progress));
  DestroyWindow(progress);

  /* Threads see the same context. */
  DWORD thread_version = 0;
  HANDLE thread = CreateThread(NULL, 0, thread_proc, &thread_version, 0, NULL);
  WaitForSingleObject(thread, INFINITE);
  CloseHandle(thread);
  line_i("BUTTON class version in a thread", thread_version);

  /* DPI awareness from the manifest. */
  DPI_AWARENESS_CONTEXT dpi = GetThreadDpiAwarenessContext();
  line_i("DPI awareness", GetAwarenessFromDpiAwarenessContext(dpi));
  line_i("per-monitor v2", AreDpiAwarenessContextsEqual(dpi, DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2));
  line_i("process DPI awareness context per-monitor v2",
         AreDpiAwarenessContextsEqual(GetDpiAwarenessContextForProcess(GetCurrentProcess()),
                                      DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2));
  finish(0);
}
