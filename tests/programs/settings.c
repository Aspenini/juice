/* A program whose manifest (settings.manifest) declares settings Windows
 * reads only when it creates the process: the UTF-8 code page, long path
 * awareness, the segment heap and the supported OS versions. It also depends
 * on common controls v6 and declares DPI awareness. */
#include "juice_test.h"

#include <commctrl.h>
#include <shlwapi.h>

#ifdef __clang__
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#endif

typedef HRESULT(CALLBACK* DllGetVersionFn)(DLLVERSIONINFO*);
typedef BOOLEAN(NTAPI* RtlAreLongPathsEnabledFn)(void);

static DWORD button_class_version(void) {
  HWND button = CreateWindowExW(0, L"BUTTON", L"juice", WS_CHILD, 0, 0, 10, 10, HWND_MESSAGE, NULL, NULL, NULL);
  HMODULE module = (HMODULE)GetClassLongPtrW(button, GCLP_HMODULE);
  DestroyWindow(button);
  DllGetVersionFn get_version = (DllGetVersionFn)GetProcAddress(module, "DllGetVersion");
  DLLVERSIONINFO info = {sizeof(info)};
  if (get_version) get_version(&info);
  return info.dwMajorVersion;
}

static DWORD WINAPI thread_proc(void* param) {
  *(DWORD*)param = button_class_version();
  return 0;
}

void mainCRTStartup(void) {
  /* activeCodePage */
  line_i("ANSI code page", GetACP());
  const char utf8[] = "\xc3\xa9t\xc3\xa9";  /* "été" */
  wchar_t wide[8];
  line_i("UTF-8 to UTF-16 characters", MultiByteToWideChar(CP_ACP, 0, utf8, -1, wide, 8));
  line_i("lstrlenA of UTF-8 bytes", lstrlenA(utf8));

  /* supportedOS: GetVersionEx reports the real version only to programs
   * that declare support for it. */
  OSVERSIONINFOW version = {sizeof(version)};
  GetVersionExW(&version);
  line_i("GetVersionEx major", version.dwMajorVersion);
  line_i("GetVersionEx minor", version.dwMinorVersion);

  /* longPathAware (also needs the LongPathsEnabled policy, which both runs share) */
  RtlAreLongPathsEnabledFn long_paths =
      (RtlAreLongPathsEnabledFn)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlAreLongPathsEnabled");
  line_i("long paths enabled", long_paths ? long_paths() : -1);

  /* heapType: the segment heap's signature is 0xDDEEDDEE, the NT heap's 0xFFEEFFEE. */
  line("process heap signature", *(const DWORD*)((const char*)GetProcessHeap() + 0x10));

  /* The dependency still applies, on the main thread and in a new thread. */
  INITCOMMONCONTROLSEX icc = {sizeof(icc), ICC_STANDARD_CLASSES};
  line_i("InitCommonControlsEx", InitCommonControlsEx(&icc));
  line_i("BUTTON class version", button_class_version());
  DWORD thread_version = 0;
  HANDLE thread = CreateThread(NULL, 0, thread_proc, &thread_version, 0, NULL);
  WaitForSingleObject(thread, INFINITE);
  CloseHandle(thread);
  line_i("BUTTON class version in a thread", thread_version);

  line_i("DPI awareness", GetAwarenessFromDpiAwarenessContext(GetThreadDpiAwarenessContext()));
  finish(0);
}
