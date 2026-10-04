/* Win32 API forwarding: kernel32, user32 (variadic wsprintfA), advapi32,
 * GetProcAddress, module queries and the command line. */
#include "juice_test.h"

typedef DWORD(WINAPI* GetCurrentProcessIdFn)(void);
typedef int(WINAPI* lstrlenAFn)(LPCSTR);

static void check(const char* label, int ok) {
  put_str(label);
  put_str(ok ? ": ok\n" : ": FAILED\n");
}

static int contains(const char* haystack, const char* needle) {
  for (; *haystack; ++haystack) {
    const char* h = haystack;
    const char* n = needle;
    while (*n && *h == *n) ++h, ++n;
    if (!*n) return 1;
  }
  return 0;
}

void mainCRTStartup(void) {
  /* Module of the running program. */
  HMODULE self = GetModuleHandleW(NULL);
  const IMAGE_DOS_HEADER* dos = (const IMAGE_DOS_HEADER*)self;
  check("GetModuleHandle(NULL) is an image", dos->e_magic == IMAGE_DOS_SIGNATURE);
  {
    const IMAGE_NT_HEADERS* nt = (const IMAGE_NT_HEADERS*)((const char*)self + dos->e_lfanew);
    check("machine matches build", nt->FileHeader.Machine ==
#if defined(_M_ARM64)
                                       IMAGE_FILE_MACHINE_ARM64
#else
                                       IMAGE_FILE_MACHINE_AMD64
#endif
    );
  }
  {
    char path[MAX_PATH];
    DWORD n = GetModuleFileNameA(NULL, path, MAX_PATH);
    check("GetModuleFileNameA names this program", n > 0 && contains(path, "winapi"));
    HMODULE again = NULL;
    check("GetModuleHandleExW(FROM_ADDRESS)",
          GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                             (LPCWSTR)&mainCRTStartup, &again) &&
              again == self);
  }

  /* Command line arguments come through intact. */
  {
    const char* cmd = GetCommandLineA();
    check("command line has argument", contains(cmd, "alpha") && contains(cmd, "two words"));
    const wchar_t* wcmd = GetCommandLineW();
    int argc = 0;
    for (const wchar_t* p = wcmd; *p; ++p) argc += *p == L'a';
    check("wide command line", argc > 0);
  }

  /* Dynamic lookup returns callable functions. */
  {
    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    GetCurrentProcessIdFn pid = (GetCurrentProcessIdFn)GetProcAddress(k32, "GetCurrentProcessId");
    check("GetProcAddress(GetCurrentProcessId)", pid && pid() == GetCurrentProcessId());
    lstrlenAFn len = (lstrlenAFn)GetProcAddress(k32, "lstrlenA");
    check("GetProcAddress(lstrlenA)", len && len("juicy") == 5);
    check("GetProcAddress(missing)", GetProcAddress(k32, "NoSuchFunctionInKernel32") == NULL &&
                                         GetLastError() == ERROR_PROC_NOT_FOUND);
    HMODULE user32 = LoadLibraryA("user32.dll");
    check("LoadLibraryA(user32)", user32 != NULL && GetProcAddress(user32, "wsprintfA") != NULL);
  }

  /* Variadic call through the thunk layer. */
  {
    char buf[128];
    int n = wsprintfA(buf, "%d|%u|%x|%s|%c|%05d|%I64x", -42, 4000000000u, 0xBEEF, "str", 'Z', 77,
                      0x123456789ABCull);
    put_str(buf);
    put_char('\n');
    line_i("wsprintfA length", n);
  }

  /* Memory management. */
  {
    unsigned char* p = (unsigned char*)VirtualAlloc(NULL, 1 << 20, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    u64 s = 0;
    for (int i = 0; i < (1 << 20); i += 4096) p[i] = (unsigned char)(i >> 12);
    for (int i = 0; i < (1 << 20); i += 4096) s += p[i];
    line_i("VirtualAlloc sum", (i64)s);
    check("VirtualFree", VirtualFree(p, 0, MEM_RELEASE));

    HANDLE heap = GetProcessHeap();
    u64* q = (u64*)HeapAlloc(heap, HEAP_ZERO_MEMORY, 64 * sizeof(u64));
    u64 z = 0;
    for (int i = 0; i < 64; ++i) z |= q[i];
    check("HeapAlloc zeroed", z == 0);
    q = (u64*)HeapReAlloc(heap, 0, q, 4096);
    check("HeapReAlloc", q != NULL && HeapSize(heap, 0, q) == 4096);
    check("HeapFree", HeapFree(heap, 0, q));
  }

  /* Error codes travel through the native TEB. */
  SetLastError(12345);
  line_i("GetLastError", (i64)GetLastError());
  {
    HANDLE h = CreateFileA("Z:\\definitely\\not\\here.txt", GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
    check("CreateFileA fails", h == INVALID_HANDLE_VALUE);
    DWORD e = GetLastError();
    check("error is path/file not found", e == ERROR_PATH_NOT_FOUND || e == ERROR_FILE_NOT_FOUND);
  }

  /* String conversion and environment. */
  {
    wchar_t wide[32];
    int n = MultiByteToWideChar(CP_UTF8, 0, "h\xC3\xA9llo", -1, wide, 32);
    line_i("MultiByteToWideChar", n);
    line_i("wide[1]", wide[1]);
    char value[64];
    SetEnvironmentVariableA("JUICE_TEST_VAR", "squeezed");
    DWORD len = GetEnvironmentVariableA("JUICE_TEST_VAR", value, sizeof(value));
    put_str(value);
    put_char('\n');
    line_i("env length", len);
  }

  /* advapi32 */
  {
    HKEY key;
    LONG r = RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 0, KEY_READ, &key);
    check("RegOpenKeyExA", r == ERROR_SUCCESS);
    if (r == ERROR_SUCCESS) {
      char name[128];
      DWORD size = sizeof(name), type = 0;
      check("RegQueryValueExA", RegQueryValueExA(key, "ProductName", NULL, &type, (BYTE*)name, &size) ==
                                    ERROR_SUCCESS && type == REG_SZ && size > 1);
      RegCloseKey(key);
    }
  }

  /* System information is reported as ARM64 to ARM64 programs. */
  {
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    check("processor architecture", si.wProcessorArchitecture ==
#if defined(_M_ARM64)
                                        PROCESSOR_ARCHITECTURE_ARM64
#else
                                        PROCESSOR_ARCHITECTURE_AMD64
#endif
    );
    check("page size", si.dwPageSize == 4096);
  }

  /* Interlocked operations. */
  {
    static volatile LONG counter;
    static volatile LONG64 counter64;
    for (int i = 0; i < 100; ++i) InterlockedIncrement(&counter);
    InterlockedAdd64(&counter64, 0x100000000ll);
    LONG64 old = InterlockedCompareExchange64(&counter64, 7, 0x100000000ll);
    LONG prev = InterlockedExchange(&counter, -5);
    line_i("interlocked counter", prev);
    line_i("interlocked cmpxchg old", old);
    line_i("interlocked counter64", counter64);
    line_i("interlocked exchange", counter);
    LONG v = InterlockedOr(&counter, 0x100);
    line_i("interlocked or", v);
    line_i("interlocked and", InterlockedAnd(&counter, 0xF0F));
  }

  finish(0);
}
