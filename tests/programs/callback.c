/* Native code calling back into the program: comparators, init-once
 * callbacks, window procedures and fiber-local-storage destructors. */
#include "juice_test.h"

typedef int(__cdecl* compare_fn)(const void*, const void*);
typedef void(__cdecl* qsort_fn)(void* base, size_t count, size_t size, compare_fn compare);
typedef void*(__cdecl* bsearch_fn)(const void* key, const void* base, size_t count, size_t size, compare_fn compare);

static int compare_calls;

static int __cdecl compare_i64(const void* a, const void* b) {
  ++compare_calls;
  i64 x = *(const i64*)a, y = *(const i64*)b;
  return x < y ? -1 : x > y;
}

/* A callback that itself calls back out to the host. */
static int __cdecl compare_strings(const void* a, const void* b) {
  return lstrcmpA(*(const char* const*)a, *(const char* const*)b);
}

static BOOL CALLBACK init_once(PINIT_ONCE once, PVOID parameter, PVOID* context) {
  (void)once;
  *(int*)parameter += 1;
  *context = (PVOID)(ULONG_PTR)0x1230;
  return TRUE;
}

static LRESULT CALLBACK window_proc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam) {
  return (LRESULT)((ULONG_PTR)hwnd + msg * 3 + wparam * 5 + (ULONG_PTR)lparam * 7);
}

static u64 fls_destroyed;
static void WINAPI fls_destructor(PVOID value) { fls_destroyed = (u64)(ULONG_PTR)value; }

void mainCRTStartup(void) {
  /* ntdll's C runtime subset, looked up dynamically. */
  HMODULE ntdll = GetModuleHandleA("ntdll.dll");
  qsort_fn qsort = (qsort_fn)GetProcAddress(ntdll, "qsort");
  bsearch_fn bsearch = (bsearch_fn)GetProcAddress(ntdll, "bsearch");
  {
    static i64 values[200];
    for (int i = 0; i < 200; ++i) values[i] = (i64)(rng() % 1000000) - 500000;
    qsort(values, 200, sizeof(values[0]), compare_i64);
    int sorted = 1;
    for (int i = 1; i < 200; ++i)
      if (values[i - 1] > values[i]) sorted = 0;
    line_i("qsort sorted", sorted);
    line_i("qsort compared", compare_calls > 200);
    line_i("first", values[0]);
    line_i("last", values[199]);
    i64 key = values[123];
    const i64* found = (const i64*)bsearch(&key, values, 200, sizeof(values[0]), compare_i64);
    line_i("bsearch", found && *found == key);
  }
  {
    const char* words[] = {"pear", "apple", "kiwi", "banana", "cherry", "fig"};
    qsort(words, 6, sizeof(words[0]), compare_strings);
    for (int i = 0; i < 6; ++i) {
      put_str(words[i]);
      put_char(' ');
    }
    put_char('\n');
  }
  {
    static INIT_ONCE once = INIT_ONCE_STATIC_INIT;
    int runs = 0;
    PVOID context = NULL;
    BOOL ok1 = InitOnceExecuteOnce(&once, init_once, &runs, &context);
    BOOL ok2 = InitOnceExecuteOnce(&once, init_once, &runs, &context);
    line_i("init once ok", ok1 && ok2);
    line_i("init once runs", runs);
    line("init once context", (u64)(ULONG_PTR)context);
  }
  line("CallWindowProcA", (u64)CallWindowProcA(window_proc, (HWND)(ULONG_PTR)opaque(0x1000), 0x10, 3, 9));
  {
    DWORD slot = FlsAlloc(fls_destructor);
    FlsSetValue(slot, (PVOID)(ULONG_PTR)0xF00D);
    FlsFree(slot);
    line("fls destructor", fls_destroyed);
  }
  finish(0);
}
