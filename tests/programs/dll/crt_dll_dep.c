/* A DLL in sub\ that imports crt_dll_deplib.dll from the same directory:
 * loadable with LOAD_WITH_ALTERED_SEARCH_PATH only. */
#include <windows.h>

__declspec(dllimport) int deplib_value(void);

__declspec(dllexport) int dep_value(void) { return deplib_value() + 1; }
