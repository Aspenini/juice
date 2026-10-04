/* The first JUICE milestone: an ARM64 console Hello World. */
#include <windows.h>

void mainCRTStartup(void) {
  static const char message[] = "Hello, World!\n";
  DWORD written;
  WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), message, sizeof(message) - 1, &written, NULL);
  ExitProcess(0);
}
