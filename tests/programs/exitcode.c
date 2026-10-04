/* The process exit code must propagate from ExitProcess. */
#include "juice_test.h"

void mainCRTStartup(void) {
  put_str("exiting with 42\n");
  finish((int)opaque(42));
}
