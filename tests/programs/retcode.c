/* Returning from the entry point (instead of calling ExitProcess) ends the
 * process with the returned value as exit code. Checked against a fixed
 * expectation only: natively, returning from the entry point merely ends the
 * main thread, which can leave loader worker threads running for a while. */
#include "juice_test.h"

int mainCRTStartup(void) {
  put_str("returning 7\n");
  flush();
  return (int)opaque(7);
}
