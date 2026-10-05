// Arguments, environment, stdio, the heap and the exit status.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char** argv) {
  printf("argc=%d\n", argc);
  for (int i = 1; i < argc; ++i) printf("argv[%d]=%s\n", i, argv[i]);
  const char* v = getenv("JUICE_TEST_VAR");
  printf("JUICE_TEST_VAR=%s\n", v ? v : "(unset)");
  char* heap = malloc(1 << 20);  // mmap
  memset(heap, 'x', 1 << 20);
  char* small[1000];
  for (int i = 0; i < 1000; ++i) small[i] = malloc(16 + i);  // brk
  for (int i = 0; i < 1000; ++i) free(small[i]);
  printf("heap ok %c\n", heap[12345]);
  free(heap);
  fprintf(stderr, "to stderr\n");
  return 3;
}
