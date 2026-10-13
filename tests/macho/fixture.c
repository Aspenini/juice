// A program with the fixups dyld handles: rebases (pointers to its own data
// and code), binds to library functions and data (with addends), weak
// imports, thread-local variables and initializers.
typedef unsigned long size_t;
int printf(const char*, ...);
void qsort(void*, size_t, size_t, int (*)(const void*, const void*));
extern char** environ;
void optional_function(void) __attribute__((weak_import));

static int compare(const void* a, const void* b) { return *(const int*)a - *(const int*)b; }

int table[] = {5, 3, 9, 1};
int* pointers[] = {&table[0], &table[2], &table[3]};
int (*functions[])(const void*, const void*) = {compare};
char*** environ_pointer = &environ;
char** environ_plus = (char**)((char*)&environ + 16);  // a bind with an addend
void (*optional)(void) = optional_function;
__thread int per_thread = 7;
const char* const names[] = {"one", "two", "three"};

__attribute__((constructor)) static void init(void) { table[0] += 1; }

int main(int argc, char** argv) {
  qsort(table, 4, sizeof(int), compare);
  printf("%d %d %d %s %d\n", argc, *pointers[1], per_thread, names[argc % 3], optional != 0);
  return functions[0](&table[0], &table[1]) < 0 ? 0 : 1;
}
