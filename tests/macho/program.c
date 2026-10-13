// A macOS program for juice-macos-sim (Windows) and juice (macOS): calls into
// a guest library (@rpath), dlopen/dlsym, callbacks with floating point and
// structure arguments from native code, setjmp/longjmp, atexit,
// thread-local variables, initializers. Declarations instead of headers, so
// it builds without a macOS SDK.
typedef unsigned long size_t;
int printf(const char*, ...);
int snprintf(char*, size_t, const char*, ...);
int puts(const char*);
void qsort(void*, size_t, size_t, int (*)(const void*, const void*));
int atexit(void (*)(void));
void* dlopen(const char*, int);
void* dlsym(void*, const char*);
typedef long jmp_buf[48];
int setjmp(jmp_buf);
void longjmp(jmp_buf, int) __attribute__((noreturn));

int library_function(int);
extern int library_value;
double library_scale(double, float);

static jmp_buf jump;
static __thread int counter = 100;
static int initialized;

__attribute__((constructor)) static void init(void) { initialized = 42; }

static void goodbye(void) { printf("goodbye %d\n", counter); }

static int by_magnitude(const void* a, const void* b) {
  const double x = *(const double*)a, y = *(const double*)b;
  const double ax = x < 0 ? -x : x, ay = y < 0 ? -y : y;
  return ax < ay ? -1 : ax > ay;
}

static void deep(int n) {
  if (n == 0) longjmp(jump, 7);
  deep(n - 1);
}

int main(int argc, char** argv) {
  printf("init %d, argc %d, argv[1] %s\n", initialized, argc, argc > 1 ? argv[1] : "-");
  printf("library %d %d %.3f\n", library_function(5), library_value, library_scale(1.5, 2.0f));

  double values[] = {3.5, -1.25, 0.5, -8.0, 2.0};
  qsort(values, 5, sizeof(double), by_magnitude);
  printf("sorted %.2f %.2f %.2f %.2f %.2f\n", values[0], values[1], values[2], values[3], values[4]);

  char buffer[64];
  snprintf(buffer, sizeof buffer, "%s-%d-%.1f-%c", "fmt", -12, 6.5, 'z');
  puts(buffer);

  void* self = dlopen(0, 0);
  int (*f)(int) = (int (*)(int))dlsym(self, "library_function");
  printf("dlsym %d\n", f ? f(1) : -1);

  int r = setjmp(jump);
  if (r == 0) deep(10);
  printf("longjmp %d\n", r);

  counter += 1;
  atexit(goodbye);
  return 3;
}
