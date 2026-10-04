/* A conventional C program using the Microsoft C runtime: formatted output,
 * floating point and math, strings, sorting with callbacks, heap, TLS and
 * atexit. Built both with the static (/MT) and the dynamic (/MD) runtime. */
#include <ctype.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static __declspec(thread) int tls_value = 7;

static int compare_ints(const void* a, const void* b) {
  int x = *(const int*)a, y = *(const int*)b;
  return (x > y) - (x < y);
}

static int compare_names(const void* a, const void* b) {
  return strcmp(*(const char* const*)a, *(const char* const*)b);
}

static void at_exit_handler(void) { printf("atexit handler ran\n"); }

static uint64_t rng_state = 88172645463325252ull;
static uint64_t rng(void) {
  rng_state ^= rng_state << 13;
  rng_state ^= rng_state >> 7;
  rng_state ^= rng_state << 17;
  return rng_state;
}

static volatile double vd(double v) { return v; }

int main(int argc, char** argv) {
  printf("argc=%d\n", argc);
  for (int i = 1; i < argc; ++i) printf("argv[%d]=[%s]\n", i, argv[i]);

  /* integer formatting */
  printf("%d %i %u %ld %lld %llu\n", -42, 17, 4000000000u, -1234567L, -9000000000000000000LL,
         18000000000000000000ULL);
  printf("%x %X %o %#x %08.3d %-6d| %+d %c %s %.3s %%\n", 0xBEEF, 0xCAFE, 0755, 255, 7, 42, 5, 'Q', "text",
         "truncated");

  /* floating point formatting */
  const double values[] = {0.0, -0.0, 1.5, 3.14159265358979, 2.718281828459045, 1e300, 1e-300, 123456789.125,
                           -0.1, 1.0 / 3.0, 6.02214076e23, 4.9e-324};
  for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); ++i)
    printf("%.17g | %e | %.3f | %g | %a\n", values[i], values[i], values[i], values[i], values[i]);
  printf("inf=%f -inf=%f nan? %d\n", vd(INFINITY), vd(-INFINITY), isnan(vd(0.0) / vd(0.0)) != 0);

  /* arithmetic and conversions */
  double a = vd(1.1), b = vd(2.2);
  float f = (float)vd(1.1);
  printf("%.17g %.17g %.17g %.17g\n", a + b, a - b, a * b, a / b);
  printf("%.9g %.9g %.9g\n", (double)(f * f), (double)(f / 3.0f), (double)(float)(a * 1e10));
  printf("%d %d %lld %u %lld\n", (int)vd(3.99), (int)vd(-3.99), (long long)vd(-1e18), (unsigned)vd(4e9),
         (long long)vd(9.2e18));
  printf("%.17g %.17g %.9g\n", (double)(long long)rng(), (double)(rng() >> 1), (double)(float)(int)rng());
  printf("cmp %d %d %d %d\n", a < b, a > b, a == vd(1.1), vd(0.0) == vd(-0.0));

  /* math library */
  printf("%.15g %.15g %.15g %.15g\n", sqrt(vd(2.0)), sin(vd(1.0)), cos(vd(0.5)), tan(vd(0.25)));
  printf("%.15g %.15g %.15g %.15g\n", exp(vd(1.0)), log(vd(10.0)), log10(vd(1234.5)), pow(vd(2.0), vd(0.5)));
  printf("%.15g %.15g %.15g\n", atan2(vd(1.0), vd(2.0)), asin(vd(0.5)), hypot(vd(3.0), vd(4.0)));
  printf("%g %g %g %g %g %g %g\n", floor(vd(-2.5)), ceil(vd(2.1)), round(vd(2.5)), round(vd(-2.5)), trunc(vd(-2.7)),
         fmod(vd(10.0), vd(3.0)), fabs(vd(-3.0)));
  printf("%g %g %g\n", fmin(vd(1.0), vd(-1.0)), fmax(vd(1.0), vd(-1.0)), copysign(vd(3.0), vd(-0.0)));

  /* parsing */
  char* end;
  printf("%.17g %ld %lu %lld\n", strtod("3.25e2xyz", &end), strtol("-0x1f", NULL, 16), strtoul("777", NULL, 8),
         atoll("-9876543210"));
  printf("rest=[%s] atof=%.6f atoi=%d\n", end, atof("  -12.5"), atoi("42abc"));
  {
    int n;
    char word[16];
    double d;
    int got = sscanf("17 apples 2.5", "%d %15s %lf", &n, word, &d);
    printf("sscanf %d: %d %s %.2f\n", got, n, word, d);
  }

  /* strings */
  {
    char buf[256];
    strcpy(buf, "JUICE");
    strcat(buf, " Uses Instruction Conversion Efficiently");
    printf("%s (%zu)\n", buf, strlen(buf));
    printf("%d %d %d\n", strcmp("abc", "abd") < 0, strncmp("abcdef", "abcxyz", 3), strcmp("b", "a") > 0);
    printf("%s | %s | %s\n", strchr(buf, 'U'), strrchr(buf, 'E'), strstr(buf, "Conversion"));
    for (char* p = buf; *p; ++p) *p = (char)toupper((unsigned char)*p);
    printf("%s\n", buf);
    memmove(buf + 4, buf, 20);
    buf[24] = 0;
    printf("%s\n", buf);
    char big[1000];
    memset(big, 'z', sizeof(big));
    big[999] = 0;
    printf("%zu %d\n", strlen(big), memcmp(big, big + 1, 500));
    char out[64];
    int len = snprintf(out, sizeof(out), "%s-%05.2f-%llx", "juice", 3.14159, 0xabcdefull);
    printf("%s %d\n", out, len);
  }

  /* qsort / bsearch with callbacks */
  {
    static int numbers[1000];
    for (int i = 0; i < 1000; ++i) numbers[i] = (int)(rng() % 100000) - 50000;
    qsort(numbers, 1000, sizeof(int), compare_ints);
    int sorted = 1;
    long long sum = 0;
    for (int i = 0; i < 1000; ++i) {
      if (i && numbers[i - 1] > numbers[i]) sorted = 0;
      sum += numbers[i];
    }
    int key = numbers[500];
    int* found = (int*)bsearch(&key, numbers, 1000, sizeof(int), compare_ints);
    printf("sorted=%d sum=%lld min=%d max=%d found=%d\n", sorted, sum, numbers[0], numbers[999],
           found && *found == key);
    const char* names[] = {"orange", "apple", "pear", "fig", "banana", "kiwi", "cherry"};
    qsort(names, 7, sizeof(names[0]), compare_names);
    for (int i = 0; i < 7; ++i) printf("%s%s", names[i], i == 6 ? "\n" : ",");
  }

  /* heap */
  {
    void* blocks[64];
    size_t total = 0;
    for (int i = 0; i < 64; ++i) {
      size_t size = 16 + (rng() % 4096);
      blocks[i] = malloc(size);
      memset(blocks[i], i, size);
      total += size;
    }
    for (int i = 0; i < 64; i += 2) blocks[i] = realloc(blocks[i], 8192);
    int ok = 1;
    for (int i = 1; i < 64; i += 2) ok &= ((unsigned char*)blocks[i])[10] == (unsigned char)i;
    for (int i = 0; i < 64; ++i) free(blocks[i]);
    int* zeros = (int*)calloc(100, sizeof(int));
    int zero_sum = 0;
    for (int i = 0; i < 100; ++i) zero_sum += zeros[i];
    free(zeros);
    printf("heap ok=%d total>0=%d calloc=%d\n", ok, total > 0, zero_sum);
  }

  tls_value += argc;
  printf("tls=%d\n", tls_value);

  atexit(at_exit_handler);
  printf("main returns 5\n");
  return 5;
}
