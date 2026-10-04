/* Control flow: recursion, loops, switch jump tables, function pointers,
 * sorting and string processing. */
#include "juice_test.h"

#define NOINLINE __declspec(noinline)

NOINLINE u64 fib(u32 n) { return n < 2 ? n : fib(n - 1) + fib(n - 2); }

NOINLINE u64 ackermann(u64 m, u64 n) {
  if (m == 0) return n + 1;
  if (n == 0) return ackermann(m - 1, 1);
  return ackermann(m - 1, ackermann(m, n - 1));
}

NOINLINE u64 gcd(u64 a, u64 b) {
  while (b) {
    u64 t = a % b;
    a = b;
    b = t;
  }
  return a;
}

NOINLINE u64 collatz_steps(u64 n) {
  u64 steps = 0;
  while (n != 1) {
    n = (n & 1) ? 3 * n + 1 : n / 2;
    ++steps;
  }
  return steps;
}

/* Dense switch -> jump table (ADR + LDR + BR on ARM64). */
NOINLINE int classify(int v) {
  switch (v) {
    case 0: return 17;
    case 1: return 4;
    case 2: return 99;
    case 3: return -3;
    case 4: return 1000;
    case 5: return 55;
    case 6: return 6;
    case 7: return -77;
    case 8: return 12345;
    case 9: return 9;
    case 10: return 31;
    case 11: return -1;
    default: return 0;
  }
}

/* Sparse switch -> compare tree. */
NOINLINE const char* weekday_name(int code) {
  switch (code) {
    case 1: return "mon";
    case 20: return "tue";
    case 300: return "wed";
    case 4000: return "thu";
    case 50000: return "fri";
    case -6: return "sat";
    case -700: return "sun";
    default: return "???";
  }
}

typedef u64 (*binop)(u64, u64);
NOINLINE u64 op_add(u64 a, u64 b) { return a + b; }
NOINLINE u64 op_mul(u64 a, u64 b) { return a * b; }
NOINLINE u64 op_xor(u64 a, u64 b) { return a ^ b; }
NOINLINE u64 op_min(u64 a, u64 b) { return a < b ? a : b; }
static binop const ops[] = {op_add, op_mul, op_xor, op_min};

NOINLINE u64 fold(const u64* v, int n, binop f, u64 init) {
  for (int i = 0; i < n; ++i) init = f(init, v[i]);
  return init;
}

static void swap(i64* a, i64* b) {
  i64 t = *a;
  *a = *b;
  *b = t;
}

NOINLINE void quicksort(i64* v, int lo, int hi) {
  while (lo < hi) {
    i64 pivot = v[(lo + hi) / 2];
    int i = lo, j = hi;
    while (i <= j) {
      while (v[i] < pivot) ++i;
      while (v[j] > pivot) --j;
      if (i <= j) swap(&v[i++], &v[j--]);
    }
    if (j - lo < hi - i) {
      quicksort(v, lo, j);
      lo = i;
    } else {
      quicksort(v, i, hi);
      hi = j;
    }
  }
}

NOINLINE int str_len(const char* s) {
  int n = 0;
  while (s[n]) ++n;
  return n;
}

NOINLINE void reverse(char* s) {
  int n = str_len(s);
  for (int i = 0, j = n - 1; i < j; ++i, --j) {
    char t = s[i];
    s[i] = s[j];
    s[j] = t;
  }
}

NOINLINE u32 crc32(const unsigned char* p, int n) {
  u32 crc = 0xFFFFFFFFu;
  for (int i = 0; i < n; ++i) {
    crc ^= p[i];
    for (int k = 0; k < 8; ++k) crc = (crc >> 1) ^ (0xEDB88320u & (0u - (crc & 1)));
  }
  return ~crc;
}

/* Many live values across calls (callee-saved registers). */
NOINLINE u64 pressure(u64 seed) {
  u64 a = seed, b = seed * 3, c = seed ^ 0x55, d = seed + 7, e = seed << 3, f = seed >> 2, g = ~seed, h = seed * seed;
  for (int i = 0; i < 10; ++i) {
    a += fib(5) ^ h;
    b ^= a + c;
    c = c * 31 + d;
    d -= e;
    e ^= f + (u64)i;
    f += g >> 3;
    g = (g << 1) | (g >> 63);
    h += a ^ b ^ c;
  }
  return a ^ b ^ c ^ d ^ e ^ f ^ g ^ h;
}

static i64 data[300];

void mainCRTStartup(void) {
  line_i("fib(24)", (i64)fib((u32)opaque(24)));
  line_i("ackermann(2,3)", (i64)ackermann(opaque(2), opaque(3)));
  line_i("gcd", (i64)gcd(opaque(1071 * 997), opaque(462 * 997)));
  {
    u64 total = 0;
    for (u64 n = 1; n < 2000; ++n) total += collatz_steps(n);
    line_i("collatz total", (i64)total);
  }
  {
    i64 sum = 0;
    for (int i = -2; i < 15; ++i) sum = sum * 3 + classify((int)opaque((u64)i));
    line_i("classify", sum);
    int codes[] = {1, 20, 300, 4000, 50000, -6, -700, 42};
    for (int i = 0; i < 8; ++i) {
      put_str(weekday_name((int)opaque((u64)codes[i])));
      put_char(' ');
    }
    put_char('\n');
  }
  {
    u64 v[64];
    for (int i = 0; i < 64; ++i) v[i] = rng() | 1;
    for (int k = 0; k < 4; ++k) line("fold", fold(v, 64, ops[opaque((u64)k)], k == 3 ? ~0ull : (u64)k));
  }
  {
    for (int i = 0; i < 300; ++i) data[i] = (i64)(rng() % 100000) - 50000;
    quicksort(data, 0, 299);
    int sorted = 1;
    for (int i = 1; i < 300; ++i)
      if (data[i - 1] > data[i]) sorted = 0;
    line_i("sorted", sorted);
    line_i("min", data[0]);
    line_i("median", data[150]);
    line_i("max", data[299]);
  }
  {
    char text[] = "JUICE Uses Instruction Conversion Efficiently";
    line_i("strlen", str_len(text));
    reverse(text);
    put_str(text);
    put_char('\n');
    line("crc32", crc32((const unsigned char*)text, str_len(text)));
  }
  line("pressure", pressure(opaque(12345)));
  finish(0);
}
