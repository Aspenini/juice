/* Loads and stores of every size, sign extension, addressing modes, struct
 * copies (SIMD register moves), unaligned access and the guest stack. */
#include "juice_test.h"

#define NOINLINE __declspec(noinline)

typedef struct {
  u64 a, b, c, d;
  u32 e;
  unsigned short f;
  unsigned char g;
  signed char h;
  i64 tail[5];
} Record;

static Record table[8];
static signed char s8[64];
static short s16[64];
static int s32[64];
static unsigned char bytes[256];

NOINLINE void fill_record(Record* r, u64 seed) {
  r->a = seed;
  r->b = seed * 3;
  r->c = ~seed;
  r->d = seed ^ 0xAAAA;
  r->e = (u32)(seed >> 7);
  r->f = (unsigned short)(seed >> 3);
  r->g = (unsigned char)seed;
  r->h = (signed char)(seed >> 1);
  for (int i = 0; i < 5; ++i) r->tail[i] = (i64)(seed << i) - 1000;
}

NOINLINE Record copy_record(const Record* r) { return *r; }  /* returned via X8 */

NOINLINE u64 hash_record(Record r) {  /* passed by reference to a copy */
  u64 h = r.a ^ (r.b << 1) ^ (r.c << 2) ^ (r.d << 3) ^ r.e ^ ((u64)r.f << 32) ^ ((u64)r.g << 48) ^ (u64)(i64)r.h;
  for (int i = 0; i < 5; ++i) h = h * 31 + (u64)r.tail[i];
  return h;
}

NOINLINE i64 sum_signed(const signed char* a, const short* b, const int* c, int n) {
  i64 s = 0;
  for (int i = 0; i < n; ++i) s += a[i] * 3 + b[i] * 5 + (i64)c[i] * 7;
  return s;
}

NOINLINE u64 indexed(const u64* base, const int* idx, int n) {
  u64 s = 0;
  for (int i = 0; i < n; ++i) s += base[idx[i]];  /* register offset, sign-extended index */
  return s;
}

NOINLINE u64 unaligned_load(const unsigned char* p, int off) {
  u64 v;
  memcpy(&v, p + off, 8);
  return v;
}

NOINLINE void unaligned_store(unsigned char* p, int off, u32 v) {
  *(volatile u32 __unaligned*)(p + off) = v;
}

NOINLINE u64 stack_heavy(int n) {
  volatile u64 local[200];
  for (int i = 0; i < 200; ++i) local[i] = (u64)i * (u64)n;
  u64 s = 0;
  for (int i = 199; i >= 0; i -= 3) s += local[i];
  return s;
}

/* Post-increment pointer walk (post-index addressing). */
NOINLINE u64 walk(const u64* p, const u64* end) {
  u64 s = 0;
  while (p != end) s = (s << 1) ^ *p++;
  return s;
}

NOINLINE void copy_backwards(u64* dst, const u64* src, int n) {
  for (int i = n - 1; i >= 0; --i) dst[i] = src[i];
}

struct Pair {
  u64 x;
  u64 y;
};

NOINLINE struct Pair make_pair(u64 x, u64 y) {
  struct Pair p = {x, y};
  return p;
}

void mainCRTStartup(void) {
  for (int i = 0; i < 8; ++i) fill_record(&table[i], rng());
  {
    u64 h = 0;
    for (int i = 0; i < 8; ++i) {
      Record copy = copy_record(&table[i]);
      h = h * 0x9E3779B97F4A7C15ull + hash_record(copy);
    }
    line("records", h);
    Record swapped = table[1];
    table[1] = table[6];
    table[6] = swapped;
    line("swap", hash_record(table[1]) - hash_record(table[6]));
  }
  {
    for (int i = 0; i < 64; ++i) {
      u64 r = rng();
      s8[i] = (signed char)r;
      s16[i] = (short)(r >> 8);
      s32[i] = (int)(r >> 24);
    }
    line_i("sum_signed", sum_signed(s8, s16, s32, 64));
  }
  {
    u64 base[32];
    int idx[50];
    for (int i = 0; i < 32; ++i) base[i] = rng();
    for (int i = 0; i < 50; ++i) idx[i] = (int)(rng() % 32);
    line("indexed", indexed(base, idx, 50));
    line("walk", walk(base, base + 32));
    u64 copy[32];
    copy_backwards(copy, base, 32);
    line("copy", (u64)memcmp(copy, base, sizeof(copy)));
  }
  {
    for (int i = 0; i < 256; ++i) bytes[i] = (unsigned char)(i * 7 + 3);
    u64 s = 0;
    for (int off = 0; off < 16; ++off) s = s * 131 + unaligned_load(bytes, off);
    line("unaligned load", s);
    for (int off = 1; off < 30; off += 3) unaligned_store(bytes, off, (u32)(0xA1B2C3D4u + (u32)off));
    line("unaligned store", unaligned_load(bytes, 5) ^ unaligned_load(bytes, 21));
  }
  line("stack", stack_heavy((int)opaque(77)));
  {
    struct Pair p = make_pair(opaque(0x1111), opaque(0x2222));
    line("pair", p.x * 3 + p.y);
  }
  {
    /* Byte/halfword stores and sign-extending reloads. */
    volatile unsigned char buf[16];
    for (int i = 0; i < 16; ++i) buf[i] = (unsigned char)(0xF0 + i);
    volatile short* hw = (volatile short*)buf;
    volatile int* w = (volatile int*)buf;
    line_i("ldrsb", (signed char)buf[3]);
    line_i("ldrsh", hw[2]);
    line_i("ldrsw", w[1]);
    hw[1] = (short)opaque(0x8000);
    line("halfword store", *(volatile u64*)buf);
  }
  finish(0);
}
