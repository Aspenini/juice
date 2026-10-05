/* Loops written to be auto-vectorized (this program is built with the
 * vectorizers enabled): integer arithmetic on every element width, saturation
 * and clamping, widening and narrowing, min/max/abs, shifts, compares and
 * selects, reductions, dot products, conversions, interleaved data, byte
 * searches and floating point. ARM64 builds use Advanced SIMD for these,
 * x86-64 builds SSE; the results must agree. */
#include "juice_test.h"

#define N 1024

int _fltused;  /* the x64 linker wants it when floating point is used without a C runtime */

/* No C runtime: the rounding functions the loops use (the compiler may still
 * turn calls into rounding instructions). Valid for the magnitudes used here. */
float floorf(float x) {
  float t = (float)(int)x;
  return t > x ? t - 1.0f : t;
}
float ceilf(float x) {
  float t = (float)(int)x;
  return t < x ? t + 1.0f : t;
}
float truncf(float x) { return (float)(int)x; }
double rint(double x) {  /* round half to even, the default rounding mode */
  double t = (double)(i64)x, d = x - t;
  if (d > 0.5 || (d == 0.5 && ((i64)t & 1))) t += 1.0;
  if (d < -0.5 || (d == -0.5 && ((i64)t & 1))) t -= 1.0;
  return t;
}

static signed char s8a[N], s8b[N], s8r[N];
static unsigned char u8a[N], u8b[N], u8r[N];
static short s16a[N], s16b[N], s16r[N];
static unsigned short u16a[N], u16r[N];
static int s32a[N], s32b[N], s32r[N];
static unsigned u32a[N], u32b[N], u32r[N];
static i64 s64a[N], s64b[N], s64r[N];
static u64 u64a[N], u64r[N];
static float f32a[N], f32b[N], f32r[N];
static double f64a[N], f64b[N], f64r[N];

static u64 hash(const void* p, size_t n) {
  const unsigned char* b = (const unsigned char*)p;
  u64 h = 0xcbf29ce484222325ull;
  for (size_t i = 0; i < n; ++i) h = (h ^ b[i]) * 0x100000001b3ull;
  return h;
}

#define CHECK(name, arr) line(name, hash(arr, sizeof(arr)))

static void fill(void) {
  for (int i = 0; i < N; ++i) {
    u64 r = rng();
    s8a[i] = (signed char)r;
    s8b[i] = (signed char)(r >> 8);
    u8a[i] = (unsigned char)(r >> 16);
    u8b[i] = (unsigned char)(r >> 24);
    s16a[i] = (short)(r >> 7);
    s16b[i] = (short)(r >> 23);
    u16a[i] = (unsigned short)(r >> 31);
    s32a[i] = (int)(r >> 3);
    s32b[i] = (int)(r >> 29) | 1;
    u32a[i] = (unsigned)(r >> 13);
    u32b[i] = (unsigned)(r >> 33) | 1;
    s64a[i] = (i64)r;
    s64b[i] = (i64)rng();
    u64a[i] = rng();
    f32a[i] = (float)(int)(r >> 40) / 1024.0f - 4096.0f;
    f32b[i] = (float)(int)(r >> 20 & 0xfffff) / 512.0f + 0.5f;
    f64a[i] = (double)(i64)(r >> 11) / 4096.0 - 1e12;
    f64b[i] = (double)(int)(r & 0xffff) / 256.0 + 1.0;
  }
}

__declspec(noinline) static void integer_ops(void) {
  for (int i = 0; i < N; ++i) s8r[i] = (signed char)(s8a[i] + s8b[i] * 3);
  CHECK("s8 add mul", s8r);
  for (int i = 0; i < N; ++i) u8r[i] = u8a[i] > u8b[i] ? u8a[i] - u8b[i] : u8b[i] - u8a[i];
  CHECK("u8 abs diff", u8r);
  for (int i = 0; i < N; ++i) {
    int v = u8a[i] + u8b[i];
    u8r[i] = (unsigned char)(v > 255 ? 255 : v);
  }
  CHECK("u8 saturating add", u8r);
  for (int i = 0; i < N; ++i) u8r[i] = (unsigned char)((u8a[i] + u8b[i] + 1) >> 1);
  CHECK("u8 rounding average", u8r);
  for (int i = 0; i < N; ++i) {
    int v = s16a[i] - s16b[i];
    s16r[i] = (short)(v > 32767 ? 32767 : v < -32768 ? -32768 : v);
  }
  CHECK("s16 saturating sub", s16r);
  for (int i = 0; i < N; ++i) s16r[i] = (short)((s16a[i] * s16b[i]) >> 16);
  CHECK("s16 mulhi", s16r);
  for (int i = 0; i < N; ++i) s32r[i] = s32a[i] * s32b[i] + (s32a[i] >> 5) - (s32b[i] << 3);
  CHECK("s32 mul shift", s32r);
  for (int i = 0; i < N; ++i) s32r[i] = s32a[i] < 0 ? -s32a[i] : s32a[i];
  CHECK("s32 abs", s32r);
  for (int i = 0; i < N; ++i) s32r[i] = s32a[i] < s32b[i] ? s32a[i] : s32b[i];
  CHECK("s32 min", s32r);
  for (int i = 0; i < N; ++i) u32r[i] = u32a[i] > u32b[i] ? u32a[i] : u32b[i];
  CHECK("u32 max", u32r);
  for (int i = 0; i < N; ++i) u32r[i] = (u32a[i] >> (i & 7)) ^ (u32b[i] << ((i >> 3) & 15));
  CHECK("u32 variable shifts", u32r);
  for (int i = 0; i < N; ++i) u32r[i] = u32a[i] / 7u;
  CHECK("u32 divide by constant", u32r);
  for (int i = 0; i < N; ++i) s64r[i] = s64a[i] + s64b[i] * 5 - (s64a[i] >> 7);
  CHECK("s64 arithmetic", s64r);
  for (int i = 0; i < N; ++i) s64r[i] = s64a[i] > s64b[i] ? s64a[i] : s64b[i];
  CHECK("s64 max", s64r);
  for (int i = 0; i < N; ++i) u64r[i] = (u64a[i] << 3) | (u64a[i] >> 61);
  CHECK("u64 rotate", u64r);
  for (int i = 0; i < N; ++i) u64r[i] = (u64)s32a[i] * (u64)u32b[i];
  CHECK("widening multiply", u64r);
  for (int i = 0; i < N; ++i) s32r[i] = s8a[i] * s16a[i];
  CHECK("mixed widths", s32r);
  for (int i = 0; i < N; ++i) u8r[i] = (unsigned char)(u32a[i] >> 4);
  CHECK("narrowing", u8r);
  for (int i = 0; i < N; ++i) {
    int v = s32a[i] >> 12;
    s16r[i] = (short)(v > 32767 ? 32767 : v < -32768 ? -32768 : v);
  }
  CHECK("narrowing with saturation", s16r);
  for (int i = 0; i < N; ++i) {
    int v = s16a[i] >> 4;
    u8r[i] = (unsigned char)(v < 0 ? 0 : v > 255 ? 255 : v);
  }
  CHECK("clamp to bytes", u8r);
  for (int i = 0; i < N; ++i) u16r[i] = (unsigned short)(u16a[i] * 0x9e37u + (u16a[i] >> 3));
  CHECK("u16 arithmetic", u16r);
  for (int i = 0; i < N; ++i) s8r[i] = s8a[i] == s8b[i] ? 1 : (s8a[i] > s8b[i] ? (signed char)-1 : 0);
  CHECK("compares", s8r);
  for (int i = 0; i < N; ++i) u32r[i] = (unsigned)__builtin_popcount(u32a[i]);
  CHECK("popcount", u32r);
}

__declspec(noinline) static void reductions(void) {
  int sum = 0;
  for (int i = 0; i < N; ++i) sum += s8a[i];
  line_i("s8 sum", sum);
  unsigned usum = 0;
  for (int i = 0; i < N; ++i) usum += u8a[i] * u8b[i];
  line_i("u8 dot product", usum);
  i64 dot = 0;
  for (int i = 0; i < N; ++i) dot += s16a[i] * s16b[i];
  line_i("s16 dot product", dot);
  i64 lsum = 0;
  for (int i = 0; i < N; ++i) lsum += s32a[i];
  line_i("s32 sum", lsum);
  int mx = -2147483647 - 1, mn = 2147483647;
  for (int i = 0; i < N; ++i) {
    mx = s32a[i] > mx ? s32a[i] : mx;
    mn = s32a[i] < mn ? s32a[i] : mn;
  }
  line_i("s32 max", mx);
  line_i("s32 min", mn);
  unsigned char umx = 0;
  for (int i = 0; i < N; ++i) umx = u8a[i] > umx ? u8a[i] : umx;
  line_i("u8 max", umx);
  u64 x = 0;
  for (int i = 0; i < N; ++i) x ^= u64a[i];
  line("u64 xor", x);
  int count = 0;
  for (int i = 0; i < N; ++i) count += s16a[i] > s16b[i];
  line_i("count greater", count);
  i64 sad = 0;
  for (int i = 0; i < N; ++i) sad += u8a[i] > u8b[i] ? u8a[i] - u8b[i] : u8b[i] - u8a[i];
  line_i("sum of absolute differences", sad);
}

__declspec(noinline) static void conversions(void) {
  for (int i = 0; i < N; ++i) f32r[i] = (float)s32a[i] * 0.25f + (float)u8a[i];
  CHECK("int to float", f32r);
  for (int i = 0; i < N; ++i) s32r[i] = (int)(f32a[i] * 3.5f);
  CHECK("float to int", s32r);
  for (int i = 0; i < N; ++i) f64r[i] = (double)s64a[i] / 65536.0;
  CHECK("s64 to double", f64r);
  for (int i = 0; i < N; ++i) s64r[i] = (i64)(f64a[i] / 3.0);
  CHECK("double to s64", s64r);
  for (int i = 0; i < N; ++i) f64r[i] = (double)f32a[i] * f64b[i];
  CHECK("float to double", f64r);
  for (int i = 0; i < N; ++i) f32r[i] = (float)(f64a[i] * 1e-9);
  CHECK("double to float", f32r);
  for (int i = 0; i < N; ++i) u32r[i] = (unsigned)(f32b[i] * 100.0f);
  CHECK("float to unsigned", u32r);
  for (int i = 0; i < N; ++i) f32r[i] = (float)u32a[i];
  CHECK("unsigned to float", f32r);
  for (int i = 0; i < N; ++i) u8r[i] = (unsigned char)(int)(f32b[i] * 8.0f);
  CHECK("float to bytes", u8r);
}

__declspec(noinline) static void floating_point(void) {
  for (int i = 0; i < N; ++i) f32r[i] = f32a[i] * f32b[i] + f32a[i] / f32b[i] - 1.5f;
  CHECK("f32 arithmetic", f32r);
  for (int i = 0; i < N; ++i) f32r[i] = f32a[i] < f32b[i] ? f32a[i] : f32b[i];
  CHECK("f32 min", f32r);
  for (int i = 0; i < N; ++i) f32r[i] = f32a[i] < 0 ? -f32a[i] : f32a[i];
  CHECK("f32 abs", f32r);
  for (int i = 0; i < N; ++i) f32r[i] = __builtin_sqrtf(f32b[i]);
  CHECK("f32 sqrt", f32r);
  for (int i = 0; i < N; ++i) f64r[i] = f64a[i] * f64b[i] - f64b[i] / 7.0;
  CHECK("f64 arithmetic", f64r);
  for (int i = 0; i < N; ++i) f64r[i] = f64a[i] > 0 ? __builtin_sqrt(f64a[i]) : -f64a[i];
  CHECK("f64 select sqrt", f64r);
  for (int i = 0; i < N; ++i) f32r[i] = __builtin_floorf(f32a[i]) + __builtin_ceilf(f32b[i]) + __builtin_truncf(f32a[i] * 0.3f);
  CHECK("f32 rounding", f32r);
  for (int i = 0; i < N; ++i) f64r[i] = __builtin_rint(f64b[i] * 10.0);
  CHECK("f64 rint", f64r);
  for (int i = 0; i < N; ++i) s32r[i] = f32a[i] > f32b[i];
  CHECK("f32 compares", s32r);
  double sum = 0;  /* in order: not reassociated without fast-math */
  for (int i = 0; i < N; ++i) sum += f64b[i];
  line("f64 sum", *(u64*)&sum);
}

__declspec(noinline) static void memory_patterns(void) {
  /* interleaved: RGB to gray, complex multiply, transpose-like gathers */
  static unsigned char rgb[N * 3], gray[N];
  for (int i = 0; i < N * 3; ++i) rgb[i] = (unsigned char)(rng() >> 7);
  for (int i = 0; i < N; ++i) gray[i] = (unsigned char)((rgb[3 * i] * 77 + rgb[3 * i + 1] * 150 + rgb[3 * i + 2] * 29) >> 8);
  CHECK("rgb to gray", gray);
  static float cplx[N * 2], out[N * 2];
  for (int i = 0; i < N * 2; ++i) cplx[i] = f32a[i % N] * 0.001f;
  for (int i = 0; i < N; ++i) {
    float re = cplx[2 * i], im = cplx[2 * i + 1];
    out[2 * i] = re * re - im * im;
    out[2 * i + 1] = 2 * re * im;
  }
  CHECK("complex square", out);
  for (int i = 0; i < N; ++i) s32r[i] = s32a[N - 1 - i];
  CHECK("reverse", s32r);
  for (int i = 0; i < N; ++i) u16r[i] = (unsigned short)((u8a[i] << 8) | u8b[i]);
  CHECK("byte pairs", u16r);
  int found = -1;
  static char text[N + 1];
  for (int i = 0; i < N; ++i) text[i] = (char)('a' + (u8a[i] % 26));
  text[N] = 0;
  for (int i = 0; i < N; ++i)
    if (text[i] == 'q' && text[i + 1] == 'u') { found = i; break; }
  line_i("first qu", found);
  int upper = 0;
  for (int i = 0; i < N; ++i) {
    char c = text[i];
    text[i] = (char)(c >= 'a' && c <= 'z' ? c - 32 : c);
    upper += text[i] == 'E';
  }
  line_i("upper E", upper);
  CHECK("upper text", text);
  static u32 table[256];
  for (int i = 0; i < 256; ++i) table[i] = (u32)(rng());
  for (int i = 0; i < N; ++i) u32r[i] = table[u8a[i]] ^ table[u8b[i]];
  CHECK("table lookups", u32r);
}

/* Typical kernels: matrix multiply (broadcast element times vector), FIR
 * filter, widening multiply-accumulate, saturating pack, 32-entry table
 * lookups, leading zeros, rounding averages and sums of absolute differences. */
__declspec(noinline) static void kernels(void) {
  static float ma[16][16], mb[16][16], mc[16][16];
  static short ia[16][16], ib[16][16];
  static int ic[16][16];
  for (int i = 0; i < 16; ++i)
    for (int j = 0; j < 16; ++j) {
      ma[i][j] = f32a[i * 16 + j] * 0.01f;
      mb[i][j] = f32b[i * 16 + j];
      ia[i][j] = (short)(s16a[i * 16 + j] >> 4);
      ib[i][j] = (short)(s16b[i * 16 + j] >> 4);
    }
  for (int i = 0; i < 16; ++i)
    for (int j = 0; j < 16; ++j) {
      mc[i][j] = 0;
      ic[i][j] = 0;
    }
  for (int i = 0; i < 16; ++i)
    for (int k = 0; k < 16; ++k) {
      const float a = ma[i][k];
      const int ai = ia[i][k];
      for (int j = 0; j < 16; ++j) {
        mc[i][j] = mc[i][j] + a * mb[k][j];
        ic[i][j] += ai * ib[k][j];
      }
    }
  CHECK("f32 matrix multiply", mc);
  CHECK("s16 matrix multiply", ic);

  static const short taps[8] = {3, -7, 12, 40, 40, 12, -7, 3};
  for (int i = 0; i < N - 8; ++i) {
    int acc = 0;
    for (int t = 0; t < 8; ++t) acc += s16a[i + t] * taps[t];
    s32r[i] = acc;
  }
  CHECK("fir filter", s32r);

  for (int i = 0; i < N; ++i) u32r[i] = 0;
  for (int r = 0; r < 4; ++r)
    for (int i = 0; i < N; ++i) u32r[i] += (unsigned)u8a[(i + r * 7) % N] * u8b[i];
  CHECK("widening accumulate", u32r);

  for (int i = 0; i < N; ++i) {
    int v = (s32a[i] >> 14) + 128;
    u8r[i] = (unsigned char)(v < 0 ? 0 : v > 255 ? 255 : v);
  }
  CHECK("saturating pack", u8r);
  for (int i = 0; i < N; ++i) {
    int v = (s32a[i] + (1 << 9)) >> 10;
    s16r[i] = (short)(v > 32767 ? 32767 : v < -32768 ? -32768 : v);
  }
  CHECK("rounding saturating pack", s16r);

  static const unsigned char table32[32] = {
      7, 3, 31, 0, 12, 19, 25, 4, 9, 30, 1, 22, 15, 27, 6, 18, 2, 29, 11, 24, 5, 16, 28, 8, 21, 14, 26, 10, 23, 13, 17, 20};
  for (int i = 0; i < N; ++i) u8r[i] = table32[u8a[i] & 31];
  CHECK("32-entry table", u8r);

  for (int i = 0; i < N; ++i) u32r[i] = u32a[i] ? (unsigned)__builtin_clz(u32a[i]) : 32u;
  CHECK("leading zeros", u32r);
  for (int i = 0; i < N; ++i) u16r[i] = (unsigned short)((u16a[i] + (unsigned short)s16b[i] + 1u) >> 1);
  CHECK("u16 rounding average", u16r);

  unsigned sad = 0;
  for (int i = 0; i < N; ++i) sad += (unsigned)(u8a[i] > u8b[i] ? u8a[i] - u8b[i] : u8b[i] - u8a[i]) * 2u;
  line_i("doubled sad", sad);
  i64 wide = 0;
  for (int i = 0; i < N; ++i) wide += (i64)s32a[i] * s32b[i];
  line_i("s32 widening dot product", wide);
  for (int i = 0; i < N; ++i) f64r[i] = (double)f32a[i] * (double)f32b[i] + (double)u32a[i];
  CHECK("float to double arithmetic", f64r);
}

void mainCRTStartup(void) {
  fill();
  integer_ops();
  reductions();
  conversions();
  floating_point();
  memory_patterns();
  kernels();
  finish(0);
}
