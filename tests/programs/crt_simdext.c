// Advanced SIMD extensions beyond Armv8.0: dot products and int8 matrix
// multiplies, SQRDMLAH/SH, BFloat16, complex arithmetic (FCMLA/FCADD),
// FMLAL/FMLSL, FJCVTZS, FRINT32/64 and the flag manipulation instructions.
// The ARM64 build uses the instructions; the x86-64 reference computes the
// same values with portable code (inputs chosen so that results are exact
// where the instructions round differently from plain C).

#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#if defined(_M_ARM64)
#include <arm_acle.h>
#include <arm_neon.h>
#endif

static void print_u32(const char* label, const uint32_t* v, int n) {
  printf("%-10s", label);
  for (int i = 0; i < n; ++i) printf(" %08x", v[i]);
  printf("\n");
}

static void print_f32(const char* label, const float* v, int n) {
  printf("%-10s", label);
  for (int i = 0; i < n; ++i) printf(" %g", v[i]);
  printf("\n");
}

static int8_t sa[16], sb[16];
static uint8_t ua[16], ub[16];
static int32_t acc32[4] = {1000, -2000, 3000, -4000};

static void dot_products(void) {
  for (int i = 0; i < 16; ++i) {
    sa[i] = (int8_t)(i * 13 - 100);
    sb[i] = (int8_t)(77 - i * 9);
    ua[i] = (uint8_t)(i * 17 + 3);
    ub[i] = (uint8_t)(250 - i * 11);
  }
  int32_t r[6][4];
#if defined(_M_ARM64)
  const int8x16_t va = vld1q_s8(sa), vb = vld1q_s8(sb);
  const uint8x16_t wa = vld1q_u8(ua), wb = vld1q_u8(ub);
  const int32x4_t acc = vld1q_s32(acc32);
  vst1q_s32(r[0], vdotq_s32(acc, va, vb));
  vst1q_u32((uint32_t*)r[1], vdotq_u32(vreinterpretq_u32_s32(acc), wa, wb));
  vst1q_s32(r[2], vdotq_laneq_s32(acc, va, vb, 3));
  vst1q_s32(r[3], vusdotq_s32(acc, wa, vb));
  vst1q_s32(r[4], vsudotq_laneq_s32(acc, va, wb, 1));
  vst1q_s32(r[5], vcombine_s32(vdot_s32(vget_low_s32(acc), vget_low_s8(va), vget_low_s8(vb)), vdup_n_s32(0)));
#else
  for (int lane = 0; lane < 4; ++lane) {
    int32_t s0 = acc32[lane], s1 = acc32[lane], s2 = acc32[lane], s3 = acc32[lane], s4 = acc32[lane];
    for (int k = 0; k < 4; ++k) {
      const int i = 4 * lane + k;
      s0 += sa[i] * sb[i];
      s1 += (int32_t)((uint32_t)ua[i] * ub[i]);
      s2 += sa[i] * sb[12 + k];
      s3 += ua[i] * sb[i];
      s4 += sa[i] * ub[4 + k];
    }
    r[0][lane] = s0, r[1][lane] = s1, r[2][lane] = s2, r[3][lane] = s3, r[4][lane] = s4;
    r[5][lane] = lane < 2 ? s0 : 0;
  }
#endif
  static const char* names[6] = {"sdot", "udot", "sdot.lane", "usdot", "sudot.lane", "sdot.2s"};
  for (int i = 0; i < 6; ++i) print_u32(names[i], (const uint32_t*)r[i], 4);

  // Matrix multiply-accumulate: 2x8 by (2x8)^T into 2x2
  int32_t m[3][4];
#if defined(_M_ARM64)
  vst1q_s32(m[0], vmmlaq_s32(acc, va, vb));
  vst1q_u32((uint32_t*)m[1], vmmlaq_u32(vreinterpretq_u32_s32(acc), wa, wb));
  vst1q_s32(m[2], vusmmlaq_s32(acc, wa, vb));
#else
  for (int i = 0; i < 2; ++i)
    for (int j = 0; j < 2; ++j) {
      int32_t s0 = acc32[2 * i + j], s1 = acc32[2 * i + j], s2 = acc32[2 * i + j];
      for (int k = 0; k < 8; ++k) {
        s0 += sa[8 * i + k] * sb[8 * j + k];
        s1 += (int32_t)((uint32_t)ua[8 * i + k] * ub[8 * j + k]);
        s2 += ua[8 * i + k] * sb[8 * j + k];
      }
      m[0][2 * i + j] = s0, m[1][2 * i + j] = s1, m[2][2 * i + j] = s2;
    }
#endif
  print_u32("smmla", (const uint32_t*)m[0], 4);
  print_u32("ummla", (const uint32_t*)m[1], 4);
  print_u32("usmmla", (const uint32_t*)m[2], 4);
}

// SQRDMLAH / SQRDMLSH: saturate((acc << bits) +- 2*a*b + (1 << (bits-1))) >> bits)
static int64_t rdm(int64_t acc, int64_t a, int64_t b, int bits, int sub) {
  // (2ab + round) >> bits computed as (ab + round/2) >> (bits-1), then + acc
  const int64_t p = a * b;
  int64_t t = ((sub ? -p : p) + ((int64_t)1 << (bits - 2))) >> (bits - 1);
  int64_t r = acc + t;
  const int64_t hi = ((int64_t)1 << (bits - 1)) - 1, lo = -((int64_t)1 << (bits - 1));
  return r > hi ? hi : r < lo ? lo : r;
}

static void rounding_doubling(void) {
  static const int16_t a16[8] = {32767, -32768, 1000, -1000, 12345, -32768, 30000, 7};
  static const int16_t b16[8] = {32767, -32768, -32768, 25000, 23456, 32767, 30000, -7};
  static const int16_t c16[8] = {100, -100, 32767, -32768, 0, 5, 30000, -30000};
  static const int32_t a32[4] = {2147483647, -2147483647 - 1, 123456789, -987654321};
  static const int32_t b32[4] = {2147483647, -2147483647 - 1, -555555555, 1999999999};
  static const int32_t c32[4] = {0, -2147483647 - 1, 2147483647, 12345};
  int16_t r16[8], s16[8];
  int32_t r32[4], s32[4], l32[4];
  int16_t h;
#if defined(_M_ARM64)
  vst1q_s16(r16, vqrdmlahq_s16(vld1q_s16(c16), vld1q_s16(a16), vld1q_s16(b16)));
  vst1q_s16(s16, vqrdmlshq_s16(vld1q_s16(c16), vld1q_s16(a16), vld1q_s16(b16)));
  vst1q_s32(r32, vqrdmlahq_s32(vld1q_s32(c32), vld1q_s32(a32), vld1q_s32(b32)));
  vst1q_s32(s32, vqrdmlshq_s32(vld1q_s32(c32), vld1q_s32(a32), vld1q_s32(b32)));
  vst1q_s32(l32, vqrdmlahq_laneq_s32(vld1q_s32(c32), vld1q_s32(a32), vld1q_s32(b32), 2));
  h = vqrdmlahh_s16(c16[3], a16[3], b16[3]);
#else
  for (int i = 0; i < 8; ++i) {
    r16[i] = (int16_t)rdm(c16[i], a16[i], b16[i], 16, 0);
    s16[i] = (int16_t)rdm(c16[i], a16[i], b16[i], 16, 1);
  }
  for (int i = 0; i < 4; ++i) {
    r32[i] = (int32_t)rdm(c32[i], a32[i], b32[i], 32, 0);
    s32[i] = (int32_t)rdm(c32[i], a32[i], b32[i], 32, 1);
    l32[i] = (int32_t)rdm(c32[i], a32[i], b32[2], 32, 0);
  }
  h = (int16_t)rdm(c16[3], a16[3], b16[3], 16, 0);
#endif
  printf("sqrdmlah16");
  for (int i = 0; i < 8; ++i) printf(" %d", r16[i]);
  printf("\nsqrdmlsh16");
  for (int i = 0; i < 8; ++i) printf(" %d", s16[i]);
  printf("\n");
  print_u32("sqrdmlah32", (const uint32_t*)r32, 4);
  print_u32("sqrdmlsh32", (const uint32_t*)s32, 4);
  print_u32("lane32", (const uint32_t*)l32, 4);
  printf("scalar     %d\n", h);
}

// BFloat16: values chosen so that every product and sum is exact.
static uint16_t to_bf16(float f) {
  uint32_t u;
  memcpy(&u, &f, 4);
  return (uint16_t)(u >> 16);
}

static float from_bf16(uint16_t h) {
  uint32_t u = (uint32_t)h << 16;
  float f;
  memcpy(&f, &u, 4);
  return f;
}

static void bfloat16(void) {
  float fa[8], fb[8], acc[4] = {1.5f, -2.25f, 100.0f, 0.125f};
  uint16_t ha[8], hb[8];
  for (int i = 0; i < 8; ++i) {
    fa[i] = (float)(i - 3) * 0.5f;
    fb[i] = (float)(7 - 2 * i) * 0.25f;
    ha[i] = to_bf16(fa[i]);
    hb[i] = to_bf16(fb[i]);
  }
  float dot[4], mm[4], lb[4], lt[4], dl[4];
#if defined(_M_ARM64)
  const bfloat16x8_t va = vreinterpretq_bf16_u16(vld1q_u16(ha)), vb = vreinterpretq_bf16_u16(vld1q_u16(hb));
  const float32x4_t vacc = vld1q_f32(acc);
  vst1q_f32(dot, vbfdotq_f32(vacc, va, vb));
  vst1q_f32(mm, vbfmmlaq_f32(vacc, va, vb));
  vst1q_f32(lb, vbfmlalbq_f32(vacc, va, vb));
  vst1q_f32(lt, vbfmlaltq_f32(vacc, va, vb));
  vst1q_f32(dl, vbfdotq_laneq_f32(vacc, va, vb, 2));
#else
  for (int i = 0; i < 4; ++i) {
    dot[i] = acc[i] + fa[2 * i] * fb[2 * i] + fa[2 * i + 1] * fb[2 * i + 1];
    lb[i] = acc[i] + fa[2 * i] * fb[2 * i];
    lt[i] = acc[i] + fa[2 * i + 1] * fb[2 * i + 1];
    dl[i] = acc[i] + fa[2 * i] * fb[4] + fa[2 * i + 1] * fb[5];
  }
  for (int i = 0; i < 2; ++i)
    for (int j = 0; j < 2; ++j) {
      float s = acc[2 * i + j];
      for (int k = 0; k < 4; ++k) s += fa[4 * i + k] * fb[4 * j + k];
      mm[2 * i + j] = s;
    }
#endif
  print_f32("bfdot", dot, 4);
  print_f32("bfmmla", mm, 4);
  print_f32("bfmlalb", lb, 4);
  print_f32("bfmlalt", lt, 4);
  print_f32("bfdot.lane", dl, 4);

  // Conversions to BFloat16, round to nearest even
  static const float cvt_values[8] = {1.0f, 1.00390625f, 1.01171875f, -3.14159265f, 65504.0f, 1e-40f, 3.4e38f, -0.0f};
  float cvt_in[8];
  for (int i = 0; i < 8; ++i) {  // not known at compile time: keep the conversions
    volatile float v = cvt_values[i];
    cvt_in[i] = v;
  }
  uint16_t out[9];
#if defined(_M_ARM64)
  bfloat16x8_t lo = vcvtq_low_bf16_f32(vld1q_f32(cvt_in));
  bfloat16x8_t both = vcvtq_high_bf16_f32(lo, vld1q_f32(cvt_in + 4));
  vst1q_u16(out, vreinterpretq_u16_bf16(both));
  bfloat16_t one = vcvth_bf16_f32(cvt_in[3]);
  memcpy(&out[8], &one, 2);
#else
  for (int i = 0; i < 8; ++i) {
    uint32_t u;
    memcpy(&u, &cvt_in[i], 4);
    out[i] = (uint16_t)((u + 0x7FFF + ((u >> 16) & 1)) >> 16);
  }
  out[8] = out[3];
#endif
  printf("bfcvt     ");
  for (int i = 0; i < 9; ++i) printf(" %04x", out[i]);
  printf("\n");
  (void)from_bf16;
}

static void complex_arith(void) {
  static const float n[4] = {1.5f, -2.0f, 0.25f, 3.0f}, m[4] = {-1.25f, 0.5f, 2.0f, -4.0f};
  static const float a[4] = {10.0f, 20.0f, -30.0f, 40.0f};
  static const double nd[2] = {1.5, -2.25}, md[2] = {0.125, 3.0}, ad[2] = {-7.0, 8.5};
  float r[7][4];
  double d[3][2];
#if defined(_M_ARM64)
  const float32x4_t vn = vld1q_f32(n), vm = vld1q_f32(m), va = vld1q_f32(a);
  vst1q_f32(r[0], vcmlaq_f32(va, vn, vm));
  vst1q_f32(r[1], vcmlaq_rot90_f32(va, vn, vm));
  vst1q_f32(r[2], vcmlaq_rot180_f32(va, vn, vm));
  vst1q_f32(r[3], vcmlaq_rot270_f32(va, vn, vm));
  vst1q_f32(r[4], vcaddq_rot90_f32(vn, vm));
  vst1q_f32(r[5], vcaddq_rot270_f32(vn, vm));
  vst1q_f32(r[6], vcmlaq_rot90_f32(vcmlaq_laneq_f32(va, vn, vm, 1), vn, vm));
  const float64x2_t dn = vld1q_f64(nd), dm = vld1q_f64(md), da = vld1q_f64(ad);
  vst1q_f64(d[0], vcmlaq_rot90_f64(vcmlaq_f64(da, dn, dm), dn, dm));
  vst1q_f64(d[1], vcmlaq_rot270_f64(vcmlaq_rot180_f64(da, dn, dm), dn, dm));
  vst1q_f64(d[2], vcaddq_rot270_f64(dn, dm));
#else
  for (int p = 0; p < 2; ++p) {
    const float nre = n[2 * p], nim = n[2 * p + 1], mre = m[2 * p], mim = m[2 * p + 1];
    const float are = a[2 * p], aim = a[2 * p + 1];
    r[0][2 * p] = fmaf(nre, mre, are), r[0][2 * p + 1] = fmaf(nre, mim, aim);
    r[1][2 * p] = fmaf(nim, -mim, are), r[1][2 * p + 1] = fmaf(nim, mre, aim);
    r[2][2 * p] = fmaf(nre, -mre, are), r[2][2 * p + 1] = fmaf(nre, -mim, aim);
    r[3][2 * p] = fmaf(nim, mim, are), r[3][2 * p + 1] = fmaf(nim, -mre, aim);
    r[4][2 * p] = nre - mim, r[4][2 * p + 1] = nim + mre;
    r[5][2 * p] = nre + mim, r[5][2 * p + 1] = nim - mre;
    // lane 1 of m (the second complex pair) at rotation 0, then rot90 with the vector
    const float lre = fmaf(nre, m[2], are), lim = fmaf(nre, m[3], aim);
    r[6][2 * p] = fmaf(nim, -mim, lre), r[6][2 * p + 1] = fmaf(nim, mre, lim);
  }
  d[0][0] = fma(nd[1], -md[1], fma(nd[0], md[0], ad[0]));
  d[0][1] = fma(nd[1], md[0], fma(nd[0], md[1], ad[1]));
  d[1][0] = fma(nd[1], md[1], fma(nd[0], -md[0], ad[0]));
  d[1][1] = fma(nd[1], -md[0], fma(nd[0], -md[1], ad[1]));
  d[2][0] = nd[0] + md[1], d[2][1] = nd[1] - md[0];
#endif
  static const char* names[7] = {"fcmla0", "fcmla90", "fcmla180", "fcmla270", "fcadd90", "fcadd270", "fcmla.lane"};
  for (int i = 0; i < 7; ++i) print_f32(names[i], r[i], 4);
  for (int i = 0; i < 3; ++i) printf("fcmla.2d   %g %g\n", d[i][0], d[i][1]);
}

static void widening_fp16(void) {
#if defined(_M_ARM64)
  float16_t hn[8], hm[8];
#else
  uint16_t hn[8], hm[8];
#endif
  // small integers and halves: exact in half precision and in the products
  static const float fn[8] = {1, -2, 3.5f, 0.25f, -8, 16, 0.5f, -1.5f};
  static const float fm[8] = {2, 3, -0.5f, 4, 1.25f, -2, 6, 0.75f};
  static const float acc[4] = {1, 2, 3, 4};
  float r[6][4];
#if defined(_M_ARM64)
  for (int i = 0; i < 8; ++i) hn[i] = (float16_t)fn[i], hm[i] = (float16_t)fm[i];
  const float16x8_t vn = vld1q_f16(hn), vm = vld1q_f16(hm);
  const float32x4_t va = vld1q_f32(acc);
  vst1q_f32(r[0], vfmlalq_low_f16(va, vn, vm));
  vst1q_f32(r[1], vfmlalq_high_f16(va, vn, vm));
  vst1q_f32(r[2], vfmlslq_low_f16(va, vn, vm));
  vst1q_f32(r[3], vfmlslq_high_f16(va, vn, vm));
  vst1q_f32(r[4], vfmlalq_laneq_low_f16(va, vn, vm, 5));
  vst1q_f32(r[5], vcombine_f32(vfmlal_low_f16(vget_low_f32(va), vget_low_f16(vn), vget_low_f16(vm)), vdup_n_f32(0)));
#else
  (void)hn, (void)hm;
  for (int i = 0; i < 4; ++i) {
    r[0][i] = acc[i] + fn[i] * fm[i];
    r[1][i] = acc[i] + fn[4 + i] * fm[4 + i];
    r[2][i] = acc[i] - fn[i] * fm[i];
    r[3][i] = acc[i] - fn[4 + i] * fm[4 + i];
    r[4][i] = acc[i] + fn[i] * fm[5];
    r[5][i] = i < 2 ? acc[i] + fn[i] * fm[i] : 0;
  }
#endif
  static const char* names[6] = {"fmlal", "fmlal2", "fmlsl", "fmlsl2", "fmlal.lane", "fmlal.2s"};
  for (int i = 0; i < 6; ++i) print_f32(names[i], r[i], 4);
}

static int32_t js_toint32(double d) {
  if (!isfinite(d)) return 0;
  double t = trunc(d);
  double m = fmod(t, 4294967296.0);
  if (m < 0) m += 4294967296.0;
  return (int32_t)(uint32_t)m;
}

static void conversions(void) {
  static const double js_in[10] = {1.5, -1.5, 2147483648.0, 4294967301.0, -0.0, NAN, 1e20, -12884901895.0, 1e300, -2147483648.0};
  printf("fjcvtzs   ");
  for (int i = 0; i < 10; ++i) {
#if defined(_M_ARM64)
    const int32_t v = __jcvt(js_in[i]);
#else
    const int32_t v = js_toint32(js_in[i]);
#endif
    printf(" %d", v);
  }
  printf("\n");

  static const float f_in[4] = {2.5f, -3.5f, 3e9f, -1e20f};
  static const double d_in[2] = {-0.5, 1e19};
  float r32z[4], r32x[4];
  double r64[2];
#if defined(_M_ARM64)
  vst1q_f32(r32z, vrnd32zq_f32(vld1q_f32(f_in)));
  vst1q_f32(r32x, vrnd32xq_f32(vld1q_f32(f_in)));
  vst1q_f64(r64, vrnd64xq_f64(vld1q_f64(d_in)));
#else
  for (int i = 0; i < 4; ++i) {
    float z = truncf(f_in[i]), x = nearbyintf(f_in[i]);
    r32z[i] = (z >= -2147483648.0f && z < 2147483648.0f) ? z : -2147483648.0f;
    r32x[i] = (x >= -2147483648.0f && x < 2147483648.0f) ? x : -2147483648.0f;
  }
  for (int i = 0; i < 2; ++i) {
    double x = nearbyint(d_in[i]);
    r64[i] = (x >= -9223372036854775808.0 && x < 9223372036854775808.0) ? x : -9223372036854775808.0;
  }
#endif
  print_f32("frint32z", r32z, 4);
  print_f32("frint32x", r32x, 4);
  printf("frint64x   %g %g (signbit %d)\n", r64[0], r64[1], signbit(r64[0]) != 0);
}

// The flag manipulation instructions, reading NZCV back.
static void flag_ops(void) {
  uint64_t f[6];
#if defined(_M_ARM64)
  uint64_t t;
  __asm__ volatile("mov %x[t], #0x60000000\n msr nzcv, %x[t]\n cfinv\n mrs %x[f0], nzcv\n"
                   "mov %x[t], #0x30000000\n msr nzcv, %x[t]\n axflag\n mrs %x[f1], nzcv\n"
                   "mov %x[t], #0x40000000\n msr nzcv, %x[t]\n xaflag\n mrs %x[f2], nzcv\n"
                   "mov %x[t], #0xa5\n rmif %x[t], #2, #0xb\n mrs %x[f3], nzcv\n"
                   "mov %x[t], #0x180\n setf8 %w[t]\n mrs %x[f4], nzcv\n"
                   "mov %x[t], #0x10000\n setf16 %w[t]\n mrs %x[f5], nzcv\n"
                   : [t] "=&r"(t), [f0] "=r"(f[0]), [f1] "=r"(f[1]), [f2] "=r"(f[2]), [f3] "=r"(f[3]),
                     [f4] "=r"(f[4]), [f5] "=r"(f[5])
                   :
                   : "cc");
#else
  f[0] = 0x40000000;  // Z C -> Z !C
  f[1] = 0x40000000;  // C V: Z = Z | V = 1, C = C & !V = 0
  f[2] = 0x30000000;  // Z only: N = !C & !Z = 0, Z = Z & C = 0, C = C | Z = 1, V = !C & Z = 1
  // RMIF: 0xa5 ror 2 = ...01001 -> low nibble 0b1001; mask 0b1011 keeps N, C, V from it; flags were
  // C|V (0x3) after the xaflag: N = 1, Z unchanged (0), C = 0, V = 1
  f[3] = 0x90000000;
  // SETF8 of 0x180: N = bit 7 = 1, Z = (0x80 == 0) = 0, V = bit 8 ^ bit 7 = 0; C unchanged (0)
  f[4] = 0x80000000;
  // SETF16 of 0x10000: N = bit 15 = 0, Z = low 16 bits zero = 1, V = bit 16 ^ bit 15 = 1; C unchanged
  f[5] = 0x50000000;
#endif
  printf("flags     ");
  for (int i = 0; i < 6; ++i) printf(" %08llx", (unsigned long long)f[i]);
  printf("\n");
}

int main(void) {
  dot_products();
  rounding_doubling();
  bfloat16();
  complex_arith();
  widening_fp16();
  conversions();
  flag_ops();
  return 0;
}
