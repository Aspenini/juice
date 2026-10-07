// Half precision arithmetic (FEAT_FP16): scalar and vector operations,
// conversions, compares and reductions. The ARM64 build uses the half
// precision instructions; the x86-64 reference computes with _Float16, which
// rounds each operation's single precision result once more to half precision
// (correct for +, -, *, / and sqrt). Results are printed as bit patterns.

#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#if defined(_M_ARM64)
#include <arm_fp16.h>
#include <arm_neon.h>
#endif

typedef _Float16 half;

static uint16_t bits(half h) {
  uint16_t u;
  memcpy(&u, &h, 2);
  return u;
}

static half from_bits(uint16_t u) {
  half h;
  memcpy(&h, &u, 2);
  return h;
}

static void print_halves(const char* label, const half* v, int n) {
  printf("%-10s", label);
  for (int i = 0; i < n; ++i) printf(" %04x", bits(v[i]));
  printf("\n");
}

// FCVTZS to 16 bits: truncate and saturate.
static int16_t sat16(float f) {
  if (f != f) return 0;
  if (f >= 32767.0f) return 32767;
  if (f <= -32768.0f) return -32768;
  return (int16_t)f;
}

// Values not known at compile time.
static half opaque(float f) {
  volatile half h = (half)f;
  return h;
}

static half A[8], B[8], C[8];

static void scalar_ops(void) {
  half r[12][8];
  for (int i = 0; i < 8; ++i) {
    const half a = A[i], b = B[i], c = C[i];
#if defined(_M_ARM64)
    r[0][i] = vaddh_f16(a, b);
    r[1][i] = vsubh_f16(a, b);
    r[2][i] = vmulh_f16(a, b);
    r[3][i] = vdivh_f16(a, b);
    r[4][i] = vsqrth_f16(vabsh_f16(a));
    r[5][i] = vfmah_f16(c, a, b);
    r[6][i] = vmaxnmh_f16(a, b);
    r[7][i] = vminh_f16(a, b);
    r[8][i] = vrndmh_f16(a);
    r[9][i] = vrndnh_f16(b);
    r[10][i] = vnegh_f16(vabsh_f16(c));
    r[11][i] = vmulxh_f16(a, c);
#else
    r[0][i] = a + b;
    r[1][i] = a - b;
    r[2][i] = a * b;
    r[3][i] = a / b;
    r[4][i] = (half)sqrtf((float)(a < 0 ? -a : a));
    r[5][i] = (half)((double)a * (double)b + (double)c);  // exact in double precision for these inputs
    r[6][i] = a > b ? a : b;
    r[7][i] = a < b ? a : b;
    r[8][i] = (half)floorf((float)a);
    r[9][i] = (half)nearbyintf((float)b);
    r[10][i] = -(c < 0 ? -c : c);
    r[11][i] = a * c;
#endif
  }
  static const char* names[12] = {"add", "sub", "mul", "div", "sqrt", "fma", "maxnm", "min", "frintm", "frintn",
                                  "fnegabs", "mulx"};
  for (int k = 0; k < 12; ++k) print_halves(names[k], r[k], 8);
}

static void scalar_conversions(void) {
  printf("to float  ");
  for (int i = 0; i < 8; ++i) printf(" %g", (double)(float)A[i]);
  printf("\nto int    ");
  for (int i = 0; i < 8; ++i) printf(" %d", (int)A[i]);
  printf("\nto uint64 ");
  for (int i = 0; i < 8; ++i) printf(" %llu", (unsigned long long)(B[i] < 0 ? 0 : (unsigned long long)B[i]));
  printf("\n");
  static const float f_in[8] = {1.0f / 3, 65519.0f, 65520.0f, 1e-6f, -2.5e-8f, 3.14159f, -0.0f, 1e9f};
  static const double d_in[4] = {0.1, -1e-5, 2049.0, 2051.0};
  static const int i_in[6] = {7, -2049, 2049, 65535, -70000, 2051};
  half out[18];
  for (int i = 0; i < 8; ++i) {
    volatile float f = f_in[i];
    out[i] = (half)f;
  }
  for (int i = 0; i < 4; ++i) {
    volatile double d = d_in[i];
    out[8 + i] = (half)d;
  }
  for (int i = 0; i < 6; ++i) {
    volatile int v = i_in[i];
    out[12 + i] = (half)v;
  }
  print_halves("from float", out, 8);
  print_halves("from dbl", out + 8, 4);
  print_halves("from int", out + 12, 6);
  printf("compare   ");
  for (int i = 0; i < 8; ++i) printf(" %d%d%d", A[i] < B[i], A[i] == B[i], A[i] >= C[i]);
  printf("\n");
}

static void vector_ops(void) {
  half r[10][8];
  int16_t ints[3][8];
  half red[4];
#if defined(_M_ARM64)
  const float16x8_t a = vld1q_f16((const float16_t*)A), b = vld1q_f16((const float16_t*)B), c = vld1q_f16((const float16_t*)C);
  vst1q_f16((float16_t*)r[0], vaddq_f16(a, b));
  vst1q_f16((float16_t*)r[1], vmulq_f16(a, b));
  vst1q_f16((float16_t*)r[2], vdivq_f16(a, b));
  vst1q_f16((float16_t*)r[3], vfmaq_f16(c, a, b));
  vst1q_f16((float16_t*)r[4], vsqrtq_f16(vabsq_f16(b)));
  vst1q_f16((float16_t*)r[5], vrndmq_f16(a));
  vst1q_f16((float16_t*)r[6], vpaddq_f16(a, b));
  vst1q_f16((float16_t*)r[7], vmulq_laneq_f16(a, c, 3));
  vst1q_f16((float16_t*)r[8], vreinterpretq_f16_u16(vcgeq_f16(a, b)));
  vst1q_f16((float16_t*)r[9], vcvtq_n_f16_s16(vcvtq_s16_f16(a), 2));
  vst1q_s16(ints[0], vcvtq_s16_f16(b));
  vst1q_s16(ints[1], vcvtnq_s16_f16(a));
  vst1q_s16(ints[2], vcvtq_n_s16_f16(c, 3));
  red[0] = vmaxnmvq_f16(a);
  red[1] = vminvq_f16(b);
  red[2] = vmaxv_f16(vget_low_f16(c));
  red[3] = vaddh_f16(vgetq_lane_f16(vpaddq_f16(a, a), 0), vdupq_n_f16(2.0)[5]);
#else
  for (int i = 0; i < 8; ++i) {
    r[0][i] = A[i] + B[i];
    r[1][i] = A[i] * B[i];
    r[2][i] = A[i] / B[i];
    r[3][i] = (half)((double)A[i] * (double)B[i] + (double)C[i]);
    r[4][i] = (half)sqrtf((float)(B[i] < 0 ? -B[i] : B[i]));
    r[5][i] = (half)floorf((float)A[i]);
    r[6][i] = i < 4 ? A[2 * i] + A[2 * i + 1] : B[2 * (i - 4)] + B[2 * (i - 4) + 1];
    r[7][i] = A[i] * C[3];
    r[8][i] = from_bits(A[i] >= B[i] ? 0xFFFF : 0);
    r[9][i] = (half)((float)sat16((float)A[i]) / 4.0f);
    ints[0][i] = sat16((float)B[i]);
    ints[1][i] = sat16(nearbyintf((float)A[i]));
    ints[2][i] = sat16((float)C[i] * 8.0f);
  }
  half m = A[0], n = B[0], o = C[0];
  for (int i = 1; i < 8; ++i) {
    if (A[i] > m) m = A[i];
    if (B[i] < n) n = B[i];
    if (i < 4 && C[i] > o) o = C[i];
  }
  red[0] = m, red[1] = n, red[2] = o;
  red[3] = (half)(A[0] + A[1]) + (half)2.0;
#endif
  static const char* names[10] = {"vadd", "vmul", "vdiv", "vfma", "vsqrt", "vfrintm", "vpadd", "vmul.lane", "vcmge",
                                  "vcvt.fix"};
  for (int k = 0; k < 10; ++k) print_halves(names[k], r[k], 8);
  for (int k = 0; k < 3; ++k) {
    printf("vcvt.int%d ", k);
    for (int i = 0; i < 8; ++i) printf(" %d", ints[k][i]);
    printf("\n");
  }
  print_halves("reduce", red, 4);
}

int main(void) {
  static const float a[8] = {1.5f, -2.25f, 1000.0f, 0.000123f, -65504.0f, 3.0f, 0.1f, 7.75f};
  static const float b[8] = {0.5f, 4.0f, -0.03125f, 3.0f, 2.0f, -3.0f, 0.2f, 1e-7f};
  static const float c[8] = {-1.0f, 0.75f, 100.0f, 2.5f, 1.0f, 9.0f, -0.5f, 0.25f};
  for (int i = 0; i < 8; ++i) A[i] = opaque(a[i]), B[i] = opaque(b[i]), C[i] = opaque(c[i]);
  scalar_ops();
  scalar_conversions();
  vector_ops();
  return 0;
}
