// More instruction extensions: SM3 and SM4, compare-and-branch (CMPBR),
// checked pointer arithmetic (CPA), unprivileged loads/stores (LSUI),
// PAuth_LR returns, FPRCVT conversions, FAMAX/FAMIN, and base AdvSIMD
// instructions: scalar SQDMULL/SQDMLAL, SUQADD/USQADD, URECPE/URSQRTE.
// The ARM64 build uses the instructions; the x86-64 reference computes the
// same values in C.

#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#if defined(_M_ARM64)
#include <arm_neon.h>
#endif

static uint32_t rol(uint32_t x, int n) { return n ? (x << n) | (x >> (32 - n)) : x; }

// --- SM3 ---------------------------------------------------------------------------------

static const uint32_t kSm3Iv[8] = {0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
                                   0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e};

static uint32_t be32(const uint8_t* p) { return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3]; }

#if defined(_M_ARM64)
static void sm3_block(uint32_t v[8], const uint8_t* p) {
  uint32x4_t w[17];
  for (int i = 0; i < 4; ++i) {
    const uint32_t q[4] = {be32(p + 16 * i), be32(p + 16 * i + 4), be32(p + 16 * i + 8), be32(p + 16 * i + 12)};
    w[i] = vld1q_u32(q);
  }
  for (int g = 4; g < 17; ++g) {  // W[4g .. 4g+3]
    const uint32x4_t t = vsm3partw1q_u32(w[g - 4], vextq_u32(w[g - 3], w[g - 2], 3), w[g - 1]);
    w[g] = vsm3partw2q_u32(t, vextq_u32(w[g - 2], w[g - 1], 2), vextq_u32(w[g - 4], w[g - 3], 3));
  }
  // abcd = {D, C, B, A}, efgh = {H, G, F, E}
  const uint32_t a0[4] = {v[3], v[2], v[1], v[0]}, e0[4] = {v[7], v[6], v[5], v[4]};
  uint32x4_t abcd = vld1q_u32(a0), efgh = vld1q_u32(e0);
  for (int g = 0; g < 16; ++g) {
    const uint32x4_t wv = w[g], wp = veorq_u32(w[g], w[g + 1]);
    for (int k = 0; k < 4; ++k) {
      const int j = 4 * g + k;
      const uint32_t t = rol(j < 16 ? 0x79cc4519u : 0x7a879d8au, j % 32);
      const uint32_t tv[4] = {0, 0, 0, t};
      const uint32x4_t ss1 = vsm3ss1q_u32(abcd, efgh, vld1q_u32(tv));
      if (j < 16) {
        switch (k) {
          case 0: abcd = vsm3tt1aq_u32(abcd, ss1, wp, 0); efgh = vsm3tt2aq_u32(efgh, ss1, wv, 0); break;
          case 1: abcd = vsm3tt1aq_u32(abcd, ss1, wp, 1); efgh = vsm3tt2aq_u32(efgh, ss1, wv, 1); break;
          case 2: abcd = vsm3tt1aq_u32(abcd, ss1, wp, 2); efgh = vsm3tt2aq_u32(efgh, ss1, wv, 2); break;
          default: abcd = vsm3tt1aq_u32(abcd, ss1, wp, 3); efgh = vsm3tt2aq_u32(efgh, ss1, wv, 3); break;
        }
      } else {
        switch (k) {
          case 0: abcd = vsm3tt1bq_u32(abcd, ss1, wp, 0); efgh = vsm3tt2bq_u32(efgh, ss1, wv, 0); break;
          case 1: abcd = vsm3tt1bq_u32(abcd, ss1, wp, 1); efgh = vsm3tt2bq_u32(efgh, ss1, wv, 1); break;
          case 2: abcd = vsm3tt1bq_u32(abcd, ss1, wp, 2); efgh = vsm3tt2bq_u32(efgh, ss1, wv, 2); break;
          default: abcd = vsm3tt1bq_u32(abcd, ss1, wp, 3); efgh = vsm3tt2bq_u32(efgh, ss1, wv, 3); break;
        }
      }
    }
  }
  uint32_t a[4], e[4];
  vst1q_u32(a, abcd);
  vst1q_u32(e, efgh);
  for (int i = 0; i < 4; ++i) v[i] ^= a[3 - i], v[4 + i] ^= e[3 - i];
}
#else
static uint32_t p0(uint32_t x) { return x ^ rol(x, 9) ^ rol(x, 17); }
static uint32_t p1(uint32_t x) { return x ^ rol(x, 15) ^ rol(x, 23); }

static void sm3_block(uint32_t v[8], const uint8_t* p) {
  uint32_t w[68], wp[64];
  for (int j = 0; j < 16; ++j) w[j] = be32(p + 4 * j);
  for (int j = 16; j < 68; ++j) w[j] = p1(w[j - 16] ^ w[j - 9] ^ rol(w[j - 3], 15)) ^ rol(w[j - 13], 7) ^ w[j - 6];
  for (int j = 0; j < 64; ++j) wp[j] = w[j] ^ w[j + 4];
  uint32_t a = v[0], b = v[1], c = v[2], d = v[3], e = v[4], f = v[5], g = v[6], h = v[7];
  for (int j = 0; j < 64; ++j) {
    const uint32_t t = j < 16 ? 0x79cc4519u : 0x7a879d8au;
    const uint32_t ss1 = rol(rol(a, 12) + e + rol(t, j % 32), 7);
    const uint32_t ss2 = ss1 ^ rol(a, 12);
    const uint32_t ff = j < 16 ? a ^ b ^ c : (a & b) | (a & c) | (b & c);
    const uint32_t gg = j < 16 ? e ^ f ^ g : (e & f) | (~e & g);
    const uint32_t tt1 = ff + d + ss2 + wp[j], tt2 = gg + h + ss1 + w[j];
    d = c, c = rol(b, 9), b = a, a = tt1, h = g, g = rol(f, 19), f = e, e = p0(tt2);
  }
  v[0] ^= a, v[1] ^= b, v[2] ^= c, v[3] ^= d, v[4] ^= e, v[5] ^= f, v[6] ^= g, v[7] ^= h;
}
#endif

static void sm3(const uint8_t* msg, size_t len) {
  uint8_t buf[256] = {0};
  memcpy(buf, msg, len);
  buf[len] = 0x80;
  const size_t total = ((len + 9 + 63) / 64) * 64;
  const uint64_t bits = (uint64_t)len * 8;
  for (int i = 0; i < 8; ++i) buf[total - 1 - i] = (uint8_t)(bits >> (8 * i));
  uint32_t v[8];
  memcpy(v, kSm3Iv, sizeof(v));
  for (size_t off = 0; off < total; off += 64) sm3_block(v, buf + off);
  printf("sm3       ");
  for (int i = 0; i < 8; ++i) printf(" %08x", v[i]);
  printf("\n");
}

// --- SM4 -------------------------------------------------------------------------------------

static const uint32_t kFk[4] = {0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc};

static uint32_t ck(int i) {
  uint32_t w = 0;
  for (int j = 0; j < 4; ++j) w = (w << 8) | (uint32_t)(((4 * i + j) * 7) & 0xFF);
  return w;
}

#if !defined(_M_ARM64)
static uint8_t sm4_sbox[256];
static unsigned gmul(unsigned a, unsigned b) {
  unsigned r = 0;
  while (b) {
    if (b & 1) r ^= a;
    a <<= 1;
    if (a & 0x100) a ^= 0x1F5;
    b >>= 1;
  }
  return r;
}
static unsigned affine(unsigned x) {
  unsigned out = 0;
  for (int i = 0; i < 8; ++i) {
    const unsigned row = ((0xA7u << i) | (0xA7u >> (8 - i))) & 0xFF;
    if (__builtin_popcount(row & x) & 1) out |= 1u << i;
  }
  return out ^ 0xD3;
}
static void make_sm4_sbox(void) {
  for (unsigned x = 0; x < 256; ++x) {
    unsigned y = affine(x), inv = 0;
    for (unsigned z = 1; y && z < 256; ++z)
      if (gmul(y, z) == 1) inv = z;
    sm4_sbox[x] = (uint8_t)affine(inv);
  }
}
static uint32_t tau(uint32_t a) {
  return (uint32_t)sm4_sbox[a >> 24] << 24 | (uint32_t)sm4_sbox[(a >> 16) & 0xFF] << 16 |
         (uint32_t)sm4_sbox[(a >> 8) & 0xFF] << 8 | sm4_sbox[a & 0xFF];
}
#endif

static void sm4(void) {
  const uint32_t key[4] = {0x01234567, 0x89abcdef, 0xfedcba98, 0x76543210};
  uint32_t rk[32];
  uint32_t data[4] = {0x01234567, 0x89abcdef, 0xfedcba98, 0x76543210};
#if defined(_M_ARM64)
  uint32_t k0[4];
  for (int i = 0; i < 4; ++i) k0[i] = key[i] ^ kFk[i];
  uint32x4_t k = vld1q_u32(k0);
  for (int r = 0; r < 8; ++r) {
    const uint32_t c[4] = {ck(4 * r), ck(4 * r + 1), ck(4 * r + 2), ck(4 * r + 3)};
    k = vsm4ekeyq_u32(k, vld1q_u32(c));
    vst1q_u32(rk + 4 * r, k);
  }
  for (int n = 0; n < 2; ++n) {  // encrypt twice
    uint32x4_t x = vld1q_u32(data);
    for (int r = 0; r < 8; ++r) x = vsm4eq_u32(x, vld1q_u32(rk + 4 * r));
    uint32_t out[4];
    vst1q_u32(out, x);
    for (int i = 0; i < 4; ++i) data[i] = out[3 - i];  // the output is X35, X34, X33, X32
  }
#else
  make_sm4_sbox();
  uint32_t kk[36];
  for (int i = 0; i < 4; ++i) kk[i] = key[i] ^ kFk[i];
  for (int i = 0; i < 32; ++i) {
    const uint32_t t = tau(kk[i + 1] ^ kk[i + 2] ^ kk[i + 3] ^ ck(i));
    kk[i + 4] = kk[i] ^ t ^ rol(t, 13) ^ rol(t, 23);
    rk[i] = kk[i + 4];
  }
  for (int n = 0; n < 2; ++n) {
    uint32_t x[36];
    memcpy(x, data, 16);
    for (int i = 0; i < 32; ++i) {
      const uint32_t t = tau(x[i + 1] ^ x[i + 2] ^ x[i + 3] ^ rk[i]);
      x[i + 4] = x[i] ^ t ^ rol(t, 2) ^ rol(t, 10) ^ rol(t, 18) ^ rol(t, 24);
    }
    for (int i = 0; i < 4; ++i) data[i] = x[35 - i];
  }
#endif
  printf("sm4 rk     %08x %08x %08x\n", rk[0], rk[1], rk[31]);
  printf("sm4 ct    ");
  for (int i = 0; i < 4; ++i) printf(" %08x", data[i]);
  printf("\n");
}

// --- base AdvSIMD ------------------------------------------------------------------------------

static unsigned recip_estimate(unsigned a) {  // 256 <= a < 512
  a = a * 2 + 1;
  unsigned b = (1u << 19) / a;
  return (b + 1) / 2;
}

static unsigned rsqrt_estimate(unsigned a) {  // 128 <= a < 512
  if (a < 256) a = a * 2 + 1;
  else a = ((a >> 1) << 1) * 2 + 2;
  unsigned b = 512;
  while ((uint64_t)a * (b + 1) * (b + 1) < ((uint64_t)1 << 28)) ++b;
  return (b + 1) / 2;
}

static int64_t sat(int64_t v, int bits) {
  const int64_t hi = ((int64_t)1 << (bits - 1)) - 1, lo = -hi - 1;
  return v > hi ? hi : v < lo ? lo : v;
}

static void simd_base(void) {
  static const int16_t s16[8] = {32767, -32768, 100, -100, 30000, -1, 0, 12345};
  static const uint16_t u16[8] = {65535, 1, 40000, 200, 3000, 65535, 0, 7};
  static const uint32_t u32[4] = {0x80000000u, 0x12345678u, 0xFFFFFFFFu, 0x40000001u};
  int16_t suq[8];
  uint16_t usq[8];
  uint32_t re[4], rs[4];
  int64_t dmull, dmlal;
  int32_t dmlalh;
#if defined(_M_ARM64)
  vst1q_s16(suq, vuqaddq_s16(vld1q_s16(s16), vld1q_u16(u16)));
  vst1q_u16(usq, vsqaddq_u16(vld1q_u16(u16), vld1q_s16(s16)));
  vst1q_u32(re, vrecpeq_u32(vld1q_u32(u32)));
  vst1q_u32(rs, vrsqrteq_u32(vld1q_u32(u32)));
  volatile int32_t a = -2147483647 - 1, b = -2147483647 - 1, c = 123456;
  dmull = vqdmulls_s32(a, b);
  dmlal = vqdmlals_s32(1000, c, -c);
  dmlalh = vqdmlalh_s16(-5, (int16_t)c, 300);
#else
  for (int i = 0; i < 8; ++i) {
    suq[i] = (int16_t)sat((int64_t)s16[i] + u16[i], 16);
    const int64_t v = (int64_t)u16[i] + s16[i];
    usq[i] = (uint16_t)(v < 0 ? 0 : v > 65535 ? 65535 : v);
  }
  for (int i = 0; i < 4; ++i) {
    re[i] = (u32[i] >> 31) ? (recip_estimate(u32[i] >> 23) & 0x1FF) << 23 : 0xFFFFFFFFu;
    rs[i] = (u32[i] >> 30) ? (rsqrt_estimate(u32[i] >> 23) & 0x1FF) << 23 : 0xFFFFFFFFu;
  }
  dmull = INT64_MAX;  // -2^31 * -2^31 * 2 saturates
  dmlal = 1000 + 2 * (int64_t)123456 * -123456;
  dmlalh = -5 + 2 * (int16_t)123456 * 300;
#endif
  printf("suqadd    ");
  for (int i = 0; i < 8; ++i) printf(" %d", suq[i]);
  printf("\nusqadd    ");
  for (int i = 0; i < 8; ++i) printf(" %u", usq[i]);
  printf("\nurecpe     %08x %08x %08x %08x\n", re[0], re[1], re[2], re[3]);
  printf("ursqrte    %08x %08x %08x %08x\n", rs[0], rs[1], rs[2], rs[3]);
  printf("sqdmull    %lld %lld %d\n", (long long)dmull, (long long)dmlal, dmlalh);

  static const float fa[4] = {-3.5f, 2.0f, -0.0f, 7.25f}, fb[4] = {1.0f, -4.5f, 0.0f, -7.25f};
  float amax[4], amin[4];
#if defined(_M_ARM64)
  vst1q_f32(amax, vamaxq_f32(vld1q_f32(fa), vld1q_f32(fb)));
  vst1q_f32(amin, vaminq_f32(vld1q_f32(fa), vld1q_f32(fb)));
#else
  for (int i = 0; i < 4; ++i) amax[i] = fmaxf(fabsf(fa[i]), fabsf(fb[i])), amin[i] = fminf(fabsf(fa[i]), fabsf(fb[i]));
#endif
  printf("famax      %g %g %g %g\n", amax[0], amax[1], amax[2], amax[3]);
  printf("famin      %g %g %g %g\n", amin[0], amin[1], amin[2], amin[3]);
}

// --- general-purpose extensions ----------------------------------------------------------------

static int cbranch(int64_t x, int64_t y) {  // a bit per CB<cc> taken
  int r = 0;
#if defined(_M_ARM64)
  __asm__("mov %w0, #0\n"
          "cbgt %x1, %x2, 1f\n b 2f\n 1: orr %w0, %w0, #1\n 2:\n"
          "cbge %x1, %x2, 1f\n b 2f\n 1: orr %w0, %w0, #2\n 2:\n"
          "cbhi %x1, %x2, 1f\n b 2f\n 1: orr %w0, %w0, #4\n 2:\n"
          "cbeq %w1, %w2, 1f\n b 2f\n 1: orr %w0, %w0, #8\n 2:\n"
          "cblt %x1, #10, 1f\n b 2f\n 1: orr %w0, %w0, #16\n 2:\n"
          "cbhi %w1, #63, 1f\n b 2f\n 1: orr %w0, %w0, #32\n 2:\n"
          "cbbgt %w1, %w2, 1f\n b 2f\n 1: orr %w0, %w0, #64\n 2:\n"
          "cbhhs %w1, %w2, 1f\n b 2f\n 1: orr %w0, %w0, #128\n 2:\n"
          "cbne %x1, #0, 1f\n b 2f\n 1: orr %w0, %w0, #256\n 2:\n"
          : "=&r"(r)
          : "r"(x), "r"(y)
          : "cc");
#else
  const uint64_t ux = (uint64_t)x, uy = (uint64_t)y;
  r |= x > y ? 1 : 0;
  r |= x >= y ? 2 : 0;
  r |= ux > uy ? 4 : 0;
  r |= (uint32_t)x == (uint32_t)y ? 8 : 0;
  r |= x < 10 ? 16 : 0;
  r |= (uint32_t)x > 63 ? 32 : 0;
  r |= (int8_t)x > (int8_t)y ? 64 : 0;
  r |= (uint16_t)x >= (uint16_t)y ? 128 : 0;
  r |= x != 0 ? 256 : 0;
#endif
  return r;
}

static uint64_t pairs[4] = {11, 22, 33, 44};
static uint64_t word = 5;

static void gp_extensions(void) {
  static const int64_t vals[6][2] = {{5, 3}, {-5, 3}, {3, 3}, {0x1FF, 0x7F}, {-0x8000, 0x7FFF}, {100, -100}};
  printf("cb        ");
  for (int i = 0; i < 6; ++i) printf(" %03x", cbranch(vals[i][0], vals[i][1]));
  printf("\n");

  uint64_t r[4];
  volatile uint64_t p = 0x1000, q = 0x30, m = 3, n = 7;
#if defined(_M_ARM64)
  __asm__("addpt %0, %4, %5, lsl #3\n subpt %1, %4, %5\n maddpt %2, %6, %7, %4\n msubpt %3, %6, %7, %4"
          : "=&r"(r[0]), "=&r"(r[1]), "=&r"(r[2]), "=&r"(r[3])
          : "r"(p), "r"(q), "r"(m), "r"(n));
#else
  r[0] = p + (q << 3), r[1] = p - q, r[2] = p + m * n, r[3] = p - m * n;
#endif
  printf("cpa        %llx %llx %llx %llx\n", (unsigned long long)r[0], (unsigned long long)r[1],
         (unsigned long long)r[2], (unsigned long long)r[3]);

  uint64_t a, b, old, base = (uint64_t)pairs;
#if defined(_M_ARM64)
  __asm__ volatile("ldtp %0, %1, [%3], #16\n sttp %1, %0, [%3]\n ldtadd %4, %2, [%5]"
                   : "=&r"(a), "=&r"(b), "=&r"(old), "+r"(base)
                   : "r"((uint64_t)10), "r"(&word)
                   : "memory");
#else
  a = pairs[0], b = pairs[1], base += 16;
  pairs[2] = b, pairs[3] = a;
  old = word, word += 10;
#endif
  printf("lsui       %llu %llu +%lld %llu %llu %llu %llu\n", (unsigned long long)a, (unsigned long long)b,
         (long long)(base - (uint64_t)pairs), (unsigned long long)pairs[2], (unsigned long long)pairs[3],
         (unsigned long long)old, (unsigned long long)word);

  // FPRCVT: integer results in SIMD&FP registers
  volatile double d = -2.5;
  volatile float f = 3.75f;
  uint64_t out[4];
#if defined(_M_ARM64)
  __asm__("fcvtns s16, %d4\n fmov %w0, s16\n fcvtzu d16, %s5\n fmov %1, d16\n"
          "fcvtms s16, %d4\n fmov %w2, s16\n scvtf d16, s17\n fmov %3, d16"
          : "=&r"(out[0]), "=&r"(out[1]), "=&r"(out[2]), "=&r"(out[3])
          : "w"(d), "w"(f)
          : "v16", "v17");
  (void)out;
  {
    // scvtf d16, s17 read whatever was in s17: compute it separately
    double cv;
    int32_t iv = -7;
    __asm__("fmov s17, %w1\n scvtf %d0, s17" : "=w"(cv) : "r"(iv) : "v17");
    memcpy(&out[3], &cv, 8);
  }
#else
  out[0] = (uint32_t)(int32_t)nearbyint(d);
  out[1] = (uint64_t)3;
  out[2] = (uint32_t)(int32_t)floor(d);
  {
    double cv = -7.0;
    memcpy(&out[3], &cv, 8);
  }
#endif
  printf("fprcvt     %llx %llx %llx %llx\n", (unsigned long long)out[0], (unsigned long long)out[1],
         (unsigned long long)out[2], (unsigned long long)out[3]);
}

int main(void) {
  const uint8_t abc[] = "abc";
  sm3(abc, 3);
  uint8_t msg[64];
  for (int i = 0; i < 64; ++i) msg[i] = (uint8_t)("abcd"[i % 4]);
  sm3(msg, 64);
  sm4();
  simd_base();
  gp_extensions();
  return 0;
}
