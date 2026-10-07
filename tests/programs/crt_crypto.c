// The Arm cryptographic extensions: AES, SHA-1, SHA-256, SHA-512, SHA-3
// (EOR3/BCAX/RAX1/XAR), PMULL (1Q) and CRC32. The ARM64 build uses the
// instructions (through intrinsics, in the usual idioms of crypto libraries);
// the x86-64 reference build computes the same values with portable code.

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#if defined(_M_ARM64)
#include <arm_acle.h>
#include <arm_neon.h>
#endif

static void print_hex(const char* label, const uint8_t* p, size_t n) {
  printf("%s ", label);
  for (size_t i = 0; i < n; ++i) printf("%02x", p[i]);
  printf("\n");
}

// --- AES-128 ----------------------------------------------------------------------------

static uint8_t gmul(uint8_t a, uint8_t b) {
  uint8_t r = 0;
  while (b) {
    if (b & 1) r ^= a;
    a = (uint8_t)((a << 1) ^ ((a & 0x80) ? 0x1B : 0));
    b >>= 1;
  }
  return r;
}

static uint8_t sbox[256], inv_sbox[256];

static void make_sbox(void) {
  for (int x = 0; x < 256; ++x) {
    uint8_t inv = 0;
    for (int y = 1; x && y < 256; ++y)
      if (gmul((uint8_t)x, (uint8_t)y) == 1) inv = (uint8_t)y;
    uint8_t s = inv;
    for (int k = 1; k <= 4; ++k) s ^= (uint8_t)((inv << k) | (inv >> (8 - k)));
    s ^= 0x63;
    sbox[x] = s;
    inv_sbox[s] = (uint8_t)x;
  }
}

static void key_expand(const uint8_t key[16], uint8_t rk[11][16]) {
  memcpy(rk[0], key, 16);
  uint8_t rcon = 1;
  for (int r = 1; r <= 10; ++r) {
    const uint8_t* p = rk[r - 1];
    uint8_t t[4] = {sbox[p[13]], sbox[p[14]], sbox[p[15]], sbox[p[12]]};
    t[0] ^= rcon;
    rcon = gmul(rcon, 2);
    for (int i = 0; i < 4; ++i) rk[r][i] = p[i] ^ t[i];
    for (int i = 4; i < 16; ++i) rk[r][i] = p[i] ^ rk[r][i - 4];
  }
}

#if defined(_M_ARM64)
static void aes_encrypt(uint8_t rk[11][16], const uint8_t in[16], uint8_t out[16]) {
  uint8x16_t b = vld1q_u8(in);
  for (int r = 0; r < 9; ++r) b = vaesmcq_u8(vaeseq_u8(b, vld1q_u8(rk[r])));
  b = vaeseq_u8(b, vld1q_u8(rk[9]));
  b = veorq_u8(b, vld1q_u8(rk[10]));
  vst1q_u8(out, b);
}

static void aes_decrypt(uint8_t rk[11][16], const uint8_t in[16], uint8_t out[16]) {
  uint8x16_t dk[11];
  dk[0] = vld1q_u8(rk[10]);
  for (int i = 1; i < 10; ++i) dk[i] = vaesimcq_u8(vld1q_u8(rk[10 - i]));
  dk[10] = vld1q_u8(rk[0]);
  uint8x16_t b = vld1q_u8(in);
  for (int r = 0; r < 9; ++r) b = vaesimcq_u8(vaesdq_u8(b, dk[r]));
  b = vaesdq_u8(b, dk[9]);
  b = veorq_u8(b, dk[10]);
  vst1q_u8(out, b);
}
#else
static void mix(uint8_t s[16], const uint8_t m[4]) {
  for (int c = 0; c < 4; ++c) {
    uint8_t col[4], out[4];
    memcpy(col, s + 4 * c, 4);
    for (int r = 0; r < 4; ++r) {
      out[r] = 0;
      for (int k = 0; k < 4; ++k) out[r] ^= gmul(col[(r + k) % 4], m[k]);
    }
    memcpy(s + 4 * c, out, 4);
  }
}

static void aes_encrypt(uint8_t rk[11][16], const uint8_t in[16], uint8_t out[16]) {
  static const uint8_t shift[16] = {0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11};
  static const uint8_t m[4] = {2, 3, 1, 1};
  uint8_t s[16], t[16];
  for (int i = 0; i < 16; ++i) s[i] = in[i] ^ rk[0][i];
  for (int r = 1; r <= 10; ++r) {
    for (int i = 0; i < 16; ++i) t[i] = sbox[s[shift[i]]];
    if (r < 10) mix(t, m);
    for (int i = 0; i < 16; ++i) s[i] = t[i] ^ rk[r][i];
  }
  memcpy(out, s, 16);
}

static void aes_decrypt(uint8_t rk[11][16], const uint8_t in[16], uint8_t out[16]) {
  static const uint8_t inv_shift[16] = {0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3};
  static const uint8_t m[4] = {14, 11, 13, 9};
  uint8_t s[16], t[16];
  for (int i = 0; i < 16; ++i) s[i] = in[i] ^ rk[10][i];
  for (int r = 9; r >= 0; --r) {
    for (int i = 0; i < 16; ++i) t[i] = inv_sbox[s[inv_shift[i]]];
    for (int i = 0; i < 16; ++i) t[i] ^= rk[r][i];
    if (r > 0) mix(t, m);
    memcpy(s, t, 16);
  }
  memcpy(out, s, 16);
}
#endif

// --- SHA-1 / SHA-256 / SHA-512 (one-shot, message fits in memory) -----------------------------

static size_t pad(const uint8_t* msg, size_t len, uint8_t* out, size_t block, size_t length_bytes) {
  size_t total = ((len + 1 + length_bytes + block - 1) / block) * block;
  memset(out, 0, total);
  memcpy(out, msg, len);
  out[len] = 0x80;
  uint64_t bits = (uint64_t)len * 8;
  for (int i = 0; i < 8; ++i) out[total - 1 - i] = (uint8_t)(bits >> (8 * i));
  return total;
}

static const uint32_t K256[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98,
    0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8,
    0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
    0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
    0xc67178f2};

static const uint64_t K512[80] = {
    0x428a2f98d728ae22ull, 0x7137449123ef65cdull, 0xb5c0fbcfec4d3b2full, 0xe9b5dba58189dbbcull, 0x3956c25bf348b538ull,
    0x59f111f1b605d019ull, 0x923f82a4af194f9bull, 0xab1c5ed5da6d8118ull, 0xd807aa98a3030242ull, 0x12835b0145706fbeull,
    0x243185be4ee4b28cull, 0x550c7dc3d5ffb4e2ull, 0x72be5d74f27b896full, 0x80deb1fe3b1696b1ull, 0x9bdc06a725c71235ull,
    0xc19bf174cf692694ull, 0xe49b69c19ef14ad2ull, 0xefbe4786384f25e3ull, 0x0fc19dc68b8cd5b5ull, 0x240ca1cc77ac9c65ull,
    0x2de92c6f592b0275ull, 0x4a7484aa6ea6e483ull, 0x5cb0a9dcbd41fbd4ull, 0x76f988da831153b5ull, 0x983e5152ee66dfabull,
    0xa831c66d2db43210ull, 0xb00327c898fb213full, 0xbf597fc7beef0ee4ull, 0xc6e00bf33da88fc2ull, 0xd5a79147930aa725ull,
    0x06ca6351e003826full, 0x142929670a0e6e70ull, 0x27b70a8546d22ffcull, 0x2e1b21385c26c926ull, 0x4d2c6dfc5ac42aedull,
    0x53380d139d95b3dfull, 0x650a73548baf63deull, 0x766a0abb3c77b2a8ull, 0x81c2c92e47edaee6ull, 0x92722c851482353bull,
    0xa2bfe8a14cf10364ull, 0xa81a664bbc423001ull, 0xc24b8b70d0f89791ull, 0xc76c51a30654be30ull, 0xd192e819d6ef5218ull,
    0xd69906245565a910ull, 0xf40e35855771202aull, 0x106aa07032bbd1b8ull, 0x19a4c116b8d2d0c8ull, 0x1e376c085141ab53ull,
    0x2748774cdf8eeb99ull, 0x34b0bcb5e19b48a8ull, 0x391c0cb3c5c95a63ull, 0x4ed8aa4ae3418acbull, 0x5b9cca4f7763e373ull,
    0x682e6ff3d6b2b8a3ull, 0x748f82ee5defb2fcull, 0x78a5636f43172f60ull, 0x84c87814a1f0ab72ull, 0x8cc702081a6439ecull,
    0x90befffa23631e28ull, 0xa4506cebde82bde9ull, 0xbef9a3f7b2c67915ull, 0xc67178f2e372532bull, 0xca273eceea26619cull,
    0xd186b8c721c0c207ull, 0xeada7dd6cde0eb1eull, 0xf57d4f7fee6ed178ull, 0x06f067aa72176fbaull, 0x0a637dc5a2c898a6ull,
    0x113f9804bef90daeull, 0x1b710b35131c471bull, 0x28db77f523047d84ull, 0x32caab7b40c72493ull, 0x3c9ebe0a15c9bebcull,
    0x431d67c49c100d4cull, 0x4cc5d4becb3e42b6ull, 0x597f299cfc657e2aull, 0x5fcb6fab3ad6faecull, 0x6c44198c4a475817ull};

static uint32_t be32(const uint8_t* p) { return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3]; }
static uint64_t be64(const uint8_t* p) { return (uint64_t)be32(p) << 32 | be32(p + 4); }

#if defined(_M_ARM64)
static void sha1_blocks(uint32_t h[5], const uint8_t* p, size_t blocks) {
  static const uint32_t K[4] = {0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6};
  uint32x4_t abcd = vld1q_u32(h);
  uint32_t e0 = h[4];
  for (; blocks--; p += 64) {
    const uint32x4_t abcd_saved = abcd;
    const uint32_t e_saved = e0;
    uint32x4_t m[4];
    for (int i = 0; i < 4; ++i) m[i] = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(p + 16 * i)));
    for (int i = 0; i < 20; ++i) {
      const uint32x4_t wk = vaddq_u32(m[i & 3], vdupq_n_u32(K[i / 5]));
      const uint32_t e1 = vsha1h_u32(vgetq_lane_u32(abcd, 0));
      if (i < 5) abcd = vsha1cq_u32(abcd, e0, wk);
      else if (i < 10 || i >= 15) abcd = vsha1pq_u32(abcd, e0, wk);
      else abcd = vsha1mq_u32(abcd, e0, wk);
      e0 = e1;
      if (i < 16) m[i & 3] = vsha1su1q_u32(vsha1su0q_u32(m[i & 3], m[(i + 1) & 3], m[(i + 2) & 3]), m[(i + 3) & 3]);
    }
    abcd = vaddq_u32(abcd, abcd_saved);
    e0 += e_saved;
  }
  vst1q_u32(h, abcd);
  h[4] = e0;
}

static void sha256_blocks(uint32_t h[8], const uint8_t* p, size_t blocks) {
  uint32x4_t s0 = vld1q_u32(h), s1 = vld1q_u32(h + 4);
  for (; blocks--; p += 64) {
    const uint32x4_t s0_saved = s0, s1_saved = s1;
    uint32x4_t m[4];
    for (int i = 0; i < 4; ++i) m[i] = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(p + 16 * i)));
    for (int i = 0; i < 16; ++i) {
      const uint32x4_t wk = vaddq_u32(m[i & 3], vld1q_u32(K256 + 4 * i));
      const uint32x4_t abcd = s0;
      s0 = vsha256hq_u32(s0, s1, wk);
      s1 = vsha256h2q_u32(s1, abcd, wk);
      if (i < 12) m[i & 3] = vsha256su1q_u32(vsha256su0q_u32(m[i & 3], m[(i + 1) & 3]), m[(i + 2) & 3], m[(i + 3) & 3]);
    }
    s0 = vaddq_u32(s0, s0_saved);
    s1 = vaddq_u32(s1, s1_saved);
  }
  vst1q_u32(h, s0);
  vst1q_u32(h + 4, s1);
}

// The structure of the Linux kernel's sha512-ce: two rounds per step, the
// state in five registers whose roles rotate.
static void sha512_blocks(uint64_t h[8], const uint8_t* p, size_t blocks) {
  uint64x2_t st[4];
  for (int i = 0; i < 4; ++i) st[i] = vld1q_u64(h + 2 * i);  // ab, cd, ef, gh
  for (; blocks--; p += 128) {
    uint64x2_t v[5] = {st[0], st[1], st[2], st[3], vdupq_n_u64(0)};
    uint64x2_t w[8];
    for (int i = 0; i < 8; ++i) w[i] = vreinterpretq_u64_u8(vrev64q_u8(vld1q_u8(p + 16 * i)));
    int r[5] = {0, 1, 2, 3, 4};
    for (int k = 0; k < 40; ++k) {
      const int i0 = r[0], i1 = r[1], i2 = r[2], i3 = r[3], i4 = r[4];
      const int in0 = k & 7;
      uint64x2_t t5 = vaddq_u64(vld1q_u64(K512 + 2 * k), w[in0]);
      const uint64x2_t t6 = vextq_u64(v[i2], v[i3], 1);
      t5 = vextq_u64(t5, t5, 1);
      const uint64x2_t t7 = vextq_u64(v[i1], v[i2], 1);
      v[i3] = vaddq_u64(v[i3], t5);
      if (k < 32) {
        t5 = vextq_u64(w[(in0 + 4) & 7], w[(in0 + 5) & 7], 1);
        w[in0] = vsha512su0q_u64(w[in0], w[(in0 + 1) & 7]);
      }
      v[i3] = vsha512hq_u64(v[i3], t6, t7);
      if (k < 32) w[in0] = vsha512su1q_u64(w[in0], w[(in0 + 7) & 7], t5);
      v[i4] = vaddq_u64(v[i1], v[i3]);
      v[i3] = vsha512h2q_u64(v[i3], v[i1], v[i0]);
      const int next[5] = {i3, i0, i4, i2, i1};
      memcpy(r, next, sizeof(r));
    }
    for (int i = 0; i < 4; ++i) st[i] = vaddq_u64(st[i], v[r[i]]);
  }
  for (int i = 0; i < 4; ++i) vst1q_u64(h + 2 * i, st[i]);
}
#else
#define ROL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#define ROR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define ROR64(x, n) (((x) >> (n)) | ((x) << (64 - (n))))

static void sha1_blocks(uint32_t h[5], const uint8_t* p, size_t blocks) {
  for (; blocks--; p += 64) {
    uint32_t w[80];
    for (int i = 0; i < 16; ++i) w[i] = be32(p + 4 * i);
    for (int i = 16; i < 80; ++i) w[i] = ROL32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];
    for (int i = 0; i < 80; ++i) {
      uint32_t f, k;
      if (i < 20) f = (b & c) | (~b & d), k = 0x5a827999;
      else if (i < 40) f = b ^ c ^ d, k = 0x6ed9eba1;
      else if (i < 60) f = (b & c) | (b & d) | (c & d), k = 0x8f1bbcdc;
      else f = b ^ c ^ d, k = 0xca62c1d6;
      uint32_t t = ROL32(a, 5) + f + e + k + w[i];
      e = d, d = c, c = ROL32(b, 30), b = a, a = t;
    }
    h[0] += a, h[1] += b, h[2] += c, h[3] += d, h[4] += e;
  }
}

static void sha256_blocks(uint32_t h[8], const uint8_t* p, size_t blocks) {
  for (; blocks--; p += 64) {
    uint32_t w[64];
    for (int i = 0; i < 16; ++i) w[i] = be32(p + 4 * i);
    for (int i = 16; i < 64; ++i) {
      uint32_t s0 = ROR32(w[i - 15], 7) ^ ROR32(w[i - 15], 18) ^ (w[i - 15] >> 3);
      uint32_t s1 = ROR32(w[i - 2], 17) ^ ROR32(w[i - 2], 19) ^ (w[i - 2] >> 10);
      w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
    for (int i = 0; i < 64; ++i) {
      uint32_t t1 = hh + (ROR32(e, 6) ^ ROR32(e, 11) ^ ROR32(e, 25)) + ((e & f) ^ (~e & g)) + K256[i] + w[i];
      uint32_t t2 = (ROR32(a, 2) ^ ROR32(a, 13) ^ ROR32(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
      hh = g, g = f, f = e, e = d + t1, d = c, c = b, b = a, a = t1 + t2;
    }
    h[0] += a, h[1] += b, h[2] += c, h[3] += d, h[4] += e, h[5] += f, h[6] += g, h[7] += hh;
  }
}

static void sha512_blocks(uint64_t h[8], const uint8_t* p, size_t blocks) {
  for (; blocks--; p += 128) {
    uint64_t w[80];
    for (int i = 0; i < 16; ++i) w[i] = be64(p + 8 * i);
    for (int i = 16; i < 80; ++i) {
      uint64_t s0 = ROR64(w[i - 15], 1) ^ ROR64(w[i - 15], 8) ^ (w[i - 15] >> 7);
      uint64_t s1 = ROR64(w[i - 2], 19) ^ ROR64(w[i - 2], 61) ^ (w[i - 2] >> 6);
      w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint64_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
    for (int i = 0; i < 80; ++i) {
      uint64_t t1 = hh + (ROR64(e, 14) ^ ROR64(e, 18) ^ ROR64(e, 41)) + ((e & f) ^ (~e & g)) + K512[i] + w[i];
      uint64_t t2 = (ROR64(a, 28) ^ ROR64(a, 34) ^ ROR64(a, 39)) + ((a & b) ^ (a & c) ^ (b & c));
      hh = g, g = f, f = e, e = d + t1, d = c, c = b, b = a, a = t1 + t2;
    }
    h[0] += a, h[1] += b, h[2] += c, h[3] += d, h[4] += e, h[5] += f, h[6] += g, h[7] += hh;
  }
}
#endif

static uint8_t padded[2048];

static void sha1(const uint8_t* msg, size_t len) {
  uint32_t h[5] = {0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0};
  sha1_blocks(h, padded, pad(msg, len, padded, 64, 8) / 64);
  uint8_t out[20];
  for (int i = 0; i < 20; ++i) out[i] = (uint8_t)(h[i / 4] >> (24 - 8 * (i % 4)));
  print_hex("sha1  ", out, 20);
}

static void sha256(const uint8_t* msg, size_t len) {
  uint32_t h[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
  sha256_blocks(h, padded, pad(msg, len, padded, 64, 8) / 64);
  uint8_t out[32];
  for (int i = 0; i < 32; ++i) out[i] = (uint8_t)(h[i / 4] >> (24 - 8 * (i % 4)));
  print_hex("sha256", out, 32);
}

static void sha512(const uint8_t* msg, size_t len) {
  uint64_t h[8] = {0x6a09e667f3bcc908ull, 0xbb67ae8584caa73bull, 0x3c6ef372fe94f82bull, 0xa54ff53a5f1d36f1ull,
                   0x510e527fade682d1ull, 0x9b05688c2b3e6c1full, 0x1f83d9abfb41bd6bull, 0x5be0cd19137e2179ull};
  sha512_blocks(h, padded, pad(msg, len, padded, 128, 16) / 128);
  uint8_t out[64];
  for (int i = 0; i < 64; ++i) out[i] = (uint8_t)(h[i / 8] >> (56 - 8 * (i % 8)));
  print_hex("sha512", out, 64);
}

// --- CRC32, PMULL, SHA-3 helpers ---------------------------------------------------------------

static uint32_t crc32_bytes(const uint8_t* p, size_t n, int castagnoli) {
  uint32_t crc = 0xFFFFFFFFu;
#if defined(_M_ARM64)
  size_t i = 0;
  for (; i + 8 <= n; i += 8) {
    uint64_t v;
    memcpy(&v, p + i, 8);
    crc = castagnoli ? __crc32cd(crc, v) : __crc32d(crc, v);
  }
  if (i + 4 <= n) {
    uint32_t v;
    memcpy(&v, p + i, 4);
    crc = castagnoli ? __crc32cw(crc, v) : __crc32w(crc, v);
    i += 4;
  }
  if (i + 2 <= n) {
    uint16_t v;
    memcpy(&v, p + i, 2);
    crc = castagnoli ? __crc32ch(crc, v) : __crc32h(crc, v);
    i += 2;
  }
  for (; i < n; ++i) crc = castagnoli ? __crc32cb(crc, p[i]) : __crc32b(crc, p[i]);
#else
  const uint32_t poly = castagnoli ? 0x82F63B78u : 0xEDB88320u;
  for (size_t i = 0; i < n; ++i) {
    crc ^= p[i];
    for (int k = 0; k < 8; ++k) crc = (crc >> 1) ^ ((crc & 1) ? poly : 0);
  }
#endif
  return ~crc;
}

static void pmull(uint64_t a, uint64_t b, uint64_t out[2]) {
#if defined(_M_ARM64)
  poly128_t r = vmull_p64((poly64_t)a, (poly64_t)b);
  memcpy(out, &r, 16);
#else
  out[0] = out[1] = 0;
  for (int k = 0; k < 64; ++k)
    if ((b >> k) & 1) {
      out[0] ^= a << k;
      if (k) out[1] ^= a >> (64 - k);
    }
#endif
}

static void sha3_ops(const uint64_t a[2], const uint64_t b[2], const uint64_t c[2], uint64_t out[4][2]) {
#if defined(_M_ARM64)
  const uint64x2_t va = vld1q_u64(a), vb = vld1q_u64(b), vc = vld1q_u64(c);
  vst1q_u64(out[0], veor3q_u64(va, vb, vc));
  vst1q_u64(out[1], vbcaxq_u64(va, vb, vc));
  vst1q_u64(out[2], vrax1q_u64(va, vb));
  vst1q_u64(out[3], vxarq_u64(va, vb, 13));
  // PMULL2: the high halves
  poly128_t r = vmull_high_p64(vreinterpretq_p64_u64(va), vreinterpretq_p64_u64(vb));
  uint64_t hi[2];
  memcpy(hi, &r, 16);
  printf("pmull2 %016llx%016llx\n", (unsigned long long)hi[1], (unsigned long long)hi[0]);
#else
  for (int i = 0; i < 2; ++i) {
    out[0][i] = a[i] ^ b[i] ^ c[i];
    out[1][i] = a[i] ^ (b[i] & ~c[i]);
    out[2][i] = a[i] ^ ((b[i] << 1) | (b[i] >> 63));
    const uint64_t x = a[i] ^ b[i];
    out[3][i] = (x >> 13) | (x << 51);
  }
  uint64_t hi[2];
  pmull(a[1], b[1], hi);
  printf("pmull2 %016llx%016llx\n", (unsigned long long)hi[1], (unsigned long long)hi[0]);
#endif
}

int main(void) {
  make_sbox();

  // FIPS-197 appendix C.1
  uint8_t key[16], pt[16], ct[16], back[16], rk[11][16];
  for (int i = 0; i < 16; ++i) key[i] = (uint8_t)i, pt[i] = (uint8_t)(i * 0x11);
  key_expand(key, rk);
  aes_encrypt(rk, pt, ct);
  aes_decrypt(rk, ct, back);
  print_hex("aes ct", ct, 16);
  print_hex("aes pt", back, 16);
  // A few more blocks with a different key, chained
  for (int i = 0; i < 16; ++i) key[i] = (uint8_t)(0xA5 ^ (i * 37));
  key_expand(key, rk);
  for (int n = 0; n < 100; ++n) aes_encrypt(rk, ct, ct);
  print_hex("aes x100", ct, 16);
  for (int n = 0; n < 100; ++n) aes_decrypt(rk, ct, ct);
  print_hex("aes back", ct, 16);

  static uint8_t msg[1000];
  for (int i = 0; i < 1000; ++i) msg[i] = (uint8_t)(i * 7 + 3);
  const uint8_t abc[] = "abc";
  sha1(abc, 3);
  sha1(msg, 1000);
  sha256(abc, 3);
  sha256(msg, 1000);
  sha512(abc, 3);
  sha512(msg, 1000);

  const uint8_t digits[] = "123456789";
  printf("crc32  %08x %08x\n", crc32_bytes(digits, 9, 0), crc32_bytes(msg, 1000, 0));
  printf("crc32c %08x %08x\n", crc32_bytes(digits, 9, 1), crc32_bytes(msg, 1000, 1));

  uint64_t prod[2];
  pmull(0x87654321fedcba98ull, 0xf0e1d2c3b4a59687ull, prod);
  printf("pmull  %016llx%016llx\n", (unsigned long long)prod[1], (unsigned long long)prod[0]);
  const uint64_t a[2] = {0x0123456789abcdefull, 0xfedcba9876543210ull};
  const uint64_t b[2] = {0xdeadbeefcafebabeull, 0x8000000000000001ull};
  const uint64_t c[2] = {0x5555aaaa3333ccccull, 0x0f0f0f0ff0f0f0f0ull};
  uint64_t out[4][2];
  sha3_ops(a, b, c, out);
  static const char* names[4] = {"eor3", "bcax", "rax1", "xar"};
  for (int i = 0; i < 4; ++i)
    printf("%-6s %016llx %016llx\n", names[i], (unsigned long long)out[i][0], (unsigned long long)out[i][1]);
  return 0;
}
