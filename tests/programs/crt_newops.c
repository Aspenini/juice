// Newer base instructions: memory copy/set (MOPS), 128-bit atomics (LSE128),
// CSSC (ABS, CNT, CTZ, SMAX/UMIN...), RCPC3 loads and stores, pointer
// authentication (PAC* / AUT* / LDRAA, not modelled: pointers pass through)
// and WFET. The ARM64 build uses inline assembly; the x86-64 reference
// computes the same values in C.

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static uint8_t src[300], dst[300];

static void dump(const char* label, const uint8_t* p, size_t n) {
  uint32_t h = 2166136261u;  // FNV-1a over the bytes
  for (size_t i = 0; i < n; ++i) h = (h ^ p[i]) * 16777619u;
  printf("%-10s %08x %02x %02x %02x\n", label, h, p[0], p[n / 2], p[n - 1]);
}

static void mops(void) {
  for (int i = 0; i < 300; ++i) src[i] = (uint8_t)(i * 7 + 1), dst[i] = 0xEE;
  uint64_t d = (uint64_t)(dst + 3), s = (uint64_t)(src + 5), n = 200;
#if defined(_M_ARM64)
  __asm__ volatile("cpyfp [%0]!, [%1]!, %2!\n cpyfm [%0]!, [%1]!, %2!\n cpyfe [%0]!, [%1]!, %2!"
                   : "+r"(d), "+r"(s), "+r"(n)
                   :
                   : "memory", "cc");
#else
  memcpy(dst + 3, src + 5, 200);
  d += 200, s += 200, n = 0;
#endif
  printf("cpyf       d+%lld s+%lld n=%llu\n", (long long)(d - (uint64_t)dst), (long long)(s - (uint64_t)src),
         (unsigned long long)n);
  dump("cpyf", dst, 300);

  // overlapping copy (memmove semantics)
  d = (uint64_t)(src + 10), s = (uint64_t)src, n = 150;
#if defined(_M_ARM64)
  __asm__ volatile("cpyp [%0]!, [%1]!, %2!\n cpym [%0]!, [%1]!, %2!\n cpye [%0]!, [%1]!, %2!"
                   : "+r"(d), "+r"(s), "+r"(n)
                   :
                   : "memory", "cc");
#else
  memmove(src + 10, src, 150);
  d += 150, s += 150, n = 0;
#endif
  dump("cpy", src, 300);

  uint64_t value = 0x1234AB;
  d = (uint64_t)(dst + 50), n = 77;
#if defined(_M_ARM64)
  __asm__ volatile("setp [%0]!, %1!, %2\n setm [%0]!, %1!, %2\n sete [%0]!, %1!, %2"
                   : "+r"(d), "+r"(n)
                   : "r"(value)
                   : "memory", "cc");
#else
  memset(dst + 50, 0xAB, 77);
  d += 77, n = 0;
#endif
  printf("set        d+%lld n=%llu\n", (long long)(d - (uint64_t)dst), (unsigned long long)n);
  dump("set", dst, 300);
}

static uint64_t cell[2] __attribute__((aligned(16)));

static void lse128(void) {
  cell[0] = 0xF0F0F0F0F0F0F0F0ull, cell[1] = 0x0123456789ABCDEFull;
  uint64_t lo = 0x00000000FFFF0000ull, hi = 0x8000000000000001ull;
#if defined(_M_ARM64)
  __asm__ volatile("ldsetpal %0, %1, [%2]" : "+r"(lo), "+r"(hi) : "r"(cell) : "memory");
#else
  {
    uint64_t o0 = cell[0], o1 = cell[1];
    cell[0] |= lo, cell[1] |= hi;
    lo = o0, hi = o1;
  }
#endif
  printf("ldsetp     old %016llx %016llx now %016llx %016llx\n", (unsigned long long)hi, (unsigned long long)lo,
         (unsigned long long)cell[1], (unsigned long long)cell[0]);
  lo = 0xFFFFFFFF00000000ull, hi = 0x00000000FFFFFFFFull;
#if defined(_M_ARM64)
  __asm__ volatile("ldclrp %0, %1, [%2]" : "+r"(lo), "+r"(hi) : "r"(cell) : "memory");
#else
  {
    uint64_t o0 = cell[0], o1 = cell[1];
    cell[0] &= ~lo, cell[1] &= ~hi;
    lo = o0, hi = o1;
  }
#endif
  printf("ldclrp     old %016llx %016llx now %016llx %016llx\n", (unsigned long long)hi, (unsigned long long)lo,
         (unsigned long long)cell[1], (unsigned long long)cell[0]);
  lo = 1, hi = 2;
#if defined(_M_ARM64)
  __asm__ volatile("swppl %0, %1, [%2]" : "+r"(lo), "+r"(hi) : "r"(cell) : "memory");
#else
  {
    uint64_t o0 = cell[0], o1 = cell[1];
    cell[0] = lo, cell[1] = hi;
    lo = o0, hi = o1;
  }
#endif
  printf("swpp       old %016llx %016llx now %016llx %016llx\n", (unsigned long long)hi, (unsigned long long)lo,
         (unsigned long long)cell[1], (unsigned long long)cell[0]);
}

static void cssc(void) {
  static const int64_t in[6] = {0, 1, -1, 0x7FFF0000, -0x123456789ALL, (int64_t)0x8000000000000000ull};
  for (int k = 0; k < 6; ++k) {
    volatile int64_t vx = in[k];
    const int64_t x = vx;
    uint64_t r[8];
#if defined(_M_ARM64)
    __asm__("abs %x0, %x8\n abs %w1, %w8\n cnt %x2, %x8\n cnt %w3, %w8\n ctz %x4, %x8\n ctz %w5, %w8\n"
            "smax %x6, %x8, #-5\n umin %w7, %w8, #200"
            : "=&r"(r[0]), "=&r"(r[1]), "=&r"(r[2]), "=&r"(r[3]), "=&r"(r[4]), "=&r"(r[5]), "=&r"(r[6]), "=&r"(r[7])
            : "r"(x));
#else
    const uint64_t u = (uint64_t)x;
    const uint32_t w = (uint32_t)u;
    r[0] = x < 0 ? 0 - u : u;
    r[1] = (int32_t)w < 0 ? (uint32_t)(0 - w) : w;
    r[2] = (uint64_t)__builtin_popcountll(u);
    r[3] = (uint64_t)__builtin_popcount(w);
    r[4] = u ? (uint64_t)__builtin_ctzll(u) : 64;
    r[5] = w ? (uint64_t)__builtin_ctz(w) : 32;
    r[6] = (uint64_t)(x > -5 ? x : -5);
    r[7] = w < 200 ? w : 200;
#endif
    printf("cssc      ");
    for (int i = 0; i < 8; ++i) printf(" %llx", (unsigned long long)r[i]);
    printf("\n");
  }
  uint64_t a = 12345, b = (uint64_t)-678, mx, mn;
#if defined(_M_ARM64)
  __asm__("smax %0, %2, %3\n umin %1, %2, %3" : "=&r"(mx), "=&r"(mn) : "r"(a), "r"(b));
#else
  mx = 12345, mn = 12345;
#endif
  printf("minmax     %llx %llx\n", (unsigned long long)mx, (unsigned long long)mn);
}

static uint64_t pair[4] = {0x1111111111111111ull, 0x2222222222222222ull, 0x3333333333333333ull, 0x4444444444444444ull};

static void rcpc3_and_pac(void) {
  uint64_t a, b, p = (uint64_t)pair, q;
#if defined(_M_ARM64)
  __asm__ volatile("ldiapp %0, %1, [%2]" : "=&r"(a), "=&r"(b) : "r"(p) : "memory");
#else
  a = pair[0], b = pair[1];
#endif
  printf("ldiapp     %llx %llx\n", (unsigned long long)a, (unsigned long long)b);
  q = (uint64_t)&pair[2];
#if defined(_M_ARM64)
  __asm__ volatile("ldapr %0, [%1], #8" : "=&r"(a), "+r"(q) : : "memory");
  __asm__ volatile("stilp %1, %2, [%0]" : : "r"(p), "r"(a + 1), "r"(b + 1) : "memory");
#else
  a = pair[2], q += 8;
  pair[0] = a + 1, pair[1] = b + 1;
#endif
  printf("ldapr      %llx +%lld %llx %llx\n", (unsigned long long)a, (long long)(q - (uint64_t)pair),
         (unsigned long long)pair[0], (unsigned long long)pair[1]);

  // Pointer authentication is not modelled: signing and authenticating leave pointers unchanged.
  uint64_t ptr = (uint64_t)&pair[3], mod = 42, loaded;
#if defined(_M_ARM64)
  __asm__ volatile("pacia %0, %2\n autia %0, %2\n xpaci %0\n pacdza %0\n autdza %0\n ldraa %1, [%0]\n wfet %2"
                   : "+r"(ptr), "=&r"(loaded)
                   : "r"(mod)
                   : "memory");
#else
  loaded = pair[3];
#endif
  printf("pac        %lld %llx\n", (long long)(ptr - (uint64_t)pair), (unsigned long long)loaded);
}

int main(void) {
  mops();
  lse128();
  cssc();
  rcpc3_and_pac();
  return 0;
}
