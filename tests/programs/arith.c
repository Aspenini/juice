/* Integer arithmetic, logic, shifts, multiplication, division, bit
 * manipulation and flag-setting comparisons over pseudo-random inputs. */
#include "juice_test.h"

#define NOINLINE __declspec(noinline)

NOINLINE u64 add64(u64 a, u64 b) { return a + b; }
NOINLINE u64 sub64(u64 a, u64 b) { return a - b; }
NOINLINE u32 add32(u32 a, u32 b) { return a + b; }
NOINLINE u32 sub32(u32 a, u32 b) { return a - b; }
NOINLINE u64 mul64(u64 a, u64 b) { return a * b; }
NOINLINE u32 mul32(u32 a, u32 b) { return a * b; }
NOINLINE u64 udiv64(u64 a, u64 b) { return a / b; }
NOINLINE u64 umod64(u64 a, u64 b) { return a % b; }
NOINLINE i64 sdiv64(i64 a, i64 b) { return a / b; }
NOINLINE i64 smod64(i64 a, i64 b) { return a % b; }
NOINLINE u32 udiv32(u32 a, u32 b) { return a / b; }
NOINLINE i32 sdiv32(i32 a, i32 b) { return a / b; }
NOINLINE u64 div10(u64 a) { return a / 10; }       /* multiply-high */
NOINLINE i64 sdiv7(i64 a) { return a / 7; }
NOINLINE u64 mulhi(u64 a, u64 b) { return (u64)(((unsigned __int128)a * b) >> 64); }
NOINLINE i64 smulhi(i64 a, i64 b) { return (i64)(((__int128)a * b) >> 64); }
NOINLINE u64 widen_mul(u32 a, u32 b) { return (u64)a * b; }
NOINLINE i64 widen_smul(i32 a, i32 b) { return (i64)a * b; }
NOINLINE u64 shl64(u64 a, unsigned s) { return a << (s & 63); }
NOINLINE u64 shr64(u64 a, unsigned s) { return a >> (s & 63); }
NOINLINE i64 sar64(i64 a, unsigned s) { return a >> (s & 63); }
NOINLINE u32 shl32(u32 a, unsigned s) { return a << (s & 31); }
NOINLINE u32 shr32(u32 a, unsigned s) { return a >> (s & 31); }
NOINLINE i32 sar32(i32 a, unsigned s) { return a >> (s & 31); }
NOINLINE u64 rotr64(u64 a, unsigned s) { s &= 63; return s ? (a >> s) | (a << (64 - s)) : a; }
NOINLINE u32 rotl32(u32 a, unsigned s) { s &= 31; return s ? (a << s) | (a >> (32 - s)) : a; }
NOINLINE u64 andnot(u64 a, u64 b) { return a & ~b; }
NOINLINE u64 ornot(u64 a, u64 b) { return a | ~b; }
NOINLINE u64 xnor(u64 a, u64 b) { return ~(a ^ b); }
NOINLINE u64 masks(u64 a) { return (a & 0xFF00FF00FF00FF00ull) | ((a | 0x0F0F) ^ 0x3333333333333333ull); }
NOINLINE u64 bfx(u64 a) { return (a >> 13) & 0x7FF; }
NOINLINE i64 sbfx(i64 a) { return (a << 20) >> 41; }
NOINLINE u64 bfi(u64 a, u64 b) { return (a & ~(0xFFull << 24)) | ((b & 0xFF) << 24); }
NOINLINE i64 sext8(u64 a) { return (signed char)a; }
NOINLINE i64 sext16(u64 a) { return (short)a; }
NOINLINE i64 sext32(u64 a) { return (int)a; }
NOINLINE u64 zext8(u64 a) { return (unsigned char)a; }
NOINLINE u64 zext16(u64 a) { return (unsigned short)a; }
NOINLINE u64 zext32(u64 a) { return (unsigned int)a; }
NOINLINE u64 clz64(u64 a) { return a ? (u64)__builtin_clzll(a) : 64; }
NOINLINE u64 ctz64(u64 a) { return a ? (u64)__builtin_ctzll(a) : 64; }
NOINLINE u32 clz32(u32 a) { return a ? (u32)__builtin_clz(a) : 32; }
NOINLINE u64 bswap64(u64 a) { return __builtin_bswap64(a); }
NOINLINE u32 bswap32(u32 a) { return __builtin_bswap32(a); }
NOINLINE u32 bswap16(u32 a) { return __builtin_bswap16((unsigned short)a); }
NOINLINE u64 bitrev(u64 a) { return __builtin_bitreverse64(a); }
NOINLINE u64 abs64(i64 a) { return a < 0 ? 0 - (u64)a : (u64)a; }
NOINLINE i64 max64(i64 a, i64 b) { return a > b ? a : b; }
NOINLINE u64 umin64(u64 a, u64 b) { return a < b ? a : b; }
NOINLINE u64 select_chain(u64 a, u64 b) { return a == b ? 1 : a < b ? 2 : (i64)a < (i64)b ? 3 : 4; }
NOINLINE u64 cinc(u64 a, u64 b) { return a + (a > b); }
NOINLINE u64 range_check(i64 a) { return a >= -100 && a <= 100; }

/* 128-bit arithmetic exercises ADDS/ADC and SUBS/SBC chains. */
NOINLINE unsigned __int128 add128(unsigned __int128 a, unsigned __int128 b) { return a + b; }
NOINLINE unsigned __int128 sub128(unsigned __int128 a, unsigned __int128 b) { return a - b; }
NOINLINE int lt128(__int128 a, __int128 b) { return a < b; }

NOINLINE int add_overflows(i64 a, i64 b) { i64 r; return __builtin_add_overflow(a, b, &r); }
NOINLINE int sub_overflows(i32 a, i32 b) { i32 r; return __builtin_sub_overflow(a, b, &r); }
NOINLINE int mul_overflows(u64 a, u64 b) { u64 r; return __builtin_mul_overflow(a, b, &r); }

static u64 checksum;
static void mix(u64 v) { checksum = (checksum ^ v) * 0x100000001B3ull; }

void mainCRTStartup(void) {
  /* Fixed edge cases. */
  line("add64 wrap", add64(opaque(~0ull), opaque(2)));
  line("sub64 wrap", sub64(opaque(1), opaque(3)));
  line("add32 wrap", add32((u32)opaque(0xFFFFFFF0u), (u32)opaque(0x20)));
  line("sdiv64 neg", (u64)sdiv64((i64)opaque((u64)-100), (i64)opaque(7)));
  line("smod64 neg", (u64)smod64((i64)opaque((u64)-100), (i64)opaque(7)));
  line("sdiv32 neg", (u64)(u32)sdiv32((i32)opaque((u64)-77), (i32)opaque(5)));
  line("udiv32", udiv32((u32)opaque(0xFFFFFFFFu), (u32)opaque(3)));
  line("div10", div10(opaque(1234567890123456789ull)));
  line("sdiv7", (u64)sdiv7((i64)opaque((u64)-1234567890123ll)));
  line("mulhi", mulhi(opaque(0xDEADBEEFCAFEBABEull), opaque(0x123456789ABCDEF0ull)));
  line("smulhi", (u64)smulhi((i64)opaque(0xDEADBEEFCAFEBABEull), (i64)opaque(0x123456789ABCDEF0ull)));
  line("widen_mul", widen_mul((u32)opaque(0xFFFFFFFF), (u32)opaque(0xFFFFFFFF)));
  line("widen_smul", (u64)widen_smul((i32)opaque((u64)-123456), (i32)opaque(654321)));
  line("clz64(1)", clz64(opaque(1)));
  line("clz64(0)", clz64(opaque(0)));
  line("ctz64", ctz64(opaque(0x8000)));
  line("clz32", clz32((u32)opaque(0x00F00000)));
  line("bswap64", bswap64(opaque(0x0102030405060708ull)));
  line("bswap32", bswap32((u32)opaque(0x01020304)));
  line("bswap16", bswap16((u32)opaque(0xAABB)));
  line("bitrev", bitrev(opaque(0x1ull)));
  line("sext8", (u64)sext8(opaque(0x80)));
  line("sext16", (u64)sext16(opaque(0x8001)));
  line("sext32", (u64)sext32(opaque(0x80000001)));
  line("abs64", abs64((i64)opaque((u64)-42)));
  line("add_overflows", (u64)add_overflows((i64)opaque(0x7FFFFFFFFFFFFFFFull), 1));
  line("sub_overflows", (u64)sub_overflows((i32)opaque(0x80000000u), 1));
  line("mul_overflows", (u64)mul_overflows(opaque(1ull << 33), opaque(1ull << 31)));
  {
    unsigned __int128 a = ((unsigned __int128)opaque(1) << 64) | opaque(~0ull);
    unsigned __int128 s = add128(a, opaque(1));
    line("add128 hi", (u64)(s >> 64));
    line("add128 lo", (u64)s);
    unsigned __int128 d = sub128(opaque(0), a);
    line("sub128 hi", (u64)(d >> 64));
    line("sub128 lo", (u64)d);
    line("lt128", (u64)lt128(-(__int128)opaque(5), (__int128)opaque(3)));
  }

  /* Randomized sweep. */
  for (int i = 0; i < 2000; ++i) {
    u64 a = rng(), b = rng();
    unsigned s = (unsigned)(rng() & 127);
    if (i % 7 == 0) b = a;
    if (i % 11 == 0) b &= 0xFF;
    if (i % 13 == 0) a = (u64)(i64)(i32)a;
    mix(add64(a, b));
    mix(sub64(a, b));
    mix(add32((u32)a, (u32)b));
    mix(sub32((u32)a, (u32)b));
    mix(mul64(a, b));
    mix(mul32((u32)a, (u32)b));
    if (b) {
      mix(udiv64(a, b));
      mix(umod64(a, b));
      if (!((i64)a == (-0x7FFFFFFFFFFFFFFFll - 1) && (i64)b == -1)) {
        mix((u64)sdiv64((i64)a, (i64)b));
        mix((u64)smod64((i64)a, (i64)b));
      }
    }
    if ((u32)b) mix(udiv32((u32)a, (u32)b));
    if ((i32)b != 0 && !((i32)a == (-0x7FFFFFFF - 1) && (i32)b == -1)) mix((u64)(u32)sdiv32((i32)a, (i32)b));
    mix(div10(a));
    mix((u64)sdiv7((i64)a));
    mix(mulhi(a, b));
    mix((u64)smulhi((i64)a, (i64)b));
    mix(widen_mul((u32)a, (u32)b));
    mix((u64)widen_smul((i32)a, (i32)b));
    mix(shl64(a, s));
    mix(shr64(a, s));
    mix((u64)sar64((i64)a, s));
    mix(shl32((u32)a, s));
    mix(shr32((u32)a, s));
    mix((u64)(u32)sar32((i32)a, s));
    mix(rotr64(a, s));
    mix(rotl32((u32)a, s));
    mix(andnot(a, b));
    mix(ornot(a, b));
    mix(xnor(a, b));
    mix(masks(a));
    mix(bfx(a));
    mix((u64)sbfx((i64)a));
    mix(bfi(a, b));
    mix((u64)sext8(a));
    mix((u64)sext16(a));
    mix((u64)sext32(a));
    mix(zext8(a));
    mix(zext16(a));
    mix(zext32(a));
    mix(clz64(a >> s % 64));
    mix(ctz64(a << s % 64));
    mix(clz32((u32)(a >> s % 64)));
    mix(bswap64(a));
    mix(bswap32((u32)a));
    mix(bswap16((u32)a));
    mix(bitrev(a));
    mix(abs64((i64)a));
    mix((u64)max64((i64)a, (i64)b));
    mix(umin64(a, b));
    mix(select_chain(a, b));
    mix(cinc(a, b));
    mix(range_check((i64)(a % 400) - 200));
    mix((u64)add_overflows((i64)a, (i64)b));
    mix((u64)sub_overflows((i32)a, (i32)b));
    mix((u64)mul_overflows(a >> (s % 64), b >> (s % 64)));
    {
      unsigned __int128 x = ((unsigned __int128)a << 64) | b, y = ((unsigned __int128)b << 64) | a;
      unsigned __int128 r1 = add128(x, y), r2 = sub128(x, y);
      mix((u64)r1);
      mix((u64)(r1 >> 64));
      mix((u64)r2);
      mix((u64)(r2 >> 64));
      mix((u64)lt128((__int128)x, (__int128)y));
    }
  }
  line("checksum", checksum);
  finish(0);
}
