/* Minimal freestanding runtime for JUICE guest test programs.
 *
 * Each test program is compiled twice - for ARM64 (run under JUICE) and for
 * x86-64 (run natively as the reference) - and the outputs are compared, so
 * programs must be deterministic and avoid implementation-defined behaviour.
 * No C runtime is linked; output goes straight to WriteFile. */
#pragma once

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef unsigned long long u64;
typedef long long i64;
typedef unsigned int u32;
typedef int i32;

#pragma function(memset)
#pragma function(memcpy)
#pragma function(memcmp)
#pragma function(strlen)

#ifdef __clang__
#pragma clang diagnostic ignored "-Wunused-function"
#endif

void* memset(void* dst, int c, size_t n) {
  volatile unsigned char* p = (volatile unsigned char*)dst;
  while (n--) *p++ = (unsigned char)c;
  return dst;
}

void* memcpy(void* dst, const void* src, size_t n) {
  volatile unsigned char* d = (volatile unsigned char*)dst;
  const volatile unsigned char* s = (const volatile unsigned char*)src;
  while (n--) *d++ = *s++;
  return dst;
}

int memcmp(const void* a, const void* b, size_t n) {
  const volatile unsigned char* x = (const volatile unsigned char*)a;
  const volatile unsigned char* y = (const volatile unsigned char*)b;
  for (; n; --n, ++x, ++y)
    if (*x != *y) return *x < *y ? -1 : 1;
  return 0;
}

size_t strlen(const char* s) {
  const volatile char* p = s;
  while (*p) ++p;
  return (size_t)(p - s);
}

static char out_buf[4096];
static unsigned out_len;

static void flush(void) {
  DWORD written;
  if (out_len) WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), out_buf, out_len, &written, NULL);
  out_len = 0;
}

static void put_char(char c) {
  if (out_len == sizeof(out_buf)) flush();
  out_buf[out_len++] = c;
}

static void put_str(const char* s) {
  while (*s) put_char(*s++);
}

static void put_u64(u64 v) {
  char tmp[24];
  int n = 0;
  do {
    tmp[n++] = (char)('0' + v % 10);
    v /= 10;
  } while (v);
  while (n) put_char(tmp[--n]);
}

static void put_i64(i64 v) {
  if (v < 0) {
    put_char('-');
    put_u64(0 - (u64)v);
  } else {
    put_u64((u64)v);
  }
}

static void put_hex(u64 v) {
  static const char digits[] = "0123456789abcdef";
  put_str("0x");
  for (int shift = 60; shift >= 0; shift -= 4) put_char(digits[(v >> shift) & 15]);
}

static void line(const char* label, u64 v) {
  put_str(label);
  put_str(" = ");
  put_hex(v);
  put_char('\n');
}

static void line_i(const char* label, i64 v) {
  put_str(label);
  put_str(" = ");
  put_i64(v);
  put_char('\n');
}

/* Deterministic pseudo-random numbers (xorshift64*). */
static u64 rng_state = 0x9E3779B97F4A7C15ull;
static u64 rng(void) {
  rng_state ^= rng_state >> 12;
  rng_state ^= rng_state << 25;
  rng_state ^= rng_state >> 27;
  return rng_state * 0x2545F4914F6CDD1Dull;
}

/* Prevents the compiler from constant-folding test inputs. */
static u64 opaque(u64 v) {
  volatile u64 x = v;
  return x;
}

static __declspec(noreturn) void finish(int code) {
  flush();
  ExitProcess((UINT)code);
}

#ifdef __cplusplus
}
#endif
