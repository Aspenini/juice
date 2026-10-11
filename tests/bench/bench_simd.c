/* Loops the compiler vectorizes (Advanced SIMD on ARM64): saxpy, a dot
 * product, a byte histogram-free checksum and a small matrix multiply. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define N 4096

static float a[N], b[N], c[N];
static uint8_t bytes[1 << 20];
static float m1[128][128], m2[128][128], m3[128][128];

int main(void) {
  for (int i = 0; i < N; ++i) {
    a[i] = (float)(i % 97) * 0.25f;
    b[i] = (float)(i % 89) * 0.5f;
  }
  for (int i = 0; i < (1 << 20); ++i) bytes[i] = (uint8_t)(i * 2654435761u >> 24);
  for (int i = 0; i < 128; ++i)
    for (int j = 0; j < 128; ++j) {
      m1[i][j] = (float)((i + j) % 7);
      m2[i][j] = (float)((i * j) % 5);
    }

  double dot_total = 0;
  for (int round = 0; round < 3000; ++round) {
    const float k = (float)(round % 3) * 0.5f;
    for (int i = 0; i < N; ++i) c[i] = k * a[i] + b[i];
    float dot = 0;
    for (int i = 0; i < N; ++i) dot += c[i] * a[i];
    dot_total += dot;
  }
  printf("saxpy/dot %.3f\n", dot_total);

  uint64_t sum = 0;
  for (int round = 0; round < 200; ++round) {
    uint32_t s = 0;
    for (int i = 0; i < (1 << 20); ++i) s += bytes[i] ^ (uint8_t)round;
    sum += s;
  }
  printf("bytes %llu\n", (unsigned long long)sum);

  for (int round = 0; round < 20; ++round)
    for (int i = 0; i < 128; ++i)
      for (int j = 0; j < 128; ++j) {
        float acc = 0;
        for (int k = 0; k < 128; ++k) acc += m1[i][k] * m2[k][j];
        m3[i][j] = acc + (float)round;
      }
  double trace = 0;
  for (int i = 0; i < 128; ++i) trace += m3[i][i];
  printf("matmul %.1f\n", trace);
  return 0;
}
