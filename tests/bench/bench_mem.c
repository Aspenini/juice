/* Memory and string work: copies, a byte-wise CRC-32, string building and
 * searching, and pointer chasing through a shuffled list. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint32_t crc_table[256];

static uint32_t crc32(const uint8_t* p, size_t n, uint32_t crc) {
  crc = ~crc;
  while (n--) crc = crc_table[(crc ^ *p++) & 0xFF] ^ (crc >> 8);
  return ~crc;
}

int main(void) {
  for (uint32_t i = 0; i < 256; ++i) {
    uint32_t c = i;
    for (int k = 0; k < 8; ++k) c = (c & 1) ? 0xEDB88320u ^ (c >> 1) : c >> 1;
    crc_table[i] = c;
  }

  const size_t size = 8 << 20;
  uint8_t* src = malloc(size);
  uint8_t* dst = malloc(size);
  for (size_t i = 0; i < size; ++i) src[i] = (uint8_t)(i * 31 + (i >> 9));
  uint32_t crc = 0;
  for (int round = 0; round < 20; ++round) {
    memcpy(dst, src + round, size - 64);
    memmove(dst + 1, dst, size - 128);
    crc ^= crc32(dst + round * 1000, 1 << 20, (uint32_t)round);
  }
  printf("copy/crc %08x\n", crc);

  char* text = malloc(4 << 20);
  size_t len = 0;
  for (int i = 0; len < (4 << 20) - 64; ++i) len += (size_t)sprintf(text + len, "word%d ", i % 9973);
  size_t found = 0;
  for (const char* p = text; (p = strstr(p, "word997 ")) != NULL; ++p) ++found;
  printf("strings %zu %zu\n", len, found);

  const size_t nodes = 1 << 21;
  uint32_t* next = malloc(nodes * sizeof(uint32_t));
  uint32_t* order = malloc(nodes * sizeof(uint32_t));
  for (uint32_t i = 0; i < nodes; ++i) order[i] = i;
  uint32_t seed = 7;
  for (size_t i = nodes - 1; i > 0; --i) {
    seed = seed * 1664525u + 1013904223u;
    const size_t j = seed % (i + 1);
    const uint32_t t = order[i];
    order[i] = order[j];
    order[j] = t;
  }
  for (size_t i = 0; i < nodes; ++i) next[order[i]] = order[(i + 1) % nodes];
  uint32_t at = 0;
  uint64_t visited = 0;
  for (int i = 0; i < 20000000; ++i) {
    at = next[at];
    visited += at;
  }
  printf("chase %llu\n", (unsigned long long)visited);
  free(src);
  free(dst);
  free(text);
  free(next);
  free(order);
  return 0;
}
