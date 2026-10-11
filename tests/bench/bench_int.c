/* Integer and branch-heavy work: a prime sieve, a hash table of collatz
 * lengths and an LCG-driven state machine. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint32_t sieve(uint32_t n) {
  uint8_t* composite = calloc(n + 1, 1);
  uint32_t count = 0;
  for (uint32_t i = 2; i <= n; ++i) {
    if (composite[i]) continue;
    ++count;
    for (uint64_t j = (uint64_t)i * i; j <= n; j += i) composite[j] = 1;
  }
  free(composite);
  return count;
}

static uint32_t collatz(uint64_t limit) {
  uint32_t best = 0;
  for (uint64_t start = 1; start < limit; ++start) {
    uint64_t x = start;
    uint32_t steps = 0;
    while (x != 1) {
      x = (x & 1) ? 3 * x + 1 : x >> 1;
      ++steps;
    }
    if (steps > best) best = steps;
  }
  return best;
}

static uint64_t state_machine(uint32_t rounds) {
  uint64_t seed = 12345, acc = 0;
  int state = 0;
  for (uint32_t i = 0; i < rounds; ++i) {
    seed = seed * 6364136223846793005ull + 1442695040888963407ull;
    const unsigned input = (unsigned)(seed >> 60);
    switch (state) {
      case 0: state = input & 3; acc += input; break;
      case 1: state = input > 7 ? 2 : 0; acc ^= seed; break;
      case 2: state = (input * 3) & 3; acc = (acc << 1) | (acc >> 63); break;
      default: state = 0; acc -= input * 17; break;
    }
  }
  return acc;
}

int main(void) {
  printf("primes %u\n", sieve(20000000));
  printf("collatz %u\n", collatz(1500000));
  printf("state %llu\n", (unsigned long long)state_machine(60000000));
  return 0;
}
