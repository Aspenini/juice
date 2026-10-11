/* Many small functions: recursion, calls through pointers (qsort's
 * comparator) and a tree built and walked with the heap. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

static __declspec(noinline) uint32_t fib(uint32_t n) { return n < 2 ? n : fib(n - 1) + fib(n - 2); }

static int compare(const void* a, const void* b) {
  const uint32_t x = *(const uint32_t*)a, y = *(const uint32_t*)b;
  return (x > y) - (x < y);
}

typedef struct Node {
  struct Node* left;
  struct Node* right;
  uint32_t key;
} Node;

static Node* insert(Node* root, uint32_t key) {
  Node** at = &root;
  while (*at) at = key < (*at)->key ? &(*at)->left : &(*at)->right;
  Node* n = malloc(sizeof(Node));
  n->left = n->right = NULL;
  n->key = key;
  *at = n;
  return root;
}

static __declspec(noinline) uint64_t walk(const Node* n, unsigned depth) {
  if (!n) return 0;
  return n->key * (uint64_t)depth + walk(n->left, depth + 1) + walk(n->right, depth + 1);
}

static void destroy(Node* n) {
  if (!n) return;
  destroy(n->left);
  destroy(n->right);
  free(n);
}

int main(void) {
  printf("fib %u\n", fib(32));

  const size_t count = 1000000;
  uint32_t* values = malloc(count * sizeof(uint32_t));
  uint32_t seed = 1;
  for (size_t i = 0; i < count; ++i) values[i] = seed = seed * 1103515245u + 12345u;
  qsort(values, count, sizeof(uint32_t), compare);
  uint64_t check = 0;
  for (size_t i = 0; i < count; i += 1000) check = check * 31 + values[i];
  printf("sorted %llu\n", (unsigned long long)check);

  Node* root = NULL;
  for (size_t i = 0; i < 300000; ++i) root = insert(root, values[(i * 7919) % count]);
  printf("tree %llu\n", (unsigned long long)walk(root, 1));
  destroy(root);
  free(values);
  return 0;
}
