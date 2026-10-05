// Threads: creation and join, futex-based locks, condition variables, TLS.
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>

static __thread int tls_value = 5;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
static long counter;
static atomic_long atomic_counter;
static int ready;

static void* worker(void* arg) {
  long id = (long)arg;
  tls_value = (int)id * 100;
  for (int i = 0; i < 20000; ++i) {
    pthread_mutex_lock(&lock);
    ++counter;
    pthread_mutex_unlock(&lock);
    atomic_fetch_add(&atomic_counter, 2);
  }
  pthread_mutex_lock(&lock);
  ++ready;
  pthread_cond_signal(&cond);
  pthread_mutex_unlock(&lock);
  return (void*)(long)(tls_value + 1);
}

int main(void) {
  enum { kThreads = 8 };
  pthread_t threads[kThreads];
  for (long i = 0; i < kThreads; ++i) pthread_create(&threads[i], NULL, worker, (void*)i);
  pthread_mutex_lock(&lock);
  while (ready < kThreads) pthread_cond_wait(&cond, &lock);
  pthread_mutex_unlock(&lock);
  long sum = 0;
  for (int i = 0; i < kThreads; ++i) {
    void* r;
    pthread_join(threads[i], &r);
    sum += (long)r;
  }
  printf("counter=%ld atomic=%ld results=%ld main tls=%d\n", counter, (long)atomic_counter, sum, tls_value);
  return 0;
}
