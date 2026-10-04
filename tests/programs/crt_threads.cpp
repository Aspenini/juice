// C++ standard library threading: std::thread, std::mutex, std::atomic,
// std::condition_variable and thread_local objects with constructors and
// destructors. With /MT the threads come from the program's own
// _beginthreadex (CreateThread); with /MD from the native UCRT, which calls
// back into the program on threads it created itself.
#include <atomic>
#include <condition_variable>
#include <cstdio>
#include <deque>
#include <mutex>
#include <thread>
#include <vector>

namespace {

std::atomic<int> constructed{0};
std::atomic<int> destructed{0};

struct PerThread {
  long long sum = 0;
  int id = -1;
  PerThread() { constructed.fetch_add(1); }
  ~PerThread() { destructed.fetch_add(1); }
};

thread_local PerThread per_thread;
thread_local int tls_plain = 5;

std::mutex mutex;
long long guarded = 0;
std::atomic<long long> atomic_total{0};

// Bounded producer/consumer queue.
std::mutex queue_mutex;
std::condition_variable not_empty, not_full;
std::deque<int> queue;
constexpr size_t kCapacity = 8;

void produce(int count) {
  for (int i = 1; i <= count; ++i) {
    std::unique_lock<std::mutex> lock(queue_mutex);
    not_full.wait(lock, [] { return queue.size() < kCapacity; });
    queue.push_back(i);
    not_empty.notify_one();
  }
}

long long consume(int count) {
  long long sum = 0;
  for (int i = 0; i < count; ++i) {
    std::unique_lock<std::mutex> lock(queue_mutex);
    not_empty.wait(lock, [] { return !queue.empty(); });
    sum += queue.front();
    queue.pop_front();
    not_full.notify_one();
  }
  return sum;
}

}  // namespace

int main() {
  constexpr int kThreads = 6;
  constexpr int kIterations = 20000;
  std::vector<long long> results(kThreads);
  std::vector<int> tls_values(kThreads);
  {
    std::vector<std::thread> threads;
    for (int t = 0; t < kThreads; ++t) {
      threads.emplace_back([t, &results, &tls_values] {
        per_thread.id = t;
        tls_plain += t;
        for (int i = 0; i < kIterations; ++i) {
          per_thread.sum += i % (t + 2);
          atomic_total.fetch_add(i & 7, std::memory_order_relaxed);
          if (i % 64 == 0) {
            std::lock_guard<std::mutex> lock(mutex);
            guarded += t + 1;
          }
        }
        results[t] = per_thread.id == t ? per_thread.sum : -1;
        tls_values[t] = tls_plain;
      });
    }
    for (auto& th : threads) th.join();
  }
  for (int t = 0; t < kThreads; ++t) std::printf("thread %d: sum=%lld tls=%d\n", t, results[t], tls_values[t]);
  std::printf("atomic total=%lld guarded=%lld\n", atomic_total.load(), guarded);
  std::printf("main thread tls=%d (unchanged)\n", tls_plain);

  long long consumed = 0;
  {
    std::thread producer(produce, 5000);
    std::thread consumer([&] { consumed = consume(5000); });
    producer.join();
    consumer.join();
  }
  std::printf("producer/consumer sum=%lld\n", consumed);

  // Thread-local objects: constructed on first use in each thread and
  // destroyed when the thread exits.
  std::printf("worker thread_local objects: constructed=%d destructed=%d\n", constructed.load(), destructed.load());
  std::printf("hardware threads > 0: %d\n", std::thread::hardware_concurrency() > 0);
  return 0;
}
