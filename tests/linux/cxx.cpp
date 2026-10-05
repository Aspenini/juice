// C++: exceptions (unwinding through the guest's libgcc), iostreams, std::thread.
#include <iostream>
#include <map>
#include <memory>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

struct Tracker {
  static int live;
  Tracker() { ++live; }
  ~Tracker() { --live; }
};
int Tracker::live = 0;

int deep(int n) {
  Tracker t;
  if (n == 0) throw std::runtime_error("bottom reached");
  return deep(n - 1) + 1;
}

int main() {
  try {
    deep(20);
  } catch (const std::exception& e) {
    std::cout << "caught: " << e.what() << ", live trackers: " << Tracker::live << "\n";
  }
  std::map<std::string, int> words;
  for (const char* w : {"juice", "arm64", "juice", "linux", "juice"}) ++words[w];
  for (const auto& [w, n] : words) std::cout << w << "=" << n << " ";
  std::cout << "\n";
  std::vector<std::thread> threads;
  std::vector<long> sums(4);
  for (int t = 0; t < 4; ++t)
    threads.emplace_back([t, &sums] {
      for (long i = 0; i < 100000; ++i) sums[t] += i % (t + 2);
    });
  for (auto& th : threads) th.join();
  for (long s : sums) std::cout << s << " ";
  std::cout << std::endl;
  auto p = std::make_shared<std::string>("shared");
  std::cout << *p << " use_count=" << p.use_count() << "\n";
  return 0;
}
