// A C++ program using the standard library: global constructors and
// destructors, virtual calls, containers, algorithms, lambdas and strings.
// (C++ exceptions are not supported by JUICE yet; built with them disabled.)
#include <algorithm>
#include <cstdio>
#include <functional>
#include <map>
#include <memory>
#include <numeric>
#include <string>
#include <unordered_map>
#include <vector>

namespace {

struct Tracer {
  std::string name;
  explicit Tracer(std::string n) : name(std::move(n)) { std::printf("construct %s\n", name.c_str()); }
  ~Tracer() { std::printf("destruct %s\n", name.c_str()); }
};

Tracer g_tracer("global");

struct Shape {
  virtual ~Shape() = default;
  virtual double area() const = 0;
  virtual std::string name() const = 0;
};

struct Circle final : Shape {
  double r;
  explicit Circle(double radius) : r(radius) {}
  double area() const override { return 3.14159265358979 * r * r; }
  std::string name() const override { return "circle(" + std::to_string(r) + ")"; }
};

struct Rect final : Shape {
  double w, h;
  Rect(double width, double height) : w(width), h(height) {}
  double area() const override { return w * h; }
  std::string name() const override { return "rect"; }
};

}  // namespace

int main() {
  std::vector<std::unique_ptr<Shape>> shapes;
  shapes.push_back(std::make_unique<Circle>(1.5));
  shapes.push_back(std::make_unique<Rect>(2.0, 3.5));
  shapes.push_back(std::make_unique<Circle>(0.25));
  std::sort(shapes.begin(), shapes.end(), [](const auto& a, const auto& b) { return a->area() < b->area(); });
  for (const auto& s : shapes) std::printf("%s area=%.6f\n", s->name().c_str(), s->area());

  std::vector<int> v(200);
  std::iota(v.begin(), v.end(), -100);
  std::reverse(v.begin(), v.end());
  std::stable_sort(v.begin(), v.end(), [](int a, int b) { return (a % 7) < (b % 7); });
  long long sum = std::accumulate(v.begin(), v.end(), 0LL, [](long long acc, int x) { return acc * 3 + x; });
  std::printf("sum=%lld first=%d last=%d\n", sum, v.front(), v.back());

  const std::string text =
      "the quick brown fox jumps over the lazy dog the fox barks and the dog sleeps while the quick cat watches";
  std::map<std::string, int> counts;
  std::unordered_map<char, int> letters;
  std::string word;
  for (char c : text + " ") {
    if (c == ' ') {
      if (!word.empty()) ++counts[word];
      word.clear();
    } else {
      word += c;
      ++letters[c];
    }
  }
  for (const auto& [w, n] : counts)
    if (n > 1) std::printf("%s:%d ", w.c_str(), n);
  std::printf("\nletters e=%d o=%d distinct=%zu\n", letters['e'], letters['o'], letters.size());

  std::function<long long(int)> fib = [&](int n) -> long long { return n < 2 ? n : fib(n - 1) + fib(n - 2); };
  std::printf("fib(30)=%lld\n", fib(30));

  std::string s = "Instruction";
  s.insert(0, "JUICE ");
  s += " Conversion";
  std::transform(s.begin(), s.end(), s.begin(), [](char c) { return c == ' ' ? '_' : c; });
  std::printf("%s find=%zu substr=%s\n", s.c_str(), s.find("Conv"), s.substr(6, 11).c_str());
  std::printf("%s %s %s\n", std::to_string(42).c_str(), std::to_string(-7.25).c_str(),
              std::to_string(1ULL << 63).c_str());
  return 0;
}
