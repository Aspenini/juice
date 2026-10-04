#include <cstdio>
#include <cstring>

#include "test.hpp"

namespace juice::test {

namespace {
int g_failures = 0;
}

std::vector<TestCase>& registry() {
  static std::vector<TestCase> tests;
  return tests;
}

void fail(const char* file, int line, const std::string& message) {
  ++g_failures;
  std::fprintf(stderr, "  %s(%d): %s\n", file, line, message.c_str());
}

}  // namespace juice::test

int main(int argc, char** argv) {
  using namespace juice::test;
  const char* filter = argc > 1 ? argv[1] : nullptr;
  int failed_tests = 0, run = 0;
  for (const TestCase& t : registry()) {
    if (filter && !std::strstr(t.name, filter)) continue;
    const int before = g_failures;
    t.fn();
    ++run;
    if (g_failures != before) {
      ++failed_tests;
      std::fprintf(stderr, "FAIL %s\n", t.name);
    } else {
      std::printf("ok   %s\n", t.name);
    }
  }
  std::printf("%d/%d tests passed\n", run - failed_tests, run);
  return failed_tests ? 1 : 0;
}
