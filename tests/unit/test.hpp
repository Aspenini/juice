#pragma once

// Tiny self-contained test framework.

#include <cstdint>
#include <format>
#include <string>
#include <vector>

namespace juice::test {

struct TestCase {
  const char* name;
  void (*fn)();
};

std::vector<TestCase>& registry();
void fail(const char* file, int line, const std::string& message);

struct Registrar {
  Registrar(const char* name, void (*fn)()) { registry().push_back({name, fn}); }
};

}  // namespace juice::test

#define JUICE_CONCAT2(a, b) a##b
#define JUICE_CONCAT(a, b) JUICE_CONCAT2(a, b)

#define TEST(name)                                                                \
  static void name();                                                             \
  static ::juice::test::Registrar JUICE_CONCAT(registrar_, name)(#name, name);    \
  static void name()

#define CHECK(cond)                                                       \
  do {                                                                    \
    if (!(cond)) ::juice::test::fail(__FILE__, __LINE__, "CHECK(" #cond ")"); \
  } while (0)

#define CHECK_EQ(actual, expected)                                                                         \
  do {                                                                                                     \
    const auto juice_a_ = (actual);                                                                        \
    const auto juice_e_ = (expected);                                                                      \
    if (!(juice_a_ == juice_e_))                                                                           \
      ::juice::test::fail(__FILE__, __LINE__,                                                              \
                          std::format("{} == {}: got 0x{:x}, expected 0x{:x}", #actual, #expected,         \
                                      static_cast<uint64_t>(juice_a_), static_cast<uint64_t>(juice_e_)));  \
  } while (0)
