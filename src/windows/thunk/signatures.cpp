// Argument kinds of native exports that mix integer and floating point
// parameters. Windows ARM64 numbers integer (X) and floating point (D)
// argument registers independently, Windows x64 assigns registers by
// position, so the generic bridge needs to know the order for these.
//
// 'i' = integer or pointer, 'f' = float or double.

#include <algorithm>
#include <cctype>
#include <string>

#include "windows/thunk/thunk_table.hpp"

namespace juice::win {
namespace {

struct Signature {
  std::string_view name;
  const char* kinds;
};

constexpr Signature kUcrt[] = {
    {"ldexp", "fi"},     {"ldexpf", "fi"},     {"frexp", "fi"},    {"frexpf", "fi"},   {"modf", "fi"},
    {"modff", "fi"},     {"scalbn", "fi"},     {"scalbnf", "fi"},  {"scalbln", "fi"},  {"scalblnf", "fi"},
    {"remquo", "ffi"},   {"remquof", "ffi"},   {"_jn", "if"},      {"_yn", "if"},      {"_ldexp", "fi"},
    {"_gcvt", "fii"},    {"_ecvt", "fiii"},    {"_fcvt", "fiii"},  {"_ecvt_s", "iifiii"},
    {"_fcvt_s", "iifiii"}, {"_gcvt_s", "iifi"},
};

bool is_ucrt(std::string_view dll) {
  std::string d(dll);
  std::transform(d.begin(), d.end(), d.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  return d.starts_with("ucrtbase") || d.starts_with("api-ms-win-crt-") || d.starts_with("msvcrt");
}

}  // namespace

const char* native_signature(std::string_view dll, std::string_view name) {
  if (!is_ucrt(dll)) return nullptr;
  for (const Signature& s : kUcrt)
    if (s.name == name) return s.kinds;
  return nullptr;
}

}  // namespace juice::win
