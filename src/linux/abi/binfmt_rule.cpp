#include "linux/abi/binfmt_rule.hpp"

#include <cstdint>
#include <cstdio>

namespace juice::lx {

namespace {

constexpr uint8_t kMagic[20] = {0x7f, 'E', 'L', 'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0xb7, 0};
// Ignore EI_OSABI's neighbour (EI_ABIVERSION) and bit 0 of e_type (2 = EXEC, 3 = DYN).
constexpr uint8_t kMask[20] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0xff, 0xff,
                               0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff};

std::string escaped(const uint8_t (&bytes)[20]) {
  std::string s;
  for (uint8_t b : bytes) {
    char buf[5];
    std::snprintf(buf, sizeof(buf), "\\x%02x", b);
    s += buf;
  }
  return s;
}

}  // namespace

std::string binfmt_rule(const std::string& interpreter, const std::string& flags) {
  return std::string(":") + kBinfmtName + ":M::" + escaped(kMagic) + ":" + escaped(kMask) + ":" + interpreter + ":" +
         flags;
}

}  // namespace juice::lx
