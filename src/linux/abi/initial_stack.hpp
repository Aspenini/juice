#pragma once

// The initial stack of a Linux process, as the kernel builds it for execve:
//
//   sp ->  argc
//          argv[0..argc-1], NULL
//          envp[...], NULL
//          auxv pairs, AT_NULL
//          ... strings (argv, envp, platform, execfn) and 16 random bytes
//   top
//
// Portable: writes through host pointers (guest and host share addresses).

#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace juice::lx {

struct InitialStackInput {
  std::vector<std::string> argv;
  std::vector<std::string> envp;
  std::vector<std::pair<uint64_t, uint64_t>> auxv;  // without AT_RANDOM, AT_PLATFORM, AT_EXECFN, AT_NULL
  std::string execfn;                              // AT_EXECFN
  std::string platform = "aarch64";                // AT_PLATFORM
  std::array<uint8_t, 16> random{};                // AT_RANDOM
};

// Build the stack below `top` (exclusive) without going below `limit`.
// Returns the initial stack pointer (16-byte aligned, pointing at argc), or 0
// if the stack is too small.
uint64_t build_initial_stack(uint64_t top, uint64_t limit, const InitialStackInput& in);

}  // namespace juice::lx
