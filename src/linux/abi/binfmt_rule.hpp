#pragma once

// The binfmt_misc rule that hands Linux AArch64 ELF programs to JUICE
// (portable: only builds the text the kernel parses).

#include <string>

namespace juice::lx {

inline constexpr const char* kBinfmtName = "juice-aarch64";

// ":name:M::magic:mask:interpreter:flags" for /proc/sys/fs/binfmt_misc/register
// or a systemd binfmt.d file. Matches ELF64 little-endian ET_EXEC and ET_DYN
// files for EM_AARCH64 (the same rule as qemu-aarch64's). `flags`:
//   P  pass the program's original argv[0] (JUICE expects it: argv is
//      interpreter, program path, argv[0], arguments...)
//   F  open the interpreter at registration time (works in containers and chroots)
//   C  credentials from the program (setuid programs) - implies O
std::string binfmt_rule(const std::string& interpreter, const std::string& flags = "PF");

}  // namespace juice::lx
