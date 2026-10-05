#pragma once

// binfmt_misc integration: once registered, the kernel runs Linux AArch64
// programs with JUICE when they are executed directly (./program), including
// from host programs, shells and containers.
//
// The registered interpreter is a `juice-binfmt` symlink next to the juice
// binary: started under that name, juice takes its arguments the way the
// kernel passes them (flag P): program path, original argv[0], arguments.

#include <expected>
#include <string>

namespace juice::lx {

inline constexpr const char* kBinfmtLauncher = "juice-binfmt";

// Path of the juice binary and of the launcher symlink beside it.
std::string juice_binary_path();
std::string binfmt_launcher_path();

// Create the launcher symlink and register the rule (needs root).
std::expected<void, std::string> install_binfmt();
// Remove the rule (needs root). Leaves the symlink.
std::expected<void, std::string> uninstall_binfmt();
// The rule for /etc/binfmt.d/juice-aarch64.conf, to register it at boot.
std::string binfmt_config();
// "enabled", "disabled" or "not registered", and the rule's interpreter.
std::string binfmt_status();

}  // namespace juice::lx
