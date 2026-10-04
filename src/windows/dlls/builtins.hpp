#pragma once

// JUICE's own implementations of Windows APIs that cannot simply be forwarded
// to the native x64 DLLs (because they must know about the guest image, take
// callbacks into guest code, or expose architecture-specific information).

#include <span>
#include <string_view>

#include "windows/thunk/thunk_table.hpp"

namespace juice::win {

struct BuiltinExport {
  std::string_view name;
  BuiltinFn fn;
};

// Returns nullptr if JUICE has no builtin for dll!name.
BuiltinFn find_builtin(std::string_view dll, std::string_view name);

// Builtins grouped by the DLL that exports them.
std::span<const BuiltinExport> kernel32_builtins();
std::span<const BuiltinExport> ucrt_builtins();

}  // namespace juice::win
