#pragma once

// Binds a guest image's imports to builtins or native x64 DLL exports.

#include <cstdint>
#include <cstdio>
#include <string>

#include "windows/pe/pe_loader.hpp"
#include "windows/thunk/thunk_table.hpp"

namespace juice::win {

struct ImportStats {
  size_t builtin = 0;
  size_t native = 0;
  size_t data = 0;
  size_t missing = 0;
};

// True if `addr` is inside an executable section of a loaded native module
// (or other executable host memory).
bool is_native_code(const void* addr);

// Guest-visible value for a native export: a thunk address for functions, or
// the export's own address for data (which the guest may access directly
// since it shares the host address space).
uint64_t guest_value_for_native_export(void* addr, ThunkTable& thunks, std::string dll, std::string name);

// Resolve every import of `image` and fill its IAT. `log` (optional) receives
// a line per import.
ImportStats resolve_imports(const pe::LoadedImage& image, ThunkTable& thunks, std::FILE* log);

}  // namespace juice::win
