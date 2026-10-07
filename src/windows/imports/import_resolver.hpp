#pragma once

// Binds a guest image's imports to builtins or native x64 DLL exports.

#include <windows.h>

#include <cstdint>
#include <cstdio>
#include <functional>
#include <optional>
#include <string>

#include "windows/pe/pe_loader.hpp"
#include "windows/thunk/thunk_table.hpp"

namespace juice::win {

struct ImportStats {
  size_t guest = 0;
  size_t builtin = 0;
  size_t native = 0;
  size_t data = 0;
  size_t missing = 0;
};

// True if `addr` is inside an executable section of a loaded native module
// (or other executable host memory).
bool is_native_code(const void* addr);

// The name a native DLL exports `ordinal` under (empty if none): native
// signatures are looked up by name.
std::string export_name_for_ordinal(HMODULE mod, uint32_t ordinal);

// Guest-visible value for a native export: a thunk address for functions, or
// the export's own address for data (which the guest may access directly
// since it shares the host address space).
uint64_t guest_value_for_native_export(void* addr, ThunkTable& thunks, std::string dll, std::string name);

// Resolve one import to a builtin, a native export or a "missing" thunk.
// `how` receives a description for logs; `stats` (optional) is updated.
uint64_t resolve_native_import(const pe::Import& import, ThunkTable& thunks, const char** how = nullptr,
                               ImportStats* stats = nullptr);

// A thunk that reports a call to an unresolved import.
uint64_t missing_import(ThunkTable& thunks, const std::string& dll, const std::string& name);

// Binds an import to an export of a guest (ARM64) DLL. Returns nullopt if
// the DLL is not a guest module, so that the import binds to a builtin or the
// native DLL instead.
using GuestImportBinder = std::function<std::optional<uint64_t>(const pe::Import& import)>;

// Resolve every import of `image` and fill its IAT. `log` (optional) receives
// a line per import.
ImportStats resolve_imports(const pe::LoadedImage& image, ThunkTable& thunks, std::FILE* log,
                            const GuestImportBinder& guest = {});

}  // namespace juice::win
