#pragma once

// The guest executable's application manifest.
//
// Windows applies an executable's manifest when it creates the process; for
// a guest, that process is juice.exe, which has no manifest. JUICE therefore
// builds an activation context from the guest's manifest and makes it the
// process default, so DLL redirection (common controls v6 and visual styles,
// other side-by-side assemblies) applies to the guest's imports and to
// everything it loads later. Process-wide settings that the manifest declares
// and that can still be changed after start-up (DPI awareness) are applied
// directly.

#include <windows.h>

#include <cstdint>
#include <cstdio>
#include <expected>
#include <string>

namespace juice::win {

struct ManifestState {
  HANDLE context = INVALID_HANDLE_VALUE;  // INVALID_HANDLE_VALUE: no manifest
  bool process_default = false;           // installed as the process default activation context
  ULONG_PTR cookie = 0;                   // otherwise activated on the loading thread
  std::string dpi_awareness;              // applied DPI awareness, empty if none declared
};

// Apply the manifest (resource RT_MANIFEST #1) of the guest image mapped at
// `image_base`, loaded from `exe_path`. Fails like a native launch would if
// the manifest is invalid or names assemblies that are not installed.
std::expected<ManifestState, std::string> apply_manifest(const std::wstring& exe_path, uint64_t image_base,
                                                         std::FILE* log);

// Activate the guest's context on the calling thread if it is not the process
// default (threads that native code created run guest code).
void activate_manifest_on_thread(const ManifestState& manifest);

}  // namespace juice::win
