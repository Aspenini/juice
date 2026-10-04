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

// --- Settings Windows reads only when it creates a process ---------------------
//
// Some manifest settings take effect only at process creation: the ANSI code
// page (activeCodePage), long path awareness, the heap type, the supportedOS
// and maxversiontested compatibility entries, and a few others. For a guest
// that declares any of them, JUICE runs itself again from a copy of juice.exe
// whose own manifest carries those settings (plus the DPI settings, which
// then also apply natively). The copies are cached per manifest under
// %LOCALAPPDATA%\juice\hosts. Dependencies stay in the guest's activation
// context (apply_manifest), so they still resolve relative to the guest.

// The host manifest for the guest at `exe_path`, or empty if the guest
// declares no setting that needs a new process.
std::string host_manifest_for(const std::wstring& exe_path);

// Run this juice command line again in a juice.exe that embeds `manifest`,
// sharing the console and standard handles; returns its exit code.
std::expected<int, std::string> run_in_host(const std::string& manifest, std::FILE* log);

// True in a process started by run_in_host(). Clears the marker, so that
// processes the guest starts don't inherit it.
bool consume_host_marker();

// Activate the guest's context on the calling thread if it is not the process
// default (threads that native code created run guest code).
void activate_manifest_on_thread(const ManifestState& manifest);

}  // namespace juice::win
