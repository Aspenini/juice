// Resource functions whose NULL module handle means "the executable".
//
// For native code that is juice.exe; for the guest it must be the program.
// These builtins substitute the program's handle and forward to the native
// functions, which work on guest images like on any mapped module.

#include <windows.h>

#include "windows/dlls/builtins.hpp"
#include "windows/guest_process.hpp"
#include "windows/thunk/thunk_table.hpp"

namespace juice::win {
namespace {

using arm64::CpuState;

// Forward to `dll!name` with argument `module_arg` replaced by the program's
// handle if it is NULL (and, for FormatMessage, only when `condition` holds).
template <const char* Dll, const char* Name, int ModuleArg>
uint64_t forward_null_module(GuestProcess& p, CpuState& s) {
  static void* const fn = reinterpret_cast<void*>(GetProcAddress(LoadLibraryA(Dll), Name));
  CpuState args = s;
  if (args.x[ModuleArg] == 0) args.x[ModuleArg] = p.exe().base();
  return call_native(fn, args).rax;
}

constexpr char kUser32[] = "user32.dll";
constexpr char kKernel32[] = "kernel32.dll";
constexpr char kLoadStringA[] = "LoadStringA";
constexpr char kLoadStringW[] = "LoadStringW";
constexpr char kFindResourceA[] = "FindResourceA";
constexpr char kFindResourceW[] = "FindResourceW";
constexpr char kFindResourceExA[] = "FindResourceExA";
constexpr char kFindResourceExW[] = "FindResourceExW";
constexpr char kLoadResource[] = "LoadResource";
constexpr char kSizeofResource[] = "SizeofResource";
constexpr char kEnumResourceTypesA[] = "EnumResourceTypesA";
constexpr char kEnumResourceTypesW[] = "EnumResourceTypesW";
constexpr char kEnumResourceTypesExA[] = "EnumResourceTypesExA";
constexpr char kEnumResourceTypesExW[] = "EnumResourceTypesExW";
constexpr char kEnumResourceNamesA[] = "EnumResourceNamesA";
constexpr char kEnumResourceNamesW[] = "EnumResourceNamesW";
constexpr char kEnumResourceNamesExA[] = "EnumResourceNamesExA";
constexpr char kEnumResourceNamesExW[] = "EnumResourceNamesExW";
constexpr char kEnumResourceLanguagesA[] = "EnumResourceLanguagesA";
constexpr char kEnumResourceLanguagesW[] = "EnumResourceLanguagesW";
constexpr char kEnumResourceLanguagesExA[] = "EnumResourceLanguagesExA";
constexpr char kEnumResourceLanguagesExW[] = "EnumResourceLanguagesExW";

// FormatMessage(flags, source, ...): with FORMAT_MESSAGE_FROM_HMODULE, a NULL
// source is the executable.
template <const char* Name>
uint64_t format_message(GuestProcess& p, CpuState& s) {
  static void* const fn = reinterpret_cast<void*>(GetProcAddress(LoadLibraryA(kKernel32), Name));
  CpuState args = s;
  if ((args.x[0] & FORMAT_MESSAGE_FROM_HMODULE) && args.x[1] == 0) args.x[1] = p.exe().base();
  return call_native(fn, args).rax;
}
constexpr char kFormatMessageA[] = "FormatMessageA";
constexpr char kFormatMessageW[] = "FormatMessageW";

constexpr BuiltinExport kKernel32Resources[] = {
    {"FindResourceA", forward_null_module<kKernel32, kFindResourceA, 0>},
    {"FindResourceW", forward_null_module<kKernel32, kFindResourceW, 0>},
    {"FindResourceExA", forward_null_module<kKernel32, kFindResourceExA, 0>},
    {"FindResourceExW", forward_null_module<kKernel32, kFindResourceExW, 0>},
    {"LoadResource", forward_null_module<kKernel32, kLoadResource, 0>},
    {"SizeofResource", forward_null_module<kKernel32, kSizeofResource, 0>},
    {"EnumResourceTypesA", forward_null_module<kKernel32, kEnumResourceTypesA, 0>},
    {"EnumResourceTypesW", forward_null_module<kKernel32, kEnumResourceTypesW, 0>},
    {"EnumResourceTypesExA", forward_null_module<kKernel32, kEnumResourceTypesExA, 0>},
    {"EnumResourceTypesExW", forward_null_module<kKernel32, kEnumResourceTypesExW, 0>},
    {"EnumResourceNamesA", forward_null_module<kKernel32, kEnumResourceNamesA, 0>},
    {"EnumResourceNamesW", forward_null_module<kKernel32, kEnumResourceNamesW, 0>},
    {"EnumResourceNamesExA", forward_null_module<kKernel32, kEnumResourceNamesExA, 0>},
    {"EnumResourceNamesExW", forward_null_module<kKernel32, kEnumResourceNamesExW, 0>},
    {"EnumResourceLanguagesA", forward_null_module<kKernel32, kEnumResourceLanguagesA, 0>},
    {"EnumResourceLanguagesW", forward_null_module<kKernel32, kEnumResourceLanguagesW, 0>},
    {"EnumResourceLanguagesExA", forward_null_module<kKernel32, kEnumResourceLanguagesExA, 0>},
    {"EnumResourceLanguagesExW", forward_null_module<kKernel32, kEnumResourceLanguagesExW, 0>},
    {"FormatMessageA", format_message<kFormatMessageA>},
    {"FormatMessageW", format_message<kFormatMessageW>},
    // kernelbase exports these too (api-ms-win-core-libraryloader).
    {"LoadStringA", forward_null_module<kUser32, kLoadStringA, 0>},
    {"LoadStringW", forward_null_module<kUser32, kLoadStringW, 0>},
};

constexpr BuiltinExport kUser32Resources[] = {
    {"LoadStringA", forward_null_module<kUser32, kLoadStringA, 0>},
    {"LoadStringW", forward_null_module<kUser32, kLoadStringW, 0>},
};

}  // namespace

std::span<const BuiltinExport> resource_builtins() { return kKernel32Resources; }
std::span<const BuiltinExport> user32_builtins() { return kUser32Resources; }

}  // namespace juice::win
