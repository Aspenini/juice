#include "windows/dlls/builtins.hpp"

#include <algorithm>
#include <cctype>
#include <string>

namespace juice::win {
namespace {

std::string lower(std::string_view s) {
  std::string out(s);
  std::transform(out.begin(), out.end(), out.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  return out;
}

// kernel32 functions are also reachable through kernelbase, ntdll forwarders
// and the api-ms-win-core-* API sets.
bool is_kernel32_family(std::string_view dll) {
  std::string d = lower(dll);
  if (d.size() > 4 && d.ends_with(".dll")) d.resize(d.size() - 4);
  return d == "kernel32" || d == "kernelbase" || d == "ntdll" || d.starts_with("api-ms-win-core-");
}

// The Visual C++ runtime: vcruntime140.dll and vcruntime140_1.dll.
// Also msvcrt.dll for its exception handling exports, when no ARM64
// vcruntime140.dll stands in for them (see guest_modules.cpp).
bool is_vcruntime_family(std::string_view dll) {
  const std::string d = lower(dll);
  return d.starts_with("vcruntime140") || d == "msvcrt.dll" || d == "msvcrt";
}

std::string base_name(std::string_view dll) {
  std::string d = lower(dll);
  if (d.size() > 4 && d.ends_with(".dll")) d.resize(d.size() - 4);
  return d;
}

BuiltinFn find_in(std::span<const BuiltinExport> exports, std::string_view name) {
  for (const BuiltinExport& e : exports)
    if (e.name == name) return e.fn;
  return nullptr;
}

}  // namespace

BuiltinFn find_builtin(std::string_view dll, std::string_view name) {
  if (is_kernel32_family(dll)) {
    if (BuiltinFn fn = find_in(exception_builtins(), name)) return fn;
    if (BuiltinFn fn = find_in(process_builtins(), name)) return fn;
    if (BuiltinFn fn = find_in(resource_builtins(), name)) return fn;
    if (BuiltinFn fn = find_in(module_list_builtins(), name)) return fn;
    if (BuiltinFn fn = find_in(thread_builtins(), name)) return fn;
    if (BuiltinFn fn = find_in(ole32_builtins(), name)) return fn;  // api-ms-win-core-com-*
    return find_in(kernel32_builtins(), name);
  }
  const std::string d = base_name(dll);
  // psapi.dll exports the kernel32 K32* functions under their plain names.
  if (d == "psapi") return find_in(module_list_builtins(), "K32" + std::string(name));
  if (d == "ole32" || d == "combase") return find_in(ole32_builtins(), name);
  if (is_vcruntime_family(dll)) return find_in(vcruntime_builtins(), name);
  if (lower(dll) == "user32.dll" || lower(dll) == "user32") return find_in(user32_builtins(), name);
  return nullptr;
}

}  // namespace juice::win
