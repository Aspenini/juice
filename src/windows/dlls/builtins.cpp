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
bool is_vcruntime_family(std::string_view dll) { return lower(dll).starts_with("vcruntime140"); }

BuiltinFn find_in(std::span<const BuiltinExport> exports, std::string_view name) {
  for (const BuiltinExport& e : exports)
    if (e.name == name) return e.fn;
  return nullptr;
}

}  // namespace

BuiltinFn find_builtin(std::string_view dll, std::string_view name) {
  if (is_kernel32_family(dll)) {
    if (BuiltinFn fn = find_in(exception_builtins(), name)) return fn;
    return find_in(kernel32_builtins(), name);
  }
  if (is_vcruntime_family(dll)) return find_in(vcruntime_builtins(), name);
  return nullptr;
}

}  // namespace juice::win
