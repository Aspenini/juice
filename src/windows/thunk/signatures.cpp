// Signatures of native exports that the generic ARM64 -> x64 call bridge
// would get wrong (see native_call.cpp for the notation): generated from the
// Windows SDK headers by tools/gen_signatures, plus a few functions those
// headers do not declare.

#include <algorithm>
#include <span>
#include <string>

#include "windows/thunk/thunk_table.hpp"

namespace juice::win {
namespace {

struct Signature {
  std::string_view name;
  const char* kinds;
};

constexpr Signature kGenerated[] = {
#include "windows/thunk/signatures_generated.inc"
};

// The C++ standard library runtime (msvcp140*.dll): _Thrd_t is {HANDLE, id}.
constexpr Signature kExtra[] = {
    {"_Thrd_join", "S16i"},
    {"_Thrd_detach", "S16"},
};

constexpr bool sorted() {
  for (size_t k = 1; k < std::size(kGenerated); ++k)
    if (!(kGenerated[k - 1].name < kGenerated[k].name)) return false;
  return true;
}
static_assert(sorted(), "signatures_generated.inc must be sorted by name");

}  // namespace

const char* native_signature(std::string_view dll, std::string_view name) {
  (void)dll;  // names are unique across the system DLLs
  const auto it = std::lower_bound(std::begin(kGenerated), std::end(kGenerated), name,
                                   [](const Signature& s, std::string_view n) { return s.name < n; });
  if (it != std::end(kGenerated) && it->name == name) return it->kinds;
  for (const Signature& s : kExtra)
    if (s.name == name) return s.kinds;
  return nullptr;
}

}  // namespace juice::win
