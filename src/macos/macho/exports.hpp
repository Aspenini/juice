#pragma once

// The exported symbols of a Mach-O image: dyld's export trie
// (LC_DYLD_EXPORTS_TRIE or the export part of LC_DYLD_INFO).

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace juice::mac {

inline constexpr uint64_t kExportKindMask = 0x03;
inline constexpr uint64_t kExportKindRegular = 0x00;
inline constexpr uint64_t kExportKindThreadLocal = 0x01;
inline constexpr uint64_t kExportKindAbsolute = 0x02;
inline constexpr uint64_t kExportWeakDefinition = 0x04;
inline constexpr uint64_t kExportReexport = 0x08;
inline constexpr uint64_t kExportStubAndResolver = 0x10;

struct Export {
  std::string name;
  uint64_t flags = 0;
  uint64_t address = 0;   // offset from the image's mach header (absolute value for kExportKindAbsolute)
  uint64_t resolver = 0;  // kExportStubAndResolver: offset of the resolver function
  int ordinal = 0;        // kExportReexport: the library (1-based dylib index) it comes from
  std::string import_name;  // kExportReexport: its name there (empty: the same name)

  bool reexport() const { return flags & kExportReexport; }
};

// Looks up one symbol (with its leading underscore).
std::optional<Export> find_export(std::span<const uint8_t> trie, std::string_view name);

// All exports, in trie order. Malformed parts of the trie are skipped.
std::vector<Export> all_exports(std::span<const uint8_t> trie);

}  // namespace juice::mac
