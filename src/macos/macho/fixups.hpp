#pragma once

// The fixups of a Mach-O image: the pointers dyld slides (rebases) and the
// pointers it sets to symbols of other images (binds). Both encodings are
// read: dyld's opcode streams (LC_DYLD_INFO) and chained fixups
// (LC_DYLD_CHAINED_FIXUPS, where the pointers themselves form linked lists
// through each page).
//
// Pointer authentication of arm64e images is ignored (JUICE doesn't
// authenticate pointers): the fixups become plain pointers.

#include <cstdint>
#include <expected>
#include <string>
#include <vector>

#include "macos/macho/macho_file.hpp"

namespace juice::mac {

// Special library ordinals of a bind
inline constexpr int kOrdinalSelf = 0;
inline constexpr int kOrdinalMainExecutable = -1;
inline constexpr int kOrdinalFlatLookup = -2;
inline constexpr int kOrdinalWeakLookup = -3;

struct Import {
  std::string name;  // with the leading underscore, as in the symbol table
  int ordinal = 0;   // 1-based index into MachOFile::dylibs, or one of the specials above
  bool weak = false; // missing is fine: the pointer becomes 0
};

struct Rebase {
  uint64_t address = 0;  // of the pointer (unslid)
  uint64_t target = 0;   // what it points to (unslid)
};

struct Bind {
  uint64_t address = 0;  // of the pointer (unslid)
  uint32_t import = 0;   // index into Fixups::imports
  int64_t addend = 0;
};

struct Fixups {
  std::vector<Import> imports;
  std::vector<Rebase> rebases;
  std::vector<Bind> binds;       // includes lazy binds (JUICE binds them all at load)
  std::vector<Bind> weak_binds;  // weak definition coalescing (opcode format): override only if found elsewhere
  bool chained = false;
  uint16_t pointer_format = 0;   // the chained pointer format (DYLD_CHAINED_PTR_*), if chained
};

// Reads all fixups of `image`; `read` reads the file, as for parse_macho.
std::expected<Fixups, std::string> read_fixups(const MachOFile& image, const FileReader& read);

// The name of a library ordinal (diagnostics).
std::string ordinal_name(const MachOFile& image, int ordinal);

}  // namespace juice::mac
