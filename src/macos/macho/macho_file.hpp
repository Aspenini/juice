#pragma once

// Mach-O parsing for macOS ARM64 programs and libraries (portable: no Apple
// headers). Handles universal ("fat") files by picking the requested slice.

#include <cstdint>
#include <expected>
#include <functional>
#include <string>
#include <string_view>
#include <vector>

namespace juice::mac {

inline constexpr uint32_t kCpuTypeArm64 = 0x0100000C;
inline constexpr uint32_t kCpuTypeX86_64 = 0x01000007;
inline constexpr uint32_t kCpuSubtypeArm64e = 2;  // (low 24 bits of cpusubtype)

inline constexpr uint32_t kMhExecute = 2;
inline constexpr uint32_t kMhDylib = 6;
inline constexpr uint32_t kMhBundle = 8;

inline constexpr uint32_t kMhPie = 0x200000;  // mach_header flags

// Section types (low byte of the section flags)
inline constexpr uint32_t kSZerofill = 0x1;
inline constexpr uint32_t kSNonLazySymbolPointers = 0x6;
inline constexpr uint32_t kSLazySymbolPointers = 0x7;
inline constexpr uint32_t kSSymbolStubs = 0x8;
inline constexpr uint32_t kSModInitFuncPointers = 0x9;
inline constexpr uint32_t kSModTermFuncPointers = 0xA;
inline constexpr uint32_t kSGbZerofill = 0xC;
inline constexpr uint32_t kSThreadLocalRegular = 0x11;
inline constexpr uint32_t kSThreadLocalZerofill = 0x12;
inline constexpr uint32_t kSThreadLocalVariables = 0x13;
inline constexpr uint32_t kSThreadLocalVariablePointers = 0x14;
inline constexpr uint32_t kSThreadLocalInitFunctionPointers = 0x15;
inline constexpr uint32_t kSInitFuncOffsets = 0x16;

// VM protections
inline constexpr uint32_t kVmProtRead = 1;
inline constexpr uint32_t kVmProtWrite = 2;
inline constexpr uint32_t kVmProtExecute = 4;

struct Section {
  std::string segment;
  std::string name;
  uint64_t addr = 0;  // unslid
  uint64_t size = 0;
  uint32_t offset = 0;  // in the slice
  uint32_t align = 0;   // power of two
  uint32_t flags = 0;
  uint32_t reserved1 = 0;  // stubs and symbol pointers: first index into the indirect symbol table
  uint32_t reserved2 = 0;  // stubs: the size of one stub

  uint32_t type() const { return flags & 0xFF; }
  bool zerofill() const {
    return type() == kSZerofill || type() == kSGbZerofill || type() == kSThreadLocalZerofill;
  }
};

struct Segment {
  std::string name;
  uint64_t vmaddr = 0;  // unslid
  uint64_t vmsize = 0;
  uint64_t fileoff = 0;  // in the slice
  uint64_t filesize = 0;
  uint32_t maxprot = 0;
  uint32_t initprot = 0;
  uint32_t flags = 0;
  std::vector<Section> sections;
};

// A library the image links: ordinal k (1-based, as binds name them) is dylibs[k - 1].
struct DylibRef {
  enum class Kind : uint8_t { Load, Weak, Reexport, Lazy, Upward };
  std::string name;  // install name: an absolute path or @rpath/@executable_path/@loader_path/...
  Kind kind = Kind::Load;
  uint32_t current_version = 0;
  uint32_t compatibility_version = 0;
};

// A range of the __LINKEDIT data (offsets in the slice), absent if size == 0.
struct LinkeditData {
  uint32_t offset = 0;
  uint32_t size = 0;
  bool present() const { return size != 0; }
};

struct MachOFile {
  uint32_t cputype = 0;
  uint32_t cpusubtype = 0;
  uint32_t filetype = 0;  // kMhExecute, kMhDylib, kMhBundle
  uint32_t flags = 0;
  uint64_t slice_offset = 0;  // of the slice in the file (non-zero in a universal file)
  uint64_t slice_size = 0;
  uint32_t header_size = 0;   // mach_header_64 plus the load commands

  std::vector<Segment> segments;  // in load command order (segment indexes as fixups use them)
  std::vector<DylibRef> dylibs;
  std::vector<std::string> rpaths;  // LC_RPATH, unexpanded
  std::string install_name;         // LC_ID_DYLIB
  std::string dylinker;             // LC_LOAD_DYLINKER

  bool has_main = false;          // LC_MAIN
  uint64_t entry_offset = 0;      //   entry point: offset from the __TEXT segment's start
  uint64_t stack_size = 0;        //   requested stack size (0 = default)
  bool has_unix_thread = false;   // LC_UNIXTHREAD (old executables)
  uint64_t thread_pc = 0;         //   the initial pc (unslid)

  // Fixups and symbols
  LinkeditData rebase, bind, weak_bind, lazy_bind, export_info;  // LC_DYLD_INFO(_ONLY)
  LinkeditData chained_fixups;  // LC_DYLD_CHAINED_FIXUPS
  LinkeditData exports_trie;    // LC_DYLD_EXPORTS_TRIE
  LinkeditData function_starts, data_in_code, code_signature;
  uint32_t symoff = 0, nsyms = 0, stroff = 0, strsize = 0;      // LC_SYMTAB
  uint32_t indirectsymoff = 0, nindirectsyms = 0;               // LC_DYSYMTAB
  uint32_t ilocalsym = 0, nlocalsym = 0, iextdefsym = 0, nextdefsym = 0, iundefsym = 0, nundefsym = 0;

  // LC_BUILD_VERSION / LC_VERSION_MIN_MACOSX: versions are xxxx.yy.zz nibbles
  uint32_t platform = 0;  // 1 = macOS, 6 = Mac Catalyst, 2 = iOS, ...
  uint32_t min_os = 0;
  uint32_t sdk = 0;

  bool encrypted = false;  // LC_ENCRYPTION_INFO_64 with cryptid != 0 (FairPlay)

  bool is_arm64e() const { return cputype == kCpuTypeArm64 && (cpusubtype & 0xFFFFFF) == kCpuSubtypeArm64e; }
  bool is_pie() const { return filetype != kMhExecute || (flags & kMhPie); }

  // Address range of the segments that occupy memory (all but __PAGEZERO), unslid.
  uint64_t min_address() const;
  uint64_t max_address() const;
  // The segment mapping file offset 0 (__TEXT): the address of the mach header.
  uint64_t header_address() const;
  // The entry point (unslid), 0 if none.
  uint64_t entry_address() const;

  const Segment* segment(std::string_view name) const;
  const Section* section(std::string_view segment_name, std::string_view section_name) const;
  // The segment and section containing `addr` (unslid), nullptr if none.
  const Segment* segment_at(uint64_t addr) const;
  const Section* section_at(uint64_t addr) const;
  // The file offset (in the slice) holding `addr`, if it has file data.
  bool file_offset_of(uint64_t addr, uint64_t& offset) const;
};

// Reads `size` bytes at `offset` of the file; false if out of range.
using FileReader = std::function<bool(uint64_t offset, void* out, size_t size)>;

struct FatArch {
  uint32_t cputype = 0;
  uint32_t cpusubtype = 0;
  uint64_t offset = 0;
  uint64_t size = 0;
};

// The slices of a universal file; one entry spanning the whole file for a
// thin Mach-O file; empty (with an error) for anything else.
std::expected<std::vector<FatArch>, std::string> macho_slices(const FileReader& read, uint64_t file_size);

// Parses the 64-bit Mach-O image for `cputype` (choosing the slice of a
// universal file; plain arm64 is preferred over arm64e).
std::expected<MachOFile, std::string> parse_macho(const FileReader& read, uint64_t file_size,
                                                  uint32_t cputype = kCpuTypeArm64);

// True if the first bytes of a file are a Mach-O or universal header.
bool is_macho(const uint8_t* header, size_t size);

// "libSystem" for "/usr/lib/libSystem.B.dylib", "Foundation" for
// ".../Foundation.framework/Versions/C/Foundation" (for diagnostics, as
// Apple's tools name libraries).
std::string dylib_short_name(std::string_view install_name);

// "x.y.z" for a packed version.
std::string version_string(uint32_t version);

inline constexpr uint64_t kPageSize4K = 0x1000;
inline constexpr uint64_t kPageSize16K = 0x4000;

}  // namespace juice::mac
