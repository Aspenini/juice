#pragma once

// A Mach-O image (the program, a library, a bundle) mapped for the guest:
// segments copied into memory at a slide, rebases applied. Binds are applied
// by the process, which knows the other images (bind_image()).

#include <cstdint>
#include <expected>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "macos/macho/exports.hpp"
#include "macos/macho/fixups.hpp"
#include "macos/macho/macho_file.hpp"

namespace juice::mac {

struct GuestImage;

// A library an image links (by ordinal).
struct Dependency {
  enum class Kind : uint8_t { Guest, Native, Missing };
  Kind kind = Kind::Missing;
  std::string name;          // the install name as the image names it
  GuestImage* image = nullptr;  // Guest
  void* native = nullptr;       // Native: the host's library handle
};

struct GuestImage {
  std::string path;          // the file it came from
  std::string install_name;  // LC_ID_DYLIB, or the path
  MachOFile file;
  Fixups fixups;
  std::vector<uint8_t> exports;  // the export trie
  uint64_t slide = 0;
  uint64_t base = 0, size = 0;   // the memory reserved for it
  std::vector<Dependency> dependencies;  // dependencies[k] is library ordinal k + 1
  bool main = false;
  bool initialized = false;

  uint64_t header() const { return file.header_address() + slide; }
  uint64_t address(uint64_t unslid) const { return unslid + slide; }
  bool contains(uint64_t addr) const { return addr >= base && addr - base < size; }
  // Is `addr` in a segment the guest may execute?
  bool is_code(uint64_t addr) const;
  // A section's address range in memory ({0, 0} if absent).
  std::pair<uint64_t, uint64_t> section_range(std::string_view segment, std::string_view section) const;
  // A section's contents in memory as `T`s.
  template <typename T>
  std::span<T> section_data(std::string_view segment, std::string_view section) const {
    const auto [begin, end] = section_range(segment, section);
    return {reinterpret_cast<T*>(begin), static_cast<size_t>((end - begin) / sizeof(T))};
  }
  // An exported symbol's address (not following re-exports; see the process).
  std::optional<Export> find_export(std::string_view name) const { return mac::find_export(exports, name); }
};

// Maps the image for `cputype` in the file at `path` (read through `read`):
// reserves memory, copies the segments, applies rebases, reads the binds and
// exports. Segments get their protections (without execute) from
// protect_image(), after the process applied the binds.
std::expected<std::unique_ptr<GuestImage>, std::string> map_image(const std::string& path, const FileReader& read,
                                                                  uint64_t file_size, uint32_t cputype = kCpuTypeArm64);

// Writes `value` to the pointer at runtime address `addr` of `image`.
void write_pointer(uint64_t addr, uint64_t value);

// Applies the segments' initial protections (read-only __TEXT, __DATA_CONST
// after binding; never executable for the host).
void protect_image(const GuestImage& image);

// Releases an image's memory.
void unmap_image(GuestImage& image);

}  // namespace juice::mac
