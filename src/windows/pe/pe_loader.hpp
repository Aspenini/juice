#pragma once

// Maps a PE image into the host address space for translation.
//
// Guest images are mapped read/write but NOT executable: the host never runs
// guest code directly, so any accidental native jump into the image faults
// immediately instead of executing ARM64 bytes as x86-64.

#include <cstdint>
#include <expected>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "windows/pe/pe_file.hpp"

namespace juice::pe {

struct Import {
  std::string dll;       // as written in the import table
  std::string name;      // empty when imported by ordinal
  uint16_t ordinal = 0;
  bool by_ordinal = false;
  uint32_t iat_rva = 0;  // address of the 64-bit IAT slot
};

struct TlsInfo {
  uint64_t raw_start = 0;  // VA of the TLS template
  uint64_t raw_end = 0;
  uint64_t index_address = 0;
  uint32_t zero_fill = 0;
  std::vector<uint64_t> callbacks;
};

struct LoadedImage {
  uint8_t* base = nullptr;
  size_t size = 0;
  uint64_t preferred_base = 0;
  uint64_t entry = 0;  // 0 if none
  uint16_t machine = 0;
  bool relocated = false;
  std::vector<Section> sections;
  std::vector<Import> imports;
  std::unordered_map<std::string, uint64_t> exports_by_name;
  std::unordered_map<uint32_t, uint64_t> exports_by_ordinal;
  std::optional<TlsInfo> tls;
  DataDirectory exception_directory;  // .pdata: RUNTIME_FUNCTION entries sorted by address

  uint64_t address() const { return reinterpret_cast<uint64_t>(base); }
  bool contains(uint64_t addr) const { return addr >= address() && addr - address() < size; }
  // True if `addr` lies in a section marked executable.
  bool is_code(uint64_t addr) const;
  template <typename T>
  T* at_rva(uint32_t rva) const { return reinterpret_cast<T*>(base + rva); }
};

std::expected<LoadedImage, std::string> map_image(const PeFile& file);
void unmap_image(LoadedImage& image);

}  // namespace juice::pe
