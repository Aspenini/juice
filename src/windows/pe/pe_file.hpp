#pragma once

// PE/COFF file parsing (no OS dependencies).

#include <array>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <string>
#include <vector>

namespace juice::pe {

inline constexpr uint16_t kMachineAmd64 = 0x8664;
inline constexpr uint16_t kMachineArm64 = 0xAA64;
inline constexpr uint16_t kMachineArm64EC = 0xA641;
inline constexpr uint16_t kMachineArm64X = 0xA64E;

inline constexpr uint32_t kScnMemExecute = 0x20000000;
inline constexpr uint32_t kScnMemRead = 0x40000000;
inline constexpr uint32_t kScnMemWrite = 0x80000000;

inline constexpr uint16_t kFileRelocsStripped = 0x0001;
inline constexpr uint16_t kFileDll = 0x2000;

enum DirectoryIndex : unsigned {
  kDirExport = 0,
  kDirImport = 1,
  kDirResource = 2,
  kDirException = 3,
  kDirSecurity = 4,
  kDirBaseReloc = 5,
  kDirDebug = 6,
  kDirTls = 9,
  kDirLoadConfig = 10,
  kDirIat = 12,
  kDirDelayImport = 13,
};

struct DataDirectory {
  uint32_t rva = 0;
  uint32_t size = 0;
};

struct Section {
  std::string name;
  uint32_t virtual_address = 0;
  uint32_t virtual_size = 0;
  uint32_t raw_offset = 0;
  uint32_t raw_size = 0;
  uint32_t characteristics = 0;
};

struct PeFile {
  std::vector<uint8_t> data;

  uint16_t machine = 0;
  uint16_t characteristics = 0;
  uint64_t image_base = 0;
  uint32_t entry_rva = 0;
  uint32_t size_of_image = 0;
  uint32_t size_of_headers = 0;
  uint32_t section_alignment = 0;
  uint16_t subsystem = 0;
  uint16_t dll_characteristics = 0;
  uint64_t stack_reserve = 0;
  uint64_t stack_commit = 0;
  std::array<DataDirectory, 16> dirs{};
  std::vector<Section> sections;

  bool is_dll() const { return (characteristics & kFileDll) != 0; }
};

const char* machine_name(uint16_t machine);

std::expected<PeFile, std::string> parse_pe(std::vector<uint8_t> data);
std::expected<PeFile, std::string> read_pe_file(const std::filesystem::path& path);

}  // namespace juice::pe
