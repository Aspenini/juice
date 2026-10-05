#pragma once

// ELF64 parsing for Linux AArch64 programs (portable: no Linux headers).

#include <cstdint>
#include <expected>
#include <functional>
#include <string>
#include <vector>

namespace juice::lx {

inline constexpr uint16_t kEtExec = 2;
inline constexpr uint16_t kEtDyn = 3;
inline constexpr uint16_t kEmAarch64 = 183;
inline constexpr uint16_t kEmX86_64 = 62;

inline constexpr uint32_t kPtLoad = 1;
inline constexpr uint32_t kPtInterp = 3;
inline constexpr uint32_t kPtPhdr = 6;
inline constexpr uint32_t kPtTls = 7;
inline constexpr uint32_t kPtGnuStack = 0x6474e551;

inline constexpr uint32_t kPfX = 1;
inline constexpr uint32_t kPfW = 2;
inline constexpr uint32_t kPfR = 4;

struct ElfSegment {
  uint32_t type = 0;
  uint32_t flags = 0;  // kPfR | kPfW | kPfX
  uint64_t offset = 0;
  uint64_t vaddr = 0;
  uint64_t filesz = 0;
  uint64_t memsz = 0;
  uint64_t align = 0;
};

struct ElfFile {
  uint16_t type = 0;     // kEtExec or kEtDyn
  uint16_t machine = 0;  // kEmAarch64
  uint64_t entry = 0;    // unrelocated
  uint64_t phoff = 0;
  uint16_t phentsize = 0;
  uint16_t phnum = 0;
  std::vector<ElfSegment> segments;  // all program headers
  std::string interpreter;           // PT_INTERP, empty for static programs
  bool executable_stack = false;     // PT_GNU_STACK with PF_X (or no PT_GNU_STACK)
  uint64_t min_vaddr = 0;            // page-aligned extent of the PT_LOAD segments
  uint64_t max_vaddr = 0;
  uint64_t phdr_vaddr = 0;           // where the program headers are in memory (unrelocated), 0 if not loaded

  bool is_dynamic() const { return type == kEtDyn; }  // position independent: loaded at a chosen base
};

// Reads `size` bytes at `offset` of the file; false if out of range.
using FileReader = std::function<bool(uint64_t offset, void* out, size_t size)>;

// Parse an AArch64 ELF64 executable or shared object.
std::expected<ElfFile, std::string> parse_elf(const FileReader& read, uint16_t expected_machine = kEmAarch64);

// The ELF machine of a file header (0 if `header` is not an ELF64 little-endian file).
// `header` must hold at least 20 bytes.
uint16_t elf_machine(const uint8_t* header, size_t size);

inline constexpr uint64_t kPageSize = 4096;
inline uint64_t page_down(uint64_t v) { return v & ~(kPageSize - 1); }
inline uint64_t page_up(uint64_t v) { return (v + kPageSize - 1) & ~(kPageSize - 1); }

}  // namespace juice::lx
