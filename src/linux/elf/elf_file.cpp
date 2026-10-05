#include "linux/elf/elf_file.hpp"

#include <algorithm>
#include <cstring>
#include <format>

namespace juice::lx {

namespace {

template <typename T>
T load(const uint8_t* p) {
  T v;
  std::memcpy(&v, p, sizeof(T));
  return v;
}

}  // namespace

uint16_t elf_machine(const uint8_t* h, size_t size) {
  if (size < 20 || h[0] != 0x7F || h[1] != 'E' || h[2] != 'L' || h[3] != 'F') return 0;
  if (h[4] != 2 || h[5] != 1) return 0;  // ELFCLASS64, little endian
  return load<uint16_t>(h + 18);
}

std::expected<ElfFile, std::string> parse_elf(const FileReader& read, uint16_t expected_machine) {
  uint8_t h[64];
  if (!read(0, h, sizeof(h))) return std::unexpected("file too small for an ELF header");
  const uint16_t machine = elf_machine(h, sizeof(h));
  if (h[0] != 0x7F || h[1] != 'E' || h[2] != 'L' || h[3] != 'F') return std::unexpected("not an ELF file");
  if (h[4] != 2) return std::unexpected("not a 64-bit ELF file");
  if (h[5] != 1) return std::unexpected("not a little-endian ELF file");
  if (machine != expected_machine)
    return std::unexpected(std::format("ELF machine {} (this runs machine {}: AArch64)", machine, expected_machine));

  ElfFile f;
  f.machine = machine;
  f.type = load<uint16_t>(h + 16);
  if (f.type != kEtExec && f.type != kEtDyn) return std::unexpected("not an executable or shared object");
  f.entry = load<uint64_t>(h + 24);
  f.phoff = load<uint64_t>(h + 32);
  f.phentsize = load<uint16_t>(h + 54);
  f.phnum = load<uint16_t>(h + 56);
  if (f.phentsize < 56 || f.phnum == 0 || f.phnum > 4096) return std::unexpected("bad program header table");

  bool have_gnu_stack = false;
  uint64_t lo = ~0ull, hi = 0;
  for (unsigned k = 0; k < f.phnum; ++k) {
    uint8_t p[56];
    if (!read(f.phoff + uint64_t{k} * f.phentsize, p, sizeof(p))) return std::unexpected("truncated program headers");
    ElfSegment s;
    s.type = load<uint32_t>(p + 0);
    s.flags = load<uint32_t>(p + 4);
    s.offset = load<uint64_t>(p + 8);
    s.vaddr = load<uint64_t>(p + 16);
    s.filesz = load<uint64_t>(p + 32);
    s.memsz = load<uint64_t>(p + 40);
    s.align = load<uint64_t>(p + 48);
    if (s.type == kPtLoad) {
      if (s.filesz > s.memsz) return std::unexpected("PT_LOAD file size exceeds memory size");
      if ((s.offset % kPageSize) != (s.vaddr % kPageSize))
        return std::unexpected("PT_LOAD offset and address are not congruent modulo the page size");
      lo = std::min(lo, page_down(s.vaddr));
      hi = std::max(hi, page_up(s.vaddr + s.memsz));
    } else if (s.type == kPtInterp) {
      if (s.filesz == 0 || s.filesz > 4096) return std::unexpected("bad PT_INTERP");
      std::string path(s.filesz, '\0');
      if (!read(s.offset, path.data(), path.size())) return std::unexpected("truncated PT_INTERP");
      if (const size_t nul = path.find('\0'); nul != std::string::npos) path.resize(nul);
      f.interpreter = std::move(path);
    } else if (s.type == kPtPhdr) {
      f.phdr_vaddr = s.vaddr;
    } else if (s.type == kPtGnuStack) {
      have_gnu_stack = true;
      f.executable_stack = (s.flags & kPfX) != 0;
    }
    f.segments.push_back(s);
  }
  if (hi == 0) return std::unexpected("no PT_LOAD segments");
  f.min_vaddr = lo;
  f.max_vaddr = hi;
  if (!have_gnu_stack) f.executable_stack = true;
  if (!f.phdr_vaddr) {
    // No PT_PHDR: the headers are where the PT_LOAD that covers phoff maps them.
    for (const ElfSegment& s : f.segments)
      if (s.type == kPtLoad && f.phoff >= s.offset && f.phoff < s.offset + s.filesz) {
        f.phdr_vaddr = s.vaddr + (f.phoff - s.offset);
        break;
      }
  }
  return f;
}

}  // namespace juice::lx
