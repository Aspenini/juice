#include "windows/pe/pe_file.hpp"

#include <algorithm>
#include <cstring>
#include <format>
#include <fstream>

namespace juice::pe {
namespace {

template <typename T>
bool read_at(const std::vector<uint8_t>& data, size_t offset, T& out) {
  if (offset > data.size() || data.size() - offset < sizeof(T)) return false;
  std::memcpy(&out, data.data() + offset, sizeof(T));
  return true;
}

}  // namespace

const char* machine_name(uint16_t machine) {
  switch (machine) {
    case kMachineAmd64: return "x86-64";
    case kMachineArm64: return "ARM64";
    case kMachineArm64EC: return "ARM64EC";
    case kMachineArm64X: return "ARM64X";
    case 0x014C: return "x86";
    case 0x01C4: return "ARM (Thumb-2)";
    default: return "unknown";
  }
}

std::expected<PeFile, std::string> parse_pe(std::vector<uint8_t> data) {
  PeFile pe;
  uint16_t mz = 0;
  if (!read_at(data, 0, mz) || mz != 0x5A4D) return std::unexpected("not an MZ executable");
  uint32_t nt = 0;
  if (!read_at(data, 0x3C, nt)) return std::unexpected("truncated DOS header");
  uint32_t sig = 0;
  if (!read_at(data, nt, sig) || sig != 0x00004550) return std::unexpected("missing PE signature");

  // IMAGE_FILE_HEADER
  const size_t fh = nt + 4;
  uint16_t num_sections = 0, opt_size = 0;
  if (!read_at(data, fh + 0, pe.machine) || !read_at(data, fh + 2, num_sections) ||
      !read_at(data, fh + 16, opt_size) || !read_at(data, fh + 18, pe.characteristics))
    return std::unexpected("truncated file header");

  // IMAGE_OPTIONAL_HEADER64
  const size_t oh = fh + 20;
  uint16_t magic = 0;
  if (!read_at(data, oh, magic)) return std::unexpected("truncated optional header");
  if (magic != 0x20B) return std::unexpected("not a PE32+ (64-bit) image");
  uint32_t num_dirs = 0;
  if (!read_at(data, oh + 16, pe.entry_rva) || !read_at(data, oh + 24, pe.image_base) ||
      !read_at(data, oh + 32, pe.section_alignment) || !read_at(data, oh + 56, pe.size_of_image) ||
      !read_at(data, oh + 60, pe.size_of_headers) || !read_at(data, oh + 68, pe.subsystem) ||
      !read_at(data, oh + 70, pe.dll_characteristics) || !read_at(data, oh + 72, pe.stack_reserve) ||
      !read_at(data, oh + 80, pe.stack_commit) || !read_at(data, oh + 108, num_dirs))
    return std::unexpected("truncated optional header");
  num_dirs = std::min<uint32_t>(num_dirs, 16);
  for (uint32_t i = 0; i < num_dirs; ++i) {
    if (!read_at(data, oh + 112 + 8 * i, pe.dirs[i].rva) || !read_at(data, oh + 116 + 8 * i, pe.dirs[i].size))
      return std::unexpected("truncated data directories");
  }

  // Section table
  const size_t st = oh + opt_size;
  for (uint16_t i = 0; i < num_sections; ++i) {
    const size_t s = st + 40 * size_t{i};
    char name[9] = {};
    if (s + 40 > data.size()) return std::unexpected("truncated section table");
    std::memcpy(name, data.data() + s, 8);
    Section sec;
    sec.name = name;
    read_at(data, s + 8, sec.virtual_size);
    read_at(data, s + 12, sec.virtual_address);
    read_at(data, s + 16, sec.raw_size);
    read_at(data, s + 20, sec.raw_offset);
    read_at(data, s + 36, sec.characteristics);
    if (sec.raw_size && (sec.raw_offset > data.size() || data.size() - sec.raw_offset < sec.raw_size))
      return std::unexpected(std::format("section {} extends past end of file", sec.name));
    pe.sections.push_back(sec);
  }

  if (pe.size_of_image == 0 || pe.size_of_headers > data.size())
    return std::unexpected("invalid image size");

  pe.data = std::move(data);
  return pe;
}

std::expected<PeFile, std::string> read_pe_file(const std::filesystem::path& path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) return std::unexpected(std::format("cannot open '{}'", path.string()));
  std::vector<uint8_t> data((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
  return parse_pe(std::move(data));
}

}  // namespace juice::pe
