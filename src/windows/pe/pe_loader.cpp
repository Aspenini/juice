#include "windows/pe/pe_loader.hpp"

#include <windows.h>

#include <algorithm>
#include <cstring>
#include <format>

namespace juice::pe {
namespace {

class ImageReader {
 public:
  explicit ImageReader(const LoadedImage& image) : image_(image) {}

  bool valid(uint64_t rva, size_t bytes) const { return rva <= image_.size && image_.size - rva >= bytes; }

  template <typename T>
  bool read(uint64_t rva, T& out) const {
    if (!valid(rva, sizeof(T))) return false;
    std::memcpy(&out, image_.base + rva, sizeof(T));
    return true;
  }

  bool read_string(uint64_t rva, std::string& out) const {
    out.clear();
    while (rva < image_.size) {
      char c = static_cast<char>(image_.base[rva++]);
      if (!c) return true;
      out.push_back(c);
    }
    return false;
  }

  // Converts a VA (as stored in TLS directories) into an RVA.
  bool va_to_rva(uint64_t va, uint64_t& rva) const {
    if (va < image_.address()) return false;
    rva = va - image_.address();
    return rva < image_.size;
  }

 private:
  const LoadedImage& image_;
};

std::expected<void, std::string> apply_relocations(LoadedImage& image, const PeFile& file, int64_t delta) {
  const DataDirectory& dir = file.dirs[kDirBaseReloc];
  if (delta == 0 || dir.size == 0) return {};
  ImageReader r(image);
  uint64_t pos = dir.rva;
  const uint64_t end = uint64_t{dir.rva} + dir.size;
  while (pos + 8 <= end) {
    uint32_t page = 0, block_size = 0;
    if (!r.read(pos, page) || !r.read(pos + 4, block_size)) return std::unexpected("truncated relocation block");
    if (block_size < 8) break;
    for (uint64_t e = pos + 8; e + 2 <= pos + block_size; e += 2) {
      uint16_t entry = 0;
      r.read(e, entry);
      unsigned type = entry >> 12;
      uint64_t target = uint64_t{page} + (entry & 0xFFF);
      switch (type) {
        case 0:  // IMAGE_REL_BASED_ABSOLUTE (padding)
          break;
        case 3: {  // IMAGE_REL_BASED_HIGHLOW
          if (!r.valid(target, 4)) return std::unexpected("relocation outside image");
          uint32_t v;
          std::memcpy(&v, image.base + target, 4);
          v += static_cast<uint32_t>(delta);
          std::memcpy(image.base + target, &v, 4);
          break;
        }
        case 10: {  // IMAGE_REL_BASED_DIR64
          if (!r.valid(target, 8)) return std::unexpected("relocation outside image");
          uint64_t v;
          std::memcpy(&v, image.base + target, 8);
          v += static_cast<uint64_t>(delta);
          std::memcpy(image.base + target, &v, 8);
          break;
        }
        default:
          return std::unexpected(std::format("unsupported base relocation type {}", type));
      }
    }
    pos += block_size;
  }
  image.relocated = true;
  return {};
}

std::expected<void, std::string> parse_imports(LoadedImage& image, const PeFile& file) {
  const DataDirectory& dir = file.dirs[kDirImport];
  if (dir.size == 0) return {};
  ImageReader r(image);
  for (uint64_t desc = dir.rva;; desc += 20) {
    uint32_t ilt = 0, name_rva = 0, iat = 0;
    if (!r.read(desc, ilt) || !r.read(desc + 12, name_rva) || !r.read(desc + 16, iat))
      return std::unexpected("truncated import descriptor");
    if (ilt == 0 && name_rva == 0 && iat == 0) break;
    std::string dll;
    if (!r.read_string(name_rva, dll)) return std::unexpected("bad import DLL name");
    uint32_t lookup = ilt ? ilt : iat;
    for (uint32_t k = 0;; ++k) {
      uint64_t entry = 0;
      if (!r.read(uint64_t{lookup} + 8ull * k, entry)) return std::unexpected("truncated import lookup table");
      if (entry == 0) break;
      Import imp;
      imp.dll = dll;
      imp.iat_rva = iat + 8 * k;
      if (entry >> 63) {
        imp.by_ordinal = true;
        imp.ordinal = static_cast<uint16_t>(entry & 0xFFFF);
      } else if (!r.read_string((entry & 0x7FFFFFFF) + 2, imp.name)) {
        return std::unexpected("bad import name");
      }
      image.imports.push_back(std::move(imp));
    }
  }
  return {};
}

void parse_exports(LoadedImage& image, const PeFile& file) {
  const DataDirectory& dir = file.dirs[kDirExport];
  if (dir.size == 0) return;
  ImageReader r(image);
  uint32_t base = 0, num_functions = 0, num_names = 0, functions = 0, names = 0, ordinals = 0;
  if (!r.read(dir.rva + 16, base) || !r.read(dir.rva + 20, num_functions) || !r.read(dir.rva + 24, num_names) ||
      !r.read(dir.rva + 28, functions) || !r.read(dir.rva + 32, names) || !r.read(dir.rva + 36, ordinals))
    return;
  for (uint32_t i = 0; i < num_functions; ++i) {
    uint32_t rva = 0;
    if (!r.read(functions + 4ull * i, rva) || rva == 0) continue;
    if (rva >= dir.rva && rva < dir.rva + dir.size) {
      // A forwarder: the RVA points at a "DLL.Name" string in the export directory.
      std::string target;
      if (r.read_string(rva, target)) image.forwarders_by_ordinal[base + i] = std::move(target);
      continue;
    }
    image.exports_by_ordinal[base + i] = image.address() + rva;
  }
  for (uint32_t i = 0; i < num_names; ++i) {
    uint32_t name_rva = 0;
    uint16_t index = 0;
    std::string name;
    if (!r.read(names + 4ull * i, name_rva) || !r.read(ordinals + 2ull * i, index) || !r.read_string(name_rva, name))
      continue;
    if (auto it = image.exports_by_ordinal.find(base + index); it != image.exports_by_ordinal.end()) {
      image.exports_by_name[name] = it->second;
    } else if (auto f = image.forwarders_by_ordinal.find(base + index); f != image.forwarders_by_ordinal.end()) {
      image.forwarders_by_name[name] = f->second;
    }
  }
}

void parse_tls(LoadedImage& image, const PeFile& file) {
  const DataDirectory& dir = file.dirs[kDirTls];
  if (dir.size == 0) return;
  ImageReader r(image);
  TlsInfo tls;
  uint64_t callbacks_va = 0;
  if (!r.read(dir.rva + 0, tls.raw_start) || !r.read(dir.rva + 8, tls.raw_end) ||
      !r.read(dir.rva + 16, tls.index_address) || !r.read(dir.rva + 24, callbacks_va) ||
      !r.read(dir.rva + 32, tls.zero_fill))
    return;
  uint64_t rva = 0;
  if (callbacks_va && r.va_to_rva(callbacks_va, rva)) {
    for (;; rva += 8) {
      uint64_t cb = 0;
      if (!r.read(rva, cb) || cb == 0) break;
      tls.callbacks.push_back(cb);
    }
  }
  image.tls = std::move(tls);
}

}  // namespace

bool LoadedImage::is_code(uint64_t addr) const {
  if (!contains(addr)) return false;
  uint64_t rva = addr - address();
  for (const Section& s : sections)
    if ((s.characteristics & kScnMemExecute) && rva >= s.virtual_address &&
        rva < uint64_t{s.virtual_address} + std::max(s.virtual_size, s.raw_size))
      return true;
  return false;
}

std::expected<LoadedImage, std::string> map_image(const PeFile& file) {
  LoadedImage image;
  image.size = file.size_of_image;
  image.preferred_base = file.image_base;
  image.machine = file.machine;
  image.sections = file.sections;

  image.base = static_cast<uint8_t*>(VirtualAlloc(reinterpret_cast<void*>(file.image_base), image.size,
                                                  MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
  if (!image.base) {
    if (file.characteristics & kFileRelocsStripped)
      return std::unexpected(std::format("image cannot be relocated and its preferred base 0x{:x} is in use",
                                         file.image_base));
    image.base = static_cast<uint8_t*>(VirtualAlloc(nullptr, image.size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    if (!image.base) return std::unexpected("out of memory mapping image");
  }

  auto fail = [&](std::string message) -> std::expected<LoadedImage, std::string> {
    unmap_image(image);
    return std::unexpected(std::move(message));
  };

  std::memcpy(image.base, file.data.data(), std::min<size_t>(file.size_of_headers, image.size));
  for (const Section& s : file.sections) {
    if (s.virtual_address >= image.size) return fail(std::format("section {} lies outside the image", s.name));
    size_t n = std::min<size_t>(s.raw_size, s.virtual_size ? s.virtual_size : s.raw_size);
    n = std::min<size_t>(n, image.size - s.virtual_address);
    if (n) std::memcpy(image.base + s.virtual_address, file.data.data() + s.raw_offset, n);
  }

  int64_t delta = static_cast<int64_t>(image.address() - file.image_base);
  if (auto r = apply_relocations(image, file, delta); !r) return fail(r.error());
  if (auto r = parse_imports(image, file); !r) return fail(r.error());
  parse_exports(image, file);
  parse_tls(image, file);
  if (const DataDirectory& ex = file.dirs[kDirException]; ex.rva && ex.size && ex.rva + uint64_t{ex.size} <= image.size)
    image.exception_directory = ex;
  image.entry = file.entry_rva ? image.address() + file.entry_rva : 0;
  return image;
}

void unmap_image(LoadedImage& image) {
  if (image.base) VirtualFree(image.base, 0, MEM_RELEASE);
  image.base = nullptr;
}

}  // namespace juice::pe
