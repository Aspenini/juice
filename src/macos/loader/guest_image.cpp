#include "macos/loader/guest_image.hpp"

#include <cstring>
#include <format>

#include "macos/loader/host_memory.hpp"

namespace juice::mac {

namespace {

constexpr uint64_t kImageAlign = kPageSize16K;  // ARM64 macOS images are laid out in 16 KB pages

uint64_t align_up(uint64_t v, uint64_t a) { return (v + a - 1) & ~(a - 1); }

}  // namespace

bool GuestImage::is_code(uint64_t addr) const {
  if (!contains(addr)) return false;
  const Segment* s = file.segment_at(addr - slide);
  return s && (s->initprot & kVmProtExecute);
}

std::pair<uint64_t, uint64_t> GuestImage::section_range(std::string_view segment, std::string_view section) const {
  const Section* s = file.section(segment, section);
  if (!s) return {0, 0};
  return {s->addr + slide, s->addr + slide + s->size};
}

void write_pointer(uint64_t addr, uint64_t value) { std::memcpy(reinterpret_cast<void*>(addr), &value, 8); }

std::expected<std::unique_ptr<GuestImage>, std::string> map_image(const std::string& path, const FileReader& read,
                                                                  uint64_t file_size, uint32_t cputype) {
  auto file = parse_macho(read, file_size, cputype);
  if (!file) return std::unexpected(file.error());
  if (file->encrypted) return std::unexpected("the image is encrypted (FairPlay): JUICE can't run it");
  auto image = std::make_unique<GuestImage>();
  image->path = path;
  image->file = std::move(*file);
  const MachOFile& f = image->file;
  image->install_name = f.install_name.empty() ? path : f.install_name;
  image->main = f.filetype == kMhExecute;

  const uint64_t lo = f.min_address(), hi = f.max_address();
  if (hi <= lo) return std::unexpected("the image occupies no memory");
  const uint64_t size = align_up(hi - lo, kImageAlign);
  // Reserve a 16 KB aligned range (at the image's own address if it's free).
  uint64_t reserved = reserve_memory(size + kImageAlign, lo);
  if (!reserved) return std::unexpected(std::format("can't reserve {} bytes for the image", size));
  const uint64_t base = align_up(reserved, kImageAlign);
  if (!f.is_pie() && base != lo) {
    release_memory(reserved, size + kImageAlign);
    return std::unexpected(std::format("the program must be loaded at 0x{:x}, which is in use", lo));
  }
  image->base = reserved;
  image->size = size + kImageAlign;
  image->slide = base - lo;

  for (const Segment& s : f.segments) {
    if (!s.filesize || !(s.initprot | s.maxprot)) continue;
    const uint64_t at = s.vmaddr + image->slide;
    if (!read(f.slice_offset + s.fileoff, reinterpret_cast<void*>(at), s.filesize))
      return std::unexpected(std::format("can't read segment {}", s.name));
  }

  auto fixups = read_fixups(f, read);
  if (!fixups) return std::unexpected("fixups: " + fixups.error());
  image->fixups = std::move(*fixups);
  for (const Rebase& r : image->fixups.rebases) write_pointer(r.address + image->slide, r.target + image->slide);

  const LinkeditData trie = f.exports_trie.present() ? f.exports_trie : f.export_info;
  if (trie.present()) {
    image->exports.resize(trie.size);
    if (!read(f.slice_offset + trie.offset, image->exports.data(), trie.size))
      return std::unexpected("can't read the export trie");
  }
  image->dependencies.resize(f.dylibs.size());
  for (size_t k = 0; k < f.dylibs.size(); ++k) image->dependencies[k].name = f.dylibs[k].name;
  return image;
}

void protect_image(const GuestImage& image) {
  for (const Segment& s : image.file.segments) {
    if (!s.vmsize || !(s.initprot | s.maxprot)) continue;
    int prot = kProtNone;
    if (s.initprot & (kVmProtRead | kVmProtExecute)) prot |= kProtRead;
    if (s.initprot & kVmProtWrite) prot |= kProtWrite;
    // __DATA_CONST is read-only after binding (initprot says so); the
    // Objective-C runtime may write to it later, so keep it writable when
    // its maximum protection allows.
    if (s.maxprot & kVmProtWrite && s.name == "__DATA_CONST") prot |= kProtWrite;
    const uint64_t begin = (s.vmaddr + image.slide) & ~(kHostPageSize - 1);
    const uint64_t end = align_up(s.vmaddr + image.slide + s.vmsize, kHostPageSize);
    protect_memory(begin, end - begin, prot);
  }
}

void unmap_image(GuestImage& image) {
  if (image.base) release_memory(image.base, image.size);
  image.base = image.size = 0;
}

}  // namespace juice::mac
