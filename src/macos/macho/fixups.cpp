#include "macos/macho/fixups.hpp"

#include <cstring>
#include <format>
#include <map>
#include <tuple>

namespace juice::mac {

namespace {

template <typename T>
T load(const uint8_t* p) {
  T v;
  std::memcpy(&v, p, sizeof(T));
  return v;
}

struct Stream {
  const uint8_t* p;
  const uint8_t* end;
  bool bad = false;

  bool done() const { return p >= end; }
  uint8_t byte() {
    if (p >= end) {
      bad = true;
      return 0;
    }
    return *p++;
  }
  uint64_t uleb() {
    uint64_t v = 0;
    for (unsigned shift = 0;; shift += 7) {
      if (p >= end || shift > 63) {
        bad = true;
        return v;
      }
      const uint8_t b = *p++;
      v |= uint64_t{b & 0x7Fu} << shift;
      if (!(b & 0x80)) return v;
    }
  }
  int64_t sleb() {
    int64_t v = 0;
    unsigned shift = 0;
    uint8_t b;
    do {
      if (p >= end || shift > 63) {
        bad = true;
        return v;
      }
      b = *p++;
      v |= int64_t{b & 0x7F} << shift;
      shift += 7;
    } while (b & 0x80);
    if (shift < 64 && (b & 0x40)) v |= -(int64_t{1} << shift);
    return v;
  }
  std::string cstring() {
    const uint8_t* s = p;
    while (p < end && *p) ++p;
    if (p >= end) {
      bad = true;
      return {};
    }
    std::string r(reinterpret_cast<const char*>(s), p - s);
    ++p;
    return r;
  }
};

class Reader {
 public:
  Reader(const MachOFile& image, const FileReader& read, Fixups& out) : image_(image), read_(read), out_(out) {}

  std::expected<std::vector<uint8_t>, std::string> linkedit(LinkeditData d, const char* what) {
    std::vector<uint8_t> bytes(d.size);
    if (d.offset > image_.slice_size || d.size > image_.slice_size - d.offset ||
        !read_(image_.slice_offset + d.offset, bytes.data(), bytes.size()))
      return std::unexpected(std::format("{} out of the file's range", what));
    return bytes;
  }

  // The 8-byte value stored at `addr` (unslid) in the file.
  std::expected<uint64_t, std::string> pointer_at(uint64_t addr) {
    uint64_t off = 0;
    uint64_t v = 0;
    if (!image_.file_offset_of(addr, off) || addr + 8 < addr || !read_(image_.slice_offset + off, &v, 8))
      return std::unexpected(std::format("fixup at 0x{:x} is outside the file's data", addr));
    return v;
  }

  uint32_t import(std::string name, int ordinal, bool weak) {
    auto key = std::make_tuple(name, ordinal, weak);
    if (auto it = imports_.find(key); it != imports_.end()) return it->second;
    const auto index = static_cast<uint32_t>(out_.imports.size());
    out_.imports.push_back({std::move(name), ordinal, weak});
    imports_.emplace(std::move(key), index);
    return index;
  }

  std::expected<void, std::string> opcode_rebases();
  std::expected<void, std::string> opcode_binds(LinkeditData data, char kind);
  std::expected<void, std::string> chained();

 private:
  std::expected<uint64_t, std::string> segment_address(uint64_t segment, uint64_t offset) {
    if (segment >= image_.segments.size()) return std::unexpected("fixup names a segment that doesn't exist");
    return image_.segments[segment].vmaddr + offset;
  }

  const MachOFile& image_;
  const FileReader& read_;
  Fixups& out_;
  std::map<std::tuple<std::string, int, bool>, uint32_t> imports_;
};

std::expected<void, std::string> Reader::opcode_rebases() {
  auto bytes = linkedit(image_.rebase, "rebase information");
  if (!bytes) return std::unexpected(bytes.error());
  Stream s{bytes->data(), bytes->data() + bytes->size()};
  uint64_t addr = 0;
  bool have_segment = false;
  auto rebase = [&]() -> std::expected<void, std::string> {
    if (!have_segment) return std::unexpected("rebase before its segment is set");
    auto target = pointer_at(addr);
    if (!target) return std::unexpected(target.error());
    out_.rebases.push_back({addr, *target});
    addr += 8;
    return {};
  };
  while (!s.done() && !s.bad) {
    const uint8_t b = s.byte();
    const uint8_t imm = b & 0x0F;
    switch (b & 0xF0) {
      case 0x00:  // DONE
        return {};
      case 0x10:  // SET_TYPE_IMM (pointer: 1; text relocations aren't used on arm64)
        if (imm != 1) return std::unexpected(std::format("rebase type {} is not supported", imm));
        break;
      case 0x20: {  // SET_SEGMENT_AND_OFFSET_ULEB
        auto a = segment_address(imm, s.uleb());
        if (!a) return std::unexpected(a.error());
        addr = *a;
        have_segment = true;
        break;
      }
      case 0x30:  // ADD_ADDR_ULEB
        addr += s.uleb();
        break;
      case 0x40:  // ADD_ADDR_IMM_SCALED
        addr += uint64_t{imm} * 8;
        break;
      case 0x50:  // DO_REBASE_IMM_TIMES
        for (unsigned k = 0; k < imm; ++k)
          if (auto r = rebase(); !r) return r;
        break;
      case 0x60: {  // DO_REBASE_ULEB_TIMES
        const uint64_t n = s.uleb();
        for (uint64_t k = 0; k < n && !s.bad; ++k)
          if (auto r = rebase(); !r) return r;
        break;
      }
      case 0x70: {  // DO_REBASE_ADD_ADDR_ULEB
        if (auto r = rebase(); !r) return r;
        addr += s.uleb();
        break;
      }
      case 0x80: {  // DO_REBASE_ULEB_TIMES_SKIPPING_ULEB
        const uint64_t n = s.uleb();
        const uint64_t skip = s.uleb();
        for (uint64_t k = 0; k < n && !s.bad; ++k) {
          if (auto r = rebase(); !r) return r;
          addr += skip;
        }
        break;
      }
      default:
        return std::unexpected(std::format("unknown rebase opcode 0x{:02x}", b));
    }
  }
  if (s.bad) return std::unexpected("truncated rebase information");
  return {};
}

// kind: 'b' bind, 'l' lazy bind, 'w' weak bind
std::expected<void, std::string> Reader::opcode_binds(LinkeditData data, char kind) {
  auto bytes = linkedit(data, "bind information");
  if (!bytes) return std::unexpected(bytes.error());
  Stream s{bytes->data(), bytes->data() + bytes->size()};
  uint64_t addr = 0;
  bool have_segment = false;
  int ordinal = kind == 'w' ? kOrdinalWeakLookup : 0;
  std::string symbol;
  bool weak_import = false, strong_definition = false;
  int64_t addend = 0;
  auto bind = [&]() -> std::expected<void, std::string> {
    if (!have_segment) return std::unexpected("bind before its segment is set");
    if (symbol.empty()) return std::unexpected("bind without a symbol");
    if (kind == 'w' && strong_definition) return {};  // the image's own strong definition: nothing to bind
    const uint32_t index = import(symbol, ordinal, weak_import);
    (kind == 'w' ? out_.weak_binds : out_.binds).push_back({addr, index, addend});
    addr += 8;
    return {};
  };
  while (!s.done() && !s.bad) {
    const uint8_t b = s.byte();
    const uint8_t imm = b & 0x0F;
    switch (b & 0xF0) {
      case 0x00:  // DONE: ends the stream, except that lazy binds are separate runs
        if (kind != 'l') return {};
        break;
      case 0x10:  // SET_DYLIB_ORDINAL_IMM
        ordinal = imm;
        break;
      case 0x20:  // SET_DYLIB_ORDINAL_ULEB
        ordinal = static_cast<int>(s.uleb());
        break;
      case 0x30:  // SET_DYLIB_SPECIAL_IMM
        ordinal = imm ? static_cast<int8_t>(0xF0 | imm) : 0;
        break;
      case 0x40:  // SET_SYMBOL_TRAILING_FLAGS_IMM
        weak_import = imm & 0x1;
        strong_definition = imm & 0x8;
        symbol = s.cstring();
        break;
      case 0x50:  // SET_TYPE_IMM
        if (imm != 1) return std::unexpected(std::format("bind type {} is not supported", imm));
        break;
      case 0x60:  // SET_ADDEND_SLEB
        addend = s.sleb();
        break;
      case 0x70: {  // SET_SEGMENT_AND_OFFSET_ULEB
        auto a = segment_address(imm, s.uleb());
        if (!a) return std::unexpected(a.error());
        addr = *a;
        have_segment = true;
        break;
      }
      case 0x80:  // ADD_ADDR_ULEB
        addr += s.uleb();
        break;
      case 0x90:  // DO_BIND
        if (auto r = bind(); !r) return r;
        break;
      case 0xA0:  // DO_BIND_ADD_ADDR_ULEB
        if (auto r = bind(); !r) return r;
        addr += s.uleb();
        break;
      case 0xB0:  // DO_BIND_ADD_ADDR_IMM_SCALED
        if (auto r = bind(); !r) return r;
        addr += uint64_t{imm} * 8;
        break;
      case 0xC0: {  // DO_BIND_ULEB_TIMES_SKIPPING_ULEB
        const uint64_t n = s.uleb();
        const uint64_t skip = s.uleb();
        for (uint64_t k = 0; k < n && !s.bad; ++k) {
          if (auto r = bind(); !r) return r;
          addr += skip;
        }
        break;
      }
      case 0xD0:  // THREADED (old arm64e kernel caches)
        return std::unexpected("threaded binds are not supported");
      default:
        return std::unexpected(std::format("unknown bind opcode 0x{:02x}", b));
    }
  }
  if (s.bad) return std::unexpected("truncated bind information");
  return {};
}

// Chained pointer formats (DYLD_CHAINED_PTR_*)
constexpr uint16_t kPtrArm64e = 1;
constexpr uint16_t kPtr64 = 2;
constexpr uint16_t kPtr64Offset = 6;
constexpr uint16_t kPtrArm64eUserland = 9;
constexpr uint16_t kPtrArm64eUserland24 = 12;

uint64_t bits(uint64_t v, unsigned lo, unsigned width) { return (v >> lo) & ((uint64_t{1} << width) - 1); }

std::expected<void, std::string> Reader::chained() {
  auto bytes = linkedit(image_.chained_fixups, "chained fixups");
  if (!bytes) return std::unexpected(bytes.error());
  const std::vector<uint8_t>& d = *bytes;
  if (d.size() < 28) return std::unexpected("truncated chained fixups header");
  const auto starts_offset = load<uint32_t>(&d[4]);
  const auto imports_offset = load<uint32_t>(&d[8]);
  const auto symbols_offset = load<uint32_t>(&d[12]);
  const auto imports_count = load<uint32_t>(&d[16]);
  const auto imports_format = load<uint32_t>(&d[20]);
  const auto symbols_format = load<uint32_t>(&d[24]);
  if (load<uint32_t>(&d[0]) != 0) return std::unexpected("unknown chained fixups version");
  if (symbols_format != 0) return std::unexpected("compressed chained fixup symbols are not supported");

  // Imports, in the order binds name them.
  struct ChainedImport {
    uint32_t index;
    int64_t addend;
  };
  std::vector<ChainedImport> imports;
  const size_t import_size = imports_format == 1 ? 4 : imports_format == 2 ? 8 : imports_format == 3 ? 16 : 0;
  if (!import_size) return std::unexpected(std::format("unknown chained import format {}", imports_format));
  if (imports_offset > d.size() || uint64_t{imports_count} * import_size > d.size() - imports_offset)
    return std::unexpected("chained fixup imports out of range");
  auto symbol_name = [&](uint64_t offset) -> std::expected<std::string, std::string> {
    const uint64_t at = uint64_t{symbols_offset} + offset;
    if (at >= d.size()) return std::unexpected("chained import name out of range");
    const auto* p = reinterpret_cast<const char*>(&d[at]);
    return std::string(p, strnlen(p, d.size() - at));
  };
  for (uint32_t k = 0; k < imports_count; ++k) {
    const uint8_t* p = &d[imports_offset + k * import_size];
    int ordinal;
    bool weak;
    uint64_t name_offset;
    int64_t addend = 0;
    if (imports_format == 3) {
      const auto v = load<uint64_t>(p);
      ordinal = static_cast<int>(bits(v, 0, 16));
      weak = bits(v, 16, 1);
      name_offset = bits(v, 32, 32);
      addend = load<int64_t>(p + 8);
    } else {
      const auto v = load<uint32_t>(p);
      ordinal = static_cast<int>(bits(v, 0, 8));
      weak = bits(v, 8, 1);
      name_offset = bits(v, 9, 23);
      if (imports_format == 2) addend = load<int32_t>(p + 4);
    }
    // Ordinals 0xF0.. (0xFFF0.. for 16-bit ordinals) are the specials; others are unsigned.
    if (imports_format == 3) {
      const auto raw = static_cast<uint16_t>(ordinal);
      ordinal = raw >= 0xFFF0 ? static_cast<int16_t>(raw) : raw;
    } else {
      const auto raw = static_cast<uint8_t>(ordinal);
      ordinal = raw >= 0xF0 ? static_cast<int8_t>(raw) : raw;
    }
    auto name = symbol_name(name_offset);
    if (!name) return std::unexpected(name.error());
    imports.push_back({import(std::move(*name), ordinal, weak), addend});
  }

  // Starts in the image: one entry per segment (load command order).
  if (starts_offset > d.size() - 4) return std::unexpected("chained starts out of range");
  const auto seg_count = load<uint32_t>(&d[starts_offset]);
  if (uint64_t{seg_count} * 4 > d.size() - starts_offset - 4) return std::unexpected("chained starts out of range");
  const uint64_t header = image_.header_address();
  out_.chained = true;

  for (uint32_t seg = 0; seg < seg_count; ++seg) {
    const auto info_offset = load<uint32_t>(&d[starts_offset + 4 + seg * 4]);
    if (!info_offset) continue;
    const uint64_t info = uint64_t{starts_offset} + info_offset;
    if (info + 22 > d.size()) return std::unexpected("chained segment starts out of range");
    const auto page_size = load<uint16_t>(&d[info + 4]);
    const auto format = load<uint16_t>(&d[info + 6]);
    const auto segment_offset = load<uint64_t>(&d[info + 8]);
    const auto page_count = load<uint16_t>(&d[info + 20]);
    if (info + 22 + uint64_t{page_count} * 2 > d.size()) return std::unexpected("chained page starts out of range");
    out_.pointer_format = format;
    const bool arm64e = format == kPtrArm64e || format == kPtrArm64eUserland || format == kPtrArm64eUserland24;
    if (!arm64e && format != kPtr64 && format != kPtr64Offset)
      return std::unexpected(std::format("chained pointer format {} is not supported", format));
    const unsigned stride = arm64e ? 8 : 4;

    for (uint16_t page = 0; page < page_count; ++page) {
      const auto start = load<uint16_t>(&d[info + 22 + page * 2]);
      if (start == 0xFFFF) continue;  // DYLD_CHAINED_PTR_START_NONE
      if (start & 0x8000) return std::unexpected("multiple chain starts per page are not supported (32-bit only)");
      uint64_t addr = header + segment_offset + uint64_t{page} * page_size + start;
      for (unsigned guard = 0; guard < 0x10000; ++guard) {
        auto raw = pointer_at(addr);
        if (!raw) return std::unexpected(raw.error());
        const uint64_t v = *raw;
        uint64_t next;
        auto bind = [&](uint64_t ordinal, int64_t inline_addend) -> std::expected<void, std::string> {
          if (ordinal >= imports.size()) return std::unexpected(std::format("chained bind at 0x{:x} names import {} of {}", addr, ordinal, imports.size()));
          out_.binds.push_back({addr, imports[ordinal].index, imports[ordinal].addend + inline_addend});
          return {};
        };
        if (arm64e) {
          next = bits(v, 51, 11);
          const bool is_bind = bits(v, 62, 1), is_auth = bits(v, 63, 1);
          const bool wide = format == kPtrArm64eUserland24;
          if (is_bind) {
            const uint64_t ordinal = bits(v, 0, wide ? 24 : 16);
            int64_t addend = 0;
            if (!is_auth) {
              addend = static_cast<int64_t>(bits(v, 32, 19));
              if (addend & (int64_t{1} << 18)) addend -= int64_t{1} << 19;  // signed 19 bits
            }
            if (auto r = bind(ordinal, addend); !r) return r;
          } else if (is_auth) {
            out_.rebases.push_back({addr, header + bits(v, 0, 32)});  // an offset from the header
          } else {
            uint64_t target = bits(v, 0, 43) | bits(v, 43, 8) << 56;
            if (format != kPtrArm64e) target += header;  // userland formats: an offset
            out_.rebases.push_back({addr, target});
          }
        } else {
          next = bits(v, 51, 12);
          if (bits(v, 63, 1)) {
            if (auto r = bind(bits(v, 0, 24), static_cast<int64_t>(bits(v, 24, 8))); !r) return r;
          } else {
            uint64_t target = bits(v, 0, 36) | bits(v, 36, 8) << 56;
            if (format == kPtr64Offset) target += header;
            out_.rebases.push_back({addr, target});
          }
        }
        if (!next) break;
        addr += next * stride;
      }
    }
  }
  return {};
}

}  // namespace

std::expected<Fixups, std::string> read_fixups(const MachOFile& image, const FileReader& read) {
  Fixups out;
  Reader r(image, read, out);
  if (image.chained_fixups.present()) {
    if (auto c = r.chained(); !c) return std::unexpected(c.error());
    return out;
  }
  if (image.rebase.present())
    if (auto c = r.opcode_rebases(); !c) return std::unexpected(c.error());
  if (image.bind.present())
    if (auto c = r.opcode_binds(image.bind, 'b'); !c) return std::unexpected(c.error());
  if (image.lazy_bind.present())
    if (auto c = r.opcode_binds(image.lazy_bind, 'l'); !c) return std::unexpected(c.error());
  if (image.weak_bind.present())
    if (auto c = r.opcode_binds(image.weak_bind, 'w'); !c) return std::unexpected(c.error());
  return out;
}

std::string ordinal_name(const MachOFile& image, int ordinal) {
  switch (ordinal) {
    case kOrdinalSelf: return "this-image";
    case kOrdinalMainExecutable: return "main-executable";
    case kOrdinalFlatLookup: return "flat-namespace";
    case kOrdinalWeakLookup: return "weak";
    default:
      if (ordinal > 0 && static_cast<size_t>(ordinal) <= image.dylibs.size())
        return dylib_short_name(image.dylibs[ordinal - 1].name);
      return std::format("ordinal-{}", ordinal);
  }
}

}  // namespace juice::mac
