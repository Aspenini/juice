#include "macos/macho/macho_file.hpp"

#include <algorithm>
#include <cstring>
#include <format>

namespace juice::mac {

namespace {

template <typename T>
T load(const uint8_t* p) {
  T v;
  std::memcpy(&v, p, sizeof(T));
  return v;
}

uint32_t load_be32(const uint8_t* p) {
  return uint32_t{p[0]} << 24 | uint32_t{p[1]} << 16 | uint32_t{p[2]} << 8 | p[3];
}
uint64_t load_be64(const uint8_t* p) { return uint64_t{load_be32(p)} << 32 | load_be32(p + 4); }

std::string fixed_string(const uint8_t* p, size_t max) {
  size_t n = 0;
  while (n < max && p[n]) ++n;
  return {reinterpret_cast<const char*>(p), n};
}

constexpr uint32_t kMagic64 = 0xFEEDFACF;
constexpr uint32_t kFatMagic = 0xCAFEBABE;
constexpr uint32_t kFatMagic64 = 0xCAFEBABF;

constexpr uint32_t kLcReqDyld = 0x80000000;
constexpr uint32_t kLcSymtab = 0x2;
constexpr uint32_t kLcUnixThread = 0x5;
constexpr uint32_t kLcDysymtab = 0xB;
constexpr uint32_t kLcLoadDylib = 0xC;
constexpr uint32_t kLcIdDylib = 0xD;
constexpr uint32_t kLcLoadDylinker = 0xE;
constexpr uint32_t kLcLoadWeakDylib = 0x18 | kLcReqDyld;
constexpr uint32_t kLcSegment64 = 0x19;
constexpr uint32_t kLcRpath = 0x1C | kLcReqDyld;
constexpr uint32_t kLcCodeSignature = 0x1D;
constexpr uint32_t kLcReexportDylib = 0x1F | kLcReqDyld;
constexpr uint32_t kLcLazyLoadDylib = 0x20;
constexpr uint32_t kLcDyldInfo = 0x22;
constexpr uint32_t kLcDyldInfoOnly = 0x22 | kLcReqDyld;
constexpr uint32_t kLcLoadUpwardDylib = 0x23 | kLcReqDyld;
constexpr uint32_t kLcVersionMinMacosx = 0x24;
constexpr uint32_t kLcFunctionStarts = 0x26;
constexpr uint32_t kLcMain = 0x28 | kLcReqDyld;
constexpr uint32_t kLcDataInCode = 0x29;
constexpr uint32_t kLcEncryptionInfo64 = 0x2C;
constexpr uint32_t kLcBuildVersion = 0x32;
constexpr uint32_t kLcDyldExportsTrie = 0x33 | kLcReqDyld;
constexpr uint32_t kLcDyldChainedFixups = 0x34 | kLcReqDyld;

constexpr uint32_t kArmThreadState64 = 6;
constexpr uint32_t kX86ThreadState64 = 4;

const char* cpu_name(uint32_t cputype, uint32_t cpusubtype) {
  switch (cputype) {
    case kCpuTypeArm64: return (cpusubtype & 0xFFFFFF) == kCpuSubtypeArm64e ? "arm64e" : "arm64";
    case kCpuTypeX86_64: return "x86_64";
    case 7: return "i386";
    case 12: return "arm";
    case 18: return "ppc";
    case 0x01000012: return "ppc64";
    default: return "unknown";
  }
}

// A string inside a load command at `offset` from its start.
std::string command_string(const std::vector<uint8_t>& cmd, uint32_t offset) {
  if (offset >= cmd.size()) return {};
  return fixed_string(cmd.data() + offset, cmd.size() - offset);
}

}  // namespace

bool is_macho(const uint8_t* h, size_t size) {
  if (size < 4) return false;
  const uint32_t le = load<uint32_t>(h);
  const uint32_t be = load_be32(h);
  return le == kMagic64 || le == 0xFEEDFACE || be == kFatMagic || be == kFatMagic64;
}

std::expected<std::vector<FatArch>, std::string> macho_slices(const FileReader& read, uint64_t file_size) {
  uint8_t h[8];
  if (!read(0, h, sizeof(h))) return std::unexpected("file too small for a Mach-O header");
  const uint32_t le = load<uint32_t>(h);
  if (le == kMagic64) {
    uint8_t m[8];
    if (!read(4, m, sizeof(m))) return std::unexpected("truncated Mach-O header");
    return std::vector<FatArch>{{load<uint32_t>(m), load<uint32_t>(m + 4), 0, file_size}};
  }
  if (le == 0xFEEDFACE) return std::unexpected("a 32-bit Mach-O file");
  const uint32_t magic = load_be32(h);
  if (magic != kFatMagic && magic != kFatMagic64) return std::unexpected("not a Mach-O file");
  const uint32_t count = load_be32(h + 4);
  if (count == 0 || count > 64) return std::unexpected("not a Mach-O file");  // (Java class files share the magic)
  std::vector<FatArch> archs;
  const size_t entry = magic == kFatMagic64 ? 32 : 20;
  for (uint32_t k = 0; k < count; ++k) {
    uint8_t e[32];
    if (!read(8 + k * entry, e, entry)) return std::unexpected("truncated universal header");
    FatArch a;
    a.cputype = load_be32(e);
    a.cpusubtype = load_be32(e + 4);
    if (magic == kFatMagic64) {
      a.offset = load_be64(e + 8);
      a.size = load_be64(e + 16);
    } else {
      a.offset = load_be32(e + 8);
      a.size = load_be32(e + 12);
    }
    if (a.offset > file_size || a.size > file_size - a.offset) return std::unexpected("universal slice out of range");
    archs.push_back(a);
  }
  return archs;
}

std::expected<MachOFile, std::string> parse_macho(const FileReader& file_read, uint64_t file_size, uint32_t cputype) {
  auto slices = macho_slices(file_read, file_size);
  if (!slices) return std::unexpected(slices.error());
  const FatArch* chosen = nullptr;
  for (const FatArch& a : *slices) {
    if (a.cputype != cputype) continue;
    // Prefer plain arm64 to arm64e (its pointer authentication is ignored, but plain is simpler).
    if (!chosen || ((chosen->cpusubtype & 0xFFFFFF) == kCpuSubtypeArm64e)) chosen = &a;
  }
  if (!chosen) {
    std::string have;
    for (const FatArch& a : *slices) have += std::string(have.empty() ? "" : ", ") + cpu_name(a.cputype, a.cpusubtype);
    return std::unexpected(std::format("no {} code in this file (it has: {})", cpu_name(cputype, 0), have));
  }

  MachOFile f;
  f.slice_offset = chosen->offset;
  f.slice_size = chosen->size;
  const uint64_t base = chosen->offset;
  auto read = [&](uint64_t offset, void* out, size_t size) {
    return offset <= f.slice_size && size <= f.slice_size - offset && file_read(base + offset, out, size);
  };

  uint8_t h[32];
  if (!read(0, h, sizeof(h))) return std::unexpected("truncated Mach-O header");
  if (load<uint32_t>(h) != kMagic64) return std::unexpected("not a 64-bit Mach-O image");
  f.cputype = load<uint32_t>(h + 4);
  f.cpusubtype = load<uint32_t>(h + 8);
  f.filetype = load<uint32_t>(h + 12);
  const uint32_t ncmds = load<uint32_t>(h + 16);
  const uint32_t sizeofcmds = load<uint32_t>(h + 20);
  f.flags = load<uint32_t>(h + 24);
  if (f.cputype != cputype) return std::unexpected("slice has the wrong CPU type");
  if (f.filetype != kMhExecute && f.filetype != kMhDylib && f.filetype != kMhBundle)
    return std::unexpected(std::format("Mach-O file type {} is not an executable, library or bundle", f.filetype));
  if (sizeofcmds > (1u << 24) || ncmds > 65536) return std::unexpected("bad load commands");
  f.header_size = 32 + sizeofcmds;

  std::vector<uint8_t> cmds(sizeofcmds);
  if (!read(32, cmds.data(), cmds.size())) return std::unexpected("truncated load commands");

  auto linkedit = [&](const uint8_t* p) { return LinkeditData{load<uint32_t>(p), load<uint32_t>(p + 4)}; };

  size_t at = 0;
  for (uint32_t k = 0; k < ncmds; ++k) {
    if (at + 8 > cmds.size()) return std::unexpected("load commands overrun their size");
    const uint8_t* c = cmds.data() + at;
    const uint32_t cmd = load<uint32_t>(c);
    const uint32_t cmdsize = load<uint32_t>(c + 4);
    if (cmdsize < 8 || cmdsize % 8 || at + cmdsize > cmds.size())
      return std::unexpected(std::format("load command {} has a bad size", k));
    const std::vector<uint8_t> body(c, c + cmdsize);
    auto need = [&](uint32_t size) { return cmdsize >= size; };

    switch (cmd) {
      case kLcSegment64: {
        if (!need(72)) return std::unexpected("short LC_SEGMENT_64");
        Segment s;
        s.name = fixed_string(c + 8, 16);
        s.vmaddr = load<uint64_t>(c + 24);
        s.vmsize = load<uint64_t>(c + 32);
        s.fileoff = load<uint64_t>(c + 40);
        s.filesize = load<uint64_t>(c + 48);
        s.maxprot = load<uint32_t>(c + 56);
        s.initprot = load<uint32_t>(c + 60);
        const uint32_t nsects = load<uint32_t>(c + 64);
        s.flags = load<uint32_t>(c + 68);
        if (72 + uint64_t{nsects} * 80 > cmdsize) return std::unexpected("LC_SEGMENT_64 sections overrun");
        if (s.filesize > s.vmsize && s.vmsize) return std::unexpected("segment file size exceeds its memory size");
        if (s.fileoff > f.slice_size || s.filesize > f.slice_size - s.fileoff)
          return std::unexpected(std::format("segment {} extends past the end of the file", s.name));
        for (uint32_t i = 0; i < nsects; ++i) {
          const uint8_t* q = c + 72 + i * 80;
          Section sec;
          sec.name = fixed_string(q, 16);
          sec.segment = fixed_string(q + 16, 16);
          sec.addr = load<uint64_t>(q + 32);
          sec.size = load<uint64_t>(q + 40);
          sec.offset = load<uint32_t>(q + 48);
          sec.align = load<uint32_t>(q + 52);
          sec.flags = load<uint32_t>(q + 64);
          sec.reserved1 = load<uint32_t>(q + 68);
          sec.reserved2 = load<uint32_t>(q + 72);
          s.sections.push_back(std::move(sec));
        }
        f.segments.push_back(std::move(s));
        break;
      }
      case kLcLoadDylib:
      case kLcLoadWeakDylib:
      case kLcReexportDylib:
      case kLcLazyLoadDylib:
      case kLcLoadUpwardDylib:
      case kLcIdDylib: {
        if (!need(24)) return std::unexpected("short dylib command");
        DylibRef d;
        d.name = command_string(body, load<uint32_t>(c + 8));
        d.current_version = load<uint32_t>(c + 16);
        d.compatibility_version = load<uint32_t>(c + 20);
        if (cmd == kLcIdDylib) {
          f.install_name = std::move(d.name);
          break;
        }
        d.kind = cmd == kLcLoadWeakDylib     ? DylibRef::Kind::Weak
                 : cmd == kLcReexportDylib   ? DylibRef::Kind::Reexport
                 : cmd == kLcLazyLoadDylib   ? DylibRef::Kind::Lazy
                 : cmd == kLcLoadUpwardDylib ? DylibRef::Kind::Upward
                                             : DylibRef::Kind::Load;
        f.dylibs.push_back(std::move(d));
        break;
      }
      case kLcRpath:
        if (!need(12)) return std::unexpected("short LC_RPATH");
        f.rpaths.push_back(command_string(body, load<uint32_t>(c + 8)));
        break;
      case kLcLoadDylinker:
        if (!need(12)) return std::unexpected("short LC_LOAD_DYLINKER");
        f.dylinker = command_string(body, load<uint32_t>(c + 8));
        break;
      case kLcMain:
        if (!need(24)) return std::unexpected("short LC_MAIN");
        f.has_main = true;
        f.entry_offset = load<uint64_t>(c + 8);
        f.stack_size = load<uint64_t>(c + 16);
        break;
      case kLcUnixThread: {
        // flavor, count, then the thread state (ARM: x0-x28, fp, lr, sp, pc, ...).
        if (!need(16)) return std::unexpected("short LC_UNIXTHREAD");
        const uint32_t flavor = load<uint32_t>(c + 8);
        if (flavor == kArmThreadState64 && need(16 + 33 * 8)) {
          f.has_unix_thread = true;
          f.thread_pc = load<uint64_t>(c + 16 + 32 * 8);
        } else if (flavor == kX86ThreadState64 && need(16 + 17 * 8)) {
          f.has_unix_thread = true;
          f.thread_pc = load<uint64_t>(c + 16 + 16 * 8);  // rip
        }
        break;
      }
      case kLcDyldInfo:
      case kLcDyldInfoOnly:
        if (!need(48)) return std::unexpected("short LC_DYLD_INFO");
        f.rebase = linkedit(c + 8);
        f.bind = linkedit(c + 16);
        f.weak_bind = linkedit(c + 24);
        f.lazy_bind = linkedit(c + 32);
        f.export_info = linkedit(c + 40);
        break;
      case kLcDyldChainedFixups:
      case kLcDyldExportsTrie:
      case kLcFunctionStarts:
      case kLcDataInCode:
      case kLcCodeSignature: {
        if (!need(16)) return std::unexpected("short linkedit data command");
        const LinkeditData d = linkedit(c + 8);
        if (cmd == kLcDyldChainedFixups) f.chained_fixups = d;
        else if (cmd == kLcDyldExportsTrie) f.exports_trie = d;
        else if (cmd == kLcFunctionStarts) f.function_starts = d;
        else if (cmd == kLcDataInCode) f.data_in_code = d;
        else f.code_signature = d;
        break;
      }
      case kLcSymtab:
        if (!need(24)) return std::unexpected("short LC_SYMTAB");
        f.symoff = load<uint32_t>(c + 8);
        f.nsyms = load<uint32_t>(c + 12);
        f.stroff = load<uint32_t>(c + 16);
        f.strsize = load<uint32_t>(c + 20);
        break;
      case kLcDysymtab:
        if (!need(80)) return std::unexpected("short LC_DYSYMTAB");
        f.ilocalsym = load<uint32_t>(c + 8);
        f.nlocalsym = load<uint32_t>(c + 12);
        f.iextdefsym = load<uint32_t>(c + 16);
        f.nextdefsym = load<uint32_t>(c + 20);
        f.iundefsym = load<uint32_t>(c + 24);
        f.nundefsym = load<uint32_t>(c + 28);
        f.indirectsymoff = load<uint32_t>(c + 56);
        f.nindirectsyms = load<uint32_t>(c + 60);
        break;
      case kLcBuildVersion:
        if (!need(24)) return std::unexpected("short LC_BUILD_VERSION");
        f.platform = load<uint32_t>(c + 8);
        f.min_os = load<uint32_t>(c + 12);
        f.sdk = load<uint32_t>(c + 16);
        break;
      case kLcVersionMinMacosx:
        if (!need(16)) return std::unexpected("short LC_VERSION_MIN_MACOSX");
        f.platform = 1;
        f.min_os = load<uint32_t>(c + 8);
        f.sdk = load<uint32_t>(c + 12);
        break;
      case kLcEncryptionInfo64:
        if (!need(20)) return std::unexpected("short LC_ENCRYPTION_INFO_64");
        f.encrypted = load<uint32_t>(c + 16) != 0;
        break;
      default:
        break;  // other commands don't matter for loading
    }
    at += cmdsize;
  }

  if (f.segments.empty()) return std::unexpected("no segments");
  if (f.filetype == kMhExecute && !f.has_main && !f.has_unix_thread)
    return std::unexpected("executable without an entry point (LC_MAIN)");
  bool header_mapped = false;
  for (const Segment& s : f.segments) header_mapped |= s.fileoff == 0 && s.filesize >= f.header_size;
  if (!header_mapped) return std::unexpected("no segment maps the Mach-O header (__TEXT)");
  return f;
}

uint64_t MachOFile::min_address() const {
  uint64_t lo = ~0ull;
  for (const Segment& s : segments)
    if (s.vmsize && (s.initprot | s.maxprot)) lo = std::min(lo, s.vmaddr);
  return lo == ~0ull ? 0 : lo;
}

uint64_t MachOFile::max_address() const {
  uint64_t hi = 0;
  for (const Segment& s : segments)
    if (s.vmsize && (s.initprot | s.maxprot)) hi = std::max(hi, s.vmaddr + s.vmsize);
  return hi;
}

uint64_t MachOFile::header_address() const {
  for (const Segment& s : segments)
    if (s.fileoff == 0 && s.filesize != 0) return s.vmaddr;
  return 0;
}

uint64_t MachOFile::entry_address() const {
  if (has_main) return header_address() + entry_offset;
  if (has_unix_thread) return thread_pc;
  return 0;
}

const Segment* MachOFile::segment(std::string_view name) const {
  for (const Segment& s : segments)
    if (s.name == name) return &s;
  return nullptr;
}

const Section* MachOFile::section(std::string_view segment_name, std::string_view section_name) const {
  for (const Segment& s : segments)
    for (const Section& sec : s.sections)
      if (sec.segment == segment_name && sec.name == section_name) return &sec;
  return nullptr;
}

const Segment* MachOFile::segment_at(uint64_t addr) const {
  for (const Segment& s : segments)
    if (addr >= s.vmaddr && addr - s.vmaddr < s.vmsize) return &s;
  return nullptr;
}

const Section* MachOFile::section_at(uint64_t addr) const {
  for (const Segment& s : segments)
    for (const Section& sec : s.sections)
      if (addr >= sec.addr && addr - sec.addr < sec.size) return &sec;
  return nullptr;
}

bool MachOFile::file_offset_of(uint64_t addr, uint64_t& offset) const {
  const Segment* s = segment_at(addr);
  if (!s || addr - s->vmaddr >= s->filesize) return false;
  offset = s->fileoff + (addr - s->vmaddr);
  return true;
}

std::string dylib_short_name(std::string_view path) {
  std::string_view leaf = path.substr(path.find_last_of('/') + 1);
  if (const size_t fw = path.find(".framework/"); fw != std::string_view::npos) {
    // .../Name.framework/Name or .../Name.framework/Versions/X/Name
    const std::string_view before = path.substr(0, fw);
    return std::string(before.substr(before.find_last_of('/') + 1));
  }
  std::string name(leaf);
  if (name.ends_with(".dylib")) name.resize(name.size() - 6);
  // libFoo.B -> libFoo, libz.1 -> libz, libc++.1 -> libc++
  if (const size_t dot = name.find('.'); dot != std::string::npos) name.resize(dot);
  for (std::string_view suffix : {"_debug", "_profile"})
    if (name.ends_with(suffix)) name.resize(name.size() - suffix.size());
  return name;
}

std::string version_string(uint32_t v) {
  if (v & 0xFF) return std::format("{}.{}.{}", v >> 16, (v >> 8) & 0xFF, v & 0xFF);
  return std::format("{}.{}", v >> 16, (v >> 8) & 0xFF);
}

}  // namespace juice::mac
