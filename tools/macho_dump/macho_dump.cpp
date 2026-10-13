// juice-macho-dump: prints what JUICE reads from a Mach-O file - libraries,
// entry point, fixups and exports - one item per line, for comparison with
// Apple's and LLVM's tools (tests/macho).
//
//   juice-macho-dump [--arch=arm64|x86_64] file

#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

#include "macos/macho/exports.hpp"
#include "macos/macho/fixups.hpp"
#include "macos/macho/macho_file.hpp"

using namespace juice::mac;

int main(int argc, char** argv) {
  uint32_t cputype = kCpuTypeArm64;
  const char* file = nullptr;
  for (int i = 1; i < argc; ++i) {
    if (std::strcmp(argv[i], "--arch=x86_64") == 0) cputype = kCpuTypeX86_64;
    else if (std::strcmp(argv[i], "--arch=arm64") == 0) cputype = kCpuTypeArm64;
    else file = argv[i];
  }
  if (!file) {
    std::fputs("usage: juice-macho-dump [--arch=arm64|x86_64] file\n", stderr);
    return 2;
  }
  std::ifstream in(file, std::ios::binary);
  if (!in) {
    std::fprintf(stderr, "juice-macho-dump: cannot open %s\n", file);
    return 1;
  }
  const std::vector<char> data((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
  const FileReader read = [&](uint64_t offset, void* out, size_t size) {
    if (offset > data.size() || size > data.size() - offset) return false;
    std::memcpy(out, data.data() + offset, size);
    return true;
  };

  auto image = parse_macho(read, data.size(), cputype);
  if (!image) {
    std::fprintf(stderr, "juice-macho-dump: %s\n", image.error().c_str());
    return 1;
  }
  const MachOFile& m = *image;
  std::printf("image %s %s\n", m.is_arm64e() ? "arm64e" : cputype == kCpuTypeArm64 ? "arm64" : "x86_64",
              m.filetype == kMhExecute ? "execute" : m.filetype == kMhDylib ? "dylib" : "bundle");
  if (!m.install_name.empty()) std::printf("install-name %s\n", m.install_name.c_str());
  for (size_t k = 0; k < m.dylibs.size(); ++k) std::printf("dylib %zu %s\n", k + 1, m.dylibs[k].name.c_str());
  for (const std::string& r : m.rpaths) std::printf("rpath %s\n", r.c_str());
  for (const Segment& s : m.segments) {
    std::printf("segment %s 0x%llx 0x%llx\n", s.name.c_str(), static_cast<unsigned long long>(s.vmaddr),
                static_cast<unsigned long long>(s.vmsize));
  }
  if (const uint64_t entry = m.entry_address()) std::printf("entry 0x%llx\n", static_cast<unsigned long long>(entry));

  auto fixups = read_fixups(m, read);
  if (!fixups) {
    std::fprintf(stderr, "juice-macho-dump: %s\n", fixups.error().c_str());
    return 1;
  }
  for (const Rebase& r : fixups->rebases) {
    if (fixups->chained)
      std::printf("rebase 0x%llx 0x%llx\n", static_cast<unsigned long long>(r.address),
                  static_cast<unsigned long long>(r.target));
    else
      std::printf("rebase 0x%llx\n", static_cast<unsigned long long>(r.address));
  }
  auto print_binds = [&](const std::vector<Bind>& binds, const char* kind) {
    for (const Bind& b : binds) {
      const Import& i = fixups->imports[b.import];
      std::printf("%s 0x%llx %s %s %lld%s\n", kind, static_cast<unsigned long long>(b.address),
                  ordinal_name(m, i.ordinal).c_str(), i.name.c_str(), static_cast<long long>(b.addend),
                  i.weak ? " weak-import" : "");
    }
  };
  print_binds(fixups->binds, "bind");
  print_binds(fixups->weak_binds, "weak-bind");

  const LinkeditData trie = m.exports_trie.present() ? m.exports_trie : m.export_info;
  if (trie.present()) {
    std::vector<uint8_t> bytes(trie.size);
    if (!read(m.slice_offset + trie.offset, bytes.data(), bytes.size())) {
      std::fputs("juice-macho-dump: export trie out of range\n", stderr);
      return 1;
    }
    for (const Export& e : all_exports(bytes)) {
      if (e.reexport()) {
        std::printf("export %s re-export %s %s\n", e.name.c_str(), ordinal_name(m, e.ordinal).c_str(),
                    e.import_name.empty() ? e.name.c_str() : e.import_name.c_str());
        continue;
      }
      const bool absolute = (e.flags & kExportKindMask) == kExportKindAbsolute;
      std::printf("export 0x%llx %s\n",
                  static_cast<unsigned long long>(absolute ? e.address : m.header_address() + e.address),
                  e.name.c_str());
      // Lookups must find what the walk found.
      auto found = find_export(bytes, e.name);
      if (!found || found->address != e.address || found->flags != e.flags) {
        std::fprintf(stderr, "juice-macho-dump: lookup of %s disagrees with the trie walk\n", e.name.c_str());
        return 1;
      }
    }
  }
  return 0;
}
