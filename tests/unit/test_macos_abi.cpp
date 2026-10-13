// Portable parts of the macOS frontend: Mach-O fixups and exports. (Real
// programs and libraries, built with LLVM, are checked by tests/macho.)

#include <cstring>
#include <string>
#include <vector>

#include "macos/eh/guest_unwind.hpp"
#include "macos/macho/exports.hpp"
#include "macos/macho/fixups.hpp"
#include "macos/macho/macho_file.hpp"
#include "test.hpp"

using namespace juice;

namespace {

template <typename T>
void put(std::vector<uint8_t>& b, size_t off, T v) {
  if (b.size() < off + sizeof(T)) b.resize(off + sizeof(T));
  std::memcpy(b.data() + off, &v, sizeof(T));
}

mac::FileReader reader(const std::vector<uint8_t>& b) {
  return [&b](uint64_t offset, void* out, size_t size) {
    if (offset > b.size() || size > b.size() - offset) return false;
    std::memcpy(out, b.data() + offset, size);
    return true;
  };
}

// An image with __TEXT at 0x100000000 and __DATA at 0x100004000 (file 0x4000).
mac::MachOFile two_segments(size_t file_size) {
  mac::MachOFile m;
  m.cputype = mac::kCpuTypeArm64;
  m.filetype = mac::kMhExecute;
  m.slice_size = file_size;
  m.segments.push_back({"__TEXT", 0x100000000, 0x4000, 0, 0x4000, 5, 5, 0, {}});
  m.segments.push_back({"__DATA", 0x100004000, 0x4000, 0x4000, 0x4000, 3, 3, 0, {}});
  return m;
}

uint64_t field(uint64_t v, unsigned lo) { return v << lo; }

}  // namespace

// arm64e pointer formats (which LLVM's linker doesn't produce): authenticated
// and plain rebases and binds, 19-bit signed addends, special ordinals.
TEST(macho_chained_arm64e) {
  std::vector<uint8_t> b(0x8000, 0);
  constexpr size_t kFixups = 0x7000;
  // dyld_chained_fixups_header
  put<uint32_t>(b, kFixups + 0, 0);    // version
  put<uint32_t>(b, kFixups + 4, 32);   // starts
  put<uint32_t>(b, kFixups + 8, 72);   // imports
  put<uint32_t>(b, kFixups + 12, 80);  // symbols
  put<uint32_t>(b, kFixups + 16, 2);   // imports count
  put<uint32_t>(b, kFixups + 20, 1);   // DYLD_CHAINED_IMPORT
  put<uint32_t>(b, kFixups + 24, 0);   // uncompressed symbols
  // dyld_chained_starts_in_image: two segments, only __DATA has fixups
  put<uint32_t>(b, kFixups + 32, 2);
  put<uint32_t>(b, kFixups + 36, 0);
  put<uint32_t>(b, kFixups + 40, 12);
  // dyld_chained_starts_in_segment at 32 + 12
  put<uint32_t>(b, kFixups + 44, 24);       // size
  put<uint16_t>(b, kFixups + 48, 0x4000);   // page size
  put<uint16_t>(b, kFixups + 50, 9);        // DYLD_CHAINED_PTR_ARM64E_USERLAND
  put<uint64_t>(b, kFixups + 52, 0x4000);   // segment offset (from the header)
  put<uint32_t>(b, kFixups + 60, 0);        // max valid pointer
  put<uint16_t>(b, kFixups + 64, 1);        // page count
  put<uint16_t>(b, kFixups + 66, 0);        // first fixup at the page's start
  // imports: _foo from library 1; _bar weak, flat lookup (ordinal -2 = 0xFE)
  put<uint32_t>(b, kFixups + 72, 1 | 0 << 9);
  put<uint32_t>(b, kFixups + 76, 0xFE | 1 << 8 | 5 << 9);
  std::memcpy(&b[kFixups + 80], "_foo\0_bar\0", 10);

  // The chain: auth rebase, plain rebase with high byte, bind with addend -4, auth bind.
  const uint64_t next = field(1, 51);
  put<uint64_t>(b, 0x4000, 0x1234 | field(0x55, 32) | field(1, 48) | field(2, 49) | next | field(1, 63));
  put<uint64_t>(b, 0x4008, 0x2000 | field(0xAB, 43) | next);
  put<uint64_t>(b, 0x4010, 0 | field((1u << 19) - 4, 32) | next | field(1, 62));
  put<uint64_t>(b, 0x4018, 1 | field(0x77, 32) | field(1, 62) | field(1, 63));

  mac::MachOFile m = two_segments(b.size());
  m.chained_fixups = {static_cast<uint32_t>(kFixups), 0x100};
  auto f = mac::read_fixups(m, reader(b));
  CHECK(f.has_value());
  CHECK(f->chained);
  CHECK_EQ(f->pointer_format, 9);
  CHECK_EQ(f->rebases.size(), 2);
  CHECK_EQ(f->rebases[0].address, 0x100004000ull);
  CHECK_EQ(f->rebases[0].target, 0x100001234ull);
  CHECK_EQ(f->rebases[1].address, 0x100004008ull);
  CHECK_EQ(f->rebases[1].target, 0xAB00000100002000ull);
  CHECK_EQ(f->binds.size(), 2);
  CHECK_EQ(f->binds[0].address, 0x100004010ull);
  CHECK(f->imports[f->binds[0].import].name == "_foo");
  CHECK_EQ(f->imports[f->binds[0].import].ordinal, 1);
  CHECK_EQ(f->binds[0].addend, -4);
  CHECK_EQ(f->binds[1].address, 0x100004018ull);
  const mac::Import& bar = f->imports[f->binds[1].import];
  CHECK(bar.name == "_bar");
  CHECK_EQ(bar.ordinal, mac::kOrdinalFlatLookup);
  CHECK(bar.weak);

  // In the original arm64e format, a plain rebase's target is an address, not an offset.
  put<uint16_t>(b, kFixups + 50, 1);  // DYLD_CHAINED_PTR_ARM64E
  put<uint64_t>(b, 0x4008, 0x100002000 | next);
  f = mac::read_fixups(m, reader(b));
  CHECK(f.has_value());
  CHECK_EQ(f->rebases[1].target, 0x100002000ull);

  // A bind naming an import that doesn't exist is an error, not a crash.
  put<uint64_t>(b, 0x4018, 7 | field(1, 62));
  CHECK(!mac::read_fixups(m, reader(b)).has_value());
}

// Opcode-encoded fixups: rebases with skips, binds with special ordinals,
// addends, and lazy binds (separate runs ended by DONE).
TEST(macho_opcode_fixups) {
  std::vector<uint8_t> b(0x8000, 0);
  put<uint64_t>(b, 0x4000, 0x100000100);
  put<uint64_t>(b, 0x4010, 0x100000200);
  put<uint64_t>(b, 0x4020, 0x100000300);
  const uint8_t rebase[] = {
      0x11,              // SET_TYPE_IMM pointer
      0x21, 0x00,        // SET_SEGMENT_AND_OFFSET_ULEB segment 1, offset 0
      0x80, 0x03, 0x08,  // DO_REBASE_ULEB_TIMES_SKIPPING_ULEB 3 times, skip 8
      0x00,
  };
  const uint8_t bind[] = {
      0x11,                          // SET_DYLIB_ORDINAL_IMM 1
      0x40, '_', 'a', 0,             // symbol _a
      0x51,                          // SET_TYPE_IMM pointer
      0x71, 0x08,                    // segment 1, offset 8
      0x90,                          // DO_BIND
      0x3F,                          // SET_DYLIB_SPECIAL_IMM -1 (main executable)
      0x41, '_', 'b', 0,             // symbol _b, weak import
      0x60, 0x7C,                    // SET_ADDEND_SLEB -4
      0x80, 0x08,                    // ADD_ADDR_ULEB 8 (0x18)
      0x90,
      0x00,
  };
  const uint8_t lazy[] = {
      0x71, 0x28, 0x12, 0x40, '_', 'c', 0, 0x90, 0x00,  // offset 0x28, library 2, _c
      0x71, 0x30, 0x11, 0x40, '_', 'd', 0, 0x90, 0x00,  // offset 0x30, library 1, _d
  };
  size_t at = 0x6000;
  mac::MachOFile m = two_segments(b.size());
  auto place = [&](const uint8_t* bytes, size_t size) {
    std::memcpy(&b[at], bytes, size);
    const mac::LinkeditData d{static_cast<uint32_t>(at), static_cast<uint32_t>(size)};
    at += 0x100;
    return d;
  };
  m.rebase = place(rebase, sizeof(rebase));
  m.bind = place(bind, sizeof(bind));
  m.lazy_bind = place(lazy, sizeof(lazy));
  auto f = mac::read_fixups(m, reader(b));
  CHECK(f.has_value());
  CHECK(!f->chained);
  CHECK_EQ(f->rebases.size(), 3);
  CHECK_EQ(f->rebases[0].address, 0x100004000ull);
  CHECK_EQ(f->rebases[0].target, 0x100000100ull);
  CHECK_EQ(f->rebases[2].address, 0x100004020ull);
  CHECK_EQ(f->rebases[2].target, 0x100000300ull);
  CHECK_EQ(f->binds.size(), 4);
  CHECK_EQ(f->binds[0].address, 0x100004008ull);
  CHECK(f->imports[f->binds[0].import].name == "_a");
  CHECK_EQ(f->binds[1].address, 0x100004018ull);
  CHECK_EQ(f->binds[1].addend, -4);
  CHECK_EQ(f->imports[f->binds[1].import].ordinal, mac::kOrdinalMainExecutable);
  CHECK(f->imports[f->binds[1].import].weak);
  CHECK_EQ(f->binds[2].address, 0x100004028ull);
  CHECK_EQ(f->imports[f->binds[2].import].ordinal, 2);
  CHECK_EQ(f->binds[3].address, 0x100004030ull);
  CHECK(f->imports[f->binds[3].import].name == "_d");

  // Truncated streams are errors.
  m.bind.size = 3;
  CHECK(!mac::read_fixups(m, reader(b)).has_value());
}

// The export trie: lookups, re-exports, resolvers, prefixes that aren't symbols.
TEST(macho_export_trie) {
  // root (0): no terminal, one child "_" -> node 6
  std::vector<uint8_t> t = {0x00, 0x01, '_', 0x00, 0x06};
  t.resize(6, 0);
  // node 6: no terminal, children "foo", "bar" (a re-export), "baz" (a resolver)
  const uint8_t node6[] = {0x00, 0x03, 'f', 'o', 'o', 0, 30, 'b', 'a', 'r', 0, 40, 'b', 'a', 'z', 0, 60};
  t.insert(t.end(), node6, node6 + sizeof(node6));
  t.resize(30, 0);
  const uint8_t foo[] = {0x03, 0x00, 0x80, 0x02, 0x00};  // terminal size 3: flags 0, address 0x100; no children
  t.insert(t.end(), foo, foo + sizeof(foo));
  t.resize(40, 0);
  const uint8_t bar[] = {0x07, 0x08, 0x02, '_', 'q', 'u', 'x', 0, 0x00};  // re-export from library 2 as _qux
  t.insert(t.end(), bar, bar + sizeof(bar));
  t.resize(60, 0);
  const uint8_t baz[] = {0x05, 0x10, 0x90, 0x01, 0xA0, 0x01, 0x00};  // stub 0x90 and resolver 0xA0
  t.insert(t.end(), baz, baz + sizeof(baz));

  auto foo_e = mac::find_export(t, "_foo");
  CHECK(foo_e.has_value());
  CHECK_EQ(foo_e->address, 0x100);
  auto bar_e = mac::find_export(t, "_bar");
  CHECK(bar_e.has_value() && bar_e->reexport());
  CHECK_EQ(bar_e->ordinal, 2);
  CHECK(bar_e->import_name == "_qux");
  auto baz_e = mac::find_export(t, "_baz");
  CHECK(baz_e.has_value());
  CHECK_EQ(baz_e->flags, mac::kExportStubAndResolver);
  CHECK_EQ(baz_e->address, 0x90);
  CHECK_EQ(baz_e->resolver, 0xA0);
  CHECK(!mac::find_export(t, "_").has_value());     // an inner node, not a symbol
  CHECK(!mac::find_export(t, "_fo").has_value());   // a prefix of an edge
  CHECK(!mac::find_export(t, "_food").has_value());
  CHECK_EQ(mac::all_exports(t).size(), 3);
  // A trie whose child points outside it doesn't crash.
  std::vector<uint8_t> bad = {0x00, 0x01, '_', 0x00, 0x7F};
  CHECK(!mac::find_export(bad, "_x").has_value());
  CHECK(mac::all_exports(bad).empty());
}

TEST(macho_names) {
  CHECK(mac::dylib_short_name("/usr/lib/libSystem.B.dylib") == "libSystem");
  CHECK(mac::dylib_short_name("/usr/lib/libc++.1.dylib") == "libc++");
  CHECK(mac::dylib_short_name("/System/Library/Frameworks/Foundation.framework/Versions/C/Foundation") ==
        "Foundation");
  CHECK(mac::dylib_short_name("@rpath/Sparkle.framework/Sparkle") == "Sparkle");
  CHECK(mac::version_string(0x000D0400) == "13.4");
  CHECK(mac::version_string(0x000E0201) == "14.2.1");
}

// Guest unwinding: DWARF CFI (a CIE and FDE as clang emits them for an
// ARM64 frame) and compact unwind's frame and frameless modes, on a made-up stack.
TEST(macos_unwind_steps) {
  alignas(16) uint64_t stack[16] = {};
  const auto base = reinterpret_cast<uint64_t>(stack);
  const mac::MemoryReader read = [](uint64_t addr, void* out, size_t size) {
    std::memcpy(out, reinterpret_cast<const void*>(addr), size);
    return true;
  };
  // The callee's frame at stack[4..]: x20, x19 below {fp, lr}.
  stack[4] = 0x2020;  // x20 (fp - 16)
  stack[5] = 0x1919;  // x19 (fp - 8)
  stack[6] = 0xF00D;  // saved fp
  stack[7] = 0x1234;  // lr
  mac::GuestFrame start;
  start.sp = base + 4 * 8;
  start.x[29] = base + 6 * 8;
  start.pc = 0x1000 + 20;  // inside the function, after its prologue

  // Compact unwind, frame mode with the X19/X20 pair.
  mac::FrameUnwindInfo compact;
  compact.encoding = 0x04000001;
  mac::GuestFrame f = start;
  CHECK(mac::step_frame(f, compact, read));
  CHECK_EQ(f.x[19], 0x1919);
  CHECK_EQ(f.x[20], 0x2020);
  CHECK_EQ(f.x[29], 0xF00D);
  CHECK_EQ(f.pc, 0x1234);
  CHECK_EQ(f.sp, base + 8 * 8);

  // Frameless: 32 bytes of stack with X19/X20 at its top; the return address in LR.
  mac::FrameUnwindInfo frameless;
  frameless.encoding = 0x02000000 | (2 << 12) | 0x001;
  f = start;
  f.sp = base + 2 * 8;  // the frame is stack[2..5]
  f.x[30] = 0x5555;
  CHECK(mac::step_frame(f, frameless, read));
  CHECK_EQ(f.x[19], 0x1919);  // at sp + 32 - 8
  CHECK_EQ(f.x[20], 0x2020);
  CHECK_EQ(f.sp, base + 6 * 8);
  CHECK_EQ(f.pc, 0x5555);

  // DWARF: stp x29, x30, [sp, #-16]!; mov x29, sp; stp x20, x19, [sp, #-16]!
  std::vector<uint8_t> eh = {
      // CIE: length 16, id 0, version 1, "zR", code align 1, data align -8, ra x30,
      // augmentation: absolute FDE pointers; def_cfa sp + 0.
      16, 0, 0, 0, 0, 0, 0, 0, 1, 'z', 'R', 0, 1, 0x78, 30, 1, 0x00, 0x0C, 31, 0,
  };
  const size_t fde = eh.size();
  std::vector<uint8_t> body = {static_cast<uint8_t>(fde + 4), 0, 0, 0};  // back to the CIE
  for (int k = 0; k < 8; ++k) body.push_back(static_cast<uint8_t>(uint64_t{0x1000} >> (8 * k)));  // pc_begin
  for (int k = 0; k < 8; ++k) body.push_back(k == 0 ? 0x40 : 0);                                // pc_range
  body.push_back(0);  // augmentation data length
  const uint8_t program[] = {
      0x44, 0x0E, 16, 0x9E, 1, 0x9D, 2,  // +4: CFA = sp + 16; x30 at CFA-8, x29 at CFA-16
      0x44, 0x0D, 29,                    // +4: CFA = x29 + 16
      0x44, 0x93, 3, 0x94, 4,            // +4: x19 at CFA-24, x20 at CFA-32
  };
  body.insert(body.end(), program, program + sizeof(program));
  while ((body.size() + 4) % 8) body.push_back(0);
  eh.push_back(static_cast<uint8_t>(body.size()));
  eh.insert(eh.end(), {0, 0, 0});
  eh.insert(eh.end(), body.begin(), body.end());
  eh.insert(eh.end(), {0, 0, 0, 0});

  mac::UnwindSections sections;
  sections.eh_frame = reinterpret_cast<uint64_t>(eh.data());
  sections.eh_frame_size = eh.size();
  mac::FrameUnwindInfo dwarf;
  CHECK(mac::find_unwind_info(sections, 0x1000 + 19, dwarf, read));
  CHECK(dwarf.dwarf);
  CHECK_EQ(dwarf.start, 0x1000);
  CHECK_EQ(dwarf.end, 0x1040);
  f = start;
  CHECK(mac::step_frame(f, dwarf, read));
  CHECK_EQ(f.x[19], 0x1919);
  CHECK_EQ(f.x[20], 0x2020);
  CHECK_EQ(f.x[29], 0xF00D);
  CHECK_EQ(f.pc, 0x1234);
  CHECK_EQ(f.sp, base + 8 * 8);
  // Inside the prologue (after the first store only): CFA = sp + 16, nothing else saved yet.
  f = start;
  f.sp = base + 6 * 8;
  f.pc = 0x1000 + 5;  // (return addresses are looked up at pc - 1)
  CHECK(mac::step_frame(f, dwarf, read));
  CHECK_EQ(f.pc, 0x1234);
  CHECK_EQ(f.sp, base + 8 * 8);
  CHECK_EQ(f.x[19], 0);
}
