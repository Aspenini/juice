// Portable parts of the Linux frontend: ELF parsing, the initial stack,
// structure and flag translation, and signal frames.

#include <cstring>
#include <string>
#include <vector>

#include "linux/abi/binfmt_rule.hpp"
#include "linux/abi/initial_stack.hpp"
#include "linux/abi/signal_frame.hpp"
#include "linux/abi/syscalls.hpp"
#include "linux/abi/translate.hpp"
#include "linux/elf/elf_file.hpp"
#include "test.hpp"

using namespace juice;

namespace {

template <typename T>
void put(std::vector<uint8_t>& b, size_t off, T v) {
  if (b.size() < off + sizeof(T)) b.resize(off + sizeof(T));
  std::memcpy(b.data() + off, &v, sizeof(T));
}

// A small AArch64 PIE: PT_PHDR, PT_INTERP, two PT_LOADs, PT_GNU_STACK.
std::vector<uint8_t> make_elf() {
  std::vector<uint8_t> b(0x200, 0);
  const uint8_t ident[16] = {0x7F, 'E', 'L', 'F', 2, 1, 1};
  std::memcpy(b.data(), ident, 16);
  put<uint16_t>(b, 16, lx::kEtDyn);
  put<uint16_t>(b, 18, lx::kEmAarch64);
  put<uint64_t>(b, 24, 0x1040);  // entry
  put<uint64_t>(b, 32, 64);      // phoff
  put<uint16_t>(b, 54, 56);
  put<uint16_t>(b, 56, 5);
  auto ph = [&](unsigned k, uint32_t type, uint32_t flags, uint64_t off, uint64_t va, uint64_t fsz, uint64_t msz) {
    const size_t p = 64 + 56 * k;
    put<uint32_t>(b, p, type);
    put<uint32_t>(b, p + 4, flags);
    put<uint64_t>(b, p + 8, off);
    put<uint64_t>(b, p + 16, va);
    put<uint64_t>(b, p + 32, fsz);
    put<uint64_t>(b, p + 40, msz);
    put<uint64_t>(b, p + 48, 0x1000);
  };
  ph(0, lx::kPtPhdr, lx::kPfR, 64, 64, 5 * 56, 5 * 56);
  ph(1, lx::kPtInterp, lx::kPfR, 0x180, 0x180, 28, 28);
  ph(2, lx::kPtLoad, lx::kPfR | lx::kPfX, 0, 0, 0x1100, 0x1100);
  ph(3, lx::kPtLoad, lx::kPfR | lx::kPfW, 0x1100, 0x2100, 0x80, 0x3000);
  ph(4, lx::kPtGnuStack, lx::kPfR | lx::kPfW, 0, 0, 0, 0);
  const char interp[] = "/lib/ld-linux-aarch64.so.1";
  std::memcpy(b.data() + 0x180, interp, sizeof(interp));
  b.resize(0x1200, 0);
  return b;
}

}  // namespace

TEST(linux_elf_parse) {
  const std::vector<uint8_t> image = make_elf();
  auto reader = [&](uint64_t off, void* out, size_t n) {
    if (off + n > image.size()) return false;
    std::memcpy(out, image.data() + off, n);
    return true;
  };
  auto f = lx::parse_elf(reader);
  CHECK(f.has_value());
  CHECK(f->is_dynamic());
  CHECK_EQ(f->entry, 0x1040u);
  CHECK(f->interpreter == "/lib/ld-linux-aarch64.so.1");
  CHECK_EQ(f->min_vaddr, 0u);
  CHECK_EQ(f->max_vaddr, 0x6000u);  // 0x2100 + 0x3000, page-aligned
  CHECK_EQ(f->phdr_vaddr, 64u);
  CHECK(!f->executable_stack);
  CHECK_EQ(lx::elf_machine(image.data(), image.size()), lx::kEmAarch64);

  std::vector<uint8_t> x86 = image;
  put<uint16_t>(x86, 18, lx::kEmX86_64);
  auto bad = lx::parse_elf([&](uint64_t off, void* out, size_t n) {
    if (off + n > x86.size()) return false;
    std::memcpy(out, x86.data() + off, n);
    return true;
  });
  CHECK(!bad.has_value());
}

TEST(linux_flag_and_struct_translation) {
  // O_RDWR | O_CREAT | O_CLOEXEC are shared; O_DIRECTORY / O_NOFOLLOW / O_DIRECT / O_LARGEFILE move.
  CHECK_EQ(lx::open_flags_to_host(02 | 0100 | 02000000), 02u | 0100u | 02000000u);
  CHECK_EQ(lx::open_flags_to_host(0040000), 0200000u);  // O_DIRECTORY
  CHECK_EQ(lx::open_flags_to_host(0100000), 0400000u);  // O_NOFOLLOW
  CHECK_EQ(lx::open_flags_to_host(0200000), 0040000u);  // O_DIRECT
  CHECK_EQ(lx::open_flags_to_host(0400000), 0100000u);  // O_LARGEFILE
  for (uint32_t f : {0u, 0x4000u, 0x8000u, 0x10000u, 0x20000u, 0x3C000u | 0x80042u})
    CHECK_EQ(lx::open_flags_to_guest(lx::open_flags_to_host(f)), f);

  lx::X64Stat x{};
  x.st_ino = 77;
  x.st_nlink = 3;
  x.st_mode = 0100644;
  x.st_size = 12345;
  x.st_blksize = 4096;
  x.st_mtime_sec = 1700000000;
  x.st_mtime_nsec = 5;
  const lx::Arm64Stat a = lx::to_arm64(x);
  CHECK_EQ(a.st_ino, 77u);
  CHECK_EQ(a.st_nlink, 3u);
  CHECK_EQ(a.st_mode, 0100644u);
  CHECK_EQ(a.st_size, 12345);
  CHECK_EQ(a.st_blksize, 4096);
  CHECK_EQ(a.st_mtime_sec, 1700000000);
  CHECK_EQ(a.st_mtime_nsec, 5u);

  CHECK(std::string(lx::sys::name(lx::sys::openat)) == "openat");
  CHECK(std::string(lx::sys::name(lx::sys::rt_sigreturn)) == "rt_sigreturn");
  CHECK(std::string(lx::sys::name(1000)) == "?");
}

TEST(linux_initial_stack) {
  std::vector<uint8_t> stack(16384);
  const uint64_t limit = reinterpret_cast<uint64_t>(stack.data());
  const uint64_t top = limit + stack.size();
  lx::InitialStackInput in;
  in.argv = {"prog", "one", "two words"};
  in.envp = {"A=1", "PATH=/bin"};
  in.auxv = {{lx::kAtPagesz, 4096}, {lx::kAtEntry, 0x400000}};
  in.execfn = "/usr/bin/prog";
  in.random[0] = 0xAB;
  const uint64_t sp = lx::build_initial_stack(top, limit, in);
  CHECK(sp != 0);
  CHECK_EQ(sp % 16, 0u);
  const auto* w = reinterpret_cast<const uint64_t*>(sp);
  CHECK_EQ(w[0], 3u);  // argc
  CHECK(std::strcmp(reinterpret_cast<const char*>(w[1]), "prog") == 0);
  CHECK(std::strcmp(reinterpret_cast<const char*>(w[3]), "two words") == 0);
  CHECK_EQ(w[4], 0u);
  CHECK(std::strcmp(reinterpret_cast<const char*>(w[5]), "A=1") == 0);
  CHECK(std::strcmp(reinterpret_cast<const char*>(w[6]), "PATH=/bin") == 0);
  CHECK_EQ(w[7], 0u);
  // auxv: our entries, then AT_RANDOM, AT_PLATFORM, AT_EXECFN, AT_NULL
  const uint64_t* aux = w + 8;
  CHECK_EQ(aux[0], lx::kAtPagesz);
  CHECK_EQ(aux[1], 4096u);
  CHECK_EQ(aux[2], lx::kAtEntry);
  CHECK_EQ(aux[4], lx::kAtRandom);
  CHECK_EQ(*reinterpret_cast<const uint8_t*>(aux[5]), 0xABu);
  CHECK_EQ(aux[6], lx::kAtPlatform);
  CHECK(std::strcmp(reinterpret_cast<const char*>(aux[7]), "aarch64") == 0);
  CHECK_EQ(aux[8], lx::kAtExecfn);
  CHECK(std::strcmp(reinterpret_cast<const char*>(aux[9]), "/usr/bin/prog") == 0);
  CHECK_EQ(aux[10], lx::kAtNull);
  // too small
  CHECK_EQ(lx::build_initial_stack(limit + 64, limit, in), 0u);
}

TEST(linux_signal_frame) {
  std::vector<uint8_t> stack(64 * 1024);
  const uint64_t top = reinterpret_cast<uint64_t>(stack.data()) + stack.size();
  arm64::CpuState s{};
  for (int i = 0; i < 31; ++i) s.x[i] = 0x1000 + i;
  s.sp = top - 128;
  s.pc = 0x400123;
  s.nzcv = 0x60000000;
  s.fpcr = 0x03000000;
  s.v[5] = {0x1111, 0x2222};
  const arm64::CpuState before = s;

  lx::SignalDelivery d;
  d.sig = 10;
  d.saved_mask = 0x4;
  d.handler = 0x500000;
  d.restorer = 0x600000;
  const uint64_t frame = lx::push_signal_frame(s, s.sp, d);
  CHECK_EQ(frame % 16, 0u);
  CHECK(frame + lx::kSignalFrameSize <= before.sp);
  CHECK_EQ(s.x[0], 10u);
  CHECK_EQ(s.x[1], frame);
  CHECK_EQ(s.x[2], frame + lx::kUcontextOffset);
  CHECK_EQ(s.pc, 0x500000u);
  CHECK_EQ(s.x[30], 0x600000u);
  CHECK_EQ(s.sp, frame);
  CHECK_EQ(*reinterpret_cast<const int32_t*>(frame), 10);  // si_signo

  // The handler may clobber registers; rt_sigreturn restores everything.
  s.x[3] = 0xdead;
  s.v[5] = {0, 0};
  uint64_t mask = 0;
  CHECK(lx::pop_signal_frame(s, mask));
  CHECK_EQ(mask, 0x4u);
  CHECK(std::memcmp(s.x, before.x, sizeof(s.x)) == 0);
  CHECK_EQ(s.sp, before.sp);
  CHECK_EQ(s.pc, before.pc);
  CHECK_EQ(s.nzcv, before.nzcv);
  CHECK_EQ(s.fpcr, before.fpcr);
  CHECK_EQ(s.v[5].lo, 0x1111u);
  CHECK_EQ(s.v[5].hi, 0x2222u);
}

TEST(linux_binfmt_rule) {
  const std::string rule = lx::binfmt_rule("/opt/juice/juice-binfmt");
  // :name:type:offset:magic:mask:interpreter:flags
  std::vector<std::string> fields;
  for (size_t pos = 1, next; pos <= rule.size(); pos = next + 1) {
    next = rule.find(':', pos);
    if (next == std::string::npos) next = rule.size();
    fields.push_back(rule.substr(pos, next - pos));
  }
  CHECK_EQ(fields.size(), 7u);
  CHECK(fields[0] == "juice-aarch64");
  CHECK(fields[1] == "M");
  CHECK(fields[2].empty());
  CHECK_EQ(fields[3].size(), 20u * 4);
  CHECK(fields[3].starts_with(R"(\x7f\x45\x4c\x46\x02\x01\x01)"));
  CHECK(fields[3].ends_with(R"(\x02\x00\xb7\x00)"));  // ET_EXEC, EM_AARCH64
  CHECK(fields[4].ends_with(R"(\xfe\xff\xff\xff)"));  // ET_EXEC and ET_DYN
  CHECK(fields[5] == "/opt/juice/juice-binfmt");
  CHECK(fields[6] == "PF");
}
