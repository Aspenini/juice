// juice.exe - run Windows ARM64 programs on x86-64 Windows.

#include <windows.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <map>
#include <string>
#include <vector>

#include "core/arm64/decode/instruction.hpp"
#include "windows/guest_process.hpp"
#include "windows/pe/pe_file.hpp"

namespace {

// Statically decode every word of the executable sections and report the
// encodings JUICE cannot translate. Data embedded in code (literal pools,
// padding) shows up too, so treat the result as an upper bound.
int scan(const wchar_t* path) {
  auto file = juice::pe::read_pe_file(path);
  if (!file) {
    std::fprintf(stderr, "juice: %s\n", file.error().c_str());
    return 1;
  }
  if (file->machine != juice::pe::kMachineArm64) {
    std::fprintf(stderr, "juice: not an ARM64 image (%s)\n", juice::pe::machine_name(file->machine));
    return 1;
  }
  struct Hit {
    uint64_t count = 0;
    uint64_t first = 0;
  };
  std::map<uint32_t, Hit> unsupported;
  uint64_t total = 0, bad = 0;
  for (const juice::pe::Section& s : file->sections) {
    if (!(s.characteristics & juice::pe::kScnMemExecute)) continue;
    const uint32_t size = std::min(s.raw_size, s.virtual_size ? s.virtual_size : s.raw_size);
    for (uint32_t off = 0; off + 4 <= size; off += 4) {
      uint32_t word;
      std::memcpy(&word, file->data.data() + s.raw_offset + off, 4);
      const uint64_t va = file->image_base + s.virtual_address + off;
      juice::arm64::Instruction insn = juice::arm64::decode(word, va);
      ++total;
      if (insn.op == juice::arm64::Op::Invalid || insn.op == juice::arm64::Op::Unsupported) {
        ++bad;
        Hit& h = unsupported[word];
        if (h.count++ == 0) h.first = va;
      }
    }
  }
  std::vector<std::pair<uint32_t, Hit>> sorted(unsupported.begin(), unsupported.end());
  std::sort(sorted.begin(), sorted.end(), [](const auto& a, const auto& b) { return a.second.count > b.second.count; });
  for (const auto& [word, hit] : sorted)
    std::printf("  %08x  x%-5llu first at 0x%llx\n", word, static_cast<unsigned long long>(hit.count),
                static_cast<unsigned long long>(hit.first));
  std::printf("%llu words scanned, %llu not translatable (%zu distinct encodings)\n",
              static_cast<unsigned long long>(total), static_cast<unsigned long long>(bad), unsupported.size());
  return bad ? 3 : 0;
}

void usage() {
  std::fputs(
      "JUICE - JUICE Uses Instruction Conversion Efficiently\n"
      "Runs Windows ARM64 executables on x86-64 Windows by dynamic binary translation.\n"
      "\n"
      "usage: juice [options] program.exe [arguments...]\n"
      "\n"
      "options:\n"
      "  --trace          log every translated block with its disassembly\n"
      "  --dump-ir        log the IR of every translated block\n"
      "  --trace-calls    log every Windows API call made by the program\n"
      "  --trace-imports  log how each import was resolved\n"
      "  --stats          print translation statistics at exit\n"
      "  --interp         execute IR with the reference interpreter instead of the JIT\n"
      "  --no-opt         disable IR optimizations\n"
      "  --block-size=N   maximum guest instructions per translated block (default 64)\n"
      "  --scan           don't run; list instructions in the program JUICE cannot translate\n"
      "  --help           show this help\n",
      stdout);
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
  juice::win::ProcessOptions options;
  bool scan_only = false;
  int i = 1;
  for (; i < argc; ++i) {
    std::wstring arg = argv[i];
    if (arg.size() < 2 || arg[0] != L'-') break;
    if (arg == L"--") {
      ++i;
      break;
    }
    if (arg == L"--trace") options.engine.trace = true;
    else if (arg == L"--dump-ir") options.engine.dump_ir = true;
    else if (arg == L"--trace-calls") options.trace_calls = true;
    else if (arg == L"--trace-imports") options.trace_imports = true;
    else if (arg == L"--stats") options.stats = options.engine.profile = true;
    else if (arg == L"--interp") options.engine.interpret = true;
    else if (arg == L"--no-opt") options.engine.optimize = false;
    else if (arg == L"--scan") scan_only = true;
    else if (arg.starts_with(L"--block-size=")) {
      long n = std::wcstol(arg.c_str() + 13, nullptr, 10);
      if (n < 1 || n > 4096) {
        std::fputs("juice: --block-size must be between 1 and 4096\n", stderr);
        return 2;
      }
      options.engine.max_block_insns = static_cast<uint32_t>(n);
    } else if (arg == L"--help" || arg == L"-h") {
      usage();
      return 0;
    } else {
      std::fwprintf(stderr, L"juice: unknown option '%ls' (see --help)\n", arg.c_str());
      return 2;
    }
  }
  if (i >= argc) {
    usage();
    return 2;
  }

  if (scan_only) return scan(argv[i]);

  std::vector<std::wstring> guest_args(argv + i + 1, argv + argc);
  juice::win::GuestProcess process(options);
  if (auto loaded = process.load(argv[i], guest_args); !loaded) {
    std::fprintf(stderr, "juice: %s\n", loaded.error().c_str());
    return 1;
  }
  return process.run();
}
