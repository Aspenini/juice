// juice - run Linux AArch64 programs on x86-64 Linux.

#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "juice/juice.hpp"
#include "linux/binfmt.hpp"
#include "linux/process.hpp"

extern char** environ;

namespace {

void usage() {
  std::fputs(
      "JUICE - JUICE Uses Instruction Conversion Efficiently\n"
      "Runs Linux AArch64 programs on x86-64 Linux by dynamic binary translation.\n"
      "\n"
      "usage: juice [options] [--] program [arguments...]\n"
      "\n"
      "options:\n"
      "  --sysroot=DIR      root of the AArch64 system the program expects: its ld.so, libraries\n"
      "                     and configuration (default: JUICE_SYSROOT or QEMU_LD_PREFIX, else\n"
      "                     where the program's ld.so is found: the host, /usr/aarch64-linux-gnu, ...)\n"
      "  --argv0=NAME       argv[0] for the program (default: the program as named)\n"
      "  --strace           log every system call\n"
      "  --trace            log every translated block with its disassembly\n"
      "  --dump-ir          log the IR of every translated block\n"
      "  --stats            print translation statistics at exit\n"
      "  --interp           execute IR with the reference interpreter instead of the JIT\n"
      "  --no-opt           disable IR optimizations\n"
      "  --block-size=N     maximum guest instructions per translated block (default 64)\n"
      "  --install-binfmt   register JUICE with binfmt_misc so AArch64 programs run directly (root)\n"
      "  --uninstall-binfmt remove that registration (root)\n"
      "  --binfmt-config    print the rule for /etc/binfmt.d/juice-aarch64.conf\n"
      "  --binfmt-status    show the current registration\n"
      "  --version          show the version\n"
      "  --help             show this help\n"
      "\n"
      "Under binfmt_misc the options come from the environment: JUICE_SYSROOT, JUICE_STRACE=1,\n"
      "JUICE_STATS=1.\n",
      stdout);
}

bool env_flag(const char* name) {
  const char* v = std::getenv(name);
  return v && *v && std::strcmp(v, "0") != 0;
}

int run(juice::lx::Options options, const std::string& program, const std::vector<std::string>& args) {
  // The sysroot is a prefix: no trailing slash.
  while (!options.sysroot.empty() && options.sysroot.back() == '/') options.sysroot.pop_back();
  juice::lx::LinuxProcess process(std::move(options));
  if (auto loaded = process.load(program, args, environ); !loaded) {
    std::fprintf(stderr, "juice: %s\n", loaded.error().c_str());
    return 1;
  }
  process.run();
}

}  // namespace

int main(int argc, char** argv) {
  juice::lx::Options options;
  if (const char* root = std::getenv("JUICE_SYSROOT")) options.sysroot = root;
  else if (const char* qemu = std::getenv("QEMU_LD_PREFIX")) options.sysroot = qemu;
  options.trace_syscalls = env_flag("JUICE_STRACE");
  options.stats = options.engine.profile = env_flag("JUICE_STATS");

  // Started by the kernel through binfmt_misc (flag P): juice-binfmt program argv[0] arguments...
  const char* self = std::strrchr(argv[0], '/');
  if (std::strcmp(self ? self + 1 : argv[0], juice::lx::kBinfmtLauncher) == 0) {
    if (argc < 3) {
      std::fprintf(stderr, "juice-binfmt: started without a program (this is the binfmt_misc launcher)\n");
      return 2;
    }
    options.argv0 = argv[2];
    return run(std::move(options), argv[1], std::vector<std::string>(argv + 3, argv + argc));
  }

  int i = 1;
  for (; i < argc; ++i) {
    std::string arg = argv[i];
    if (arg.size() < 2 || arg[0] != '-') break;
    if (arg == "--") {
      ++i;
      break;
    }
    if (arg.starts_with("--sysroot=")) options.sysroot = arg.substr(10);
    else if (arg.starts_with("--argv0=")) options.argv0 = arg.substr(8);
    else if (arg == "--strace") options.trace_syscalls = true;
    else if (arg == "--trace") options.engine.trace = true;
    else if (arg == "--dump-ir") options.engine.dump_ir = true;
    else if (arg == "--stats") options.stats = options.engine.profile = true;
    else if (arg == "--interp") options.engine.interpret = true;
    else if (arg == "--no-opt") options.engine.optimize = false;
    else if (arg.starts_with("--block-size=")) {
      const long n = std::strtol(arg.c_str() + 13, nullptr, 10);
      if (n < 1 || n > 4096) {
        std::fputs("juice: --block-size must be between 1 and 4096\n", stderr);
        return 2;
      }
      options.engine.max_block_insns = static_cast<uint32_t>(n);
    } else if (arg == "--install-binfmt" || arg == "--uninstall-binfmt") {
      auto done = arg == "--install-binfmt" ? juice::lx::install_binfmt() : juice::lx::uninstall_binfmt();
      if (!done) {
        std::fprintf(stderr, "juice: %s\n", done.error().c_str());
        return 1;
      }
      std::printf("%s\n", arg == "--install-binfmt" ? "registered: AArch64 programs now run with JUICE"
                                                     : "unregistered");
      return 0;
    } else if (arg == "--binfmt-config") {
      std::fputs(juice::lx::binfmt_config().c_str(), stdout);
      return 0;
    } else if (arg == "--binfmt-status") {
      std::fputs(juice::lx::binfmt_status().c_str(), stdout);
      return 0;
    } else if (arg == "--version") {
      std::printf("juice %s\n", juice::kVersion);
      return 0;
    } else if (arg == "--help" || arg == "-h") {
      usage();
      return 0;
    } else {
      std::fprintf(stderr, "juice: unknown option '%s' (see --help)\n", arg.c_str());
      return 2;
    }
  }
  if (i >= argc) {
    usage();
    return 2;
  }
  return run(std::move(options), argv[i], std::vector<std::string>(argv + i + 1, argv + argc));
}
