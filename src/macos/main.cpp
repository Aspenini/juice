// juice - run macOS ARM64 programs on Intel Macs.

#include <CoreFoundation/CoreFoundation.h>
#include <dlfcn.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <memory>
#include <string>
#include <vector>

#include "juice/juice.hpp"
#include "macos/host/native_system.hpp"
#include "macos/macho/macho_file.hpp"
#include "macos/objc/objc_bridge.hpp"
#include "macos/objc/swift_bridge.hpp"
#include "macos/process/mac_process.hpp"

extern char** environ;

namespace {

void usage() {
  std::fputs(
      "JUICE - JUICE Uses Instruction Conversion Efficiently\n"
      "Runs macOS ARM64 programs on Intel Macs by dynamic binary translation.\n"
      "\n"
      "usage: juice [options] [--] program [arguments...]\n"
      "\n"
      "options:\n"
      "  --library-path=DIRS  directories (':' separated) searched for the program's libraries\n"
      "                       first (as DYLD_LIBRARY_PATH; also JUICE_LIBRARY_PATH)\n"
      "  --argv0=NAME         argv[0] for the program (default: the program as named)\n"
      "  --trace-calls        log calls between the program and native code\n"
      "  --trace-binds        log how the program's imports resolve\n"
      "  --trace              log every translated block with its disassembly\n"
      "  --dump-ir            log the IR of every translated block\n"
      "  --dump-x64           log the x86-64 code of every translated block\n"
      "  --interp             execute IR with the reference interpreter instead of the JIT\n"
      "  --no-opt             disable IR optimizations\n"
      "  --version            show the version\n"
      "  --help               show this help\n",
      stdout);
}

std::vector<std::string> split(const std::string& s, char sep) {
  std::vector<std::string> out;
  size_t start = 0;
  while (start <= s.size()) {
    const size_t end = s.find(sep, start);
    const std::string part = s.substr(start, end == std::string::npos ? std::string::npos : end - start);
    if (!part.empty()) out.push_back(part);
    if (end == std::string::npos) break;
    start = end + 1;
  }
  return out;
}

// Does the file have code this Mac runs itself (x86_64, or no ARM64 at all)?
bool runs_natively(const std::string& path) {
  std::ifstream in(path, std::ios::binary | std::ios::ate);
  if (!in) return false;
  const auto size = static_cast<uint64_t>(in.tellg());
  const juice::mac::FileReader read = [&](uint64_t offset, void* out, size_t n) {
    in.clear();
    in.seekg(static_cast<std::streamoff>(offset));
    in.read(static_cast<char*>(out), static_cast<std::streamsize>(n));
    return static_cast<size_t>(in.gcount()) == n;
  };
  auto slices = juice::mac::macho_slices(read, size);
  if (!slices) return false;
  bool arm64 = false, x86_64 = false;
  for (const auto& a : *slices) {
    arm64 |= a.cputype == juice::mac::kCpuTypeArm64;
    x86_64 |= a.cputype == juice::mac::kCpuTypeX86_64;
  }
  return x86_64 || !arm64;
}

// The executable of an application bundle (Foo.app), or `path` itself.
std::string bundle_executable(const std::string& path) {
  struct stat st{};
  if (stat(path.c_str(), &st) != 0 || !S_ISDIR(st.st_mode)) return path;
  std::string result = path;
  CFURLRef url = CFURLCreateFromFileSystemRepresentation(nullptr, reinterpret_cast<const UInt8*>(path.data()),
                                                         static_cast<CFIndex>(path.size()), true);
  if (!url) return path;
  if (CFBundleRef bundle = CFBundleCreate(nullptr, url)) {
    if (CFURLRef exe = CFBundleCopyExecutableURL(bundle)) {
      char buffer[4096];
      if (CFURLGetFileSystemRepresentation(exe, true, reinterpret_cast<UInt8*>(buffer), sizeof(buffer)))
        result = buffer;
      CFRelease(exe);
    }
    CFRelease(bundle);
  }
  CFRelease(url);
  return result;
}

}  // namespace

int main(int argc, char** argv) {
  juice::mac::MacOptions options;
  if (const char* paths = std::getenv("JUICE_LIBRARY_PATH")) options.library_paths = split(paths, ':');
  int i = 1;
  for (; i < argc; ++i) {
    std::string arg = argv[i];
    if (arg.size() < 2 || arg[0] != '-') break;
    if (arg == "--") {
      ++i;
      break;
    }
    if (arg.starts_with("--library-path=")) {
      for (const std::string& dir : split(arg.substr(15), ':')) options.library_paths.push_back(dir);
    } else if (arg.starts_with("--argv0=")) {
      options.argv0 = arg.substr(8);
    } else if (arg == "--trace-calls") {
      options.trace_calls = true;
    } else if (arg == "--trace-binds") {
      options.trace_binds = true;
    } else if (arg == "--trace") {
      options.engine.trace = true;
    } else if (arg == "--dump-ir") {
      options.engine.dump_ir = true;
    } else if (arg == "--dump-x64") {
      options.engine.dump_code = true;
    } else if (arg == "--interp") {
      options.engine.interpret = true;
    } else if (arg == "--no-opt") {
      options.engine.optimize = false;
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
  // An application bundle runs its executable.
  const std::string program = bundle_executable(argv[i]);
  if (runs_natively(program)) {
    // As macOS itself would: an Intel program needs no translation.
    std::vector<char*> native_argv(argv + i, argv + argc);
    native_argv[0] = const_cast<char*>(program.c_str());
    native_argv.push_back(nullptr);
    execv(program.c_str(), native_argv.data());
    std::perror(("juice: " + program).c_str());
    return 1;
  }

  std::vector<std::string> environment;
  for (char** e = environ; e && *e; ++e) environment.emplace_back(*e);

  // The system's frameworks find the main bundle (resources, Info.plist)
  // from the process's path, which is juice's: CoreFoundation takes it from
  // CFProcessPath instead when set. It's read once, the first time it's needed.
  char resolved[PATH_MAX];
  const std::string program_path = realpath(program.c_str(), resolved) ? std::string(resolved) : program;
  setenv("CFProcessPath", program_path.c_str(), 1);

  static juice::mac::MacNativeSystem system;
  juice::mac::install_exception_support();
  auto process = std::make_unique<juice::mac::MacProcess>(options, system);
  juice::mac::install_fault_handler(*process);
  // Objective-C: the program's classes on the system's runtime.
  dlopen("/usr/lib/libobjc.A.dylib", RTLD_LAZY | RTLD_GLOBAL);
  static juice::mac::ObjcRuntime objc;
  std::unique_ptr<juice::mac::ObjcBridge> bridge;
  if (objc.load(system)) {
    bridge = std::make_unique<juice::mac::ObjcBridge>(*process, objc);
    bridge->install();
  }
  juice::mac::SwiftBridge swift(*process);
  swift.install();
  if (auto loaded = process->load(program, std::vector<std::string>(argv + i + 1, argv + argc), environment); !loaded) {
    std::fprintf(stderr, "juice: %s\n", loaded.error().c_str());
    return 1;
  }
  juice::mac::set_native_arguments(*process);
  // Fix the main bundle now, then keep CFProcessPath from the program's child processes.
  CFBundleGetMainBundle();
  unsetenv("CFProcessPath");
  const int code = process->run();
  // exit() runs the atexit handlers (the program's too: native code calls them).
  std::exit(code);
}
