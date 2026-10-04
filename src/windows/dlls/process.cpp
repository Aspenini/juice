// Process creation builtins.
//
// The native CreateProcess can't start ARM64 programs on an x64 machine. When
// a guest starts one, these builtins start juice.exe on it instead (with this
// process's JUICE settings) and hand the guest the juice process, whose exit
// code is the program's. Everything else goes to the native CreateProcess.

#include <windows.h>

#include <cwctype>
#include <filesystem>
#include <format>
#include <optional>
#include <string>
#include <vector>

#include "windows/dlls/builtins.hpp"
#include "windows/guest_process.hpp"

namespace juice::win {
namespace {

using arm64::CpuState;

template <typename T>
T* ptr(uint64_t v) {
  return reinterpret_cast<T*>(static_cast<uintptr_t>(v));
}

std::wstring widen(const char* s) {
  if (!s) return {};
  const int n = MultiByteToWideChar(CP_ACP, 0, s, -1, nullptr, 0);
  std::wstring out(n > 0 ? n - 1 : 0, L'\0');
  if (n > 1) MultiByteToWideChar(CP_ACP, 0, s, -1, out.data(), n);
  return out;
}

// Quote one argument so that CommandLineToArgvW reproduces it.
std::wstring quote(const std::wstring& arg) {
  if (!arg.empty() && arg.find_first_of(L" \t\n\v\"") == std::wstring::npos) return arg;
  std::wstring out = L"\"";
  for (size_t i = 0;; ++i) {
    size_t backslashes = 0;
    while (i < arg.size() && arg[i] == L'\\') {
      ++i;
      ++backslashes;
    }
    if (i == arg.size()) {
      out.append(backslashes * 2, L'\\');
      break;
    }
    if (arg[i] == L'"') {
      out.append(backslashes * 2 + 1, L'\\');
    } else {
      out.append(backslashes, L'\\');
    }
    out.push_back(arg[i]);
  }
  out.push_back(L'"');
  return out;
}

// The program a command line names (its first token, as CreateProcess reads
// it) and the rest of the command line.
void split_command_line(const std::wstring& cmd, std::wstring& program, std::wstring& rest) {
  size_t i = 0;
  while (i < cmd.size() && (cmd[i] == L' ' || cmd[i] == L'\t')) ++i;
  if (i < cmd.size() && cmd[i] == L'"') {
    const size_t end = cmd.find(L'"', i + 1);
    program = cmd.substr(i + 1, end == std::wstring::npos ? std::wstring::npos : end - i - 1);
    i = end == std::wstring::npos ? cmd.size() : end + 1;
  } else {
    const size_t end = cmd.find_first_of(L" \t", i);
    program = cmd.substr(i, end == std::wstring::npos ? std::wstring::npos : end - i);
    i = end == std::wstring::npos ? cmd.size() : end;
  }
  while (i < cmd.size() && (cmd[i] == L' ' || cmd[i] == L'\t')) ++i;
  rest = cmd.substr(i);
}

// Find the program file the way CreateProcess does: a path as given (relative
// to the current directory), else the application's directory, the current
// directory, the system directories and PATH; ".exe" is appended if needed.
std::optional<std::wstring> find_program(GuestProcess& p, const std::wstring& name, bool search) {
  if (name.empty()) return std::nullopt;
  std::wstring dirs;
  if (search && name.find_first_of(L"\\/:") == std::wstring::npos) {
    dirs = std::filesystem::path(p.exe().path).parent_path().wstring() + L";.";
    wchar_t buffer[MAX_PATH];
    if (GetSystemDirectoryW(buffer, MAX_PATH)) dirs += std::wstring(L";") + buffer;
    if (GetWindowsDirectoryW(buffer, MAX_PATH)) dirs += std::wstring(L";") + buffer;
    if (DWORD n = GetEnvironmentVariableW(L"PATH", nullptr, 0)) {
      std::wstring path(n, L'\0');
      path.resize(GetEnvironmentVariableW(L"PATH", path.data(), n));
      dirs += L";" + path;
    }
  }
  wchar_t found[MAX_PATH * 4];
  if (SearchPathW(dirs.empty() ? nullptr : dirs.c_str(), name.c_str(), L".exe", static_cast<DWORD>(std::size(found)),
                  found, nullptr)) {
    return std::wstring(found);
  }
  return std::nullopt;
}

bool is_arm64_program(const std::wstring& path) {
  pe::PeHeaderInfo header;
  return pe::peek_pe_header(path, header) && header.machine == pe::kMachineArm64 && !header.is_dll();
}

// The juice command line that runs `program` like `application`/`command_line`
// would have, or nothing if they don't name an ARM64 program.
std::optional<std::wstring> juice_command_line(GuestProcess& p, const std::wstring& application,
                                               const std::wstring& command_line) {
  std::wstring argv0, rest;
  split_command_line(command_line, argv0, rest);
  const std::optional<std::wstring> program =
      application.empty() ? find_program(p, argv0, true) : find_program(p, application, false);
  if (!program || !is_arm64_program(*program)) return std::nullopt;
  if (argv0.empty()) argv0 = application;

  wchar_t juice[MAX_PATH * 4];
  GetModuleFileNameW(nullptr, juice, static_cast<DWORD>(std::size(juice)));
  const ProcessOptions& o = p.options();
  std::wstring cmd = quote(juice);
  if (o.engine.interpret) cmd += L" --interp";
  if (!o.engine.optimize) cmd += L" --no-opt";
  if (o.engine.max_block_insns != runtime::EngineOptions{}.max_block_insns)
    cmd += std::format(L" --block-size={}", o.engine.max_block_insns);
  // The child gets exactly this process's DLL directories (including the
  // Visual Studio runtime, if one was found).
  for (const std::wstring& dir : o.dll_paths) cmd += L" " + quote(L"--dll-path=" + dir);
  cmd += L" --no-vs-runtime";
  cmd += L" " + quote(L"--argv0=" + argv0);
  cmd += L" -- " + quote(*program);
  if (!rest.empty()) cmd += L" " + rest;
  return cmd;
}

// CreateProcessW(application, command_line, process_attributes, thread_attributes,
//                inherit_handles, flags, environment, current_directory | startup_info, process_information)
// The last two arguments are on the guest stack.
uint64_t CreateProcessW_(GuestProcess& p, CpuState& s) {
  const auto* stack = ptr<const uint64_t>(s.sp);
  const auto* application = ptr<const wchar_t>(s.x[0]);
  auto* command_line = ptr<wchar_t>(s.x[1]);
  const std::optional<std::wstring> cmd =
      juice_command_line(p, application ? application : L"", command_line ? command_line : L"");
  if (!cmd) {
    return CreateProcessW(application, command_line, ptr<SECURITY_ATTRIBUTES>(s.x[2]), ptr<SECURITY_ATTRIBUTES>(s.x[3]),
                          static_cast<BOOL>(s.x[4]), static_cast<DWORD>(s.x[5]), ptr<void>(s.x[6]),
                          ptr<const wchar_t>(s.x[7]), ptr<STARTUPINFOW>(stack[0]), ptr<PROCESS_INFORMATION>(stack[1]));
  }
  std::wstring mutable_cmd = *cmd;
  return CreateProcessW(nullptr, mutable_cmd.data(), ptr<SECURITY_ATTRIBUTES>(s.x[2]), ptr<SECURITY_ATTRIBUTES>(s.x[3]),
                        static_cast<BOOL>(s.x[4]), static_cast<DWORD>(s.x[5]), ptr<void>(s.x[6]),
                        ptr<const wchar_t>(s.x[7]), ptr<STARTUPINFOW>(stack[0]), ptr<PROCESS_INFORMATION>(stack[1]));
}

uint64_t CreateProcessA_(GuestProcess& p, CpuState& s) {
  const auto* stack = ptr<const uint64_t>(s.sp);
  const auto* application = ptr<const char>(s.x[0]);
  auto* command_line = ptr<char>(s.x[1]);
  const std::optional<std::wstring> cmd = juice_command_line(p, widen(application), widen(command_line));
  const DWORD flags = static_cast<DWORD>(s.x[5]);
  if (!cmd) {
    return CreateProcessA(application, command_line, ptr<SECURITY_ATTRIBUTES>(s.x[2]), ptr<SECURITY_ATTRIBUTES>(s.x[3]),
                          static_cast<BOOL>(s.x[4]), flags, ptr<void>(s.x[6]), ptr<const char>(s.x[7]),
                          ptr<STARTUPINFOA>(stack[0]), ptr<PROCESS_INFORMATION>(stack[1]));
  }
  // The wide call needs a STARTUPINFOW (and keeps an extended one's attribute list).
  const auto* sa = ptr<const STARTUPINFOA>(stack[0]);
  STARTUPINFOEXW si{};
  std::memcpy(&si.StartupInfo, sa, sizeof(STARTUPINFOA));  // same layout; the strings are converted below
  si.StartupInfo.cb = sizeof(STARTUPINFOW);
  const std::wstring desktop = widen(sa->lpDesktop), title = widen(sa->lpTitle);
  si.StartupInfo.lpReserved = nullptr;
  si.StartupInfo.lpDesktop = sa->lpDesktop ? const_cast<wchar_t*>(desktop.c_str()) : nullptr;
  si.StartupInfo.lpTitle = sa->lpTitle ? const_cast<wchar_t*>(title.c_str()) : nullptr;
  if (flags & EXTENDED_STARTUPINFO_PRESENT) {
    si.StartupInfo.cb = sizeof(STARTUPINFOEXW);
    si.lpAttributeList = reinterpret_cast<const STARTUPINFOEXA*>(sa)->lpAttributeList;
  }
  const std::wstring directory = widen(ptr<const char>(s.x[7]));
  std::wstring mutable_cmd = *cmd;
  return CreateProcessW(nullptr, mutable_cmd.data(), ptr<SECURITY_ATTRIBUTES>(s.x[2]), ptr<SECURITY_ATTRIBUTES>(s.x[3]),
                        static_cast<BOOL>(s.x[4]), flags, ptr<void>(s.x[6]), s.x[7] ? directory.c_str() : nullptr,
                        &si.StartupInfo, ptr<PROCESS_INFORMATION>(stack[1]));
}

constexpr BuiltinExport kProcess[] = {
    {"CreateProcessA", CreateProcessA_},
    {"CreateProcessW", CreateProcessW_},
};

}  // namespace

std::span<const BuiltinExport> process_builtins() { return kProcess; }

}  // namespace juice::win
