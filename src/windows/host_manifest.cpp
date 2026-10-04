// Running the guest in a juice.exe whose own manifest carries the guest's
// process-creation settings; see manifest.hpp.

#include <windows.h>
#include <shellapi.h>

#include <cstdint>
#include <cstring>
#include <filesystem>
#include <format>
#include <string>
#include <vector>

#include "windows/manifest.hpp"

#pragma comment(lib, "shell32.lib")

namespace juice::win {

namespace {


struct Setting {
  const char* ns;
  const char* name;
  bool needs_new_process;  // false: apply_manifest() handles it in process
};

// <windowsSettings> elements carried over to the host manifest.
constexpr Setting kSettings[] = {
    {"http://schemas.microsoft.com/SMI/2005/WindowsSettings", "dpiAware", false},
    {"http://schemas.microsoft.com/SMI/2016/WindowsSettings", "dpiAwareness", false},
    {"http://schemas.microsoft.com/SMI/2017/WindowsSettings", "gdiScaling", false},
    {"http://schemas.microsoft.com/SMI/2019/WindowsSettings", "activeCodePage", true},
    {"http://schemas.microsoft.com/SMI/2016/WindowsSettings", "longPathAware", true},
    {"http://schemas.microsoft.com/SMI/2020/WindowsSettings", "heapType", true},
    {"http://schemas.microsoft.com/SMI/2005/WindowsSettings", "disableTheming", true},
    {"http://schemas.microsoft.com/SMI/2011/WindowsSettings", "disableWindowFiltering", true},
    {"http://schemas.microsoft.com/SMI/2011/WindowsSettings", "printerDriverIsolation", true},
    {"http://schemas.microsoft.com/SMI/2013/WindowsSettings", "highResolutionScrollingAware", true},
    {"http://schemas.microsoft.com/SMI/2013/WindowsSettings", "ultraHighResolutionScrollingAware", true},
};

std::wstring widen(const char* s) { return std::wstring(s, s + std::strlen(s)); }

std::string to_utf8(const wchar_t* s) {
  const int n = WideCharToMultiByte(CP_UTF8, 0, s, -1, nullptr, 0, nullptr, nullptr);
  std::string out(n > 0 ? n - 1 : 0, '\0');
  if (n > 1) WideCharToMultiByte(CP_UTF8, 0, s, -1, out.data(), n, nullptr, nullptr);
  return out;
}

std::string xml_escape(const std::string& s) {
  std::string out;
  for (char c : s) {
    switch (c) {
      case '&': out += "&amp;"; break;
      case '<': out += "&lt;"; break;
      case '>': out += "&gt;"; break;
      case '"': out += "&quot;"; break;
      default: out.push_back(c);
    }
  }
  return out;
}

// The setting's value as written in the manifest, trimmed; empty if absent.
std::string query_setting(HANDLE context, const Setting& setting) {
  wchar_t buffer[512] = {};
  SIZE_T written = 0;
  const std::wstring ns = widen(setting.ns), name = widen(setting.name);
  if (!QueryActCtxSettingsW(0, context, ns.c_str(), name.c_str(), buffer, std::size(buffer) - 1, &written)) return {};
  std::string value = to_utf8(buffer);
  const size_t first = value.find_first_not_of(" \t\r\n");
  if (first == std::string::npos) return {};
  return value.substr(first, value.find_last_not_of(" \t\r\n") - first + 1);
}

std::string guid_string(const GUID& g) {
  return std::format("{{{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}}}", g.Data1, g.Data2,
                     g.Data3, g.Data4[0], g.Data4[1], g.Data4[2], g.Data4[3], g.Data4[4], g.Data4[5], g.Data4[6],
                     g.Data4[7]);
}

// <supportedOS> and <maxversiontested> entries.
std::string compatibility_entries(HANDLE context) {
  SIZE_T needed = 0;
  QueryActCtxW(0, context, nullptr, CompatibilityInformationInActivationContext, nullptr, 0, &needed);
  if (needed < sizeof(DWORD)) return {};
  std::vector<uint8_t> buffer(needed);
  if (!QueryActCtxW(0, context, nullptr, CompatibilityInformationInActivationContext, buffer.data(), buffer.size(),
                    &needed)) {
    return {};
  }
  const auto* info = reinterpret_cast<const ACTIVATION_CONTEXT_COMPATIBILITY_INFORMATION*>(buffer.data());
  std::string out;
  for (DWORD i = 0; i < info->ElementCount; ++i) {
    const COMPATIBILITY_CONTEXT_ELEMENT& e = info->Elements[i];
    if (e.Type == ACTCTX_COMPATIBILITY_ELEMENT_TYPE_OS) {
      out += std::format("      <supportedOS Id=\"{}\"/>\n", guid_string(e.Id));
    } else if (e.Type == ACTCTX_COMPATIBILITY_ELEMENT_TYPE_MAXVERSIONTESTED) {
      const uint64_t v = e.MaxVersionTested;
      out += std::format("      <maxversiontested Id=\"{}.{}.{}.{}\"/>\n", v >> 48, (v >> 32) & 0xFFFF,
                         (v >> 16) & 0xFFFF, v & 0xFFFF);
    }
  }
  return out;
}

uint64_t fnv1a(const void* data, size_t size, uint64_t h = 0xcbf29ce484222325ull) {
  const auto* p = static_cast<const uint8_t*>(data);
  for (size_t i = 0; i < size; ++i) h = (h ^ p[i]) * 0x100000001b3ull;
  return h;
}

std::wstring module_path(HMODULE module) {
  std::wstring path(MAX_PATH, L'\0');
  for (;;) {
    const DWORD n = GetModuleFileNameW(module, path.data(), static_cast<DWORD>(path.size()));
    if (n < path.size()) {
      path.resize(n);
      return path;
    }
    path.resize(path.size() * 2);
  }
}

// A copy of this juice.exe with `manifest` embedded, created on first use.
std::expected<std::wstring, std::string> host_executable(const std::string& manifest) {
  const std::wstring self = module_path(nullptr);
  WIN32_FILE_ATTRIBUTE_DATA attributes{};
  if (!GetFileAttributesExW(self.c_str(), GetFileExInfoStandard, &attributes))
    return std::unexpected(std::format("cannot read juice.exe attributes (error {})", GetLastError()));

  // One copy per juice.exe installation, build and manifest: <install>-<build>-<manifest>.
  const uint64_t install = fnv1a(self.data(), self.size() * sizeof(wchar_t));
  uint64_t build = fnv1a(&attributes.ftLastWriteTime, sizeof(attributes.ftLastWriteTime));
  build = fnv1a(&attributes.nFileSizeLow, sizeof(attributes.nFileSizeLow), build);
  const uint64_t manifest_key = fnv1a(manifest.data(), manifest.size());

  wchar_t local[MAX_PATH] = {};
  if (!GetEnvironmentVariableW(L"LOCALAPPDATA", local, MAX_PATH) && !GetTempPathW(MAX_PATH, local))
    return std::unexpected("no LOCALAPPDATA or TEMP directory");
  const std::filesystem::path hosts = std::filesystem::path(local) / L"juice" / L"hosts";
  const std::wstring prefix = std::format(L"{:08x}-", static_cast<uint32_t>(install));
  const std::wstring current = std::format(L"{}{:08x}-", prefix, static_cast<uint32_t>(build));
  const std::filesystem::path dir = hosts / std::format(L"{}{:016x}", current, manifest_key);
  const std::filesystem::path exe = dir / L"juice.exe";
  if (GetFileAttributesW(exe.c_str()) != INVALID_FILE_ATTRIBUTES) return exe.wstring();

  // Copies made for earlier builds of this juice.exe are stale (best effort:
  // one that is still running stays until next time).
  std::error_code ignored;
  for (const auto& entry : std::filesystem::directory_iterator(hosts, ignored)) {
    const std::wstring name = entry.path().filename().wstring();
    if (name.starts_with(prefix) && !name.starts_with(current)) std::filesystem::remove_all(entry.path(), ignored);
  }

  std::error_code ec;
  std::filesystem::create_directories(dir, ec);
  if (ec) return std::unexpected(std::format("cannot create {}: {}", dir.string(), ec.message()));
  // Build under a private name, then rename: concurrent launches may race.
  const std::filesystem::path tmp = dir / std::format(L"juice.{}.tmp", GetCurrentProcessId());
  if (!CopyFileW(self.c_str(), tmp.c_str(), FALSE))
    return std::unexpected(std::format("cannot copy juice.exe (error {})", GetLastError()));
  HANDLE update = BeginUpdateResourceW(tmp.c_str(), FALSE);
  bool ok = update && UpdateResourceW(update, MAKEINTRESOURCEW(24) /* RT_MANIFEST */, MAKEINTRESOURCEW(1),
                                      MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL), const_cast<char*>(manifest.data()),
                                      static_cast<DWORD>(manifest.size()));
  if (update) ok = EndUpdateResourceW(update, !ok) && ok;
  if (!ok) {
    const DWORD error = GetLastError();
    DeleteFileW(tmp.c_str());
    return std::unexpected(std::format("cannot embed the manifest (error {})", error));
  }
  if (!MoveFileExW(tmp.c_str(), exe.c_str(), 0)) {
    DeleteFileW(tmp.c_str());
    if (GetFileAttributesW(exe.c_str()) == INVALID_FILE_ATTRIBUTES)
      return std::unexpected(std::format("cannot create {} (error {})", exe.string(), GetLastError()));
  }
  return exe.wstring();
}

BOOL WINAPI ignore_console_control(DWORD) { return TRUE; }  // the host process handles Ctrl+C

// The requested execution level, if it asks for more than the invoker's rights.
const char* elevated_run_level(HANDLE context) {
  ACTIVATION_CONTEXT_RUN_LEVEL_INFORMATION info{};
  SIZE_T written = 0;
  if (!QueryActCtxW(0, context, nullptr, RunlevelInformationInActivationContext, &info, sizeof(info), &written))
    return nullptr;
  if (info.RunLevel == ACTCTX_RUN_LEVEL_HIGHEST_AVAILABLE) return "highestAvailable";
  if (info.RunLevel == ACTCTX_RUN_LEVEL_REQUIRE_ADMIN) return "requireAdministrator";
  return nullptr;
}

// juice's own arguments: the command line without the program name.
std::wstring arguments_of(const wchar_t* command_line) {
  const wchar_t* p = command_line;
  if (*p == L'"') {
    for (++p; *p && *p != L'"'; ++p) {
    }
    if (*p) ++p;
  } else {
    while (*p && *p != L' ' && *p != L'\t') ++p;
  }
  while (*p == L' ' || *p == L'\t') ++p;
  return p;
}

void make_inheritable(HANDLE h) {
  if (h && h != INVALID_HANDLE_VALUE) SetHandleInformation(h, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
}

// The program asks for administrator rights: start the host through UAC
// like the shell would. An elevated process can't share this console, so it
// gets a window of its own; its exit code is still returned.
std::expected<int, std::string> run_elevated(const std::wstring& exe, const std::wstring& arguments, int show) {
  std::fprintf(stderr, "juice: the program requires elevation; it runs in a new administrator window\n");
  std::fflush(stderr);
  std::wstring directory(MAX_PATH, L'\0');
  directory.resize(GetCurrentDirectoryW(static_cast<DWORD>(directory.size()), directory.data()));
  SHELLEXECUTEINFOW info{};
  info.cbSize = sizeof(info);
  info.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC;
  info.lpVerb = L"runas";
  info.lpFile = exe.c_str();
  info.lpParameters = arguments.c_str();
  info.lpDirectory = directory.c_str();
  info.nShow = show;
  if (!ShellExecuteExW(&info) || !info.hProcess) {
    const DWORD error = GetLastError();
    if (error == ERROR_CANCELLED) return std::unexpected("elevation was declined");
    return std::unexpected(std::format("cannot start the elevated host process (error {})", error));
  }
  SetConsoleCtrlHandler(ignore_console_control, TRUE);
  WaitForSingleObject(info.hProcess, INFINITE);
  DWORD code = 1;
  GetExitCodeProcess(info.hProcess, &code);
  CloseHandle(info.hProcess);
  return static_cast<int>(code);
}

}  // namespace

std::string host_manifest_for(const std::wstring& exe_path) {
  ACTCTXW actctx{};
  actctx.cbSize = sizeof(actctx);
  actctx.dwFlags = ACTCTX_FLAG_RESOURCE_NAME_VALID;
  actctx.lpSource = exe_path.c_str();
  actctx.lpResourceName = MAKEINTRESOURCEW(1);
  HANDLE context = CreateActCtxW(&actctx);
  if (context == INVALID_HANDLE_VALUE) return {};  // no manifest, or an invalid one (reported by apply_manifest)

  bool needs_new_process = false;
  std::string settings;
  for (const Setting& s : kSettings) {
    const std::string value = query_setting(context, s);
    if (value.empty()) continue;
    needs_new_process |= s.needs_new_process;
    settings += std::format("      <{0} xmlns=\"{1}\">{2}</{0}>\n", s.name, s.ns, xml_escape(value));
  }
  const std::string compatibility = compatibility_entries(context);
  const char* run_level = elevated_run_level(context);
  ReleaseActCtx(context);
  if (!needs_new_process && compatibility.empty() && !run_level) return {};

  std::string manifest =
      "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n"
      "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\">\n"
      "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">\n"
      "    <security><requestedPrivileges>\n"
      "      <requestedExecutionLevel level=\"" +
      std::string(run_level ? run_level : "asInvoker") +
      "\" uiAccess=\"false\"/>\n"
      "    </requestedPrivileges></security>\n"
      "  </trustInfo>\n";
  if (!compatibility.empty()) {
    manifest += "  <compatibility xmlns=\"urn:schemas-microsoft-com:compatibility.v1\">\n    <application>\n" +
                compatibility + "    </application>\n  </compatibility>\n";
  }
  if (!settings.empty()) {
    manifest += "  <application xmlns=\"urn:schemas-microsoft-com:asm.v3\">\n    <windowsSettings>\n" + settings +
                "    </windowsSettings>\n  </application>\n";
  }
  manifest += "</assembly>\n";
  return manifest;
}

std::expected<int, std::string> run_in_host(const std::string& manifest, std::FILE* log) {
  auto exe = host_executable(manifest);
  if (!exe) return std::unexpected(exe.error());
  if (log) {
    std::fprintf(log, "[juice] manifest: running in host process %ls with manifest:\n%s", exe->c_str(),
                 manifest.c_str());
  }

  STARTUPINFOW si{};
  GetStartupInfoW(&si);
  si.cb = sizeof(si);
  si.lpReserved = nullptr;
  si.cbReserved2 = 0;
  si.lpReserved2 = nullptr;
  si.dwFlags = (si.dwFlags & ~STARTF_USEHOTKEY) | STARTF_USESTDHANDLES;
  si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
  si.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
  si.hStdError = GetStdHandle(STD_ERROR_HANDLE);
  make_inheritable(si.hStdInput);
  make_inheritable(si.hStdOutput);
  make_inheritable(si.hStdError);

  // The host must not outlive this process (e.g. when a test runner kills it).
  HANDLE job = CreateJobObjectW(nullptr, nullptr);
  if (job) {
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits, sizeof(limits));
  }

  // `--in-host` keeps the host from starting a host of its own.
  const std::wstring arguments = L"--in-host " + arguments_of(GetCommandLineW());
  std::wstring command_line = L"\"" + *exe + L"\" " + arguments;
  PROCESS_INFORMATION pi{};
  const BOOL created = CreateProcessW(exe->c_str(), command_line.data(), nullptr, nullptr, TRUE, CREATE_SUSPENDED,
                                      nullptr, nullptr, &si, &pi);
  if (!created && GetLastError() == ERROR_ELEVATION_REQUIRED) {
    if (job) CloseHandle(job);
    return run_elevated(*exe, arguments, si.dwFlags & STARTF_USESHOWWINDOW ? si.wShowWindow : SW_SHOWNORMAL);
  }
  if (!created) {
    const DWORD error = GetLastError();
    if (job) CloseHandle(job);
    return std::unexpected(std::format("cannot start the host process (error {})", error));
  }
  if (job) AssignProcessToJobObject(job, pi.hProcess);
  SetConsoleCtrlHandler(ignore_console_control, TRUE);
  ResumeThread(pi.hThread);
  CloseHandle(pi.hThread);
  WaitForSingleObject(pi.hProcess, INFINITE);
  DWORD code = 1;
  GetExitCodeProcess(pi.hProcess, &code);
  CloseHandle(pi.hProcess);
  if (job) CloseHandle(job);
  return static_cast<int>(code);
}


}  // namespace juice::win
