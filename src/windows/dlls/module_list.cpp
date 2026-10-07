// Module enumeration builtins: psapi (the kernel32 K32* functions, which
// psapi.dll exports under their plain names) and toolhelp's Module32First/Next.
//
// For this process the guest sees its own modules (the program first, in place
// of juice.exe) followed by the native DLLs the process has loaded.

#include <windows.h>

#include <psapi.h>
#include <tlhelp32.h>

#include <cstring>
#include <mutex>
#include <string>
#include <unordered_map>
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

std::string wide_to_ansi(const std::wstring& s) {
  int n = WideCharToMultiByte(CP_ACP, 0, s.c_str(), -1, nullptr, 0, nullptr, nullptr);
  std::string out(n > 0 ? n - 1 : 0, '\0');
  if (n > 1) WideCharToMultiByte(CP_ACP, 0, s.c_str(), -1, out.data(), n, nullptr, nullptr);
  return out;
}

bool is_this_process(uint64_t process) {
  return process == reinterpret_cast<uint64_t>(GetCurrentProcess()) ||
         GetProcessId(ptr<void>(process)) == GetCurrentProcessId();
}

HMODULE host_exe() { return GetModuleHandleW(nullptr); }

const GuestModule* guest_module(GuestProcess& p, uint64_t handle) {
  return handle == 0 ? &p.exe() : p.module_by_handle(handle);
}

// Copies with truncation, as the psapi functions do: returns the characters copied.
template <typename Char>
uint64_t copy_truncated(const std::basic_string<Char>& s, Char* buffer, DWORD size) {
  if (size == 0) return 0;
  const size_t n = s.size() < size ? s.size() : size - 1;
  std::memcpy(buffer, s.c_str(), n * sizeof(Char));
  buffer[n] = 0;
  return n;
}

// K32EnumProcessModules(process, modules, cb, needed)
uint64_t enum_process_modules(GuestProcess& p, CpuState& s) {
  if (!is_this_process(s.x[0])) {
    return K32EnumProcessModules(ptr<void>(s.x[0]), ptr<HMODULE>(s.x[1]), static_cast<DWORD>(s.x[2]),
                                 ptr<DWORD>(s.x[3]));
  }
  std::vector<HMODULE> list;
  for (const GuestModule* m : p.loaded_modules()) list.push_back(reinterpret_cast<HMODULE>(m->base()));
  DWORD needed = 0;
  K32EnumProcessModules(GetCurrentProcess(), nullptr, 0, &needed);
  std::vector<HMODULE> native(needed / sizeof(HMODULE) + 16);
  if (!K32EnumProcessModules(GetCurrentProcess(), native.data(), static_cast<DWORD>(native.size() * sizeof(HMODULE)),
                             &needed))
    return FALSE;
  native.resize(needed / sizeof(HMODULE));
  for (HMODULE h : native)
    if (h != host_exe()) list.push_back(h);

  auto* out = ptr<HMODULE>(s.x[1]);
  const size_t capacity = static_cast<DWORD>(s.x[2]) / sizeof(HMODULE);
  for (size_t i = 0; i < list.size() && i < capacity; ++i) out[i] = list[i];
  if (s.x[3]) *ptr<DWORD>(s.x[3]) = static_cast<DWORD>(list.size() * sizeof(HMODULE));
  return TRUE;
}

uint64_t K32EnumProcessModules_(GuestProcess& p, CpuState& s) { return enum_process_modules(p, s); }

// K32EnumProcessModulesEx(process, modules, cb, needed, filter): ARM64 modules
// count as 64-bit ones.
uint64_t K32EnumProcessModulesEx_(GuestProcess& p, CpuState& s) {
  if (!is_this_process(s.x[0])) {
    return K32EnumProcessModulesEx(ptr<void>(s.x[0]), ptr<HMODULE>(s.x[1]), static_cast<DWORD>(s.x[2]),
                                   ptr<DWORD>(s.x[3]), static_cast<DWORD>(s.x[4]));
  }
  if (static_cast<DWORD>(s.x[4]) == LIST_MODULES_32BIT) {
    if (s.x[3]) *ptr<DWORD>(s.x[3]) = 0;
    return TRUE;
  }
  return enum_process_modules(p, s);
}

// K32GetModuleInformation(process, module, info, cb)
uint64_t K32GetModuleInformation_(GuestProcess& p, CpuState& s) {
  if (is_this_process(s.x[0])) {
    if (const GuestModule* m = guest_module(p, s.x[1])) {
      if (static_cast<DWORD>(s.x[3]) < sizeof(MODULEINFO)) {
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
      }
      auto* info = ptr<MODULEINFO>(s.x[2]);
      info->lpBaseOfDll = ptr<void>(m->base());
      info->SizeOfImage = static_cast<DWORD>(m->image.size);
      info->EntryPoint = ptr<void>(m->image.entry);
      return TRUE;
    }
  }
  return K32GetModuleInformation(ptr<void>(s.x[0]), ptr<HINSTANCE__>(s.x[1]), ptr<MODULEINFO>(s.x[2]),
                                 static_cast<DWORD>(s.x[3]));
}

// K32GetModuleBaseName(process, module, buffer, size)
uint64_t K32GetModuleBaseNameA_(GuestProcess& p, CpuState& s) {
  if (is_this_process(s.x[0]))
    if (const GuestModule* m = guest_module(p, s.x[1]))
      return copy_truncated(wide_to_ansi(m->display_name()), ptr<char>(s.x[2]), static_cast<DWORD>(s.x[3]));
  return K32GetModuleBaseNameA(ptr<void>(s.x[0]), ptr<HINSTANCE__>(s.x[1]), ptr<char>(s.x[2]),
                               static_cast<DWORD>(s.x[3]));
}

uint64_t K32GetModuleBaseNameW_(GuestProcess& p, CpuState& s) {
  if (is_this_process(s.x[0]))
    if (const GuestModule* m = guest_module(p, s.x[1]))
      return copy_truncated(m->display_name(), ptr<wchar_t>(s.x[2]), static_cast<DWORD>(s.x[3]));
  return K32GetModuleBaseNameW(ptr<void>(s.x[0]), ptr<HINSTANCE__>(s.x[1]), ptr<wchar_t>(s.x[2]),
                               static_cast<DWORD>(s.x[3]));
}

// K32GetModuleFileNameEx(process, module, buffer, size)
uint64_t K32GetModuleFileNameExA_(GuestProcess& p, CpuState& s) {
  if (is_this_process(s.x[0]))
    if (const GuestModule* m = guest_module(p, s.x[1]))
      return copy_truncated(wide_to_ansi(m->path), ptr<char>(s.x[2]), static_cast<DWORD>(s.x[3]));
  return K32GetModuleFileNameExA(ptr<void>(s.x[0]), ptr<HINSTANCE__>(s.x[1]), ptr<char>(s.x[2]),
                                 static_cast<DWORD>(s.x[3]));
}

uint64_t K32GetModuleFileNameExW_(GuestProcess& p, CpuState& s) {
  if (is_this_process(s.x[0]))
    if (const GuestModule* m = guest_module(p, s.x[1]))
      return copy_truncated(m->path, ptr<wchar_t>(s.x[2]), static_cast<DWORD>(s.x[3]));
  return K32GetModuleFileNameExW(ptr<void>(s.x[0]), ptr<HINSTANCE__>(s.x[1]), ptr<wchar_t>(s.x[2]),
                                 static_cast<DWORD>(s.x[3]));
}

// --- toolhelp ---------------------------------------------------------------------------
//
// A module snapshot of this process lists the guest modules (captured at
// Module32First) before the native entries, juice.exe's left out.

struct SnapshotWalk {
  std::vector<uint64_t> guest;  // module bases
  size_t next = 0;
};

std::mutex g_walk_mutex;
std::unordered_map<HANDLE, SnapshotWalk> g_walks;

void fill_entry(const GuestModule& m, MODULEENTRY32W& e) {
  e.th32ModuleID = 1;
  e.th32ProcessID = GetCurrentProcessId();
  e.GlblcntUsage = e.ProccntUsage = 0xFFFF;
  e.modBaseAddr = ptr<BYTE>(m.base());
  e.modBaseSize = static_cast<DWORD>(m.image.size);
  e.hModule = reinterpret_cast<HMODULE>(m.base());
  wcsncpy_s(e.szModule, m.display_name().c_str(), _TRUNCATE);
  wcsncpy_s(e.szExePath, m.path.c_str(), _TRUNCATE);
}

// The next entry of a walk; `first` restarts it.
bool module_entry(GuestProcess& p, HANDLE snapshot, MODULEENTRY32W& e, bool first) {
  std::unique_lock lock(g_walk_mutex);
  if (first) {
    MODULEENTRY32W probe{};
    probe.dwSize = sizeof(probe);
    if (!Module32FirstW(snapshot, &probe)) {
      g_walks.erase(snapshot);
      return false;
    }
    if (probe.th32ProcessID != GetCurrentProcessId()) {
      g_walks.erase(snapshot);
      e = probe;
      return true;
    }
    SnapshotWalk walk;
    for (const GuestModule* m : p.loaded_modules()) walk.guest.push_back(m->base());
    g_walks[snapshot] = std::move(walk);
  }
  auto it = g_walks.find(snapshot);
  if (it == g_walks.end()) return Module32NextW(snapshot, &e);  // another process's snapshot
  SnapshotWalk& walk = it->second;
  while (walk.next < walk.guest.size()) {
    const GuestModule* m = p.module_by_handle(walk.guest[walk.next++]);
    if (!m) continue;  // unloaded since
    fill_entry(*m, e);
    return true;
  }
  while (Module32NextW(snapshot, &e)) {
    if (e.hModule != host_exe()) return true;
  }
  return false;
}

template <bool First>
uint64_t module32_w(GuestProcess& p, CpuState& s) {
  auto* out = ptr<MODULEENTRY32W>(s.x[1]);
  if (!out || out->dwSize < sizeof(MODULEENTRY32W)) {
    SetLastError(ERROR_INVALID_PARAMETER);
    return FALSE;
  }
  MODULEENTRY32W e{};
  e.dwSize = sizeof(e);
  if (!module_entry(p, ptr<void>(s.x[0]), e, First)) return FALSE;
  *out = e;
  return TRUE;
}

template <bool First>
uint64_t module32_a(GuestProcess& p, CpuState& s) {
  auto* out = ptr<MODULEENTRY32>(s.x[1]);
  if (!out || out->dwSize < sizeof(MODULEENTRY32)) {
    SetLastError(ERROR_INVALID_PARAMETER);
    return FALSE;
  }
  MODULEENTRY32W e{};
  e.dwSize = sizeof(e);
  if (!module_entry(p, ptr<void>(s.x[0]), e, First)) return FALSE;
  out->th32ModuleID = e.th32ModuleID;
  out->th32ProcessID = e.th32ProcessID;
  out->GlblcntUsage = e.GlblcntUsage;
  out->ProccntUsage = e.ProccntUsage;
  out->modBaseAddr = e.modBaseAddr;
  out->modBaseSize = e.modBaseSize;
  out->hModule = e.hModule;
  strncpy_s(out->szModule, wide_to_ansi(e.szModule).c_str(), _TRUNCATE);
  strncpy_s(out->szExePath, wide_to_ansi(e.szExePath).c_str(), _TRUNCATE);
  return TRUE;
}

constexpr BuiltinExport kModuleList[] = {
    {"K32EnumProcessModules", K32EnumProcessModules_},
    {"K32EnumProcessModulesEx", K32EnumProcessModulesEx_},
    {"K32GetModuleInformation", K32GetModuleInformation_},
    {"K32GetModuleBaseNameA", K32GetModuleBaseNameA_},
    {"K32GetModuleBaseNameW", K32GetModuleBaseNameW_},
    {"K32GetModuleFileNameExA", K32GetModuleFileNameExA_},
    {"K32GetModuleFileNameExW", K32GetModuleFileNameExW_},
    {"Module32First", module32_a<true>},
    {"Module32Next", module32_a<false>},
    {"Module32FirstW", module32_w<true>},
    {"Module32NextW", module32_w<false>},
};

}  // namespace

std::span<const BuiltinExport> module_list_builtins() { return kModuleList; }

}  // namespace juice::win
