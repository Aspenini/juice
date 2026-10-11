// Native code's view of the guest's modules.
//
// The guest's own calls to the module functions are builtins, but native
// DLLs working for it (MFC, COM, the shell, the native C runtime) ask the
// native loader, which knows nothing of the guest modules JUICE mapped: for
// it the process's main module is juice.exe. So the imports of native modules
// that resolve to the loader query functions are redirected here, and answer
// for guest modules (with NULL, as for a native program, meaning the guest
// program): GetModuleFileName, GetModuleHandle(Ex) and GetProcAddress.
//
// Native modules loaded later are patched as the loader reports them
// (LdrRegisterDllNotification). juice.exe and the core system DLLs keep the
// native functions.

#include "windows/native_hooks.hpp"

#include <windows.h>

#include <psapi.h>

#include <cstring>
#include <string>
#include <vector>

#include "windows/guest_process.hpp"

namespace juice::win {
namespace {

GuestProcess* g_guest = nullptr;

decltype(&GetModuleFileNameW) real_GetModuleFileNameW;
decltype(&GetModuleFileNameA) real_GetModuleFileNameA;
decltype(&GetModuleHandleW) real_GetModuleHandleW;
decltype(&GetModuleHandleA) real_GetModuleHandleA;
decltype(&GetModuleHandleExW) real_GetModuleHandleExW;
decltype(&GetModuleHandleExA) real_GetModuleHandleExA;
decltype(&GetProcAddress) real_GetProcAddress;

GuestModule* guest_module(HMODULE handle) {
  if (!handle) return g_guest->module_by_handle(g_guest->exe().base());
  return g_guest->module_by_handle(reinterpret_cast<uint64_t>(handle));
}

std::wstring widen(const char* s) {
  const int n = MultiByteToWideChar(CP_ACP, 0, s, -1, nullptr, 0);
  std::wstring out(n > 0 ? n - 1 : 0, L'\0');
  if (n > 1) MultiByteToWideChar(CP_ACP, 0, s, -1, out.data(), n);
  return out;
}

// GetModuleFileName's truncation rules.
template <typename Char>
DWORD copy_path(const std::basic_string<Char>& path, Char* buffer, DWORD size) {
  if (size == 0) {
    SetLastError(ERROR_INSUFFICIENT_BUFFER);
    return 0;
  }
  if (path.size() < size) {
    std::memcpy(buffer, path.c_str(), (path.size() + 1) * sizeof(Char));
    SetLastError(ERROR_SUCCESS);
    return static_cast<DWORD>(path.size());
  }
  std::memcpy(buffer, path.c_str(), (size - 1) * sizeof(Char));
  buffer[size - 1] = 0;
  SetLastError(ERROR_INSUFFICIENT_BUFFER);
  return size;
}

DWORD WINAPI hook_GetModuleFileNameW(HMODULE module, LPWSTR buffer, DWORD size) {
  if (const GuestModule* m = guest_module(module)) return copy_path(m->path, buffer, size);
  return real_GetModuleFileNameW(module, buffer, size);
}

DWORD WINAPI hook_GetModuleFileNameA(HMODULE module, LPSTR buffer, DWORD size) {
  if (const GuestModule* m = guest_module(module)) {
    const int n = WideCharToMultiByte(CP_ACP, 0, m->path.c_str(), -1, nullptr, 0, nullptr, nullptr);
    std::string path(n > 0 ? n - 1 : 0, '\0');
    if (n > 1) WideCharToMultiByte(CP_ACP, 0, m->path.c_str(), -1, path.data(), n, nullptr, nullptr);
    return copy_path(path, buffer, size);
  }
  return real_GetModuleFileNameA(module, buffer, size);
}

HMODULE WINAPI hook_GetModuleHandleW(LPCWSTR name) {
  if (!name) return reinterpret_cast<HMODULE>(g_guest->exe().base());
  if (const GuestModule* m = g_guest->find_loaded_module(name)) return reinterpret_cast<HMODULE>(m->base());
  return real_GetModuleHandleW(name);
}

HMODULE WINAPI hook_GetModuleHandleA(LPCSTR name) {
  if (!name) return reinterpret_cast<HMODULE>(g_guest->exe().base());
  if (const GuestModule* m = g_guest->find_loaded_module(widen(name))) return reinterpret_cast<HMODULE>(m->base());
  return real_GetModuleHandleA(name);
}

// The guest module GetModuleHandleEx means, if any.
GuestModule* module_for_ex(DWORD flags, const void* name_or_address, bool wide) {
  if (flags & GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS)
    return g_guest->module_at(reinterpret_cast<uint64_t>(name_or_address));
  if (!name_or_address) return guest_module(nullptr);
  return g_guest->find_loaded_module(wide ? std::wstring(static_cast<const wchar_t*>(name_or_address))
                                          : widen(static_cast<const char*>(name_or_address)));
}

BOOL module_handle_ex(DWORD flags, GuestModule& m, HMODULE* out) {
  if (!(flags & GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT) || (flags & GET_MODULE_HANDLE_EX_FLAG_PIN))
    g_guest->reference_module(m, (flags & GET_MODULE_HANDLE_EX_FLAG_PIN) != 0);
  if (out) *out = reinterpret_cast<HMODULE>(m.base());
  return TRUE;
}

BOOL WINAPI hook_GetModuleHandleExW(DWORD flags, LPCWSTR name, HMODULE* out) {
  if (GuestModule* m = module_for_ex(flags, name, true)) return module_handle_ex(flags, *m, out);
  return real_GetModuleHandleExW(flags, name, out);
}

BOOL WINAPI hook_GetModuleHandleExA(DWORD flags, LPCSTR name, HMODULE* out) {
  if (GuestModule* m = module_for_ex(flags, name, false)) return module_handle_ex(flags, *m, out);
  return real_GetModuleHandleExA(flags, name, out);
}

FARPROC WINAPI hook_GetProcAddress(HMODULE module, LPCSTR name) {
  if (module) {
    if (GuestModule* m = g_guest->module_by_handle(reinterpret_cast<uint64_t>(module))) {
      if (const uint64_t address = g_guest->guest_export(*m, name)) return reinterpret_cast<FARPROC>(address);
      SetLastError(ERROR_PROC_NOT_FOUND);
      return nullptr;
    }
  }
  return real_GetProcAddress(module, name);
}

// The functions to redirect: the addresses imports may hold (kernelbase's,
// and kernel32's where that is a function of its own) and the hooks.
struct Redirect {
  std::vector<void*> targets;
  void* hook;
};
std::vector<Redirect> g_redirects;

void add_redirect(const char* name, void* hook, void** real) {
  Redirect r;
  r.hook = hook;
  for (const wchar_t* dll : {L"kernelbase.dll", L"kernel32.dll"}) {
    if (HMODULE m = GetModuleHandleW(dll)) {
      if (void* f = reinterpret_cast<void*>(GetProcAddress(m, name))) {
        r.targets.push_back(f);
        if (!*real) *real = f;
      }
    }
  }
  g_redirects.push_back(std::move(r));
}

bool keeps_native_functions(HMODULE module) {
  if (module == GetModuleHandleW(nullptr)) return true;  // juice.exe
  for (const wchar_t* dll : {L"ntdll.dll", L"kernelbase.dll", L"kernel32.dll"})
    if (module == GetModuleHandleW(dll)) return true;
  return false;
}

// Redirect the import address table entries of `module` that hold one of the functions.
void patch_module(HMODULE module) {
  if (!module || keeps_native_functions(module)) return;
  auto* base = reinterpret_cast<uint8_t*>(module);
  const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
  if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;
  const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
  if (nt->Signature != IMAGE_NT_SIGNATURE || nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) return;
  const IMAGE_DATA_DIRECTORY& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
  if (!dir.VirtualAddress) return;
  for (auto* d = reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(base + dir.VirtualAddress); d->Name; ++d) {
    for (auto* slot = reinterpret_cast<void**>(base + d->FirstThunk); *slot; ++slot) {
      for (const Redirect& r : g_redirects) {
        bool match = false;
        for (void* t : r.targets) match |= *slot == t;
        if (!match) continue;
        DWORD old = 0;
        if (VirtualProtect(slot, sizeof(void*), PAGE_READWRITE, &old)) {
          *slot = r.hook;
          VirtualProtect(slot, sizeof(void*), old, &old);
        }
        break;
      }
    }
  }
}

// LdrRegisterDllNotification's callback: patch DLLs as they load.
struct DllNotificationData {
  ULONG flags;
  const void* full_name;
  const void* base_name;
  void* dll_base;
  ULONG size_of_image;
};
constexpr ULONG kDllLoaded = 1;

VOID CALLBACK on_dll_notification(ULONG reason, const DllNotificationData* data, void*) {
  if (reason == kDllLoaded && data) patch_module(static_cast<HMODULE>(data->dll_base));
}

}  // namespace

void install_native_hooks(GuestProcess& process) {
  if (g_guest) return;
  g_guest = &process;
  add_redirect("GetModuleFileNameW", reinterpret_cast<void*>(&hook_GetModuleFileNameW),
               reinterpret_cast<void**>(&real_GetModuleFileNameW));
  add_redirect("GetModuleFileNameA", reinterpret_cast<void*>(&hook_GetModuleFileNameA),
               reinterpret_cast<void**>(&real_GetModuleFileNameA));
  add_redirect("GetModuleHandleW", reinterpret_cast<void*>(&hook_GetModuleHandleW),
               reinterpret_cast<void**>(&real_GetModuleHandleW));
  add_redirect("GetModuleHandleA", reinterpret_cast<void*>(&hook_GetModuleHandleA),
               reinterpret_cast<void**>(&real_GetModuleHandleA));
  add_redirect("GetModuleHandleExW", reinterpret_cast<void*>(&hook_GetModuleHandleExW),
               reinterpret_cast<void**>(&real_GetModuleHandleExW));
  add_redirect("GetModuleHandleExA", reinterpret_cast<void*>(&hook_GetModuleHandleExA),
               reinterpret_cast<void**>(&real_GetModuleHandleExA));
  add_redirect("GetProcAddress", reinterpret_cast<void*>(&hook_GetProcAddress),
               reinterpret_cast<void**>(&real_GetProcAddress));

  using RegisterFn = LONG(NTAPI*)(ULONG, decltype(&on_dll_notification), void*, void**);
  if (auto reg = reinterpret_cast<RegisterFn>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "LdrRegisterDllNotification"))) {
    void* cookie = nullptr;
    reg(0, &on_dll_notification, nullptr, &cookie);
  }
  HMODULE modules[1024];
  DWORD needed = 0;
  if (K32EnumProcessModules(GetCurrentProcess(), modules, sizeof(modules), &needed)) {
    for (DWORD i = 0; i < needed / sizeof(HMODULE) && i < 1024; ++i) patch_module(modules[i]);
  }
}

}  // namespace juice::win
