// COM activation builtins: CoGetClassObject, CoCreateInstance and
// CoCreateInstanceEx for in-process servers that are ARM64 DLLs.
//
// The native COM runtime would load the server's DLL itself, which it cannot
// do for an ARM64 one. JUICE looks the class up in the registry
// (CLSID\{...}\InprocServer32); if that names an ARM64 DLL it loads it as a
// guest module and asks its DllGetClassObject for the class factory. The
// objects are guest objects, so the guest calls their methods directly.
// Every other class (and other contexts) goes to the native COM runtime.

#include <windows.h>

#include <objbase.h>

#include <cstdio>
#include <mutex>
#include <set>
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

template <typename Fn>
Fn* ole32_function(const char* name) {
  static HMODULE ole32 = LoadLibraryW(L"ole32.dll");
  return reinterpret_cast<Fn*>(GetProcAddress(ole32, name));
}

constexpr IID kIidClassFactory = {0x00000001, 0x0000, 0x0000, {0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}};

std::wstring guid_string(const GUID& g) {
  wchar_t s[40];
  swprintf_s(s, L"{%08lX-%04hX-%04hX-%02hhX%02hhX-%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX}", g.Data1, g.Data2, g.Data3,
             g.Data4[0], g.Data4[1], g.Data4[2], g.Data4[3], g.Data4[4], g.Data4[5], g.Data4[6], g.Data4[7]);
  return s;
}

// A registration-free class: the server DLL a manifest of the active
// activation context names for it (a <comClass> of a <file>), in the
// directory of the assembly that declares it.
std::wstring manifest_server(const CLSID& clsid) {
  // The COM server redirection data of the section (as Windows lays it out).
  struct ComServerRedirection {
    ULONG size, flags;
    DWORD threading_model;
    GUID reference_clsid, configured_clsid, implemented_clsid, type_library;
    ULONG module_length, module_offset;  // offset from the section base
  };
  ACTCTX_SECTION_KEYED_DATA data{};
  data.cbSize = sizeof(data);
  if (!FindActCtxSectionGuid(FIND_ACTCTX_SECTION_KEY_RETURN_HACTCTX, nullptr,
                             ACTIVATION_CONTEXT_SECTION_COM_SERVER_REDIRECTION, &clsid, &data))
    return {};
  const auto* r = static_cast<const ComServerRedirection*>(data.lpData);
  std::wstring module(reinterpret_cast<const wchar_t*>(static_cast<const char*>(data.lpSectionBase) + r->module_offset),
                      r->module_length / sizeof(wchar_t));
  std::wstring directory;
  SIZE_T needed = 0;
  DWORD index = data.ulAssemblyRosterIndex;
  QueryActCtxW(0, data.hActCtx, &index, AssemblyDetailedInformationInActivationContext, nullptr, 0, &needed);
  if (needed) {
    std::vector<char> buffer(needed);
    auto* info = reinterpret_cast<ACTIVATION_CONTEXT_ASSEMBLY_DETAILED_INFORMATION*>(buffer.data());
    // The directory of the assembly's manifest (lpAssemblyDirectoryName is a
    // side-by-side store name, not a path, for private assemblies too).
    if (QueryActCtxW(0, data.hActCtx, &index, AssemblyDetailedInformationInActivationContext, info, needed, &needed) &&
        info->lpAssemblyManifestPath) {
      const std::wstring manifest(info->lpAssemblyManifestPath, info->ulManifestPathLength / sizeof(wchar_t));
      const size_t slash = manifest.find_last_of(L"\\/");
      if (slash != std::wstring::npos) directory = manifest.substr(0, slash);
    }
  }
  ReleaseActCtx(data.hActCtx);
  if (module.empty()) return {};
  if (!directory.empty() && directory.back() != L'\\') directory += L'\\';
  return directory + module;  // (no directory: found on the search path, next to the program first)
}

// The class's in-process server DLL, from the registry (environment variables expanded).
std::wstring inproc_server(const CLSID& clsid) {
  const std::wstring key = L"CLSID\\" + guid_string(clsid) + L"\\InprocServer32";
  wchar_t path[MAX_PATH * 2];
  DWORD size = sizeof(path);
  if (RegGetValueW(HKEY_CLASSES_ROOT, key.c_str(), nullptr, RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ, nullptr, path,
                   &size) != ERROR_SUCCESS)
    return {};
  return path;
}

// DllGetClassObject of the class's server if that is an ARM64 DLL, else 0.
// A server stays loaded once used (as with COM, until CoFreeUnusedLibraries).
uint64_t guest_class_object_entry(GuestProcess& p, const CLSID& clsid, uint32_t context) {
  if (!(context & (CLSCTX_INPROC_SERVER | CLSCTX_INPROC_HANDLER))) return 0;
  // Manifests (registration-free COM) come first, as for the native COM runtime.
  std::wstring server = manifest_server(clsid);
  if (server.empty()) server = inproc_server(clsid);
  if (server.empty()) return 0;
  static std::mutex mutex;
  static std::set<uint64_t> loaded;
  std::lock_guard lock(mutex);
  GuestModule* m = p.find_loaded_module(server);
  if (!m || !loaded.contains(m->base())) {
    bool guest = false;
    const uint64_t handle = p.load_library(server, LOAD_WITH_ALTERED_SEARCH_PATH, guest);
    if (!guest || !handle) return 0;
    loaded.insert(handle);
    m = p.module_by_handle(handle);
  }
  if (!m) return 0;
  const uint64_t entry = p.guest_export(*m, "DllGetClassObject");
  if (p.options().trace_calls)
    std::fprintf(stderr, "[juice] COM class %ls: ARM64 server %ls\n", guid_string(clsid).c_str(), server.c_str());
  return entry;
}

// A method of a guest COM object (vtable slot `slot`).
uint64_t call_method(GuestProcess& p, uint64_t object, unsigned slot, std::initializer_list<uint64_t> rest) {
  const uint64_t fn = ptr<const uint64_t>(*ptr<const uint64_t>(object))[slot];
  NativeCallbackTarget::Args args{};
  args.gpr[0] = object;
  size_t i = 1;
  for (uint64_t v : rest) args.gpr[i++] = v;
  return p.call_guest(fn, args).x0;
}

uint64_t hresult(uint64_t v) { return static_cast<uint32_t>(v); }
uint64_t hresult(HRESULT v) { return static_cast<uint32_t>(v); }

// Creates an object of a guest server's class: class factory, CreateInstance, Release.
uint64_t create_guest_instance(GuestProcess& p, uint64_t entry, uint64_t clsid, uint64_t outer, uint64_t iid,
                               uint64_t out) {
  uint64_t factory = 0;
  HRESULT hr = static_cast<HRESULT>(
      p.call_guest(entry, {clsid, reinterpret_cast<uint64_t>(&kIidClassFactory), reinterpret_cast<uint64_t>(&factory)}));
  if (FAILED(hr)) return hresult(hr);
  if (!factory) return hresult(E_UNEXPECTED);
  hr = static_cast<HRESULT>(call_method(p, factory, 3, {outer, iid, out}));  // IClassFactory::CreateInstance
  call_method(p, factory, 2, {});                                             // Release
  return hresult(hr);
}

// CoGetClassObject(clsid, context, server_info, iid, out)
uint64_t CoGetClassObject_(GuestProcess& p, CpuState& s) {
  if (const uint64_t entry = guest_class_object_entry(p, *ptr<const CLSID>(s.x[0]), static_cast<uint32_t>(s.x[1])))
    return hresult(p.call_guest(entry, {s.x[0], s.x[3], s.x[4]}));
  using Fn = HRESULT WINAPI(REFCLSID, DWORD, LPVOID, REFIID, LPVOID*);
  return hresult(ole32_function<Fn>("CoGetClassObject")(*ptr<const CLSID>(s.x[0]), static_cast<DWORD>(s.x[1]),
                                                       ptr<void>(s.x[2]), *ptr<const IID>(s.x[3]),
                                                       ptr<void*>(s.x[4])));
}

// CoCreateInstance(clsid, outer, context, iid, out)
uint64_t CoCreateInstance_(GuestProcess& p, CpuState& s) {
  if (const uint64_t entry = guest_class_object_entry(p, *ptr<const CLSID>(s.x[0]), static_cast<uint32_t>(s.x[2]))) {
    if (s.x[4]) *ptr<uint64_t>(s.x[4]) = 0;
    return create_guest_instance(p, entry, s.x[0], s.x[1], s.x[3], s.x[4]);
  }
  using Fn = HRESULT WINAPI(REFCLSID, LPUNKNOWN, DWORD, REFIID, LPVOID*);
  return hresult(ole32_function<Fn>("CoCreateInstance")(*ptr<const CLSID>(s.x[0]), ptr<IUnknown>(s.x[1]),
                                                       static_cast<DWORD>(s.x[2]), *ptr<const IID>(s.x[3]),
                                                       ptr<void*>(s.x[4])));
}

// CoCreateInstanceEx(clsid, outer, context, server_info, count, results)
uint64_t CoCreateInstanceEx_(GuestProcess& p, CpuState& s) {
  const auto count = static_cast<DWORD>(s.x[4]);
  auto* results = ptr<MULTI_QI>(s.x[5]);
  if (const uint64_t entry = guest_class_object_entry(p, *ptr<const CLSID>(s.x[0]), static_cast<uint32_t>(s.x[2]))) {
    if (count == 0 || !results) return hresult(E_INVALIDARG);
    for (DWORD i = 0; i < count; ++i) {
      results[i].pItf = nullptr;
      results[i].hr = E_NOINTERFACE;
    }
    uint64_t object = 0;
    const HRESULT hr = static_cast<HRESULT>(create_guest_instance(p, entry, s.x[0], s.x[1],
                                                                  reinterpret_cast<uint64_t>(results[0].pIID),
                                                                  reinterpret_cast<uint64_t>(&object)));
    if (FAILED(hr)) {
      for (DWORD i = 0; i < count; ++i) results[i].hr = hr;
      return hresult(hr);
    }
    results[0].pItf = ptr<IUnknown>(object);
    results[0].hr = S_OK;
    DWORD found = 1;
    for (DWORD i = 1; i < count; ++i) {  // IUnknown::QueryInterface
      results[i].hr = static_cast<HRESULT>(call_method(p, object, 0, {reinterpret_cast<uint64_t>(results[i].pIID),
                                                                     reinterpret_cast<uint64_t>(&results[i].pItf)}));
      if (SUCCEEDED(results[i].hr)) ++found;
    }
    return hresult(found == count ? S_OK : CO_S_NOTALLINTERFACES);
  }
  using Fn = HRESULT WINAPI(REFCLSID, IUnknown*, DWORD, COSERVERINFO*, DWORD, MULTI_QI*);
  return hresult(ole32_function<Fn>("CoCreateInstanceEx")(*ptr<const CLSID>(s.x[0]), ptr<IUnknown>(s.x[1]),
                                                         static_cast<DWORD>(s.x[2]), ptr<COSERVERINFO>(s.x[3]), count,
                                                         results));
}

constexpr BuiltinExport kOle32[] = {
    {"CoGetClassObject", CoGetClassObject_},
    {"CoCreateInstance", CoCreateInstance_},
    {"CoCreateInstanceEx", CoCreateInstanceEx_},
};

}  // namespace

std::span<const BuiltinExport> ole32_builtins() { return kOle32; }

}  // namespace juice::win
