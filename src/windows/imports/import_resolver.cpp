#include "windows/imports/import_resolver.hpp"

#include <windows.h>

#include <algorithm>
#include <cstring>
#include <format>
#include <unordered_map>

#include "windows/dlls/builtins.hpp"

namespace juice::win {

bool is_native_code(const void* addr) {
  HMODULE mod = nullptr;
  if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                         static_cast<LPCWSTR>(addr), &mod)) {
    auto* base = reinterpret_cast<const uint8_t*>(mod);
    auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
    const IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    uint64_t rva = static_cast<uint64_t>(static_cast<const uint8_t*>(addr) - base);
    for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
      uint64_t size = std::max(sec->Misc.VirtualSize, sec->SizeOfRawData);
      if (rva >= sec->VirtualAddress && rva < sec->VirtualAddress + size)
        return (sec->Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
    }
    return false;
  }
  MEMORY_BASIC_INFORMATION mbi{};
  if (!VirtualQuery(addr, &mbi, sizeof(mbi))) return false;
  return (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
}

uint64_t guest_value_for_native_export(void* addr, ThunkTable& thunks, std::string dll, std::string name) {
  if (!is_native_code(addr)) return reinterpret_cast<uint64_t>(addr);
  const char* signature = native_signature(dll, name);
  return thunks.add_native(addr, std::move(dll), std::move(name), signature);
}

uint64_t resolve_native_import(const pe::Import& imp, ThunkTable& thunks, const char** how, ImportStats* stats) {
  const std::string display = imp.by_ordinal ? std::format("#{}", imp.ordinal) : imp.name;
  const char* result = "";
  uint64_t value = 0;
  if (BuiltinFn fn = imp.by_ordinal ? nullptr : find_builtin(imp.dll, imp.name)) {
    Thunk t;
    t.kind = Thunk::Kind::Builtin;
    t.dll = imp.dll;
    t.name = imp.name;
    t.builtin = fn;
    value = thunks.add(std::move(t));
    result = "builtin";
    if (stats) ++stats->builtin;
  } else {
    HMODULE mod = LoadLibraryA(imp.dll.c_str());
    void* addr = nullptr;
    if (mod) {
      addr = reinterpret_cast<void*>(
          GetProcAddress(mod, imp.by_ordinal ? MAKEINTRESOURCEA(imp.ordinal) : imp.name.c_str()));
    }
    if (addr) {
      value = guest_value_for_native_export(addr, thunks, imp.dll, display);
      const bool data = value == reinterpret_cast<uint64_t>(addr);
      result = data ? "data" : "native";
      if (stats) ++(data ? stats->data : stats->native);
    } else {
      value = missing_import(thunks, imp.dll, display);
      result = mod ? "MISSING (no such export)" : "MISSING (DLL not found)";
      if (stats) ++stats->missing;
    }
  }
  if (how) *how = result;
  return value;
}

uint64_t missing_import(ThunkTable& thunks, const std::string& dll, const std::string& name) {
  Thunk t;
  t.kind = Thunk::Kind::Missing;
  t.dll = dll;
  t.name = name;
  return thunks.add(std::move(t));
}

ImportStats resolve_imports(const pe::LoadedImage& image, ThunkTable& thunks, std::FILE* log,
                            const GuestImportBinder& guest) {
  ImportStats stats;
  for (const pe::Import& imp : image.imports) {
    const char* how = "";
    uint64_t value = 0;
    if (std::optional<uint64_t> bound = guest ? guest(imp) : std::nullopt) {
      value = *bound;
      how = "guest";
      ++stats.guest;
    } else {
      value = resolve_native_import(imp, thunks, &how, &stats);
    }
    std::memcpy(image.base + imp.iat_rva, &value, sizeof(value));
    if (log) {
      std::fprintf(log, "[juice] import %s!%s -> %s 0x%llx\n", imp.dll.c_str(),
                   imp.by_ordinal ? std::format("#{}", imp.ordinal).c_str() : imp.name.c_str(), how,
                   static_cast<unsigned long long>(value));
    }
  }
  return stats;
}

}  // namespace juice::win
