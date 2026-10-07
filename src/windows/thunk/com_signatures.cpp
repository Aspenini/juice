// Signatures of native COM methods the generic call bridge would get wrong:
// methods taking floats, structures of floats (D2D1_POINT_2F, ...) or small
// structures by value (Direct2D, DirectWrite, Direct3D, WIC, XAudio2, Media
// Foundation, ...), generated from the SDK headers by tools/gen_signatures.
//
// The guest reaches such a method through an object's vtable, so JUICE only
// sees a native code address and the object (X0). It finds the vtable slot
// that holds the address, and for each interface with a listed method in that
// slot asks the object (QueryInterface) whether it implements the interface
// with that very method. The answer is cached per address.
//
// QueryInterface is only called on objects of system DLLs other than the
// C/C++ runtime (whose C++ objects, such as locale facets, are not COM
// objects), and every access is guarded against faults.

#include <windows.h>
#include <unknwn.h>

#include <algorithm>
#include <cwctype>
#include <mutex>
#include <string>
#include <unordered_map>

#include "windows/thunk/thunk_table.hpp"

namespace juice::win {
namespace {

struct ComMethod {
  GUID iid;
  const char* name;
  unsigned slot;
  const char* kinds;
};

constexpr ComMethod kMethods[] = {
#include "windows/thunk/com_signatures_generated.inc"
};

struct ComInterface {
  GUID iid;
  const char* name;
  int base;  // index into kInterfaces, or -1
};

constexpr ComInterface kInterfaces[] = {
#include "windows/thunk/com_interfaces_generated.inc"
};

constexpr const char* kCallbacks[] = {
#include "windows/thunk/callback_signatures_generated.inc"
};

constexpr unsigned max_slot() {
  unsigned m = 0;
  for (const ComMethod& c : kMethods) m = std::max(m, c.slot);
  return m;
}

// Reads the pointer at `addr`, 0 if that faults. (The load is in a function of
// its own: clang only catches faults raised by calls made inside __try.)
__declspec(noinline) uint64_t load_pointer(const volatile uint64_t* addr) { return *addr; }

uint64_t read_pointer(uint64_t addr) {
  __try {
    return load_pointer(reinterpret_cast<const volatile uint64_t*>(addr));
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    return 0;
  }
}

// The vtable slot of `fn` in the object's (first) vtable, or -1.
int find_slot(uint64_t self, uint64_t fn) {
  const uint64_t vtbl = read_pointer(self);
  if (!vtbl) return -1;
  for (unsigned k = 3; k <= max_slot(); ++k)
    if (read_pointer(vtbl + 8 * k) == fn) return static_cast<int>(k);
  return -1;
}

// Does the object implement `iid` with `fn` in `slot`?
bool implements(uint64_t self, const GUID& iid, unsigned slot, uint64_t fn) {
  bool match = false;
  __try {
    auto* obj = reinterpret_cast<IUnknown*>(self);
    void* out = nullptr;
    if (SUCCEEDED(obj->QueryInterface(iid, &out)) && out) {
      match = read_pointer(read_pointer(reinterpret_cast<uint64_t>(out)) + 8 * slot) == fn;
      static_cast<IUnknown*>(out)->Release();
    }
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    match = false;
  }
  return match;
}

bool runtime_module(uint64_t fn) {
  HMODULE module = nullptr;
  if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                          reinterpret_cast<LPCWSTR>(fn), &module))
    return true;
  wchar_t path[MAX_PATH] = {};
  GetModuleFileNameW(module, path, MAX_PATH);
  std::wstring name = path;
  if (size_t slash = name.find_last_of(L"\\/"); slash != std::wstring::npos) name = name.substr(slash + 1);
  std::transform(name.begin(), name.end(), name.begin(), [](wchar_t c) { return static_cast<wchar_t>(std::towlower(static_cast<wint_t>(c))); });
  for (const wchar_t* prefix : {L"msvcp", L"vcruntime", L"ucrtbase", L"concrt", L"vccorlib", L"msvcrt", L"api-ms-win-crt-"})
    if (name.starts_with(prefix)) return true;
  return false;
}

std::mutex g_mutex;
std::unordered_map<uint64_t, const ComMethod*> g_cache;

// --- the guest's callbacks and objects handed to native code -----------------------------

bool (*g_is_guest_code)(uint64_t) = nullptr;
std::mutex g_callbacks_mutex;
std::unordered_map<uint64_t, const char*> g_callbacks;  // guest function -> signature
std::unordered_map<uint64_t, int> g_vtables;            // guest vtable -> interface


}  // namespace

const char* com_method_signature(uint64_t fn, uint64_t self, std::string* name) {
  {
    std::lock_guard lock(g_mutex);
    if (auto it = g_cache.find(fn); it != g_cache.end()) {
      if (it->second && name) *name = it->second->name;
      return it->second ? it->second->kinds : nullptr;
    }
  }
  const ComMethod* found = nullptr;
  if (self && !runtime_module(fn)) {
    const int slot = find_slot(self, fn);
    if (slot >= 0) {
      for (const ComMethod& m : kMethods) {
        if (m.slot != static_cast<unsigned>(slot)) continue;
        if (implements(self, m.iid, m.slot, fn)) {
          found = &m;
          break;
        }
      }
    }
  }
  std::lock_guard lock(g_mutex);
  g_cache.emplace(fn, found);
  if (found && name) *name = found->name;
  return found ? found->kinds : nullptr;
}

void set_guest_code_predicate(bool (*is_guest_code)(uint64_t addr)) { g_is_guest_code = is_guest_code; }

void note_callback_argument(char kind, unsigned index, uint64_t value) {
  if (!value || !g_is_guest_code) return;
  if (kind == 'C') {
    if (index >= std::size(kCallbacks) || !g_is_guest_code(value)) return;
    std::lock_guard lock(g_callbacks_mutex);
    g_callbacks[value] = kCallbacks[index];
    return;
  }
  // An object: the guest's own if its first method (QueryInterface) is guest code.
  if (index >= std::size(kInterfaces)) return;
  const uint64_t vtable = read_pointer(value);
  if (!vtable || !g_is_guest_code(read_pointer(vtable))) return;
  std::lock_guard lock(g_callbacks_mutex);
  g_vtables[vtable] = static_cast<int>(index);
}

const char* guest_callback_signature(uint64_t fn, uint64_t first_arg) {
  int iface = -1;
  uint64_t vtable = 0;
  {
    std::lock_guard lock(g_callbacks_mutex);
    if (auto it = g_callbacks.find(fn); it != g_callbacks.end()) return it->second;
    if (g_vtables.empty() || !first_arg) return nullptr;
  }
  vtable = read_pointer(first_arg);
  {
    std::lock_guard lock(g_callbacks_mutex);
    auto it = g_vtables.find(vtable);
    if (it == g_vtables.end()) return nullptr;
    iface = it->second;
  }
  // The method in the slot holding `fn`, of the interface or one it derives from.
  for (; iface >= 0; iface = kInterfaces[iface].base) {
    for (const ComMethod& m : kMethods) {
      if (!IsEqualGUID(m.iid, kInterfaces[iface].iid)) continue;
      if (read_pointer(vtable + 8 * m.slot) == fn) return m.kinds;
    }
  }
  return nullptr;
}

}  // namespace juice::win
