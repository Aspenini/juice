// kernel32 builtins.
//
// Each function receives the guest CPU state with its arguments in X0-X7
// (Windows ARM64 calling convention) and returns the value for X0.

#include <windows.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <string>

#include "windows/dlls/builtins.hpp"
#include "windows/guest_process.hpp"

namespace juice::win {
namespace {

using arm64::CpuState;

template <typename T>
T* ptr(uint64_t v) {
  return reinterpret_cast<T*>(static_cast<uintptr_t>(v));
}

std::wstring ansi_to_wide(const char* s) {
  int n = MultiByteToWideChar(CP_ACP, 0, s, -1, nullptr, 0);
  std::wstring out(n > 0 ? n - 1 : 0, L'\0');
  if (n > 1) MultiByteToWideChar(CP_ACP, 0, s, -1, out.data(), n);
  return out;
}

std::string wide_to_ansi(const std::wstring& s) {
  int n = WideCharToMultiByte(CP_ACP, 0, s.c_str(), -1, nullptr, 0, nullptr, nullptr);
  std::string out(n > 0 ? n - 1 : 0, '\0');
  if (n > 1) WideCharToMultiByte(CP_ACP, 0, s.c_str(), -1, out.data(), n, nullptr, nullptr);
  return out;
}

// GetModuleFileName semantics: truncate and report ERROR_INSUFFICIENT_BUFFER.
template <typename Char>
uint64_t copy_module_path(const std::basic_string<Char>& path, Char* buffer, DWORD size) {
  if (size == 0) {
    SetLastError(ERROR_INSUFFICIENT_BUFFER);
    return 0;
  }
  if (path.size() < size) {
    std::memcpy(buffer, path.c_str(), (path.size() + 1) * sizeof(Char));
    SetLastError(ERROR_SUCCESS);
    return path.size();
  }
  std::memcpy(buffer, path.c_str(), (size - 1) * sizeof(Char));
  buffer[size - 1] = 0;
  SetLastError(ERROR_INSUFFICIENT_BUFFER);
  return size;
}

// --- module functions --------------------------------------------------------------

uint64_t module_handle(GuestProcess& p, const std::wstring& name) {
  if (const GuestModule* m = p.find_loaded_module(name)) return m->base();
  return reinterpret_cast<uint64_t>(GetModuleHandleW(name.c_str()));
}

uint64_t GetModuleHandleA_(GuestProcess& p, CpuState& s) {
  if (s.x[0] == 0) return p.exe().base();
  return module_handle(p, ansi_to_wide(ptr<const char>(s.x[0])));
}

uint64_t GetModuleHandleW_(GuestProcess& p, CpuState& s) {
  if (s.x[0] == 0) return p.exe().base();
  return module_handle(p, ptr<const wchar_t>(s.x[0]));
}

uint64_t module_handle_ex(GuestProcess& p, CpuState& s, bool wide) {
  const DWORD flags = static_cast<DWORD>(s.x[0]);
  auto* out = ptr<HMODULE>(s.x[2]);
  GuestModule* guest = nullptr;
  if (flags & GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS) {
    guest = p.module_at(s.x[1]);
  } else if (s.x[1] == 0) {
    guest = p.module_by_handle(p.exe().base());
  } else {
    guest = p.find_loaded_module(wide ? std::wstring(ptr<const wchar_t>(s.x[1])) : ansi_to_wide(ptr<const char>(s.x[1])));
  }
  if (guest) {
    if (!(flags & GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT) || (flags & GET_MODULE_HANDLE_EX_FLAG_PIN))
      p.reference_module(*guest, (flags & GET_MODULE_HANDLE_EX_FLAG_PIN) != 0);
    if (out) *out = reinterpret_cast<HMODULE>(guest->base());
    return TRUE;
  }
  return wide ? GetModuleHandleExW(flags, ptr<const wchar_t>(s.x[1]), out)
              : GetModuleHandleExA(flags, ptr<const char>(s.x[1]), out);
}

uint64_t GetModuleHandleExA_(GuestProcess& p, CpuState& s) { return module_handle_ex(p, s, false); }
uint64_t GetModuleHandleExW_(GuestProcess& p, CpuState& s) { return module_handle_ex(p, s, true); }

uint64_t GetProcAddress_(GuestProcess& p, CpuState& s) {
  return p.get_proc_address(s.x[0], ptr<const char>(s.x[1]));
}

const GuestModule* guest_module(GuestProcess& p, uint64_t handle) {
  return handle == 0 ? &p.exe() : p.module_by_handle(handle);
}

uint64_t GetModuleFileNameA_(GuestProcess& p, CpuState& s) {
  if (const GuestModule* m = guest_module(p, s.x[0]))
    return copy_module_path(wide_to_ansi(m->path), ptr<char>(s.x[1]), static_cast<DWORD>(s.x[2]));
  return GetModuleFileNameA(ptr<HINSTANCE__>(s.x[0]), ptr<char>(s.x[1]), static_cast<DWORD>(s.x[2]));
}

uint64_t GetModuleFileNameW_(GuestProcess& p, CpuState& s) {
  if (const GuestModule* m = guest_module(p, s.x[0]))
    return copy_module_path(m->path, ptr<wchar_t>(s.x[1]), static_cast<DWORD>(s.x[2]));
  return GetModuleFileNameW(ptr<HINSTANCE__>(s.x[0]), ptr<wchar_t>(s.x[1]), static_cast<DWORD>(s.x[2]));
}

// LoadLibrary: ARM64 DLLs JUICE finds become guest modules; everything else
// (and loads as data or resources, which work for any architecture) is native.
constexpr DWORD kDataLoadFlags =
    LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE | LOAD_LIBRARY_AS_IMAGE_RESOURCE;

uint64_t load_library(GuestProcess& p, const std::wstring& name, DWORD flags) {
  if (!(flags & kDataLoadFlags)) {
    bool guest = false;
    const uint64_t handle = p.load_library(name, flags, guest);
    if (guest) return handle;
  }
  return reinterpret_cast<uint64_t>(LoadLibraryExW(name.c_str(), nullptr, flags));
}

uint64_t LoadLibraryA_(GuestProcess& p, CpuState& s) { return load_library(p, ansi_to_wide(ptr<const char>(s.x[0])), 0); }
uint64_t LoadLibraryW_(GuestProcess& p, CpuState& s) { return load_library(p, ptr<const wchar_t>(s.x[0]), 0); }
uint64_t LoadLibraryExA_(GuestProcess& p, CpuState& s) {
  return load_library(p, ansi_to_wide(ptr<const char>(s.x[0])), static_cast<DWORD>(s.x[2]));
}
uint64_t LoadLibraryExW_(GuestProcess& p, CpuState& s) {
  return load_library(p, ptr<const wchar_t>(s.x[0]), static_cast<DWORD>(s.x[2]));
}

// The search directories apply to both loaders: JUICE's for ARM64 DLLs and the
// native one for the rest.
uint64_t SetDllDirectoryA_(GuestProcess& p, CpuState& s) {
  const char* dir = ptr<const char>(s.x[0]);
  if (!SetDllDirectoryA(dir)) return FALSE;
  p.set_dll_directory(dir ? ansi_to_wide(dir).c_str() : nullptr);
  return TRUE;
}

uint64_t SetDllDirectoryW_(GuestProcess& p, CpuState& s) {
  const wchar_t* dir = ptr<const wchar_t>(s.x[0]);
  if (!SetDllDirectoryW(dir)) return FALSE;
  p.set_dll_directory(dir);
  return TRUE;
}

uint64_t AddDllDirectory_(GuestProcess& p, CpuState& s) {
  const wchar_t* dir = ptr<const wchar_t>(s.x[0]);
  DLL_DIRECTORY_COOKIE cookie = AddDllDirectory(dir);
  if (cookie) p.add_dll_directory(reinterpret_cast<uint64_t>(cookie), dir);
  return reinterpret_cast<uint64_t>(cookie);
}

uint64_t RemoveDllDirectory_(GuestProcess& p, CpuState& s) {
  if (!RemoveDllDirectory(ptr<void>(s.x[0]))) return FALSE;
  p.remove_dll_directory(s.x[0]);
  return TRUE;
}

uint64_t SetDefaultDllDirectories_(GuestProcess& p, CpuState& s) {
  const DWORD flags = static_cast<DWORD>(s.x[0]);
  if (!SetDefaultDllDirectories(flags)) return FALSE;
  p.set_default_dll_directories(flags);
  return TRUE;
}

uint64_t DisableThreadLibraryCalls_(GuestProcess& p, CpuState& s) {
  if (p.disable_thread_library_calls(s.x[0])) return TRUE;
  return DisableThreadLibraryCalls(ptr<HINSTANCE__>(s.x[0]));
}

// --- process functions ---------------------------------------------------------------

uint64_t GetCommandLineA_(GuestProcess& p, CpuState&) { return reinterpret_cast<uint64_t>(p.command_line_a().c_str()); }
uint64_t GetCommandLineW_(GuestProcess& p, CpuState&) { return reinterpret_cast<uint64_t>(p.command_line_w().c_str()); }

uint64_t ExitProcess_(GuestProcess& p, CpuState& s) { p.exit(static_cast<uint32_t>(s.x[0])); }

// CreateThread(attributes, stack_size, start, parameter, flags, thread_id)
uint64_t CreateThread_(GuestProcess& p, CpuState& s) {
  return reinterpret_cast<uint64_t>(p.create_thread(ptr<SECURITY_ATTRIBUTES>(s.x[0]), s.x[1], s.x[2], s.x[3],
                                                    static_cast<uint32_t>(s.x[4]), ptr<DWORD>(s.x[5])));
}

uint64_t ExitThread_(GuestProcess& p, CpuState& s) { p.exit_thread(static_cast<uint32_t>(s.x[0])); }

// Guest modules are not modules the native loader knows about: their
// references are JUICE's, and they must never reach the native FreeLibrary.
uint64_t FreeLibrary_(GuestProcess& p, CpuState& s) {
  if (p.free_library(s.x[0])) return TRUE;
  return FreeLibrary(ptr<HINSTANCE__>(s.x[0]));
}

uint64_t FreeLibraryAndExitThread_(GuestProcess& p, CpuState& s) {
  if (!p.free_library(s.x[0])) FreeLibrary(ptr<HINSTANCE__>(s.x[0]));
  p.exit_thread(static_cast<uint32_t>(s.x[1]));
}

// --- system information ------------------------------------------------------------------

void patch_system_info(SYSTEM_INFO* info) {
  info->wProcessorArchitecture = PROCESSOR_ARCHITECTURE_ARM64;
  info->dwProcessorType = 0;
  info->wProcessorLevel = 0;
  info->wProcessorRevision = 0;
}

uint64_t GetSystemInfo_(GuestProcess&, CpuState& s) {
  GetSystemInfo(ptr<SYSTEM_INFO>(s.x[0]));
  patch_system_info(ptr<SYSTEM_INFO>(s.x[0]));
  return 0;
}

uint64_t GetNativeSystemInfo_(GuestProcess&, CpuState& s) {
  GetNativeSystemInfo(ptr<SYSTEM_INFO>(s.x[0]));
  patch_system_info(ptr<SYSTEM_INFO>(s.x[0]));
  return 0;
}

// What an ARM64 Windows reports, for the instructions JUICE translates. The
// PF_ numbers are shared with x86: x86-only features are absent on ARM64.
uint64_t IsProcessorFeaturePresent_(GuestProcess&, CpuState& s) {
  const DWORD feature = static_cast<DWORD>(s.x[0]);
  switch (feature) {
    case 18:  // PF_ARM_VFP_32_REGISTERS_AVAILABLE
    case 19:  // PF_ARM_NEON_INSTRUCTIONS_AVAILABLE
    case 24:  // PF_ARM_DIVIDE_INSTRUCTION_AVAILABLE
    case 25:  // PF_ARM_64BIT_LOADSTORE_ATOMIC
    case 27:  // PF_ARM_FMAC_INSTRUCTIONS_AVAILABLE
    case 29:  // PF_ARM_V8_INSTRUCTIONS_AVAILABLE
    case 30:  // PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE
    case 31:  // PF_ARM_V8_CRC32_INSTRUCTIONS_AVAILABLE
    case 34:  // PF_ARM_V81_ATOMIC_INSTRUCTIONS_AVAILABLE
    case 43:  // PF_ARM_V82_DP_INSTRUCTIONS_AVAILABLE
    case 44:  // PF_ARM_V83_JSCVT_INSTRUCTIONS_AVAILABLE
    case 45:  // PF_ARM_V83_LRCPC_INSTRUCTIONS_AVAILABLE
    case 62:  // PF_ARM_LSE2_AVAILABLE
    case 64:  // PF_ARM_SHA3_INSTRUCTIONS_AVAILABLE
    case 65:  // PF_ARM_SHA512_INSTRUCTIONS_AVAILABLE
    case 66:  // PF_ARM_V82_I8MM_INSTRUCTIONS_AVAILABLE
    case 67:  // PF_ARM_V82_FP16_INSTRUCTIONS_AVAILABLE
    case 68:  // PF_ARM_V86_BF16_INSTRUCTIONS_AVAILABLE
      return TRUE;
    case 22:  // PF_RDWRFSGSBASE_AVAILABLE
    case 26:  // PF_ARM_EXTERNAL_CACHE_AVAILABLE
    case 28:  // PF_RDRAND_INSTRUCTION_AVAILABLE
      return FALSE;
    default:
      // Below 18: generic and x86 features (NX, fast fail, ... come from the host);
      // above: x86 ISA extensions, SVE, SME and the like, none of which JUICE provides.
      if (feature < 18 || feature == 20 || feature == 21 || feature == 23) {
        switch (feature) {
          case 3: case 6: case 7: case 8: case 10: case 11: case 13: case 17:  // MMX, SSE, 3DNow!, RDTSC, XSAVE, ...
            return FALSE;
          default:
            break;
        }
        return IsProcessorFeaturePresent(feature);
      }
      return FALSE;
  }
}

// --- context capture --------------------------------------------------------------------

// Fills an ARM64 CONTEXT (the x64 RtlCaptureContext would write a differently
// sized x64 CONTEXT into the guest's buffer).
uint64_t RtlCaptureContext_(GuestProcess&, CpuState& s) {
  constexpr size_t kContextSize = 0x390;
  constexpr DWORD kContextArm64Full = 0x00400007;
  auto* ctx = ptr<uint8_t>(s.x[0]);
  std::memset(ctx, 0, kContextSize);
  DWORD flags = kContextArm64Full;
  DWORD cpsr = static_cast<DWORD>(s.nzcv);
  std::memcpy(ctx + 0x000, &flags, 4);
  std::memcpy(ctx + 0x004, &cpsr, 4);
  std::memcpy(ctx + 0x008, s.x, 31 * 8);
  std::memcpy(ctx + 0x100, &s.sp, 8);
  std::memcpy(ctx + 0x108, &s.x[30], 8);  // pc = return address of the call
  std::memcpy(ctx + 0x110, s.v, 32 * 16);
  DWORD fpcr = static_cast<DWORD>(s.fpcr), fpsr = static_cast<DWORD>(s.fpsr);
  std::memcpy(ctx + 0x310, &fpcr, 4);
  std::memcpy(ctx + 0x314, &fpsr, 4);
  return 0;
}

constexpr BuiltinExport kKernel32[] = {
    {"GetModuleHandleA", GetModuleHandleA_},
    {"GetModuleHandleW", GetModuleHandleW_},
    {"GetModuleHandleExA", GetModuleHandleExA_},
    {"GetModuleHandleExW", GetModuleHandleExW_},
    {"GetProcAddress", GetProcAddress_},
    {"LoadLibraryA", LoadLibraryA_},
    {"LoadLibraryW", LoadLibraryW_},
    {"LoadLibraryExA", LoadLibraryExA_},
    {"LoadLibraryExW", LoadLibraryExW_},
    {"DisableThreadLibraryCalls", DisableThreadLibraryCalls_},
    {"SetDllDirectoryA", SetDllDirectoryA_},
    {"SetDllDirectoryW", SetDllDirectoryW_},
    {"AddDllDirectory", AddDllDirectory_},
    {"RemoveDllDirectory", RemoveDllDirectory_},
    {"SetDefaultDllDirectories", SetDefaultDllDirectories_},
    {"GetModuleFileNameA", GetModuleFileNameA_},
    {"GetModuleFileNameW", GetModuleFileNameW_},
    {"GetCommandLineA", GetCommandLineA_},
    {"GetCommandLineW", GetCommandLineW_},
    {"ExitProcess", ExitProcess_},
    {"CreateThread", CreateThread_},
    {"ExitThread", ExitThread_},
    {"FreeLibrary", FreeLibrary_},
    {"FreeLibraryAndExitThread", FreeLibraryAndExitThread_},
    {"GetSystemInfo", GetSystemInfo_},
    {"GetNativeSystemInfo", GetNativeSystemInfo_},
    {"IsProcessorFeaturePresent", IsProcessorFeaturePresent_},
    {"RtlCaptureContext", RtlCaptureContext_},
};

}  // namespace

std::span<const BuiltinExport> kernel32_builtins() { return kKernel32; }

}  // namespace juice::win
