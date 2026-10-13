#include "macos/loader/host_memory.hpp"

#if defined(_WIN32)
#include <windows.h>
#else
#include <sys/mman.h>
#endif

namespace juice::mac {

uint64_t reserve_memory(uint64_t size, uint64_t preferred) {
#if defined(_WIN32)
  void* p = nullptr;
  if (preferred) p = VirtualAlloc(reinterpret_cast<void*>(preferred), size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
  if (!p) p = VirtualAlloc(nullptr, size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
  return reinterpret_cast<uint64_t>(p);
#else
  void* hint = reinterpret_cast<void*>(preferred);
  void* p = mmap(hint, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
  if (p == MAP_FAILED) return 0;
  return reinterpret_cast<uint64_t>(p);
#endif
}

bool protect_memory(uint64_t addr, uint64_t size, int prot) {
#if defined(_WIN32)
  const DWORD p = prot & kProtWrite ? PAGE_READWRITE : prot & kProtRead ? PAGE_READONLY : PAGE_NOACCESS;
  DWORD old = 0;
  return VirtualProtect(reinterpret_cast<void*>(addr), size, p, &old) != 0;
#else
  const int p = (prot & kProtRead ? PROT_READ : 0) | (prot & kProtWrite ? PROT_WRITE : 0);
  return mprotect(reinterpret_cast<void*>(addr), size, p) == 0;
#endif
}

void release_memory(uint64_t addr, uint64_t size) {
#if defined(_WIN32)
  (void)size;
  VirtualFree(reinterpret_cast<void*>(addr), 0, MEM_RELEASE);
#else
  munmap(reinterpret_cast<void*>(addr), size);
#endif
}

}  // namespace juice::mac
