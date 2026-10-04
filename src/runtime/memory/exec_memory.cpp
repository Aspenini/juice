#include "runtime/memory/exec_memory.hpp"

#include <cstring>
#include <new>

#if defined(_WIN32)
#include <windows.h>
#else
#include <sys/mman.h>
#endif

namespace juice::runtime {

CodeArena::CodeArena(size_t capacity) : capacity_(capacity) {
#if defined(_WIN32)
  base_ = static_cast<uint8_t*>(VirtualAlloc(nullptr, capacity, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE));
#else
  void* p = mmap(nullptr, capacity, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  base_ = p == MAP_FAILED ? nullptr : static_cast<uint8_t*>(p);
#endif
  if (!base_) throw std::bad_alloc();
}

CodeArena::~CodeArena() {
#if defined(_WIN32)
  VirtualFree(base_, 0, MEM_RELEASE);
#else
  munmap(base_, capacity_);
#endif
}

void* CodeArena::add(std::span<const uint8_t> code) {
  size_t start = (used_ + 15) & ~size_t{15};
  if (start + code.size() > capacity_) return nullptr;
  std::memcpy(base_ + start, code.data(), code.size());
  used_ = start + code.size();
#if defined(_WIN32)
  FlushInstructionCache(GetCurrentProcess(), base_ + start, code.size());
#endif
  return base_ + start;
}

void CodeArena::reset() { used_ = 0; }

}  // namespace juice::runtime
