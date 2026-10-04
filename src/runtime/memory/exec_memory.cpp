#include "runtime/memory/exec_memory.hpp"

#include <cstring>
#include <new>

#if defined(_WIN32)
#include <windows.h>
#else
#include <sys/mman.h>
#endif

namespace juice::runtime {

namespace {
constexpr size_t kCommitChunk = size_t{1} << 20;
}

CodeArena::CodeArena(size_t capacity) : capacity_(capacity) {
#if defined(_WIN32)
  base_ = static_cast<uint8_t*>(VirtualAlloc(nullptr, capacity, MEM_RESERVE, PAGE_NOACCESS));
#else
  void* p = mmap(nullptr, capacity, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
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

bool CodeArena::commit(size_t end) {
  if (end <= committed_) return true;
  if (end > capacity_) return false;
  size_t target = (end + kCommitChunk - 1) & ~(kCommitChunk - 1);
  if (target > capacity_) target = capacity_;
#if defined(_WIN32)
  if (!VirtualAlloc(base_ + committed_, target - committed_, MEM_COMMIT, PAGE_EXECUTE_READWRITE)) return false;
#else
  if (mprotect(base_ + committed_, target - committed_, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) return false;
#endif
  committed_ = target;
  return true;
}

void* CodeArena::add(std::span<const uint8_t> code) {
  size_t start = (used_ + 15) & ~size_t{15};
  if (!commit(start + code.size())) return nullptr;
  std::memcpy(base_ + start, code.data(), code.size());
  used_ = start + code.size();
#if defined(_WIN32)
  FlushInstructionCache(GetCurrentProcess(), base_ + start, code.size());
#endif
  return base_ + start;
}

}  // namespace juice::runtime
