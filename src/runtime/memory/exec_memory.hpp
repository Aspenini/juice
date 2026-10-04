#pragma once

// Executable memory arena for translated code.

#include <cstddef>
#include <cstdint>
#include <span>

namespace juice::runtime {

class CodeArena {
 public:
  explicit CodeArena(size_t capacity = 64 * 1024 * 1024);
  ~CodeArena();
  CodeArena(const CodeArena&) = delete;
  CodeArena& operator=(const CodeArena&) = delete;

  // Copies `code` into the arena. Returns nullptr when the arena is full.
  void* add(std::span<const uint8_t> code);

  // Discards all code (callers must drop every pointer they hold).
  void reset();

  bool contains(const void* p) const {
    auto a = reinterpret_cast<uintptr_t>(p);
    auto b = reinterpret_cast<uintptr_t>(base_);
    return a >= b && a < b + capacity_;
  }
  size_t used() const { return used_; }
  size_t capacity() const { return capacity_; }
  const uint8_t* base() const { return base_; }

 private:
  uint8_t* base_ = nullptr;
  size_t capacity_ = 0;
  size_t used_ = 0;
};

}  // namespace juice::runtime
