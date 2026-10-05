#pragma once

// Executable memory arena for translated code.
//
// A large address range is reserved up front and committed as it fills, so
// code never moves and is never discarded while threads may be running it.

#include <cstddef>
#include <cstdint>
#include <span>

namespace juice::runtime {

class CodeArena {
 public:
  explicit CodeArena(size_t capacity = size_t{1} << 30);
  ~CodeArena();
  CodeArena(const CodeArena&) = delete;
  CodeArena& operator=(const CodeArena&) = delete;

  // Copies `code` into the arena. Returns nullptr when the arena is full.
  // Not synchronized: callers serialize additions.
  void* add(std::span<const uint8_t> code);

  bool contains(const void* p) const {
    auto a = reinterpret_cast<uintptr_t>(p);
    auto b = reinterpret_cast<uintptr_t>(base_);
    return a >= b && a < b + capacity_;
  }
  size_t used() const { return used_; }
  size_t capacity() const { return capacity_; }
  const uint8_t* base() const { return base_; }

 private:
  bool commit(size_t end);

  uint8_t* base_ = nullptr;
  size_t capacity_ = 0;
  size_t committed_ = 0;
  size_t used_ = 0;
};

}  // namespace juice::runtime
