#include "windows/thunk/thunk_table.hpp"

#include <windows.h>

#include <new>
#include <stdexcept>

namespace juice::win {

ThunkTable::ThunkTable(size_t capacity) : capacity_(capacity) {
  // Reserved but never committed: the host faults if it ever executes or
  // dereferences a thunk address.
  base_ = VirtualAlloc(nullptr, capacity_ * kStride, MEM_RESERVE, PAGE_NOACCESS);
  if (!base_) throw std::bad_alloc();
  thunks_.reserve(capacity_);
  Thunk sentinel;
  sentinel.kind = Thunk::Kind::ReturnSentinel;
  sentinel.name = "<return to host>";
  add(std::move(sentinel));
}

ThunkTable::~ThunkTable() { VirtualFree(base_, 0, MEM_RELEASE); }

uint64_t ThunkTable::add(Thunk thunk) {
  std::lock_guard lock(mutex_);
  return add_locked(std::move(thunk));
}

uint64_t ThunkTable::add_locked(Thunk thunk) {
  if (thunks_.size() >= capacity_) throw std::runtime_error("thunk table full");
  const uint64_t addr = begin() + thunks_.size() * kStride;
  thunks_.push_back(std::move(thunk));
  count_.store(thunks_.size(), std::memory_order_release);
  return addr;
}

Thunk* ThunkTable::find_native(void* fn) {
  std::lock_guard lock(mutex_);
  auto it = by_native_.find(fn);
  return it == by_native_.end() ? nullptr : &thunks_[(it->second - begin()) / kStride];
}

uint64_t ThunkTable::add_native(void* fn, std::string dll, std::string name, const char* signature) {
  std::lock_guard lock(mutex_);
  auto it = by_native_.find(fn);
  if (it != by_native_.end()) return it->second;
  Thunk t;
  t.kind = Thunk::Kind::Native;
  t.dll = std::move(dll);
  t.name = std::move(name);
  t.native = fn;
  t.signature = signature;
  uint64_t addr = add_locked(std::move(t));
  by_native_[fn] = addr;
  return addr;
}

}  // namespace juice::win
