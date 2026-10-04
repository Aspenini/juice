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
  Thunk sentinel;
  sentinel.kind = Thunk::Kind::ReturnSentinel;
  sentinel.name = "<return to host>";
  thunks_.push_back(std::move(sentinel));
}

ThunkTable::~ThunkTable() { VirtualFree(base_, 0, MEM_RELEASE); }

uint64_t ThunkTable::add(Thunk thunk) {
  if (thunks_.size() >= capacity_) throw std::runtime_error("thunk table full");
  uint64_t addr = begin() + used_bytes();
  thunks_.push_back(std::move(thunk));
  return addr;
}

uint64_t ThunkTable::add_native(void* fn, std::string dll, std::string name, const char* signature) {
  auto it = by_native_.find(fn);
  if (it != by_native_.end()) return it->second;
  Thunk t;
  t.kind = Thunk::Kind::Native;
  t.dll = std::move(dll);
  t.name = std::move(name);
  t.native = fn;
  t.signature = signature;
  uint64_t addr = add(std::move(t));
  by_native_[fn] = addr;
  return addr;
}

}  // namespace juice::win
