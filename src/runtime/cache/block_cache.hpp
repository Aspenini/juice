#pragma once

// Cache of translated guest blocks, keyed by guest pc.

#include <array>
#include <cstdint>
#include <memory>
#include <unordered_map>

#include "core/ir/ir.hpp"

namespace juice::runtime {

struct TranslatedBlock {
  uint64_t guest_pc = 0;
  uint64_t guest_end = 0;
  uint32_t guest_insns = 0;
  void* code = nullptr;             // host entry point (JIT mode)
  size_t code_size = 0;
  std::unique_ptr<ir::Block> ir;    // retained for the interpreter backend
  uint64_t executions = 0;
};

class BlockCache {
 public:
  BlockCache() { fast_.fill(nullptr); }

  TranslatedBlock* lookup(uint64_t pc) {
    TranslatedBlock*& entry = fast_[index(pc)];
    if (entry && entry->guest_pc == pc) return entry;
    auto it = blocks_.find(pc);
    if (it == blocks_.end()) return nullptr;
    entry = it->second.get();
    return entry;
  }

  TranslatedBlock* insert(std::unique_ptr<TranslatedBlock> block);

  // Drop blocks overlapping guest range [begin, end) (self-modifying code).
  size_t invalidate(uint64_t begin, uint64_t end);
  void clear();

  size_t size() const { return blocks_.size(); }
  const std::unordered_map<uint64_t, std::unique_ptr<TranslatedBlock>>& blocks() const { return blocks_; }

 private:
  static constexpr size_t kFastSize = 4096;
  static size_t index(uint64_t pc) { return (pc >> 2) & (kFastSize - 1); }

  std::array<TranslatedBlock*, kFastSize> fast_;
  std::unordered_map<uint64_t, std::unique_ptr<TranslatedBlock>> blocks_;
};

}  // namespace juice::runtime
