#pragma once

// Cache of translated guest blocks, keyed by guest pc.
//
// Not synchronized: the Engine guards it with its own lock. Blocks are never
// destroyed while the cache lives (invalidated blocks are retired, not
// freed), because another thread may still be executing them or hold a
// pointer to them in its lookup table.

#include <cstdint>
#include <memory>
#include <unordered_map>
#include <vector>

#include "core/ir/ir.hpp"

namespace juice::runtime {

struct TranslatedBlock {
  uint64_t guest_pc = 0;
  uint64_t guest_end = 0;
  uint32_t guest_insns = 0;
  void* code = nullptr;             // host entry point (JIT mode)
  size_t code_size = 0;
  std::unique_ptr<ir::Block> ir;    // retained for the interpreter backend
  uint64_t executions = 0;          // only counted when profiling (updated atomically)
};

class BlockCache {
 public:
  TranslatedBlock* find(uint64_t pc) const {
    auto it = blocks_.find(pc);
    return it == blocks_.end() ? nullptr : it->second.get();
  }

  TranslatedBlock* insert(std::unique_ptr<TranslatedBlock> block);

  // Retire blocks overlapping guest range [begin, end) (self-modifying code).
  size_t invalidate(uint64_t begin, uint64_t end);

  size_t size() const { return blocks_.size(); }
  const std::unordered_map<uint64_t, std::unique_ptr<TranslatedBlock>>& blocks() const { return blocks_; }

 private:
  std::unordered_map<uint64_t, std::unique_ptr<TranslatedBlock>> blocks_;
  std::vector<std::unique_ptr<TranslatedBlock>> retired_;
};

}  // namespace juice::runtime
