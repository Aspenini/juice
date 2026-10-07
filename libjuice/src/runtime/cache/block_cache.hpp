#pragma once

// Cache of translated guest blocks, keyed by guest pc.
//
// Not synchronized: the Engine guards it with its own lock. Blocks are never
// destroyed while the cache lives (invalidated blocks are retired, not
// freed), because another thread may still be executing them or hold a
// pointer to them in its lookup table.

#include <cstdint>
#include <map>
#include <memory>
#include <unordered_map>
#include <vector>

#include "core/ir/ir.hpp"
#include "core/jit/x64/emitter.hpp"

namespace juice::runtime {

struct TranslatedBlock {
  uint64_t guest_pc = 0;
  uint64_t guest_end = 0;
  uint32_t guest_insns = 0;
  void* code = nullptr;             // host entry point (JIT mode)
  size_t code_size = 0;
  std::unique_ptr<ir::Block> ir;    // retained for the interpreter backend
  uint64_t executions = 0;          // only counted when profiling (updated atomically)
  bool host = false;                // host code reached by the guest: no translation, see Environment::is_host_code
  std::vector<x64::FaultSite> fault_sites;  // JIT mode: host code that may fault -> guest instruction

  // The guest pc of the instruction a fault at host code offset `offset` belongs to.
  uint64_t fault_pc(size_t offset) const;
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

  // The block (current or retired) whose host code contains `host_pc`.
  const TranslatedBlock* find_code(uintptr_t host_pc) const;

  size_t size() const { return blocks_.size(); }
  const std::unordered_map<uint64_t, std::unique_ptr<TranslatedBlock>>& blocks() const { return blocks_; }

 private:
  std::unordered_map<uint64_t, std::unique_ptr<TranslatedBlock>> blocks_;
  std::vector<std::unique_ptr<TranslatedBlock>> retired_;
  std::map<uintptr_t, const TranslatedBlock*> by_code_;  // host code start -> block (never removed)
};

}  // namespace juice::runtime
