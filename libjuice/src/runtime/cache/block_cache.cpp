#include "runtime/cache/block_cache.hpp"

namespace juice::runtime {

uint64_t TranslatedBlock::fault_pc(size_t offset) const {
  uint64_t pc = guest_pc;
  for (const x64::FaultSite& f : fault_sites) {
    if (f.host_offset > offset) break;
    pc = guest_pc + f.guest_offset;
  }
  return pc;
}

const TranslatedBlock* BlockCache::find_code(uintptr_t host_pc) const {
  auto it = by_code_.upper_bound(host_pc);
  if (it == by_code_.begin()) return nullptr;
  --it;
  const TranslatedBlock* b = it->second;
  return host_pc - it->first < b->code_size ? b : nullptr;
}

TranslatedBlock* BlockCache::insert(std::unique_ptr<TranslatedBlock> block) {
  TranslatedBlock* raw = block.get();
  if (raw->code) by_code_[reinterpret_cast<uintptr_t>(raw->code)] = raw;
  auto& slot = blocks_[raw->guest_pc];
  if (slot) retired_.push_back(std::move(slot));
  slot = std::move(block);
  return raw;
}

size_t BlockCache::invalidate(uint64_t begin, uint64_t end) {
  size_t removed = 0;
  for (auto it = blocks_.begin(); it != blocks_.end();) {
    const TranslatedBlock& b = *it->second;
    if (b.guest_pc < end && b.guest_end > begin) {
      retired_.push_back(std::move(it->second));
      it = blocks_.erase(it);
      ++removed;
    } else {
      ++it;
    }
  }
  return removed;
}

}  // namespace juice::runtime
