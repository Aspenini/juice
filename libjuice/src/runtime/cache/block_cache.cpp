#include "runtime/cache/block_cache.hpp"

namespace juice::runtime {

TranslatedBlock* BlockCache::insert(std::unique_ptr<TranslatedBlock> block) {
  TranslatedBlock* raw = block.get();
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
