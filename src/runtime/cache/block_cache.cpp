#include "runtime/cache/block_cache.hpp"

namespace juice::runtime {

TranslatedBlock* BlockCache::insert(std::unique_ptr<TranslatedBlock> block) {
  TranslatedBlock* raw = block.get();
  blocks_[raw->guest_pc] = std::move(block);
  fast_[index(raw->guest_pc)] = raw;
  return raw;
}

size_t BlockCache::invalidate(uint64_t begin, uint64_t end) {
  size_t removed = 0;
  for (auto it = blocks_.begin(); it != blocks_.end();) {
    const TranslatedBlock& b = *it->second;
    if (b.guest_pc < end && b.guest_end > begin) {
      TranslatedBlock*& entry = fast_[index(b.guest_pc)];
      if (entry == it->second.get()) entry = nullptr;
      it = blocks_.erase(it);
      ++removed;
    } else {
      ++it;
    }
  }
  return removed;
}

void BlockCache::clear() {
  blocks_.clear();
  fast_.fill(nullptr);
}

}  // namespace juice::runtime
