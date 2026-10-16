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
  const uint64_t last = raw->guest_end > raw->guest_pc ? raw->guest_end - 1 : raw->guest_pc;
  for (uint64_t page = raw->guest_pc >> kPageShift; page <= last >> kPageShift; ++page)
    by_page_[page].push_back(raw->guest_pc);
  auto& slot = blocks_[raw->guest_pc];
  if (slot) retired_.push_back(std::move(slot));
  slot = std::move(block);
  return raw;
}

std::vector<TranslatedBlock*> BlockCache::invalidate(uint64_t begin, uint64_t end) {
  std::vector<TranslatedBlock*> removed;
  if (end <= begin) return removed;
  auto retire = [&](std::unordered_map<uint64_t, std::unique_ptr<TranslatedBlock>>::iterator it) {
    removed.push_back(it->second.get());
    retired_.push_back(std::move(it->second));
    return blocks_.erase(it);
  };
  const uint64_t first_page = begin >> kPageShift, last_page = (end - 1) >> kPageShift;
  if (last_page - first_page >= by_page_.size()) {
    // A range with more pages than blocks have (an unmapped region): look at every block.
    for (auto it = blocks_.begin(); it != blocks_.end();) {
      const TranslatedBlock& b = *it->second;
      if (b.guest_pc < end && b.guest_end > begin) it = retire(it);
      else ++it;
    }
    return removed;
  }
  for (uint64_t page = first_page; page <= last_page; ++page) {
    auto entry = by_page_.find(page);
    if (entry == by_page_.end()) continue;
    std::vector<uint64_t>& pcs = entry->second;
    size_t keep = 0;
    for (uint64_t pc : pcs) {
      auto it = blocks_.find(pc);
      if (it == blocks_.end()) continue;  // (stale)
      const TranslatedBlock& b = *it->second;
      const uint64_t last = b.guest_end > b.guest_pc ? b.guest_end - 1 : b.guest_pc;
      if (page < b.guest_pc >> kPageShift || page > last >> kPageShift) continue;  // (a newer block at that pc)
      if (b.guest_pc < end && b.guest_end > begin) {
        retire(it);
        continue;
      }
      pcs[keep++] = pc;
    }
    pcs.resize(keep);
    if (pcs.empty()) by_page_.erase(entry);
  }
  return removed;
}

}  // namespace juice::runtime
