#include "runtime/engine.hpp"

#include <algorithm>
#include <array>
#include <format>
#include <mutex>
#include <stdexcept>

#include "core/arm64/decode/instruction.hpp"
#include "core/arm64/lift/lifter.hpp"

namespace juice::runtime {

namespace {

thread_local arm64::CpuState* t_current_state = nullptr;

struct CurrentStateScope {
  explicit CurrentStateScope(arm64::CpuState* s) : saved(t_current_state) { t_current_state = s; }
  ~CurrentStateScope() { t_current_state = saved; }
  arm64::CpuState* saved;
};

// Per-thread direct-mapped pc -> block table in front of the shared map. It
// belongs to one engine at a time and is cleared when that engine's
// generation changes (translations were invalidated).
struct FastTable {
  static constexpr size_t kSize = 4096;
  uint64_t engine = 0;
  uint64_t generation = 0;
  std::array<TranslatedBlock*, kSize> entries{};
};
thread_local FastTable t_fast;

// IR value slots for translated blocks; one per thread (blocks never run
// concurrently on one thread, and nested runs happen between blocks).
thread_local std::vector<uint64_t> t_scratch;

std::atomic<uint64_t> g_next_engine_id{1};

size_t count_live(const ir::Block& b) {
  return static_cast<size_t>(std::count_if(b.insts.begin(), b.insts.end(),
                                           [](const ir::Inst& i) { return i.op != ir::Opcode::Nop; }));
}

}  // namespace

arm64::CpuState* Engine::current_state() { return t_current_state; }

Engine::Engine(Environment& env, EngineOptions options)
    : env_(env),
      options_(options),
      layout_(arm64::state_layout()),
      emitter_(layout_),
      id_(g_next_engine_id.fetch_add(1)) {
  auto [lo, hi] = env_.host_range();
  host_lo_ = lo;
  host_size_ = hi > lo ? hi - lo : 0;
}

TranslatedBlock* Engine::lookup(uint64_t pc) {
  FastTable& table = t_fast;
  const uint64_t generation = generation_.load(std::memory_order_acquire);
  if (table.engine != id_ || table.generation != generation) {
    table.entries.fill(nullptr);
    table.engine = id_;
    table.generation = generation;
  }
  TranslatedBlock*& entry = table.entries[(pc >> 2) & (FastTable::kSize - 1)];
  if (entry && entry->guest_pc == pc) return entry;

  {
    std::shared_lock lock(mutex_);
    if (TranslatedBlock* b = cache_.find(pc)) return entry = b;
  }
  std::unique_lock lock(mutex_);
  TranslatedBlock* b = cache_.find(pc);  // another thread may have translated it meanwhile
  if (!b) b = translate_locked(pc);
  return entry = b;
}

TranslatedBlock* Engine::translate_locked(uint64_t pc) {
  if (env_.is_host_code(pc)) {
    // Remember the answer like a translation, so later visits take the fast path.
    auto tb = std::make_unique<TranslatedBlock>();
    tb->guest_pc = pc;
    tb->guest_end = pc + 4;
    tb->host = true;
    return cache_.insert(std::move(tb));
  }

  arm64::CodeReader reader = [this](uint64_t addr, uint32_t& word) { return env_.read_code(addr, word); };

  uint32_t max_insns = options_.max_block_insns;
  for (;;) {
    ir::Block block = arm64::lift_block(pc, reader, {max_insns});
    const size_t before = block.insts.size();
    if (options_.optimize) ir::optimize(block);
    const size_t after = count_live(block);

    if (options_.trace || options_.dump_ir) {
      std::string text = std::format("[juice] block 0x{:x}: {} guest insns, {} -> {} IR insts\n", pc,
                                     block.guest_insns, before, after);
      for (uint64_t a = block.guest_pc; a < block.guest_end; a += 4) {
        uint32_t word = 0;
        if (!env_.read_code(a, word)) break;
        text += std::format("    {:016x}  {:08x}  {}\n", a, word, arm64::disassemble(arm64::decode(word, a)));
      }
      if (options_.dump_ir)
        text += ir::to_string(block, [](uint16_t s) { return std::string(arm64::slot_name(s)); });
      std::fputs(text.c_str(), options_.log);
    }

    auto tb = std::make_unique<TranslatedBlock>();
    tb->guest_pc = block.guest_pc;
    tb->guest_end = block.guest_end;
    tb->guest_insns = block.guest_insns;

    if (options_.interpret) {
      tb->ir = std::make_unique<ir::Block>(std::move(block));
    } else {
      std::vector<uint8_t> code = emitter_.compile(block);
      if (code.empty()) {
        if (max_insns <= 1) throw std::runtime_error("block too large to compile");
        max_insns /= 2;
        continue;
      }
      void* entry = arena_.add(code);
      if (!entry) throw std::runtime_error("out of space for translated code");
      tb->code = entry;
      tb->code_size = code.size();
      stats_.code_bytes += code.size();
    }

    ++stats_.blocks_translated;
    stats_.guest_insns_translated += tb->guest_insns;
    stats_.ir_insts += before;
    stats_.ir_insts_removed += before - after;
    return cache_.insert(std::move(tb));
  }
}

void Engine::invalidate(uint64_t begin, uint64_t end) {
  std::unique_lock lock(mutex_);
  if (cache_.invalidate(begin, end)) generation_.fetch_add(1, std::memory_order_release);
}

void Engine::run(arm64::CpuState& s, uint64_t stop_pc) {
  CurrentStateScope scope(&s);
  if (t_scratch.size() < x64::kMaxBlockValues) t_scratch.assign(x64::kMaxBlockValues, 0);
  uint64_t* const scratch = t_scratch.data();

  for (;;) {
    const uint64_t pc = s.pc;
    if (pc == stop_pc) return;

    if (pc - host_lo_ < host_size_) {
      if (env_.on_host_address(s) == Action::Stop) return;
      continue;
    }

    TranslatedBlock* block = lookup(pc);
    if (options_.profile) {
      std::atomic_ref<uint64_t>(block->executions).fetch_add(1, std::memory_order_relaxed);
      dispatches_.fetch_add(1, std::memory_order_relaxed);
    }

    if (block->host) {
      if (env_.on_host_address(s) == Action::Stop) return;
      continue;
    }

    s.block_pc = pc;
    if (block->code) {
      reinterpret_cast<x64::BlockFn>(block->code)(&s, scratch);
    } else {
      ir::interpret(*block->ir, reinterpret_cast<uint64_t*>(&s), layout_);
    }

    if (s.exit_reason != 0) {
      Action action = env_.on_exit(s);
      s.exit_reason = 0;
      s.exit_info = 0;
      if (action == Action::Stop) return;
    }
  }
}

EngineStats Engine::stats() const {
  std::shared_lock lock(mutex_);
  EngineStats s = stats_;
  s.dispatches = dispatches_.load(std::memory_order_relaxed);
  return s;
}

void Engine::print_stats(std::FILE* out, size_t hot_blocks) const {
  const EngineStats s = stats();
  std::fprintf(out, "[juice] blocks translated: %llu (%llu guest insns)\n",
               static_cast<unsigned long long>(s.blocks_translated),
               static_cast<unsigned long long>(s.guest_insns_translated));
  std::fprintf(out, "[juice] IR insts: %llu (%llu removed by optimizer)\n", static_cast<unsigned long long>(s.ir_insts),
               static_cast<unsigned long long>(s.ir_insts_removed));
  std::fprintf(out, "[juice] x86-64 code: %llu bytes, dispatches: %llu\n", static_cast<unsigned long long>(s.code_bytes),
               static_cast<unsigned long long>(s.dispatches));

  std::vector<std::pair<uint64_t, const TranslatedBlock*>> blocks;
  {
    std::shared_lock lock(mutex_);
    for (const auto& [pc, b] : cache_.blocks())
      if (!b->host) blocks.emplace_back(std::atomic_ref<uint64_t>(const_cast<uint64_t&>(b->executions)).load(), b.get());
  }
  std::sort(blocks.begin(), blocks.end(), [](const auto& a, const auto& b) { return a.first > b.first; });
  if (blocks.size() > hot_blocks) blocks.resize(hot_blocks);
  for (const auto& [count, b] : blocks)
    std::fprintf(out, "[juice]   hot block 0x%llx: %llu executions, %u insns\n",
                 static_cast<unsigned long long>(b->guest_pc), static_cast<unsigned long long>(count), b->guest_insns);
}

}  // namespace juice::runtime
