#include "runtime/engine.hpp"

#include <algorithm>
#include <format>
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
      scratch_(x64::kMaxBlockValues, 0) {
  auto [lo, hi] = env_.host_range();
  host_lo_ = lo;
  host_size_ = hi > lo ? hi - lo : 0;
}

TranslatedBlock* Engine::translate(uint64_t pc) {
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
      if (!entry) {
        // Out of code space: start over with an empty cache.
        cache_.clear();
        arena_.reset();
        ++stats_.cache_flushes;
        entry = arena_.add(code);
        if (!entry) throw std::runtime_error("translated block larger than the code arena");
      }
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

void Engine::run(arm64::CpuState& s, uint64_t stop_pc) {
  CurrentStateScope scope(&s);
  for (;;) {
    const uint64_t pc = s.pc;
    if (pc == stop_pc) return;

    if (pc - host_lo_ < host_size_) {
      if (env_.on_host_address(s) == Action::Stop) return;
      continue;
    }

    TranslatedBlock* block = cache_.lookup(pc);
    if (!block) block = translate(pc);
    ++block->executions;
    ++stats_.dispatches;

    s.block_pc = pc;
    if (block->code) {
      reinterpret_cast<x64::BlockFn>(block->code)(&s, scratch_.data());
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

void Engine::print_stats(std::FILE* out, size_t hot_blocks) const {
  std::fprintf(out, "[juice] blocks translated: %llu (%llu guest insns)\n",
               static_cast<unsigned long long>(stats_.blocks_translated),
               static_cast<unsigned long long>(stats_.guest_insns_translated));
  std::fprintf(out, "[juice] IR insts: %llu (%llu removed by optimizer)\n",
               static_cast<unsigned long long>(stats_.ir_insts),
               static_cast<unsigned long long>(stats_.ir_insts_removed));
  std::fprintf(out, "[juice] x86-64 code: %llu bytes, dispatches: %llu, cache flushes: %llu\n",
               static_cast<unsigned long long>(stats_.code_bytes), static_cast<unsigned long long>(stats_.dispatches),
               static_cast<unsigned long long>(stats_.cache_flushes));

  std::vector<const TranslatedBlock*> blocks;
  for (const auto& [pc, b] : cache_.blocks()) blocks.push_back(b.get());
  std::sort(blocks.begin(), blocks.end(),
            [](const TranslatedBlock* a, const TranslatedBlock* b) { return a->executions > b->executions; });
  if (blocks.size() > hot_blocks) blocks.resize(hot_blocks);
  for (const TranslatedBlock* b : blocks)
    std::fprintf(out, "[juice]   hot block 0x%llx: %llu executions, %u insns\n",
                 static_cast<unsigned long long>(b->guest_pc), static_cast<unsigned long long>(b->executions),
                 b->guest_insns);
}

}  // namespace juice::runtime
