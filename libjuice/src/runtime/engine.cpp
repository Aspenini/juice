#include "runtime/engine.hpp"

#if defined(_WIN32)
#include <windows.h>
#endif
#if defined(_MSC_VER)
#include <intrin.h>
#endif

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

// IR value slots for translated blocks, after the chaining header; one per
// thread (blocks never run concurrently on one thread, and nested runs happen
// between blocks).
thread_local std::vector<uint64_t> t_scratch;

x64::ChainLayout chain_layout(const EngineOptions& options, void* engine, void* helper) {
  x64::ChainLayout c;
  if (options.interpret || options.profile) return c;  // profiling counts every block in the dispatcher
  TranslatedBlock probe;
  auto offset = [&](const void* field) {
    return static_cast<int32_t>(static_cast<const char*>(field) - reinterpret_cast<const char*>(&probe));
  };
  c.table_mask = static_cast<uint32_t>(FastTable::kSize - 1);
  c.entry_guest_pc = offset(&probe.guest_pc);
  c.entry_chain_target = offset(&probe.chain_target);
  c.interrupt_offset = static_cast<uint32_t>(offsetof(arm64::CpuState, interrupt));
  c.block_pc_offset = static_cast<uint32_t>(offsetof(arm64::CpuState, block_pc));
  c.link_helper = reinterpret_cast<uint64_t>(helper);
  c.link_context = reinterpret_cast<uint64_t>(engine);
  return c;
}

void patch(int32_t* rel32, const void* to) {
  const auto rel = static_cast<int32_t>(reinterpret_cast<intptr_t>(to) - reinterpret_cast<intptr_t>(rel32 + 1));
  std::atomic_ref<int32_t>(*rel32).store(rel, std::memory_order_release);
}

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
      emitter_(layout_, chain_layout(options, this, reinterpret_cast<void*>(&Engine::link_helper))),
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
    ir::Block block = arm64::lift_block(pc, reader, {max_insns, options_.tls_vector_offset});
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
      std::vector<x64::FaultSite> fault_sites;
      std::vector<x64::LinkSite> link_sites;
      size_t body = 0;
      std::vector<uint8_t> code = emitter_.compile(block, &fault_sites, &body, &link_sites);
      if (code.empty()) {
        if (max_insns <= 1) throw std::runtime_error("block too large to compile");
        max_insns /= 2;
        continue;
      }
      void* entry = arena_.add(code);
      tb->fault_sites = std::move(fault_sites);
      if (entry && !options_.profile) tb->chain_target = static_cast<uint8_t*>(entry) + body;
      for (const x64::LinkSite& l : link_sites) {
        auto* base = static_cast<uint8_t*>(entry);
        tb->links.push_back({reinterpret_cast<int32_t*>(base + l.rel32_offset), base + l.stub_offset, l.target_pc});
      }
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

std::optional<uint64_t> Engine::fault_pc(uint64_t host_pc) const {
  std::shared_lock lock(mutex_);
  const TranslatedBlock* b = cache_.find_code(static_cast<uintptr_t>(host_pc));
  if (!b) return std::nullopt;
  return b->fault_pc(static_cast<size_t>(host_pc - reinterpret_cast<uint64_t>(b->code)));
}

void Engine::invalidate(uint64_t begin, uint64_t end) {
  std::unique_lock lock(mutex_);
  const std::vector<TranslatedBlock*> retired = cache_.invalidate(begin, end);
  for (TranslatedBlock* b : retired) unlink_incoming(*b);
  if (!retired.empty()) generation_.fetch_add(1, std::memory_order_release);
}

// --- direct links --------------------------------------------------------------------

#if defined(_MSC_VER)
#define JUICE_RETURN_ADDRESS() _ReturnAddress()
#else
#define JUICE_RETURN_ADDRESS() __builtin_return_address(0)
#endif

// Called by a block's link stub: the block is found by the return address.
void* Engine::link_helper(Engine* engine, uint32_t site) {
  const auto from = reinterpret_cast<uintptr_t>(JUICE_RETURN_ADDRESS());
  const auto* header = reinterpret_cast<const x64::ChainHeader*>(t_scratch.data());
  std::unique_lock lock(engine->mutex_);
  const TranslatedBlock* block = engine->cache_.find_code(from);
  if (!block || site >= block->links.size()) return nullptr;
  return engine->link(*block, site, header->stop_pc);
}

// Link `from`'s site to its target if that is translated: returns the body
// to jump to, or null for the dispatcher to take over.
void* Engine::link(const TranslatedBlock& from, uint32_t site, uint64_t stop_pc) {
  const uint64_t target_pc = from.links[site].target_pc;
  if (target_pc == stop_pc) return nullptr;
  TranslatedBlock* target = cache_.find(target_pc);
  if (!target || !target->chain_target) return nullptr;
  // Only current blocks are linked (a retired one may still be running, but
  // nothing would unlink its sites).
  auto& source = const_cast<TranslatedBlock&>(from);
  if (links_enabled_ && cache_.find(from.guest_pc) == &source && !source.links[site].to) {
    source.links[site].to = target;
    target->incoming.emplace_back(&source, site);
    patch(source.links[site].rel32, target->chain_target);
  }
  return target->chain_target;
}

void Engine::unlink_incoming(TranslatedBlock& block) {
  for (const auto& [source, site] : block.incoming) {
    TranslatedBlock::Link& l = source->links[site];
    if (l.to != &block) continue;
    patch(l.rel32, l.stub);
    l.to = nullptr;
  }
  block.incoming.clear();
}

void Engine::disable_links() {
  std::unique_lock lock(mutex_);
  if (!links_enabled_) return;
  links_enabled_ = false;
  cache_.for_each([](const TranslatedBlock& b) {
    for (const TranslatedBlock::Link& l : b.links)
      if (l.to) patch(l.rel32, l.stub);
  });
}

#if defined(_WIN32)
namespace {

struct InterpreterFault {
  uint64_t address = 0;
  uint64_t access = 0;
  uint32_t code = 0;
};

int interpreter_fault_filter(EXCEPTION_POINTERS* info, InterpreterFault& fault) {
  const EXCEPTION_RECORD* rec = info->ExceptionRecord;
  switch (rec->ExceptionCode) {
    case EXCEPTION_ACCESS_VIOLATION:
    case EXCEPTION_IN_PAGE_ERROR:
    case STATUS_GUARD_PAGE_VIOLATION:
      fault.code = rec->ExceptionCode;
      fault.access = rec->NumberParameters >= 1 ? rec->ExceptionInformation[0] : 0;
      fault.address = rec->NumberParameters >= 2 ? rec->ExceptionInformation[1] : 0;
      return EXCEPTION_EXECUTE_HANDLER;
    default:
      return EXCEPTION_CONTINUE_SEARCH;
  }
}

// Guest memory accesses of the interpreter that fault (the JIT's are handled
// by the front end's fault handler instead). The call must be inside __try
// for the fault to be caught, so this function has no C++ objects to unwind.
bool interpret_guarded(const ir::Block& block, uint64_t* state, const ir::StateLayout& layout,
                       volatile size_t* current, InterpreterFault& fault) {
  __try {
    ir::interpret(block, state, layout, current);
    return true;
  } __except (interpreter_fault_filter(GetExceptionInformation(), fault)) {
    return false;
  }
}

}  // namespace
#endif

void Engine::interpret(const ir::Block& block, arm64::CpuState& s) {
#if defined(_WIN32)
  volatile size_t current = 0;
  InterpreterFault fault;
  if (!interpret_guarded(block, reinterpret_cast<uint64_t*>(&s), layout_, &current, fault)) {
    s.pc = ir::guest_pc_of(block, current);
    s.exit_reason = static_cast<uint32_t>(arm64::ExitReason::MemoryFault);
    s.exit_info = static_cast<uint32_t>(fault.access);
    s.fault_address = fault.address;
    s.fault_code = fault.code;
  }
#else
  ir::interpret(block, reinterpret_cast<uint64_t*>(&s), layout_);
#endif
}

void Engine::run(arm64::CpuState& s, uint64_t stop_pc) {
  CurrentStateScope scope(&s);
  // A stop at a pc blocks may be translated at: links would jump past it.
  if (links_enabled_ && stop_pc != ~0ull && !(stop_pc - host_lo_ < host_size_)) disable_links();
  if (t_scratch.size() < x64::kChainHeaderSlots + x64::kMaxBlockValues)
    t_scratch.assign(x64::kChainHeaderSlots + x64::kMaxBlockValues, 0);
  auto* const header = reinterpret_cast<x64::ChainHeader*>(t_scratch.data());
  uint64_t* const scratch = t_scratch.data() + x64::kChainHeaderSlots;

  for (;;) {
    if (std::atomic_ref<uint64_t>(s.interrupt).load(std::memory_order_relaxed)) {
      std::atomic_ref<uint64_t>(s.interrupt).store(0, std::memory_order_relaxed);
      if (env_.on_interrupt(s) == Action::Stop) return;
    }
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
      // For chaining: blocks continue into their successors through this
      // thread's table while it is current (see x64::ChainHeader).
      const FastTable& table = t_fast;
      header->stop_pc = stop_pc;
      header->generation = reinterpret_cast<const uint64_t*>(&generation_);
      header->table_generation = table.generation;
      header->table = reinterpret_cast<void* const*>(table.entries.data());
      reinterpret_cast<x64::BlockFn>(block->code)(&s, scratch);
    } else {
      interpret(*block->ir, s);
    }

    if (s.exit_reason == static_cast<uint32_t>(arm64::ExitReason::CodeModified)) {
      // IC IVAU: the guest rewrote code in this cache line (CTR_EL0 says 64 bytes).
      const uint64_t line = (s.exit_info == 31 ? 0 : s.x[s.exit_info]) & ~uint64_t{63};
      s.exit_reason = 0;
      s.exit_info = 0;
      invalidate(line, line + 64);
      continue;
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
