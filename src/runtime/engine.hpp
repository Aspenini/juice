#pragma once

// The JUICE execution engine: translates guest blocks on demand, caches them
// and dispatches between them. Everything OS specific (what lives at special
// addresses, what to do on SVC/BRK, how to read guest code) is delegated to an
// Environment.

#include <cstdint>
#include <cstdio>
#include <memory>
#include <utility>
#include <vector>

#include "core/arm64/state/cpu_state.hpp"
#include "core/ir/ir.hpp"
#include "core/jit/x64/emitter.hpp"
#include "runtime/cache/block_cache.hpp"
#include "runtime/memory/exec_memory.hpp"

namespace juice::runtime {

enum class Action { Continue, Stop };

class Environment {
 public:
  virtual ~Environment() = default;

  // Read one instruction word of guest code.
  virtual bool read_code(uint64_t addr, uint32_t& word) = 0;

  // Guest addresses in [first, second) are owned by the environment. When the
  // guest pc enters this range, on_host_address() is called instead of
  // translating code (used for API thunks and return sentinels).
  virtual std::pair<uint64_t, uint64_t> host_range() const = 0;
  virtual Action on_host_address(arm64::CpuState& state) = 0;

  // A block exited with state.exit_reason != None (SVC, BRK, UDF, ...).
  virtual Action on_exit(arm64::CpuState& state) = 0;
};

struct EngineOptions {
  bool optimize = true;         // run IR optimizations
  bool interpret = false;       // execute IR with the reference interpreter instead of the JIT
  bool trace = false;           // log each translated block
  bool dump_ir = false;         // log the IR of each translated block
  uint32_t max_block_insns = 64;
  std::FILE* log = stderr;
};

struct EngineStats {
  uint64_t blocks_translated = 0;
  uint64_t guest_insns_translated = 0;
  uint64_t ir_insts = 0;
  uint64_t ir_insts_removed = 0;
  uint64_t code_bytes = 0;
  uint64_t dispatches = 0;
  uint64_t cache_flushes = 0;
};

class Engine {
 public:
  Engine(Environment& env, EngineOptions options = {});

  // Run until the guest pc equals `stop_pc` or the environment returns Stop.
  // May be called re-entrantly (e.g. from a host call that calls back into
  // guest code).
  void run(arm64::CpuState& state, uint64_t stop_pc = ~0ull);

  TranslatedBlock* translate(uint64_t pc);
  void invalidate(uint64_t begin, uint64_t end) { cache_.invalidate(begin, end); }

  const EngineStats& stats() const { return stats_; }
  const BlockCache& cache() const { return cache_; }
  const CodeArena& arena() const { return arena_; }
  const EngineOptions& options() const { return options_; }

  // State of the guest currently executing on this thread (for fault reporting).
  static arm64::CpuState* current_state();

  void print_stats(std::FILE* out, size_t hot_blocks = 10) const;

 private:
  Environment& env_;
  EngineOptions options_;
  ir::StateLayout layout_;
  x64::Emitter emitter_;
  CodeArena arena_;
  BlockCache cache_;
  std::vector<uint64_t> scratch_;
  uint64_t host_lo_ = 0;
  uint64_t host_size_ = 0;
  EngineStats stats_;
};

}  // namespace juice::runtime
