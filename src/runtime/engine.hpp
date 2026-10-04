#pragma once

// The JUICE execution engine: translates guest blocks on demand, caches them
// and dispatches between them. Everything OS specific (what lives at special
// addresses, what to do on SVC/BRK, how to read guest code) is delegated to an
// Environment.
//
// Thread safety: run() may be called concurrently from any number of host
// threads, each with its own CpuState. Translated code is shared. Each thread
// keeps a private direct-mapped lookup table in front of the shared block map,
// so the common dispatch path takes no lock.

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <memory>
#include <shared_mutex>
#include <utility>
#include <vector>

#include "core/arm64/state/cpu_state.hpp"
#include "core/ir/ir.hpp"
#include "core/jit/x64/emitter.hpp"
#include "runtime/cache/block_cache.hpp"
#include "runtime/memory/exec_memory.hpp"

namespace juice::runtime {

enum class Action { Continue, Stop };

// Callbacks may be invoked concurrently from several threads.
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

  // Is `pc`, outside host_range(), host code rather than guest code (e.g. a
  // native function the guest reached through a pointer such as a COM vtable
  // entry)? Asked once per address, before translating it; when true, entering
  // `pc` calls on_host_address() as well.
  virtual bool is_host_code(uint64_t pc) {
    (void)pc;
    return false;
  }

  // A block exited with state.exit_reason != None (SVC, BRK, UDF, ...).
  virtual Action on_exit(arm64::CpuState& state) = 0;
};

struct EngineOptions {
  bool optimize = true;         // run IR optimizations
  bool interpret = false;       // execute IR with the reference interpreter instead of the JIT
  bool trace = false;           // log each translated block
  bool dump_ir = false;         // log the IR of each translated block
  bool profile = false;         // count dispatches and block executions
  uint32_t max_block_insns = 64;
  std::FILE* log = stderr;
};

struct EngineStats {
  uint64_t blocks_translated = 0;
  uint64_t guest_insns_translated = 0;
  uint64_t ir_insts = 0;
  uint64_t ir_insts_removed = 0;
  uint64_t code_bytes = 0;
  uint64_t dispatches = 0;  // only when profiling
};

class Engine {
 public:
  Engine(Environment& env, EngineOptions options = {});

  // Run until the guest pc equals `stop_pc` or the environment returns Stop.
  // May be called re-entrantly (e.g. from a host call that calls back into
  // guest code) and concurrently from several threads.
  void run(arm64::CpuState& state, uint64_t stop_pc = ~0ull);

  // Forget translations of guest code in [begin, end).
  void invalidate(uint64_t begin, uint64_t end);

  EngineStats stats() const;
  const CodeArena& arena() const { return arena_; }
  const EngineOptions& options() const { return options_; }

  // State of the guest currently executing on this thread (for fault reporting).
  static arm64::CpuState* current_state();

  void print_stats(std::FILE* out, size_t hot_blocks = 10) const;

 private:
  TranslatedBlock* lookup(uint64_t pc);
  TranslatedBlock* translate_locked(uint64_t pc);

  Environment& env_;
  EngineOptions options_;
  ir::StateLayout layout_;
  x64::Emitter emitter_;
  const uint64_t id_;
  uint64_t host_lo_ = 0;
  uint64_t host_size_ = 0;

  mutable std::shared_mutex mutex_;  // guards cache_, arena_ additions and stats_
  CodeArena arena_;
  BlockCache cache_;
  EngineStats stats_;
  std::atomic<uint64_t> generation_{0};  // bumped by invalidate(): per-thread tables must be cleared
  std::atomic<uint64_t> dispatches_{0};
};

}  // namespace juice::runtime
