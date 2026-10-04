// Concurrency: atomic IR semantics and several host threads running guest
// code through one shared engine.

#include <atomic>
#include <cstring>
#include <thread>
#include <vector>

#include "core/ir/ir.hpp"
#include "runtime/engine.hpp"
#include "test.hpp"

using namespace juice;
using arm64::CpuState;

namespace {

constexpr uint64_t kCodeBase = 0x20000;

// Each thread repeats x1 times:
//   - increment [x0] with an LDAXR/STLXR retry loop
//   - LDADDAL 1 into [x2]
//   - add (1, 2) to the 128-bit pair at [x3] with an LDAXP/STLXP retry loop
//   - increment the 32-bit [x11] with a CASAL retry loop
//   - increment its private counter [x16] with plain loads and stores
// then DMB ISH, STLR x1 (0) to [x17] and BRK #0.
const std::vector<uint32_t> kStressLoop = {
    0xc85ffc04,  // loop: ldaxr x4, [x0]
    0x91000484,  //   add x4, x4, #1
    0xc805fc04,  //   stlxr w5, x4, [x0]
    0x35ffffa5,  //   cbnz w5, loop
    0xd2800026,  //   mov x6, #1
    0xf8e60047,  //   ldaddal x6, x7, [x2]
    0xc87fa468,  // pair: ldaxp x8, x9, [x3]
    0x91000508,  //   add x8, x8, #1
    0x91000929,  //   add x9, x9, #2
    0xc82aa468,  //   stlxp w10, x8, x9, [x3]
    0x35ffff8a,  //   cbnz w10, pair
    0xb940016c,  // cas: ldr w12, [x11]
    0x1100058d,  //   add w13, w12, #1
    0x2a0c03ee,  //   mov w14, w12
    0x88eefd6d,  //   casal w14, w13, [x11]
    0x6b0c01df,  //   cmp w14, w12
    0x54ffff61,  //   b.ne cas
    0xf940020f,  //   ldr x15, [x16]
    0x910005ef,  //   add x15, x15, #1
    0xf900020f,  //   str x15, [x16]
    0xf1000421,  //   subs x1, x1, #1
    0x54fffd61,  //   b.ne loop
    0xd5033bbf,  //   dmb ish
    0xc89ffe21,  //   stlr x1, [x17]
    0xd4200000,  //   brk #0
};

class SharedEnv final : public runtime::Environment {
 public:
  explicit SharedEnv(const std::vector<uint32_t>& code) : code_(code) {}
  bool read_code(uint64_t addr, uint32_t& word) override {
    if (addr < kCodeBase || addr >= kCodeBase + 4 * code_.size()) return false;
    word = code_[(addr - kCodeBase) / 4];
    return true;
  }
  std::pair<uint64_t, uint64_t> host_range() const override { return {0, 0}; }
  runtime::Action on_host_address(CpuState&) override { return runtime::Action::Stop; }
  runtime::Action on_exit(CpuState& s) override {
    if (s.exit_reason != static_cast<uint32_t>(arm64::ExitReason::Brk)) bad_exits.fetch_add(1);
    return runtime::Action::Stop;
  }
  std::atomic<int> bad_exits{0};

 private:
  const std::vector<uint32_t>& code_;
};

struct alignas(16) Shared {
  uint64_t exclusive = 0;
  uint64_t lse = 0;
  alignas(16) uint64_t pair[2] = {0, 0};
  uint32_t cas = 0;
  uint64_t done[8] = {};
  uint64_t private_counter[8] = {};
};

void stress(const char* name, runtime::EngineOptions options, uint64_t iterations) {
  constexpr int kThreads = 4;
  SharedEnv env(kStressLoop);
  runtime::Engine engine(env, options);
  Shared shared;
  for (auto& d : shared.done) d = 1;

  std::vector<std::thread> threads;
  for (int t = 0; t < kThreads; ++t) {
    threads.emplace_back([&, t] {
      CpuState s{};
      s.x[0] = reinterpret_cast<uint64_t>(&shared.exclusive);
      s.x[1] = iterations;
      s.x[2] = reinterpret_cast<uint64_t>(&shared.lse);
      s.x[3] = reinterpret_cast<uint64_t>(shared.pair);
      s.x[11] = reinterpret_cast<uint64_t>(&shared.cas);
      s.x[16] = reinterpret_cast<uint64_t>(&shared.private_counter[t]);
      s.x[17] = reinterpret_cast<uint64_t>(&shared.done[t]);
      s.pc = kCodeBase;
      engine.run(s);
    });
  }
  for (auto& th : threads) th.join();

  const uint64_t total = kThreads * iterations;
  auto check = [&](uint64_t actual, uint64_t expected, const char* what) {
    if (actual != expected)
      test::fail(__FILE__, __LINE__, std::format("{}: {} = {}, expected {}", name, what, actual, expected));
  };
  check(shared.exclusive, total, "ldaxr/stlxr counter");
  check(shared.lse, total, "ldaddal counter");
  check(shared.pair[0], total, "ldaxp/stlxp low");
  check(shared.pair[1], 2 * total, "ldaxp/stlxp high");
  check(shared.cas, total, "casal counter");
  for (int t = 0; t < kThreads; ++t) {
    check(shared.private_counter[t], iterations, "private counter");
    check(shared.done[t], 0, "stlr flag");
  }
  CHECK_EQ(env.bad_exits.load(), 0);
}

uint64_t eval_atomic(ir::Opcode op, uint8_t size, uint64_t a, uint64_t b, uint64_t c = 0, uint8_t aux = 0) {
  ir::Inst in;
  in.op = op;
  in.size = size;
  in.aux = aux;
  return ir::execute_atomic(in, a, b, c);
}

}  // namespace

TEST(ir_atomic_semantics) {
  using ir::AtomicOp;
  using ir::Opcode;
  alignas(16) uint64_t mem[2] = {0x1122334455667788ull, 0};
  const uint64_t p = reinterpret_cast<uint64_t>(mem);
  auto rmw = [&](AtomicOp op, uint8_t size, uint64_t v) {
    return eval_atomic(Opcode::AtomicRmw, size, p, v, 0, static_cast<uint8_t>(op));
  };

  CHECK_EQ(rmw(AtomicOp::Add, 1, 0x10), 0x88u);  // byte add: returns old, wraps within the byte
  CHECK_EQ(mem[0], 0x1122334455667798ull);
  CHECK_EQ(rmw(AtomicOp::Clr, 2, 0x00F0), 0x7798u);
  CHECK_EQ(mem[0] & 0xFFFF, 0x7708u);
  CHECK_EQ(rmw(AtomicOp::Swap, 8, 5), 0x1122334455667708ull);
  CHECK_EQ(rmw(AtomicOp::SMax, 4, 0xFFFFFFFF), 5u);  // max(5, -1) = 5
  CHECK_EQ(mem[0], 5u);
  CHECK_EQ(rmw(AtomicOp::UMax, 4, 0xFFFFFFFF), 5u);
  CHECK_EQ(mem[0], 0xFFFFFFFFu);
  CHECK_EQ(rmw(AtomicOp::SMin, 4, 3), 0xFFFFFFFFu);  // min(-1, 3) = -1
  CHECK_EQ(mem[0], 0xFFFFFFFFu);

  // CAS returns the old value; stores only on match.
  mem[0] = 7;
  CHECK_EQ(eval_atomic(Opcode::AtomicCas, 8, p, 6, 100), 7u);
  CHECK_EQ(mem[0], 7u);
  CHECK_EQ(eval_atomic(Opcode::AtomicCas, 8, p, 7, 100), 7u);
  CHECK_EQ(mem[0], 100u);

  // 128-bit pair: {expected lo, hi, desired lo, hi}
  mem[0] = 1;
  mem[1] = 2;
  uint64_t operands[4] = {1, 3, 10, 20};
  CHECK_EQ(eval_atomic(Opcode::AtomicCasPair, 8, p, reinterpret_cast<uint64_t>(operands)), 1u);
  CHECK_EQ(mem[1], 2u);
  operands[1] = 2;
  CHECK_EQ(eval_atomic(Opcode::AtomicCasPair, 8, p, reinterpret_cast<uint64_t>(operands)), 0u);
  CHECK_EQ(mem[0], 10u);
  CHECK_EQ(mem[1], 20u);
}

TEST(threads_share_one_engine_jit) {
  stress("jit", {}, 20000);
}

TEST(threads_share_one_engine_unoptimized) {
  runtime::EngineOptions options;
  options.optimize = false;
  options.max_block_insns = 1;
  stress("jit-noopt-1", options, 5000);
}

TEST(threads_share_one_engine_interpreter) {
  runtime::EngineOptions options;
  options.interpret = true;
  stress("interp", options, 5000);
}

// Many threads racing to translate the same code for the first time.
TEST(threads_translate_concurrently) {
  for (int round = 0; round < 20; ++round) stress("first-touch", {}, 50);
}
