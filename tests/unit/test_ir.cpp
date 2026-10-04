// IR semantics, optimizer and x86-64 backend tests.
//
// The backend tests build blocks that apply every opcode to values read from
// guest state, then run them both through the JIT and through the reference
// interpreter on pseudo-random inputs and compare the resulting state.

#include <array>
#include <cstring>
#include <random>

#include "core/ir/ir.hpp"
#include "core/jit/x64/emitter.hpp"
#include "runtime/memory/exec_memory.hpp"
#include "test.hpp"

using namespace juice;
using ir::Opcode;
using ir::Predicate;

namespace {

constexpr uint16_t kSlots = 64;
constexpr uint16_t kPc = 60;

ir::StateLayout layout() {
  ir::StateLayout l;
  l.pc_slot = kPc;
  l.exit_reason_offset = 61 * 8;
  l.exit_info_offset = 61 * 8 + 4;
  l.slot_count = kSlots;
  return l;
}

using State = std::array<uint64_t, kSlots>;

runtime::CodeArena& arena() {
  static runtime::CodeArena a(4 << 20);
  return a;
}

void run_jit(const ir::Block& block, State& state) {
  static std::vector<uint64_t> scratch(x64::kMaxBlockValues);
  std::vector<uint8_t> code = x64::Emitter(layout()).compile(block);
  void* fn = arena().add(code);
  if (!fn) {
    arena().reset();
    fn = arena().add(code);
  }
  reinterpret_cast<x64::BlockFn>(fn)(state.data(), scratch.data());
}

void run_interp(const ir::Block& block, State& state) { ir::interpret(block, state.data(), layout()); }

// Builds a block computing `op` over slots 0..2 for both widths, with the
// result in slots 10 (64-bit) and 11 (32-bit).
ir::Block op_block(Opcode op, uint8_t aux) {
  ir::Block block;
  ir::Builder b(block);
  for (uint8_t size : {uint8_t{8}, uint8_t{4}}) {
    ir::ValueId a = b.get(0), x = b.get(1), c = b.get(2);
    ir::ValueId r = b.emit(op, size, a, x, c, 0, aux);
    b.set(size == 8 ? 10 : 11, r);
  }
  b.jump(0x1234);
  return block;
}

// Variant where the second operand is a constant (exercises immediate forms).
ir::Block op_block_const(Opcode op, uint8_t aux, uint64_t k) {
  ir::Block block;
  ir::Builder b(block);
  for (uint8_t size : {uint8_t{8}, uint8_t{4}}) {
    ir::ValueId a = b.get(0), c = b.get(2);
    ir::ValueId r = b.emit(op, size, a, b.constant(k), c, 0, aux);
    b.set(size == 8 ? 10 : 11, r);
  }
  b.jump(0x1234);
  return block;
}

uint64_t interesting(std::mt19937_64& rng) {
  static constexpr uint64_t specials[] = {0, 1, 2, 31, 32, 63, 64, 0x7F, 0x80, 0xFF, 0x7FFFFFFF, 0x80000000,
                                          0xFFFFFFFF, 0x100000000ull, 0x7FFFFFFFFFFFFFFFull,
                                          0x8000000000000000ull, ~0ull, ~1ull, 0xFFFFFFFF80000000ull};
  switch (rng() % 4) {
    case 0: return specials[rng() % std::size(specials)];
    case 1: return rng() & 0xFF;
    case 2: return static_cast<uint64_t>(static_cast<int64_t>(static_cast<int32_t>(rng())));
    default: return rng();
  }
}

void compare_backends(const char* name, const ir::Block& block, std::mt19937_64& rng, int iterations) {
  for (int it = 0; it < iterations; ++it) {
    State in{};
    for (int s = 0; s < 4; ++s) in[s] = interesting(rng);
    in[2] = (rng() & 1) ? (rng() & 0xF0000000u) : in[2];  // plausible packed flags
    State jit = in, interp = in;
    run_jit(block, jit);
    run_interp(block, interp);
    if (jit != interp) {
      for (int s = 0; s < kSlots; ++s) {
        if (jit[s] != interp[s]) {
          test::fail(__FILE__, __LINE__,
                     std::format("{}: slot {} jit=0x{:x} interp=0x{:x} (inputs 0x{:x}, 0x{:x}, 0x{:x})", name, s,
                                 jit[s], interp[s], in[0], in[1], in[2]));
          return;
        }
      }
    }
  }
}

}  // namespace

TEST(ir_evaluate_basics) {
  auto eval = [](Opcode op, uint8_t size, uint64_t a, uint64_t b, uint64_t c = 0, uint8_t aux = 0) {
    ir::Inst in;
    in.op = op;
    in.size = size;
    in.aux = aux;
    return ir::evaluate(in, a, b, c);
  };
  CHECK_EQ(eval(Opcode::Add, 4, 0xFFFFFFFF, 1), 0u);
  CHECK_EQ(eval(Opcode::Sub, 8, 0, 1), ~0ull);
  CHECK_EQ(eval(Opcode::UDiv, 8, 10, 0), 0u);
  CHECK_EQ(eval(Opcode::SDiv, 8, 0x8000000000000000ull, ~0ull), 0x8000000000000000ull);
  CHECK_EQ(eval(Opcode::SDiv, 4, static_cast<uint64_t>(-7), 2), 0xFFFFFFFDu);
  CHECK_EQ(eval(Opcode::AShr, 4, 0x80000000, 4), 0xF8000000u);
  CHECK_EQ(eval(Opcode::Ror, 4, 1, 1), 0x80000000u);
  CHECK_EQ(eval(Opcode::Shl, 8, 1, 65), 2u);  // amount taken modulo width
  CHECK_EQ(eval(Opcode::Clz, 4, 0, 0), 32u);
  CHECK_EQ(eval(Opcode::Clz, 8, 1, 0), 63u);
  CHECK_EQ(eval(Opcode::UMulH, 8, ~0ull, ~0ull), ~0ull - 1);
  CHECK_EQ(eval(Opcode::SMulH, 8, ~0ull, ~0ull), 0u);
  CHECK_EQ(eval(Opcode::SExt, 8, 0x80, 0, 0, 8), 0xFFFFFFFFFFFFFF80ull);
  CHECK_EQ(eval(Opcode::SExt, 4, 0x80, 0, 0, 8), 0xFFFFFF80ull);
  CHECK_EQ(eval(Opcode::Cmp, 4, 0x1FFFFFFFF, 0xFFFFFFFF, 0, static_cast<uint8_t>(Predicate::Eq)), 1u);
  CHECK_EQ(eval(Opcode::Cmp, 8, ~0ull, 0, 0, static_cast<uint8_t>(Predicate::Slt)), 1u);
}

TEST(ir_flags) {
  // 0xFFFFFFFF + 1 (32-bit): Z and C set.
  CHECK_EQ(ir::flags_add(0xFFFFFFFF, 1, 0, 4), ir::kFlagZ | ir::kFlagC);
  // 0x7FFFFFFF + 1: N and V set.
  CHECK_EQ(ir::flags_add(0x7FFFFFFF, 1, 0, 4), ir::kFlagN | ir::kFlagV);
  // 5 - 7 (64-bit): N set, no carry (borrow).
  CHECK_EQ(ir::flags_add(5, ~7ull, 1, 8), ir::kFlagN);
  // 7 - 5: carry set (no borrow).
  CHECK_EQ(ir::flags_add(7, ~5ull, 1, 8), ir::kFlagC);
  CHECK(ir::condition_holds(0 /*eq*/, ir::kFlagZ));
  CHECK(!ir::condition_holds(1 /*ne*/, ir::kFlagZ));
  CHECK(ir::condition_holds(8 /*hi*/, ir::kFlagC));
  CHECK(!ir::condition_holds(8 /*hi*/, ir::kFlagC | ir::kFlagZ));
  CHECK(ir::condition_holds(11 /*lt*/, ir::kFlagN));
  CHECK(ir::condition_holds(12 /*gt*/, ir::kFlagN | ir::kFlagV));
  CHECK(ir::condition_holds(14 /*al*/, 0));
  CHECK_EQ(ir::condition_mask(14), 0xFFFFu);
}

TEST(ir_optimizer_folds_and_forwards) {
  ir::Block block;
  ir::Builder b(block);
  ir::ValueId x = b.get(1);
  ir::ValueId sum = b.add(b.constant(2), b.constant(3));  // folds to 5
  b.set(0, b.add(x, sum));
  ir::ValueId again = b.get(0);                           // forwarded from the set
  b.set(0, b.add(again, b.constant(0)));                  // add 0 -> alias; first set becomes dead
  b.set(2, b.get(1));
  b.jump(0x40);

  ir::OptimizeStats stats = ir::optimize(block);
  CHECK(stats.folded >= 2);
  CHECK(stats.forwarded >= 2);
  CHECK(stats.dead_stores >= 1);

  State s{};
  s[1] = 100;
  run_interp(block, s);
  CHECK_EQ(s[0], 105u);
  CHECK_EQ(s[2], 100u);
  CHECK_EQ(s[kPc], 0x40u);
}

TEST(ir_optimizer_constant_branch) {
  ir::Block block;
  ir::Builder b(block);
  ir::ValueId c = b.cmp(Predicate::Ult, b.constant(1), b.constant(2));
  b.branch(c, 0x100, 0x200);
  ir::optimize(block);
  CHECK(block.term.kind == ir::Terminator::Kind::Jump);
  CHECK_EQ(block.term.target, 0x100u);
}

TEST(jit_matches_interpreter_for_every_opcode) {
  std::mt19937_64 rng(1234);
  struct Case {
    Opcode op;
    uint8_t aux;
  };
  std::vector<Case> cases = {
      {Opcode::Add, 0},       {Opcode::Sub, 0},       {Opcode::Mul, 0},       {Opcode::UMulH, 0},
      {Opcode::SMulH, 0},     {Opcode::UDiv, 0},      {Opcode::SDiv, 0},      {Opcode::And, 0},
      {Opcode::Or, 0},        {Opcode::Xor, 0},       {Opcode::Shl, 0},       {Opcode::LShr, 0},
      {Opcode::AShr, 0},      {Opcode::Ror, 0},       {Opcode::Not, 0},       {Opcode::Neg, 0},
      {Opcode::Clz, 0},       {Opcode::Bswap, 0},     {Opcode::SExt, 8},      {Opcode::SExt, 16},
      {Opcode::SExt, 32},     {Opcode::ZExt, 8},      {Opcode::ZExt, 16},     {Opcode::ZExt, 32},
      {Opcode::Select, 0},    {Opcode::Adc, 0},       {Opcode::Sbc, 0},       {Opcode::FlagsAdd, 0},
      {Opcode::FlagsSub, 0},  {Opcode::FlagsAdc, 0},  {Opcode::FlagsSbc, 0},  {Opcode::FlagsLogic, 0},
  };
  for (uint8_t p = 0; p <= static_cast<uint8_t>(Predicate::Sge); ++p) cases.push_back({Opcode::Cmp, p});
  for (uint8_t cond = 0; cond < 16; ++cond) cases.push_back({Opcode::CondHolds, cond});

  for (const Case& c : cases) {
    if ((c.op == Opcode::UMulH || c.op == Opcode::SMulH)) {
      // 64-bit only
      ir::Block block;
      ir::Builder b(block);
      b.set(10, b.emit(c.op, 8, b.get(0), b.get(1)));
      b.jump(0);
      compare_backends(ir::opcode_name(c.op), block, rng, 300);
      continue;
    }
    std::string name = std::format("{}/{}", ir::opcode_name(c.op), c.aux);
    compare_backends(name.c_str(), op_block(c.op, c.aux), rng, 300);
    for (uint64_t k : {0ull, 1ull, 5ull, 31ull, 63ull, 0x7FFFFFFFull, 0xFFFFFFFFull, ~0ull, 0x123456789ull})
      compare_backends((name + " (const)").c_str(), op_block_const(c.op, c.aux, k), rng, 20);
  }
}

TEST(jit_memory_and_state_transfers) {
  alignas(16) static uint8_t memory[64];
  for (int i = 0; i < 64; ++i) memory[i] = static_cast<uint8_t>(0x80 + i * 3);

  for (int size_i : {1, 2, 4, 8}) {
    const auto size = static_cast<uint8_t>(size_i);
    for (bool sign : {false, true}) {
      ir::Block block;
      ir::Builder b(block);
      ir::ValueId addr = b.add(b.get(0), b.constant(3));
      b.set(10, b.load(addr, size, sign));
      b.store(b.add(b.get(0), b.constant(32)), b.get(1), size);
      b.jump(0);
      State jit{}, interp{};
      jit[0] = interp[0] = reinterpret_cast<uint64_t>(memory);
      jit[1] = interp[1] = 0x1122334455667788ull;
      uint8_t before[64];
      std::memcpy(before, memory, 64);
      run_jit(block, jit);
      uint8_t after_jit[64];
      std::memcpy(after_jit, memory, 64);
      std::memcpy(memory, before, 64);
      run_interp(block, interp);
      CHECK(jit == interp);
      CHECK(std::memcmp(after_jit, memory, 64) == 0);
    }
  }

  for (int size_i : {1, 2, 4, 8, 16}) {
    const auto size = static_cast<uint8_t>(size_i);
    ir::Block block;
    ir::Builder b(block);
    b.load_to_state(b.get(0), 20, size, 16);
    b.store_from_state(b.add(b.get(0), b.constant(40)), 4, size);
    b.jump(0);
    State jit{}, interp{};
    for (int s = 0; s < kSlots; ++s) jit[s] = interp[s] = 0xA5A5A5A5A5A5A5A5ull * (s + 1);
    jit[0] = interp[0] = reinterpret_cast<uint64_t>(memory);
    uint8_t before[64];
    std::memcpy(before, memory, 64);
    run_jit(block, jit);
    uint8_t after_jit[64];
    std::memcpy(after_jit, memory, 64);
    std::memcpy(memory, before, 64);
    run_interp(block, interp);
    CHECK(jit == interp);
    CHECK(std::memcmp(after_jit, memory, 64) == 0);
  }
}

TEST(jit_terminators) {
  for (int kind = 0; kind < 4; ++kind) {
    ir::Block block;
    ir::Builder b(block);
    switch (kind) {
      case 0: b.jump(0xDEADBEEF12345678ull); break;
      case 1: b.jump_indirect(b.get(0)); break;
      case 2: b.branch(b.get(1), 0x1000, 0x2000); break;
      case 3: b.exit(3, 0xABCD, 0x5000); break;
    }
    for (uint64_t cond : {0ull, 1ull, 0x100000000ull}) {
      State jit{}, interp{};
      jit[0] = interp[0] = 0x4444;
      jit[1] = interp[1] = cond;
      run_jit(block, jit);
      run_interp(block, interp);
      CHECK(jit == interp);
    }
  }
}
