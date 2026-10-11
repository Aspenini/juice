// IR semantics, optimizer and x86-64 backend tests.
//
// The backend tests build blocks that apply every opcode to values read from
// guest state, then run them both through the JIT and through the reference
// interpreter on pseudo-random inputs and compare the resulting state.

#include <array>
#include <bit>
#include <cstring>
#include <format>
#include <random>
#include <stdexcept>
#include <string>

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
  static runtime::CodeArena a(256 << 20);
  return a;
}

void run_jit(const ir::Block& block, State& state) {
  static std::vector<uint64_t> scratch(x64::kMaxBlockValues);
  std::vector<uint8_t> code = x64::Emitter(layout()).compile(block);
  void* fn = arena().add(code);
  if (!fn) throw std::runtime_error("test code arena exhausted");
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

namespace {

uint64_t lane(ir::VecOp op, unsigned aux, uint64_t a, uint64_t b = 0, uint64_t c = 0) {
  ir::Inst in;
  in.op = Opcode::VLane;
  in.size = 8;
  in.imm = static_cast<uint64_t>(op);
  in.aux = static_cast<uint8_t>(aux);
  return ir::evaluate(in, a, b, c);
}

// Floating point bit patterns worth checking: NaNs (quiet and signaling,
// with payloads), infinities, zeros, denormals and the integer conversion
// boundaries, besides ordinary values.
uint64_t fp_interesting(std::mt19937_64& rng, unsigned size) {
  static constexpr double doubles[] = {0.0, -0.0, 1.0, -1.0, 0.5, -0.5, 1.5, 2.5, -2.5, 3.0, 1e300, -1e300,
                                       4294967295.0, 4294967296.0, 4294967295.5, 2147483647.0, 2147483648.0,
                                       -2147483648.0, -2147483649.0, -2147483648.5, 9223372036854775807.0,
                                       9223372036854775808.0, -9223372036854775808.0, 18446744073709551615.0,
                                       18446744073709551616.0, 1e-310, -1e-310, 1e19, -1e19};
  static constexpr uint64_t double_bits[] = {0x7FF0000000000000ull, 0xFFF0000000000000ull, 0x7FF8000000000000ull,
                                             0xFFF8000000000123ull, 0x7FF0000000000001ull, 0x7FF4000000000abcull,
                                             0xFFF0000000000042ull};
  static constexpr uint32_t float_bits[] = {0x7F800000u, 0xFF800000u, 0x7FC00000u, 0xFFC00123u, 0x7F800001u,
                                            0x7FA00abcu, 0x00000001u, 0x80000001u, 0x4F000000u, 0xCF000000u,
                                            0x4F800000u, 0x5F000000u, 0xDF000000u, 0x5F800000u};
  const unsigned pick = rng() % 4;
  if (size == 8) {
    if (pick == 0) return std::bit_cast<uint64_t>(doubles[rng() % std::size(doubles)]);
    if (pick == 1) return double_bits[rng() % std::size(double_bits)];
    if (pick == 2) return std::bit_cast<uint64_t>(static_cast<double>(static_cast<int64_t>(rng())) / (1 + rng() % 1000));
    return rng();
  }
  if (pick == 0) return std::bit_cast<uint32_t>(static_cast<float>(doubles[rng() % std::size(doubles)]));
  if (pick == 1) return float_bits[rng() % std::size(float_bits)];
  if (pick == 2) return std::bit_cast<uint32_t>(static_cast<float>(static_cast<int32_t>(rng())) / (1 + rng() % 1000));
  return rng() & 0xFFFF'FFFFu;
}

// One FP operation of the given sizes on slots 0..2 (as `in_size` values),
// its result in slot 10.
void compare_fp(const char* name, Opcode op, uint8_t size, uint8_t aux, unsigned in_size, bool int_inputs,
                std::mt19937_64& rng, int iterations) {
  ir::Block block;
  ir::Builder b(block);
  b.set(10, b.emit(op, size, b.get(0), b.get(1), b.get(2), 0, aux));
  b.jump(0x1234);
  for (int it = 0; it < iterations; ++it) {
    State in{};
    for (int s = 0; s < 3; ++s) in[s] = int_inputs ? interesting(rng) : fp_interesting(rng, in_size);
    State jit = in, interp = in;
    run_jit(block, jit);
    run_interp(block, interp);
    if (jit[10] != interp[10]) {
      test::fail(__FILE__, __LINE__,
                 std::format("{} (size {}, aux 0x{:x}): jit=0x{:x} interp=0x{:x} (inputs 0x{:x}, 0x{:x}, 0x{:x})", name,
                             size, aux, jit[10], interp[10], in[0], in[1], in[2]));
      return;
    }
  }
}

// A vector half operation on slots 0..2, its result in slot 10. `make`
// gives the inputs; `shift_const` >= 0 makes the second operand that constant.
template <typename Make>
void compare_vec(const std::string& name, Opcode op, uint8_t aux, uint64_t imm, Make make, int iterations,
                 int64_t shift_const = -1) {
  ir::Block block;
  ir::Builder b(block);
  const ir::ValueId second = shift_const >= 0 ? b.constant(static_cast<uint64_t>(shift_const)) : b.get(1);
  b.set(10, b.emit(op, 8, b.get(0), second, b.get(2), imm, aux));
  b.jump(0x1234);
  for (int it = 0; it < iterations; ++it) {
    State in{};
    for (int s = 0; s < 3; ++s) in[s] = make(s);
    State jit = in, interp = in;
    run_jit(block, jit);
    run_interp(block, interp);
    if (jit[10] != interp[10]) {
      test::fail(__FILE__, __LINE__,
                 std::format("{} (aux 0x{:x}): jit=0x{:x} interp=0x{:x} (inputs 0x{:x}, 0x{:x}, 0x{:x})", name, aux,
                             jit[10], interp[10], in[0], in[1], in[2]));
      return;
    }
  }
}

}  // namespace

// Conditions fused with the compare that sets the flags (no packed NZCV
// when only conditions use it) agree with the evaluator, for every condition.
TEST(jit_fuses_conditions_with_flag_operations) {
  std::mt19937_64 rng(99);
  for (Opcode flags : {Opcode::FlagsSub, Opcode::FlagsAdd, Opcode::FlagsLogic, Opcode::FCmp}) {
    for (uint8_t size : {uint8_t{4}, uint8_t{8}}) {
      for (uint8_t cond = 0; cond < 16; ++cond) {
        for (bool store_flags : {false, true}) {
          ir::Block block;
          ir::Builder b(block);
          const ir::ValueId f = b.emit(flags, size, b.get(0), b.get(1));
          b.set(10, b.cond_holds(f, cond));
          if (store_flags) b.set(11, f);
          b.jump(0);
          compare_backends(std::format("{}{} cond {}{}", ir::opcode_name(flags), size, cond,
                                       store_flags ? " (flags stored)" : "").c_str(),
                           block, rng, 300);
        }
        // A select on the condition (the JIT selects on the x86 flags).
        for (uint8_t select_size : {uint8_t{4}, uint8_t{8}}) {
          ir::Block block;
          ir::Builder b(block);
          const ir::ValueId f = b.emit(flags, size, b.get(0), b.get(1));
          const ir::ValueId c = b.cond_holds(f, cond);
          b.set(10, b.select(c, b.get(2), b.get(3), select_size));
          b.set(11, b.select(c, b.constant(0), b.get(1), select_size));
          b.jump(0);
          compare_backends(std::format("{}{} cond {} select{}", ir::opcode_name(flags), size, cond, select_size).c_str(),
                           block, rng, 300);
        }
      }
    }
  }
}

// The JIT's inline SSE paths for vector halves agree with the evaluator.
TEST(jit_matches_interpreter_for_vector_halves) {
  std::mt19937_64 rng(777);
  // Integer lanes: random bits, with lanes often equal or extreme.
  auto ints = [&](int) {
    switch (rng() % 4) {
      case 0: return 0x7F80007FFFFF8000ull ^ (rng() & 0x0101010101010101ull);
      case 1: return rng() & 0x8181818181818181ull;
      default: return rng();
    }
  };
  for (unsigned esize : {1u, 2u, 4u, 8u}) {
    const auto e = static_cast<uint8_t>(esize);
    compare_vec(std::format("vadd{}", esize), Opcode::VAdd, e, 0, ints, 500);
    compare_vec(std::format("vsub{}", esize), Opcode::VSub, e, 0, ints, 500);
    compare_vec(std::format("vmul{}", esize), Opcode::VMul, e, 0, ints, 500);
    compare_vec(std::format("vabs{}", esize), Opcode::VAbs, e, 0, ints, 500);
    for (uint8_t sign = 0; sign < 2; ++sign) {
      compare_vec(std::format("vmax{}", esize), Opcode::VMax, static_cast<uint8_t>(e | sign << 4), 0, ints, 500);
      compare_vec(std::format("vmin{}", esize), Opcode::VMin, static_cast<uint8_t>(e | sign << 4), 0, ints, 500);
    }
    for (uint8_t pred = 0; pred <= static_cast<uint8_t>(ir::VecPred::Tst); ++pred) {
      // Equal lanes matter for the compares: make b a copy of a with some lanes changed.
      auto pairs = [&](int s) -> uint64_t {
        static uint64_t a;
        if (s == 0) return a = ints(0);
        if (s != 1) return rng();
        uint64_t keep = 0;  // 16-bit chunks of b that equal a's; the rest independent
        for (unsigned k = 0; k < 4; ++k)
          if (rng() & 1) keep |= 0xFFFFull << (16 * k);
        return (a & keep) | (ints(0) & ~keep);
      };
      compare_vec(std::format("vcmp{}/{}", esize, pred), Opcode::VCmp, static_cast<uint8_t>(e | pred << 4), 0, pairs, 500);
    }
    for (Opcode op : {Opcode::VShl, Opcode::VLShr, Opcode::VAShr}) {
      for (int64_t k : {0, 1, 3, 7, 8, 15, 16, 31, 32, 63, 64, 100})
        compare_vec(std::format("{}{} #{}", ir::opcode_name(op), esize, k), op, e, 0, ints, 50, k);
      compare_vec(std::format("{}{} by register", ir::opcode_name(op), esize), op, e, 0,
                  [&](int s) { return s == 1 ? rng() % 80 : rng(); }, 300);
    }
    if (esize < 8) {
      for (uint8_t mode = 0; mode < 4; ++mode)
        compare_vec(std::format("vwiden{}/{}", esize, mode), Opcode::VWiden, static_cast<uint8_t>(e | mode << 4), 0,
                    ints, 300);
    }
  }
  for (uint8_t part = 0; part < 2; ++part) {
    compare_vec(std::format("tbl part {}", part), Opcode::VLane, part, static_cast<uint64_t>(ir::VecOp::TblPart),
                [&](int s) { return s == 1 ? (rng() & 0x1F1F1F1F1F1F1F1Full) | (rng() % 3 ? 0 : rng()) : rng(); },
                1000);
  }
  // Floating point lanes: two floats or one double per half.
  for (unsigned esize : {4u, 8u}) {
    auto fps = [&](int) {
      return esize == 8 ? fp_interesting(rng, 8) : fp_interesting(rng, 4) | fp_interesting(rng, 4) << 32;
    };
    for (ir::VecOp op : {ir::VecOp::FAdd, ir::VecOp::FSub, ir::VecOp::FMul, ir::VecOp::FDiv, ir::VecOp::FMla,
                         ir::VecOp::FMls, ir::VecOp::FCmEq, ir::VecOp::FCmGe, ir::VecOp::FCmGt})
      compare_vec(std::format("fp lane op {} size {}", static_cast<int>(op), esize), Opcode::VLane,
                  static_cast<uint8_t>(esize), static_cast<uint64_t>(op), fps, 2000);
  }
}

// The JIT's inline SSE paths for scalar floating point agree with the
// evaluator, NaN rules, saturation and rounding modes included.
TEST(jit_matches_interpreter_for_scalar_fp) {
  std::mt19937_64 rng(4321);
  for (uint8_t size : {uint8_t{4}, uint8_t{8}}) {
    for (Opcode op : {Opcode::FAdd, Opcode::FSub, Opcode::FMul, Opcode::FDiv, Opcode::FSqrt, Opcode::FMadd,
                      Opcode::FCmp})
      compare_fp(ir::opcode_name(op), op, size, 0, size, false, rng, 3000);
  }
  for (uint8_t size : {uint8_t{4}, uint8_t{8}})
    for (uint8_t mode = 0; mode < 5; ++mode) compare_fp("frint", Opcode::FRint, size, mode, size, false, rng, 3000);
  compare_fp("fcvt d->s", Opcode::FCvt, 4, 8, 8, false, rng, 3000);
  compare_fp("fcvt s->d", Opcode::FCvt, 8, 4, 4, false, rng, 3000);
  for (uint8_t size : {uint8_t{4}, uint8_t{8}})
    for (uint8_t aux = 0; aux < 4; ++aux) compare_fp("int->fp", Opcode::IntToF, size, aux, 8, true, rng, 2000);
  for (uint8_t size : {uint8_t{4}, uint8_t{8}}) {
    for (uint8_t mode = 0; mode < 5; ++mode) {
      for (uint8_t sign = 0; sign < 2; ++sign) {
        for (uint8_t from_double = 0; from_double < 2; ++from_double) {
          const auto aux = static_cast<uint8_t>(mode | sign << 3 | from_double << 4);
          compare_fp("fp->int", Opcode::FToInt, size, aux, from_double ? 8 : 4, false, rng, 2000);
        }
      }
    }
  }
}

TEST(vlane_semantics) {
  using ir::VecOp;
  // Arm's 8-bit estimates (values as the hardware returns them)
  CHECK_EQ(lane(VecOp::FRecpe, 4, 0x400000003F800000ull), 0x3EFF80003F7F8000ull);  // 1/2, 1/1
  CHECK_EQ(lane(VecOp::FRsqrte, 4, 0x408000003F800000ull), 0x3EFF80003F7F8000ull); // 1/sqrt(4), 1/sqrt(1)
  CHECK_EQ(lane(VecOp::FRecps, 4, 0x40000000ull, 0x3F000000ull), 0x400000003F800000ull);  // 2 - 2 * 0.5, 2 - 0 * 0
  // saturation
  CHECK_EQ(lane(VecOp::SatAdd, 1 | 16, 0x7F, 0x01), 0x7Full);
  CHECK_EQ(lane(VecOp::SatSub, 1, 0x05, 0x09), 0x00ull);
  CHECK_EQ(lane(VecOp::SatNarrow, 1, 0xFF00'0100ull), 0x807Full);  // s16 -> s8: 256 -> 127, -256 -> -128
  CHECK_EQ(lane(VecOp::SatNarrow, 1 | 32, 0xFF00'0100ull), 0x00FFull);  // s16 -> u8
  CHECK_EQ(lane(VecOp::SatDMulHigh, 2 | 16 | 32, 0x4000, 0x4000), 0x2000ull);
  CHECK_EQ(lane(VecOp::SatDMulHigh, 2 | 16, 0x8000, 0x8000), 0x7FFFull);
  // shifts
  CHECK_EQ(lane(VecOp::RShr, 1, 0x03, 1), 0x02ull);
  CHECK_EQ(lane(VecOp::ShlReg, 1 | 16, 0xFD, 0xFF), 0xFEull);  // -3 >> 1 (arithmetic)
  CHECK_EQ(lane(VecOp::RShlReg, 1, 0x03, 0xFF), 0x02ull);
  CHECK_EQ(lane(VecOp::SatShlImm, 1, 0x40, 1), 0x7Full);        // signed: 64 << 1 saturates
  CHECK_EQ(lane(VecOp::SatShlImm, 1 | 16, 0x40, 1), 0x80ull);    // unsigned: fits
  // bytes
  CHECK_EQ(lane(VecOp::PMul, 1, 0x03, 0x03), 0x05ull);
  CHECK_EQ(lane(VecOp::TblPart, 0, 0, 0xFFFFFFFFFFFF0901ull, 0x0807060504030201ull), 0x02ull);  // 9, 0xFF: out of range
  CHECK_EQ(lane(VecOp::AddLongPairwise, 1, 0xFFFF), 0x1FEull);
  // conversions
  CHECK_EQ(lane(VecOp::FCvtUp, 4, 0x3C00), 0x3F800000ull);       // half 1.0 -> single
  CHECK_EQ(lane(VecOp::FCvtDown, 2, 0x3FC00000ull, 0), 0x3E00ull);  // single 1.5 -> half
  CHECK_EQ(lane(VecOp::FToInt, 4 | (3 << 4) | 128, 0x3FA00000ull, 2), 5ull);  // 1.25 * 4
  CHECK_EQ(lane(VecOp::IntToF, 4 | 16, 5, 2), 0x3FA00000ull);  // 5 / 4
}

TEST(jit_matches_interpreter_for_vlane) {
  std::mt19937_64 rng(4321);
  for (unsigned op = 0; op < static_cast<unsigned>(ir::VecOp::Count_); ++op) {
    for (unsigned aux : {1u, 2u | 16u, 4u, 8u | 16u, 4u | (3u << 4) | 128u}) {
      ir::Block block;
      ir::Builder b(block);
      b.set(10, b.emit(Opcode::VLane, 8, b.get(0), b.get(1), b.get(2), op, static_cast<uint8_t>(aux)));
      b.jump(0);
      compare_backends(std::format("v.lane.{}/{}", op, aux).c_str(), block, rng, 50);
    }
  }
}
