// End-to-end translation tests: ARM64 machine code -> decoder -> lifter ->
// optimizer -> x86-64 JIT, checked against known results. Every snippet runs
// under three engine configurations (optimized JIT, unoptimized JIT with
// one-instruction blocks, and the IR interpreter) which must agree exactly.
//
// Encodings come from the LLVM assembler.

#include <algorithm>
#include <bit>
#include <cstring>
#include <functional>
#include <random>

#include "core/arm64/decode/instruction.hpp"
#include "core/arm64/lift/lifter.hpp"
#include "runtime/engine.hpp"
#include "test.hpp"

using namespace juice;
using arm64::CpuState;

namespace {

constexpr uint64_t kCodeBase = 0x10000;
constexpr uint32_t kBrk0 = 0xd4200000;

class TestEnv final : public runtime::Environment {
 public:
  explicit TestEnv(std::vector<uint32_t> code) : code_(std::move(code)) {}

  bool read_code(uint64_t addr, uint32_t& word) override {
    if (addr < kCodeBase || addr >= kCodeBase + 4 * code_.size()) return false;
    word = code_[(addr - kCodeBase) / 4];
    return true;
  }
  std::pair<uint64_t, uint64_t> host_range() const override { return {0, 0}; }
  runtime::Action on_host_address(CpuState&) override { return runtime::Action::Stop; }
  runtime::Action on_exit(CpuState& s) override {
    last_exit = static_cast<arm64::ExitReason>(s.exit_reason);
    return runtime::Action::Stop;
  }

  arm64::ExitReason last_exit = arm64::ExitReason::None;

 private:
  std::vector<uint32_t> code_;
};

struct Config {
  const char* name;
  runtime::EngineOptions options;
};

std::vector<Config> configs() {
  runtime::EngineOptions jit;
  runtime::EngineOptions noopt;
  noopt.optimize = false;
  noopt.max_block_insns = 1;
  runtime::EngineOptions interp;
  interp.interpret = true;
  return {{"jit", jit}, {"jit-noopt-1", noopt}, {"interp", interp}};
}

bool same_state(const CpuState& a, const CpuState& b) {
  CpuState x = a, y = b;
  x.block_pc = y.block_pc = 0;  // depends on block boundaries
  return std::memcmp(&x, &y, sizeof(CpuState)) == 0;
}

// Runs `code` (terminated by BRK #0) from kCodeBase. `setup` initializes the
// state. Returns the final state of the first configuration after checking that
// all configurations agree.
CpuState run(const std::vector<uint32_t>& code, const std::function<void(CpuState&)>& setup,
             const char* what = "snippet") {
  std::vector<uint32_t> program = code;
  program.push_back(kBrk0);
  CpuState first{};
  bool have_first = false;
  for (const Config& cfg : configs()) {
    TestEnv env(program);
    runtime::EngineOptions options = cfg.options;
    options.log = stderr;
    runtime::Engine engine(env, options);
    CpuState s{};
    if (setup) setup(s);
    s.pc = kCodeBase;
    engine.run(s);
    if (env.last_exit != arm64::ExitReason::Brk) {
      test::fail(__FILE__, __LINE__, std::format("{} [{}]: stopped with {} at 0x{:x}", what, cfg.name,
                                                 arm64::to_string(env.last_exit), s.pc));
    }
    if (!have_first) {
      first = s;
      have_first = true;
    } else if (!same_state(first, s)) {
      for (int r = 0; r < 31; ++r)
        if (first.x[r] != s.x[r])
          test::fail(__FILE__, __LINE__,
                     std::format("{} [{}]: x{} = 0x{:x}, jit gave 0x{:x}", what, cfg.name, r, s.x[r], first.x[r]));
      if (first.nzcv != s.nzcv)
        test::fail(__FILE__, __LINE__, std::format("{} [{}]: nzcv differs", what, cfg.name));
      test::fail(__FILE__, __LINE__, std::format("{} [{}]: state differs between configurations", what, cfg.name));
    }
  }
  return first;
}

}  // namespace

TEST(translate_arithmetic) {
  CpuState s = run({0x8b020020 /* add x0, x1, x2 */, 0xcb820c23 /* sub x3, x1, x2, asr #3 */,
                    0x8b224824 /* add x4, x1, w2, uxtw #2 */},
                   [](CpuState& s) {
                     s.x[1] = 5;
                     s.x[2] = 0xFFFFFFFF00000040ull;
                   });
  CHECK_EQ(s.x[0], 0xFFFFFFFF00000045ull);
  CHECK_EQ(s.x[3], 5 - (0xFFFFFFFF00000040ull >> 3 | 0xE000000000000000ull));
  CHECK_EQ(s.x[4], 5 + (0x40u << 2));
}

TEST(translate_flags) {
  CpuState s = run({0x2b020020 /* adds w0, w1, w2 */}, [](CpuState& s) {
    s.x[1] = 0xFFFFFFFF;
    s.x[2] = 1;
  });
  CHECK_EQ(s.x[0], 0u);
  CHECK_EQ(s.nzcv, 0x60000000u);  // Z C

  s = run({0xeb020020 /* subs x0, x1, x2 */}, [](CpuState& s) {
    s.x[1] = 5;
    s.x[2] = 7;
  });
  CHECK_EQ(s.x[0], static_cast<uint64_t>(-2));
  CHECK_EQ(s.nzcv, 0x80000000u);  // N

  // adcs x0, x1, x2 with carry in; sbcs w3, w1, w2
  s = run({0xba020020, 0x7a020023}, [](CpuState& s) {
    s.x[1] = ~0ull;
    s.x[2] = 0;
    s.nzcv = 0x20000000;
  });
  CHECK_EQ(s.x[0], 0u);
  CHECK_EQ(s.x[3], 0xFFFFFFFFu);  // carry from adcs set C: 0xFFFFFFFF - 0 - 0
}

TEST(translate_moves_and_bitfields) {
  CpuState s = run({0xd2a24680 /* movz x0, #0x1234, lsl #16 */, 0xf28acf00 /* movk x0, #0x5678 */,
                    0x12800001 /* movn w1, #0 */, 0x92089c22 /* and x2, x1, #0xff00ff00ff00ff00 */,
                    0xd3442c83 /* ubfx x3, x4, #4, #8 */, 0x93442c85 /* sbfx x5, x4, #4, #8 */,
                    0xb3783c86 /* bfi x6, x4, #8, #16 */, 0x33042c87 /* bfxil w7, w4, #4, #8 */,
                    0xd37df088 /* lsl x8, x4, #3 */, 0x13037c89 /* asr w9, w4, #3 */,
                    0x93401c8a /* sxtb x10, w4 */, 0x53003c8b /* uxth w11, w4 */},
                   [](CpuState& s) {
                     s.x[4] = 0x87654321F0F0ABCDull;
                     s.x[6] = 0x1111111111111111ull;
                     s.x[7] = 0x2222222222222222ull;
                   });
  CHECK_EQ(s.x[0], 0x12345678u);
  CHECK_EQ(s.x[1], 0xFFFFFFFFu);
  CHECK_EQ(s.x[2], 0xFF00FF00u);
  CHECK_EQ(s.x[3], 0xBCu);
  CHECK_EQ(s.x[5], static_cast<uint64_t>(-0x44));  // 0xBC sign-extended
  CHECK_EQ(s.x[6], 0x1111111111ABCD11ull);
  CHECK_EQ(s.x[7], 0x222222BCu);                   // W write clears the top half
  CHECK_EQ(s.x[8], 0x87654321F0F0ABCDull << 3);
  CHECK_EQ(s.x[9], 0xFE1E1579u);                   // 0xF0F0ABCD asr 3 (32-bit)
  CHECK_EQ(s.x[10], static_cast<uint64_t>(-0x33));
  CHECK_EQ(s.x[11], 0xABCDu);
}

TEST(translate_conditional) {
  // cmp x1, x2; csel x0, x1, x2, lt; cset w3, eq; csetm x4, hi; cneg x5, x1, mi; ccmp x1, x2, #4, ne
  std::vector<uint32_t> code = {0xeb02003f, 0x9a82b020, 0x1a9f17e3, 0xda9f93e4, 0xda815425, 0xfa421024};
  CpuState s = run(code, [](CpuState& s) {
    s.x[1] = static_cast<uint64_t>(-3);
    s.x[2] = 10;
  });
  CHECK_EQ(s.x[0], static_cast<uint64_t>(-3));  // -3 < 10 (signed)
  CHECK_EQ(s.x[3], 0u);
  CHECK_EQ(s.x[4], ~0ull);                      // unsigned 0xFF..FD > 10
  CHECK_EQ(s.x[5], 3u);
  CHECK_EQ(s.nzcv, 0xA0000000u);                // ne held: flags of cmp again (N, C)

  s = run(code, [](CpuState& s) {
    s.x[1] = 7;
    s.x[2] = 7;
  });
  CHECK_EQ(s.x[0], 7u);
  CHECK_EQ(s.x[3], 1u);
  CHECK_EQ(s.x[4], 0u);
  CHECK_EQ(s.x[5], 7u);
  CHECK_EQ(s.nzcv, 0x40000000u);  // eq: ccmp condition false -> nzcv = #4 (Z)
}

TEST(translate_multiply_divide) {
  CpuState s = run({0x9b027c20 /* mul x0, x1, x2 */, 0x9b020c23 /* madd x3, x1, x2, x3 */,
                    0x1b028c24 /* msub w4, w1, w2, w3 */, 0x9bc27c25 /* umulh x5, x1, x2 */,
                    0x9b427c26 /* smulh x6, x1, x2 */, 0x9ac20827 /* udiv x7, x1, x2 */,
                    0x9ac20c28 /* sdiv x8, x1, x2 */, 0x9ac20d29 /* sdiv x9, x9, x2 */,
                    0x9ac2096a /* udiv x10, x11, x2 */},
                   [](CpuState& s) {
                     s.x[1] = static_cast<uint64_t>(-100);
                     s.x[2] = 7;
                     s.x[3] = 1000;
                     s.x[9] = 0x8000000000000000ull;
                     s.x[11] = 0;
                   });
  CHECK_EQ(s.x[0], static_cast<uint64_t>(-700));
  CHECK_EQ(s.x[3], 300u);
  CHECK_EQ(s.x[4], 1000u);  // w3 (now 300) - (-700)
  CHECK_EQ(s.x[5], 6u);
  CHECK_EQ(s.x[6], ~0ull);
  CHECK_EQ(s.x[7], static_cast<uint64_t>(-100) / 7);
  CHECK_EQ(s.x[8], static_cast<uint64_t>(-14));
  CHECK_EQ(s.x[10], 0u);

  // Division by zero yields zero, INT64_MIN / -1 yields INT64_MIN.
  s = run({0x9ac20820 /* udiv x0, x1, x2 */, 0x9ac20c23 /* sdiv x3, x1, x2 */, 0x9ac40ca5 /* sdiv x5, x5, x4 */},
          [](CpuState& s) {
            s.x[1] = 1234;
            s.x[2] = 0;
            s.x[4] = ~0ull;
            s.x[5] = 0x8000000000000000ull;
          });
  CHECK_EQ(s.x[0], 0u);
  CHECK_EQ(s.x[3], 0u);
  CHECK_EQ(s.x[5], 0x8000000000000000ull);
}

TEST(translate_bit_operations) {
  CpuState s = run({0xdac01020 /* clz x0, x1 */, 0x5ac00022 /* rbit w2, w1 */, 0xdac00c23 /* rev x3, x1 */,
                    0x5ac00424 /* rev16 w4, w1 */, 0xdac00825 /* rev32 x5, x1 */, 0xdac01426 /* cls x6, x1 */,
                    0x93c23027 /* extr x7, x1, x2, #12 */, 0x13811428 /* ror w8, w1, #5 */},
                   [](CpuState& s) { s.x[1] = 0x00F0000012345678ull; });
  CHECK_EQ(s.x[0], 8u);
  CHECK_EQ(s.x[2], 0x1E6A2C48u);
  CHECK_EQ(s.x[3], 0x785634120000F000ull);
  CHECK_EQ(s.x[4], 0x34127856u);
  CHECK_EQ(s.x[5], 0x0000F00078563412ull);
  CHECK_EQ(s.x[6], 7u);
  CHECK_EQ(s.x[7], (s.x[2] >> 12) | (0x00F0000012345678ull << 52));
  CHECK_EQ(s.x[8], (0x12345678u >> 5) | (0x12345678u << 27));
}

TEST(translate_loads_and_stores) {
  alignas(16) static uint8_t mem[256];
  const uint64_t base = reinterpret_cast<uint64_t>(mem) + 64;

  CpuState s = run({0xf8408c20 /* ldr x0, [x1, #8]! */, 0xb81fc422 /* str w2, [x1], #-4 */,
                    0xa9411023 /* ldp x3, x4, [x1, #16] */, 0x39800425 /* ldrsb x5, [x1, #1] */,
                    0x79c00426 /* ldrsh w6, [x1, #2] */, 0xb8a77827 /* ldrsw x7, [x1, x7, lsl #2] */,
                    0xb868d828 /* ldr w8, [x1, w8, sxtw #2] */, 0xf85fd029 /* ldur x9, [x1, #-3] */,
                    0x79000c22 /* strh w2, [x1, #6] */},
                   [&](CpuState& s) {
                     for (int i = 0; i < 256; ++i) mem[i] = static_cast<uint8_t>(0x80 + i);
                     s.x[1] = base;
                     s.x[2] = 0xCAFEF00D;
                     s.x[7] = 2;
                     s.x[8] = static_cast<uint64_t>(-1);
                   });
  // x1 = base + 8 after pre-index, then base + 4 after the post-index store.
  CHECK_EQ(s.x[1], base + 4);
  uint64_t expect_x0 = 0;
  for (int k = 7; k >= 0; --k) expect_x0 = (expect_x0 << 8) | static_cast<uint8_t>(0x80 + 64 + 8 + k);
  CHECK_EQ(s.x[0], expect_x0);
  uint32_t stored;
  std::memcpy(&stored, reinterpret_cast<void*>(base + 8), 4);
  CHECK_EQ(stored, 0xF00DF00Du);  // str w2 at base+8, then strh w2 at base+10
  CHECK_EQ(static_cast<int64_t>(s.x[5]), static_cast<int8_t>(mem[64 + 5]));
  CHECK_EQ(s.x[6], static_cast<uint32_t>(static_cast<int32_t>(static_cast<int16_t>(mem[70] | (mem[71] << 8)))));
  uint16_t half;
  std::memcpy(&half, reinterpret_cast<void*>(base + 10), 2);
  CHECK_EQ(half, 0xF00Du);
}

TEST(translate_pairs_and_stack) {
  alignas(16) static uint64_t stack[16];
  const uint64_t top = reinterpret_cast<uint64_t>(stack + 16);
  // stp x3, x4, [sp, #-16]!; ldpsw x0, x1, [sp]; ldp x5, x6, [sp], #16
  CpuState s = run({0xa9bf13e3, 0x694007e0, 0xa8c11be5}, [&](CpuState& s) {
    s.sp = top;
    s.x[3] = 0xFFFFFFFF80000000ull;
    s.x[4] = 0x7FFFFFFF;
  });
  CHECK_EQ(s.sp, top);
  CHECK_EQ(s.x[0], 0xFFFFFFFF80000000ull);  // ldpsw: sign-extended low word of x3
  CHECK_EQ(s.x[1], 0xFFFFFFFFFFFFFFFFull);  // high word of x3
  CHECK_EQ(s.x[5], 0xFFFFFFFF80000000ull);
  CHECK_EQ(s.x[6], 0x7FFFFFFFu);
}

TEST(translate_branches) {
  // sum = 0; for (i = 10; i != 0; --i) sum += i;
  //   mov x0, #0          d2800000
  //   mov x1, #10         d2800141
  // loop:
  //   add x0, x0, x1      8b010000
  //   subs x1, x1, #1     f1000421
  //   b.ne loop           54ffffc1
  CpuState s = run({0xd2800000, 0xd2800141, 0x8b010000, 0xf1000421, 0x54ffffc1}, nullptr, "loop");
  CHECK_EQ(s.x[0], 55u);
  CHECK_EQ(s.x[1], 0u);

  // bl over one instruction to a function that returns:
  //   bl func      94000003
  //   add x2, x2, #1  91000442
  //   b end        14000003
  // func:
  //   mov x2, #40  d2800502
  //   ret          d65f03c0
  // end:
  s = run({0x94000003, 0x91000442, 0x14000003, 0xd2800502, 0xd65f03c0}, nullptr, "call");
  CHECK_EQ(s.x[2], 41u);
  CHECK_EQ(s.x[30], kCodeBase + 4);

  // cbz / tbnz
  //   cbz x0, +8       b4000040
  //   mov x5, #1       d2800025
  //   tbnz w1, #3, +8  37180041
  //   mov x6, #1       d2800026
  s = run({0xb4000040, 0xd2800025, 0x37180041, 0xd2800026}, [](CpuState& s) { s.x[1] = 8; }, "cbz/tbnz");
  CHECK_EQ(s.x[5], 0u);
  CHECK_EQ(s.x[6], 0u);
}

TEST(translate_simd_moves) {
  alignas(16) static uint8_t mem[64];
  // movi v0.2d, #0; fmov d1, x2; fmov x3, d1; dup v2.16b, w4; mov v3.d[1], x5;
  // str q2, [x6]; ldr q4, [x6]; umov w7, v4.b[3]; mov v5.16b, v4.16b; movi v7.4s, #0xff, lsl #8;
  // fmov s8, w9; mov v9.s[2], w10; smov x11, v9.h[5]
  CpuState s = run({0x6f00e400, 0x9e670041, 0x9e660023, 0x4e010c82, 0x4e181ca3, 0x3d8000c2, 0x3dc000c4,
                    0x0e073c87, 0x4ea41c85, 0x4f0727e7, 0x1e270128, 0x4e141d49, 0x4e162d2b},
                   [&](CpuState& s) {
                     s.v[0] = {1, 2};
                     s.x[2] = 0x1122334455667788ull;
                     s.x[4] = 0x1AB;
                     s.x[5] = 0xDEAD;
                     s.x[6] = reinterpret_cast<uint64_t>(mem);
                     s.x[9] = 0xFFFFFFFF12345678ull;
                     s.v[9] = {0x1111111111111111ull, 0x2222222222222222ull};
                     s.x[10] = 0x8765ABCD;
                   });
  CHECK_EQ(s.v[0].lo, 0u);
  CHECK_EQ(s.v[0].hi, 0u);
  CHECK_EQ(s.v[1].lo, 0x1122334455667788ull);
  CHECK_EQ(s.x[3], 0x1122334455667788ull);
  CHECK_EQ(s.v[2].lo, 0xABABABABABABABABull);
  CHECK_EQ(s.v[2].hi, 0xABABABABABABABABull);
  CHECK_EQ(s.v[3].hi, 0xDEADu);
  CHECK_EQ(s.v[4].hi, 0xABABABABABABABABull);
  CHECK_EQ(s.x[7], 0xABu);
  CHECK_EQ(s.v[5].lo, s.v[4].lo);
  CHECK_EQ(s.v[7].lo, 0x0000FF000000FF00ull);
  CHECK_EQ(s.v[8].lo, 0x12345678u);
  CHECK_EQ(s.v[8].hi, 0u);
  CHECK_EQ(s.v[9].hi, 0x222222228765ABCDull);
  CHECK_EQ(s.x[11], 0xFFFFFFFFFFFF8765ull);
}

TEST(translate_scalar_fp_moves) {
  // fmov d1, d0; mov d2, v1.d[1]; fmov s3, s4 (0x1e204083)
  CpuState s = run({0x1e604001, 0x5e180422, 0x1e204083}, [](CpuState& s) {
    s.v[0] = {0x1111, 0x2222};
    s.v[1] = {0x3333, 0x4444};
    s.v[2] = {0x5555, 0x6666};
    s.v[3] = {0x7777, 0x8888};
    s.v[4] = {0xAAAAAAAABBBBBBBBull, 0x9999};
  });
  CHECK_EQ(s.v[1].lo, 0x1111u);
  CHECK_EQ(s.v[1].hi, 0u);
  CHECK_EQ(s.v[2].lo, 0u);  // v1.d[1] after the first fmov cleared it
  CHECK_EQ(s.v[2].hi, 0u);
  CHECK_EQ(s.v[3].lo, 0xBBBBBBBBu);
  CHECK_EQ(s.v[3].hi, 0u);
}

namespace {

// 128-bit vector register as bytes / lanes, for reference computations.
struct Vec {
  uint8_t b[16];
  static Vec of(const arm64::VReg& r) {
    Vec v;
    std::memcpy(v.b, &r.lo, 8);
    std::memcpy(v.b + 8, &r.hi, 8);
    return v;
  }
  template <typename T>
  T lane(unsigned i) const {
    T x;
    std::memcpy(&x, b + i * sizeof(T), sizeof(T));
    return x;
  }
};

template <typename T>
uint64_t pack(std::initializer_list<T> lanes, unsigned skip = 0) {
  uint8_t bytes[16] = {};
  unsigned i = 0;
  for (T x : lanes) std::memcpy(bytes + (i++) * sizeof(T), &x, sizeof(T));
  uint64_t r;
  std::memcpy(&r, bytes + skip, 8);
  return r;
}

}  // namespace

TEST(translate_neon_integer) {
  alignas(16) static uint8_t src[32];
  alignas(16) static uint8_t dst[32];
  alignas(16) static uint8_t lane_src[4] = {0xA1, 0xB2, 0xC3, 0xD4};
  for (int k = 0; k < 32; ++k) src[k] = static_cast<uint8_t>(k * 37 + 11);
  src[16 + 3] = src[3];
  src[16 + 7] = src[7];
  src[20] = 0x80;  // negative halfword in v1 for cmlt
  src[21] = 0xF0;

  const std::vector<uint32_t> code = {
      0x4cdfa020, 0x6e218c02, 0x4ea1bc03, 0x6e21a404, 0x6e31a805, 0x0f0c8406, 0x0e612827, 0x6e011808,
      0x4e413809, 0x4e81580a, 0x0e20580b, 0x2f0aa40c, 0x4f10a42d, 0x6ea13c0e, 0x6ee11c0f, 0x4c00a042,
      0x0dff2870, 0x4e71b834, 0x6e303815, 0x4e60a836, 0x4e200817,
  };
  const uint64_t base = reinterpret_cast<uint64_t>(src);
  CpuState s = run(code, [&](CpuState& s) {
    std::memset(dst, 0, sizeof(dst));
    s.x[1] = base;
    s.x[2] = reinterpret_cast<uint64_t>(dst);
    s.x[3] = reinterpret_cast<uint64_t>(lane_src);
    s.v[15] = {0x0123456789ABCDEFull, 0xFEDCBA9876543210ull};
    for (int r = 16; r < 20; ++r) s.v[r] = {0x1111111111111111ull * (r - 15), 0x2222222222222222ull};
  });

  Vec v0, v1;
  std::memcpy(v0.b, src, 16);
  std::memcpy(v1.b, src + 16, 16);
  CHECK_EQ(s.x[1], base + 32);  // post-index

  for (unsigned i = 0; i < 16; ++i)  // cmeq
    CHECK_EQ(Vec::of(s.v[2]).b[i], v0.b[i] == v1.b[i] ? 0xFFu : 0u);
  for (unsigned i = 0; i < 4; ++i) {  // addp .4s
    const Vec& src_v = i < 2 ? v0 : v1;
    const unsigned k = (i % 2) * 2;
    CHECK_EQ(Vec::of(s.v[3]).lane<uint32_t>(i), src_v.lane<uint32_t>(k) + src_v.lane<uint32_t>(k + 1));
  }
  for (unsigned i = 0; i < 16; ++i) {  // umaxp .16b
    const Vec& src_v = i < 8 ? v0 : v1;
    const unsigned k = (i % 8) * 2;
    CHECK_EQ(Vec::of(s.v[4]).b[i], std::max(src_v.b[k], src_v.b[k + 1]));
  }
  CHECK_EQ(s.v[5].lo, *std::min_element(v0.b, v0.b + 16));  // uminv
  CHECK_EQ(s.v[5].hi, 0u);
  for (unsigned i = 0; i < 8; ++i)  // shrn .8b, .8h, #4
    CHECK_EQ(Vec::of(s.v[6]).b[i], static_cast<uint8_t>(v0.lane<uint16_t>(i) >> 4));
  CHECK_EQ(s.v[6].hi, 0u);
  for (unsigned i = 0; i < 4; ++i)  // xtn .4h, .4s
    CHECK_EQ(Vec::of(s.v[7]).lane<uint16_t>(i), static_cast<uint16_t>(v1.lane<uint32_t>(i)));
  for (unsigned i = 0; i < 16; ++i)  // ext #3
    CHECK_EQ(Vec::of(s.v[8]).b[i], src[i + 3]);
  for (unsigned k = 0; k < 4; ++k) {  // zip1 .8h
    CHECK_EQ(Vec::of(s.v[9]).lane<uint16_t>(2 * k), v0.lane<uint16_t>(k));
    CHECK_EQ(Vec::of(s.v[9]).lane<uint16_t>(2 * k + 1), v1.lane<uint16_t>(k));
  }
  CHECK_EQ(s.v[10].lo, pack<uint32_t>({v0.lane<uint32_t>(1), v0.lane<uint32_t>(3)}));  // uzp2 .4s
  CHECK_EQ(s.v[10].hi, pack<uint32_t>({v1.lane<uint32_t>(1), v1.lane<uint32_t>(3)}));
  for (unsigned i = 0; i < 8; ++i)  // cnt .8b
    CHECK_EQ(Vec::of(s.v[11]).b[i], static_cast<uint8_t>(std::popcount(v0.b[i])));
  CHECK_EQ(s.v[11].hi, 0u);
  for (unsigned i = 0; i < 8; ++i)  // ushll .8h, .8b, #2
    CHECK_EQ(Vec::of(s.v[12]).lane<uint16_t>(i), static_cast<uint16_t>(v0.b[i] << 2));
  for (unsigned i = 0; i < 4; ++i)  // sshll2 .4s, .8h, #0
    CHECK_EQ(Vec::of(s.v[13]).lane<int32_t>(i), static_cast<int32_t>(v1.lane<int16_t>(4 + i)));
  for (unsigned i = 0; i < 4; ++i)  // cmhs .4s
    CHECK_EQ(Vec::of(s.v[14]).lane<uint32_t>(i), v0.lane<uint32_t>(i) >= v1.lane<uint32_t>(i) ? ~0u : 0u);
  {  // bif: d = (d & m) | (n & ~m)
    uint64_t m_lo, m_hi, n_lo, n_hi;
    std::memcpy(&n_lo, v0.b, 8);
    std::memcpy(&n_hi, v0.b + 8, 8);
    std::memcpy(&m_lo, v1.b, 8);
    std::memcpy(&m_hi, v1.b + 8, 8);
    CHECK_EQ(s.v[15].lo, (0x0123456789ABCDEFull & m_lo) | (n_lo & ~m_lo));
    CHECK_EQ(s.v[15].hi, (0xFEDCBA9876543210ull & m_hi) | (n_hi & ~m_hi));
  }
  CHECK(std::memcmp(dst, &s.v[2], 16) == 0);  // st1 {v2, v3}
  CHECK(std::memcmp(dst + 16, &s.v[3], 16) == 0);
  for (int r = 0; r < 4; ++r) {  // ld4 {v16-v19}.b[2]
    uint64_t expect = 0x1111111111111111ull * (r + 1);
    expect = (expect & ~0xFF0000ull) | (uint64_t{lane_src[r]} << 16);
    CHECK_EQ(s.v[16 + r].lo, expect);
    CHECK_EQ(s.v[16 + r].hi, 0x2222222222222222ull);
  }
  CHECK_EQ(s.x[3], reinterpret_cast<uint64_t>(lane_src) + 4);
  {
    uint16_t sum16 = 0;
    for (unsigned i = 0; i < 8; ++i) sum16 = static_cast<uint16_t>(sum16 + v1.lane<uint16_t>(i));
    CHECK_EQ(s.v[20].lo, sum16);  // addv h20
    unsigned sum8 = 0;
    for (unsigned i = 0; i < 16; ++i) sum8 += v0.b[i];
    CHECK_EQ(s.v[21].lo, sum8);  // uaddlv h21
  }
  for (unsigned i = 0; i < 8; ++i)  // cmlt .8h, #0
    CHECK_EQ(Vec::of(s.v[22]).lane<uint16_t>(i), v1.lane<int16_t>(i) < 0 ? 0xFFFFu : 0u);
  {
    uint64_t lo, hi;  // rev64 .16b
    std::memcpy(&lo, v0.b, 8);
    std::memcpy(&hi, v0.b + 8, 8);
    CHECK_EQ(s.v[23].lo, std::byteswap(lo));
    CHECK_EQ(s.v[23].hi, std::byteswap(hi));
  }
}

TEST(translate_floating_point) {
  auto d = [](double v) { return std::bit_cast<uint64_t>(v); };
  auto f = [](float v) { return uint64_t{std::bit_cast<uint32_t>(v)}; };
  const std::vector<uint32_t> code = {
      0x1e622820, 0x1e250883, 0x1e621826, 0x1f422027, 0x1f62a029, 0x1e622020, 0x9e7800ca, 0x9e62018b,
      0x1e64c0cd, 0x1e6e900e, 0x1e22c08f, 0x1e62cc30, 0x1e61c051, 0x1e744a72, 0x1e767a75, 0x1e390097,
      0x1e230338, 0x1e61403a, 0x1e20c39b, 0x1e202088, 0x1e620424, 0x9e6400dd,
  };
  CpuState s = run(code, [&](CpuState& s) {
    s.v[1] = {d(2.5), 0xAAAA};
    s.v[2] = {d(-0.75), 0xAAAA};
    s.v[4] = {f(1.5f), 0};
    s.v[5] = {f(-2.0f), 0};
    s.v[8] = {d(10.0), 0};
    s.v[19] = {d(1.0), 0};
    s.v[20] = {d(3.0), 0};
    s.v[22] = {0x7FF8000000000123ull, 0};  // quiet NaN
    s.v[28] = {f(-4.5f), 0};
    s.x[12] = static_cast<uint64_t>(-7);
    s.x[25] = 3000000000u;
  });
  CHECK_EQ(s.v[0].lo, d(1.75));                      // fadd
  CHECK_EQ(s.v[0].hi, 0u);                           // scalar writes clear the upper half
  CHECK_EQ(s.v[3].lo, f(-3.0f));                     // fmul (single)
  CHECK_EQ(s.v[6].lo, d(2.5 / -0.75));               // fdiv
  CHECK_EQ(s.v[7].lo, d(8.125));                     // fmadd
  CHECK_EQ(s.v[9].lo, d(-11.875));                   // fnmsub: n*m - a
  CHECK_EQ(s.x[10], static_cast<uint64_t>(-3));      // fcvtzs
  CHECK_EQ(s.v[11].lo, d(-7.0));                     // scvtf
  CHECK_EQ(s.v[13].lo, d(-3.0));                     // frintp
  CHECK_EQ(s.v[14].lo, d(1.25));                     // fmov #imm
  CHECK_EQ(s.v[15].lo, d(1.5));                      // fcvt d, s
  CHECK_EQ(s.v[16].lo, d(2.5));                      // fcsel gt (after fcmp d1, d2)
  CHECK_EQ(s.v[17].lo, 0x7FF8000000000000ull);       // fsqrt(-0.75): Arm default NaN
  CHECK_EQ(s.v[18].lo, d(3.0));                      // fmax
  CHECK_EQ(s.v[21].lo, d(1.0));                      // fminnm with a quiet NaN
  CHECK_EQ(s.x[23], 1u);                             // fcvtzu w, s
  CHECK_EQ(s.v[24].lo, f(3000000000.0f));            // ucvtf s, w
  CHECK_EQ(s.v[26].lo, d(-2.5));                     // fneg
  CHECK_EQ(s.v[27].lo, f(4.5f));                     // fabs (single)
  CHECK_EQ(s.nzcv, 0x40000000u);                     // fccmp eq failed after fcmp s4, #0 -> #4
  CHECK_EQ(s.x[29], static_cast<uint64_t>(-3));      // fcvtas
}

TEST(ir_fp_semantics) {
  auto eval = [](ir::Opcode op, uint8_t size, uint64_t a, uint64_t b = 0, uint64_t c = 0, uint8_t aux = 0) {
    ir::Inst in;
    in.op = op;
    in.size = size;
    in.aux = aux;
    return ir::evaluate(in, a, b, c);
  };
  auto d = [](double v) { return std::bit_cast<uint64_t>(v); };
  const uint8_t fcvtzs64 = static_cast<uint8_t>(ir::FpRound::Zero) | 8 | 16;
  CHECK_EQ(eval(ir::Opcode::FToInt, 8, d(1e300), 0, 0, fcvtzs64), 0x7FFFFFFFFFFFFFFFull);    // saturates
  CHECK_EQ(eval(ir::Opcode::FToInt, 8, d(-1e300), 0, 0, fcvtzs64), 0x8000000000000000ull);
  CHECK_EQ(eval(ir::Opcode::FToInt, 8, 0x7FF8000000000000ull, 0, 0, fcvtzs64), 0u);          // NaN -> 0
  CHECK_EQ(eval(ir::Opcode::FToInt, 4, d(-5.0), 0, 0, static_cast<uint8_t>(ir::FpRound::Zero) | 16), 0u);
  CHECK_EQ(eval(ir::Opcode::FMax, 8, d(-0.0), d(0.0)), d(0.0));
  CHECK_EQ(eval(ir::Opcode::FMin, 8, d(0.0), d(-0.0)), d(-0.0));
  CHECK_EQ(eval(ir::Opcode::FAdd, 8, 0x7FF0000000000001ull, d(1.0)), 0x7FF8000000000001ull);  // SNaN quieted
  CHECK_EQ(eval(ir::Opcode::FCmp, 8, 0x7FF8000000000000ull, d(1.0)), ir::kFlagC | ir::kFlagV);
  CHECK_EQ(eval(ir::Opcode::FRint, 8, d(2.5), 0, 0, static_cast<uint8_t>(ir::FpRound::NearestEven)), d(2.0));
  CHECK_EQ(eval(ir::Opcode::FRint, 8, d(2.5), 0, 0, static_cast<uint8_t>(ir::FpRound::NearestAway)), d(3.0));
}

TEST(translate_atomics) {
  alignas(16) static uint64_t cell[2];
  // ldxr x0, [x1]; stxr w2, x3, [x1]; ldadd x4, x5, [x1]; cas x6, x7, [x1]; swp w8, w9, [x1]
  CpuState s = run({0xc85f7c20, 0xc8027c23, 0xf8240025, 0xc8a67c27, 0xb8288029}, [&](CpuState& s) {
    cell[0] = 100;
    s.x[1] = reinterpret_cast<uint64_t>(cell);
    s.x[2] = 99;
    s.x[3] = 200;
    s.x[4] = 5;
    s.x[6] = 205;  // matches -> store x7
    s.x[7] = 0x1234567890ull;
    s.x[8] = 0xAAAA;
  });
  CHECK_EQ(s.x[0], 100u);
  CHECK_EQ(s.x[2], 0u);  // store-exclusive succeeded
  CHECK_EQ(s.x[5], 200u);
  CHECK_EQ(s.x[6], 205u);
  CHECK_EQ(s.x[9], 0x34567890u);
  CHECK_EQ(cell[0], 0x120000AAAAull);
}

TEST(translate_casp) {
  alignas(16) static uint64_t pair[2];
  // caspal x2, x3, x4, x5, [x0]: matches -> stores x4:x5, x2:x3 keep the old value
  CpuState s = run({0x4862FC04}, [&](CpuState& s) {
    pair[0] = 10;
    pair[1] = 20;
    s.x[0] = reinterpret_cast<uint64_t>(pair);
    s.x[2] = 10;
    s.x[3] = 20;
    s.x[4] = 111;
    s.x[5] = 222;
  });
  CHECK_EQ(pair[0], 111u);
  CHECK_EQ(pair[1], 222u);
  CHECK_EQ(s.x[2], 10u);
  CHECK_EQ(s.x[3], 20u);
  // no match: memory unchanged, x2:x3 receive its value
  s = run({0x4862FC04}, [&](CpuState& s) {
    s.x[0] = reinterpret_cast<uint64_t>(pair);
    s.x[2] = 1;
    s.x[3] = 2;
    s.x[4] = 3;
    s.x[5] = 4;
  });
  CHECK_EQ(pair[0], 111u);
  CHECK_EQ(pair[1], 222u);
  CHECK_EQ(s.x[2], 111u);
  CHECK_EQ(s.x[3], 222u);

  alignas(8) static uint32_t words[2];
  // casp w6, w7, w8, w9, [x1]
  s = run({0x08267C28}, [&](CpuState& s) {
    words[0] = 0x11;
    words[1] = 0x22;
    s.x[1] = reinterpret_cast<uint64_t>(words);
    s.x[6] = 0x11;
    s.x[7] = 0x22;
    s.x[8] = 0x33;
    s.x[9] = 0x44;
  });
  CHECK_EQ(words[0], 0x33u);
  CHECK_EQ(words[1], 0x44u);
  CHECK_EQ(s.x[6], 0x11u);
  CHECK_EQ(s.x[7], 0x22u);
}

TEST(translate_system_registers) {
  // msr nzcv, x1; mrs x0, nzcv; msr tpidr_el0, x2; mrs x3, tpidr_el0
  CpuState s = run({0xd51b4201, 0xd53b4200, 0xd51bd042, 0xd53bd043}, [](CpuState& s) {
    s.x[1] = 0xF0000000FFFFFFFFull;
    s.x[2] = 0x7777;
  });
  CHECK_EQ(s.x[0], 0xF0000000u);
  CHECK_EQ(s.nzcv, 0xF0000000u);
  CHECK_EQ(s.x[3], 0x7777u);
  CHECK_EQ(s.tpidr_el0, 0x7777u);
}

TEST(translate_exits) {
  {
    TestEnv env({0xd4000021 /* svc #1 */});
    runtime::Engine engine(env);
    CpuState s{};
    s.pc = kCodeBase;
    engine.run(s);
    CHECK(env.last_exit == arm64::ExitReason::Svc);
    CHECK_EQ(s.pc, kCodeBase + 4);
  }
  {
    TestEnv env({0xd503201f /* nop */, 0x00000000 /* udf */});
    runtime::Engine engine(env);
    CpuState s{};
    s.pc = kCodeBase;
    engine.run(s);
    CHECK(env.last_exit == arm64::ExitReason::Undefined);
    CHECK_EQ(s.pc, kCodeBase + 4);
  }
  {
    TestEnv env({0x14000100 /* b far away */});
    runtime::Engine engine(env);
    CpuState s{};
    s.pc = kCodeBase;
    engine.run(s);
    CHECK(env.last_exit == arm64::ExitReason::FetchFault);
    CHECK_EQ(s.pc, kCodeBase + 0x400);
  }
}

// Random data-processing instructions: the optimized JIT, unoptimized JIT and
// interpreter must agree on every one of them.
TEST(translate_random_data_processing) {
  std::mt19937_64 rng(42);
  int tested = 0;
  for (int attempt = 0; attempt < 400000 && tested < 3000; ++attempt) {
    uint32_t word = static_cast<uint32_t>(rng());
    // Steer towards the data-processing encoding space.
    if (rng() & 1) word = (word & ~(0x7u << 26)) | (0x4u << 26);  // data processing (immediate)
    else word = (word & ~(0x7u << 25)) | (0x5u << 25);              // data processing (register)
    arm64::Instruction insn = arm64::decode(word, kCodeBase);
    using arm64::Op;
    if (insn.op == Op::Invalid || insn.op == Op::Unsupported || arm64::is_block_terminator(insn)) continue;
    switch (insn.op) {
      case Op::Ldr: case Op::Str: case Op::Ldp: case Op::Stp: case Op::Ldxr: case Op::Stxr: case Op::Ldxp:
      case Op::Stxp: case Op::Cas: case Op::Swp: case Op::Ldadd: case Op::Ldclr: case Op::Ldeor: case Op::Ldset:
      case Op::Ldsmax: case Op::Ldsmin: case Op::Ldumax: case Op::Ldumin: case Op::Mrs: case Op::Msr:
        continue;
      default:
        break;
    }
    uint64_t seed = rng();
    run({word},
        [seed](CpuState& s) {
          std::mt19937_64 r(seed);
          for (auto& x : s.x) {
            switch (r() % 4) {
              case 0: x = r() & 0xFF; break;
              case 1: x = static_cast<uint64_t>(static_cast<int64_t>(static_cast<int32_t>(r()))); break;
              default: x = r(); break;
            }
          }
          s.x[18] = 0;
          s.sp = r() & ~uint64_t{15};
          s.nzcv = (r() & 0xF) << 28;
          for (auto& v : s.v) v = {r(), r()};
        },
        arm64::disassemble(insn).c_str());
    ++tested;
  }
  CHECK(tested > 1000);
}
