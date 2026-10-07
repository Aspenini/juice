#include <cstdint>

#include "core/arm64/decode/instruction.hpp"
#include "test.hpp"

using namespace juice::arm64;

namespace {

// Encodings produced by the LLVM assembler (see the comments).
struct Sample {
  uint32_t word;
  const char* text;
};

constexpr Sample kSupported[] = {
    {0x8b020020, "add x0, x1, x2"},         {0x2b020020, "adds w0, w1, w2"},
    {0xeb020020, "subs x0, x1, x2"},        {0xd2a24680, "movz x0, #0x1234, lsl #16"},
    {0xf28acf00, "movk x0, #0x5678"},       {0x12800000, "movn w0, #0"},
    {0x92089c20, "and x0, x1, #0xff00.."},  {0xd3442c20, "ubfx x0, x1, #4, #8"},
    {0x93442c20, "sbfx x0, x1, #4, #8"},    {0xb3783c20, "bfi x0, x1, #8, #16"},
    {0x33042c20, "bfxil w0, w1, #4, #8"},   {0xd37df020, "lsl x0, x1, #3"},
    {0x13037c20, "asr w0, w1, #3"},         {0x93401c20, "sxtb x0, w1"},
    {0x53003c20, "uxth w0, w1"},            {0xeb02003f, "cmp x1, x2"},
    {0x9a82b020, "csel x0, x1, x2, lt"},    {0x1a9f17e0, "cset w0, eq"},
    {0xda9f93e0, "csetm x0, hi"},           {0xda815420, "cneg x0, x1, mi"},
    {0xfa421024, "ccmp x1, x2, #4, ne"},    {0x9b027c20, "mul x0, x1, x2"},
    {0x9b020c20, "madd x0, x1, x2, x3"},    {0x1b028c20, "msub w0, w1, w2, w3"},
    {0x9bc27c20, "umulh x0, x1, x2"},       {0x9b427c20, "smulh x0, x1, x2"},
    {0x9ac20820, "udiv x0, x1, x2"},        {0x9ac20c20, "sdiv x0, x1, x2"},
    {0xdac01020, "clz x0, x1"},             {0x5ac00020, "rbit w0, w1"},
    {0xdac00c20, "rev x0, x1"},             {0x5ac00420, "rev16 w0, w1"},
    {0xdac00820, "rev32 x0, x1"},           {0xdac01420, "cls x0, x1"},
    {0x93c23020, "extr x0, x1, x2, #12"},   {0x13811420, "ror w0, w1, #5"},
    {0xba020020, "adcs x0, x1, x2"},        {0x7a020020, "sbcs w0, w1, w2"},
    {0xf8408c20, "ldr x0, [x1, #8]!"},      {0xb81fc422, "str w2, [x1], #-4"},
    {0xa9411023, "ldp x3, x4, [x1, #16]"},  {0xa9bf13e3, "stp x3, x4, [sp, #-16]!"},
    {0x39800420, "ldrsb x0, [x1, #1]"},     {0x79c00420, "ldrsh w0, [x1, #2]"},
    {0xb8a27820, "ldrsw x0, [x1, x2, lsl #2]"},
    {0xb862d820, "ldr w0, [x1, w2, sxtw #2]"},
    {0x39400c20, "ldrb w0, [x1, #3]"},      {0x79000c22, "strh w2, [x1, #6]"},
    {0xf85fd020, "ldur x0, [x1, #-3]"},     {0x6f00e400, "movi v0.2d, #0"},
    {0x9e670041, "fmov d1, x2"},            {0x9e660023, "fmov x3, d1"},
    {0x4e010c82, "dup v2.16b, w4"},         {0x4e181ca3, "mov v3.d[1], x5"},
    {0x3d8000c2, "str q2, [x6]"},           {0x3dc000c4, "ldr q4, [x6]"},
    {0x0e073c87, "umov w7, v4.b[3]"},       {0x4ea41c85, "mov v5.16b, v4.16b"},
    {0x6e261cc6, "eor v6.16b, v6.16b, v6.16b"},
    {0x4f0727e7, "movi v7.4s, #0xff, lsl #8"},
    {0x1e270128, "fmov s8, w9"},            {0x4e141d49, "mov v9.s[2], w10"},
    {0x4e162d2b, "smov x11, v9.h[5]"},      {0xc85f7c20, "ldxr x0, [x1]"},
    {0xc8027c23, "stxr w2, x3, [x1]"},      {0xf8220020, "ldadd x2, x0, [x1]"},
    {0xc8a27c23, "cas x2, x3, [x1]"},       {0xb8228020, "swp w2, w0, [x1]"},
    {0x885ffc20, "ldaxr w0, [x1]"},         {0xc89ffc23, "stlr x3, [x1]"},
    {0xd53b4200, "mrs x0, nzcv"},           {0xd51b4201, "msr nzcv, x1"},
    {0xd51bd042, "msr tpidr_el0, x2"},      {0xd53bd043, "mrs x3, tpidr_el0"},
    {0xb4000040, "cbz x0, .+8"},            {0x35ffffe0, "cbnz w0, .-4"},
    {0xb6400060, "tbz x0, #40, .+12"},      {0x37180080, "tbnz w0, #3, .+16"},
    {0x54ffffc1, "b.ne .-8"},               {0x94000040, "bl .+0x100"},
    {0xd65f03c0, "ret"},                    {0xd61f0200, "br x16"},
    {0xd63f0100, "blr x8"},                 {0x14001000, "b .+0x4000"},
    {0x90028a80, "adrp x0, .+0x5000"},      {0x10000081, "adr x1, .+0x10"},
    {0xd4000021, "svc #1"},                 {0xd43e0060, "brk #0xf003"},
    {0xd503201f, "nop"},                    {0x58000100, "ldr x0, .+0x20"},
    {0x910043ff, "add sp, sp, #0x10"},      {0xd14083e0, "sub x0, sp, #0x20, lsl #12"},
    {0x8b224820, "add x0, x1, w2, uxtw #2"},{0xcb820c20, "sub x0, x1, x2, asr #3"},
    {0xaa220020, "orn x0, x1, x2"},         {0x6a220820, "bics w0, w1, w2, lsl #2"},
    {0xcae21c20, "eon x0, x1, x2, ror #7"}, {0x1ac22020, "lsl w0, w1, w2"},
    {0x9ac22820, "asr x0, x1, x2"},         {0x9ac22c20, "ror x0, x1, x2"},
    {0x9ba20c20, "umaddl x0, w1, w2, x3"},  {0x9b228c20, "smsubl x0, w1, w2, x3"},
    {0x3a45a822, "ccmn w1, #5, #2, ge"},    {0x5a82d020, "csinv w0, w1, w2, le"},
    {0x69410440, "ldpsw x0, x1, [x2, #8]"}, {0xadff0440, "ldp q0, q1, [x2, #-32]!"},
    {0x6c810440, "stp d0, d1, [x2], #16"},  {0xf9800000, "prfm pldl1keep, [x0]"},
    {0xd5033bbf, "dmb ish"},                {0xd503233f, "paciasp"},
    {0xc8dffc20, "ldar x0, [x1]"},
    {0x1e604001, "fmov d1, d0"},            {0x5e180422, "mov d2, v1.d[1]"},
    // optional extensions
    {0x1ac34041, "crc32b w1, w2, w3"},      {0x9ac35c41, "crc32cx w1, w2, x3"},
    {0x4e284841, "aese v1.16b, v2.16b"},    {0x4e287841, "aesimc v1.16b, v2.16b"},
    {0x5e030041, "sha1c q1, s2, v3.4s"},    {0x5e033041, "sha1su0 v1.4s, v2.4s, v3.4s"},
    {0x5e280841, "sha1h s1, s2"},           {0x5e282841, "sha256su0 v1.4s, v2.4s"},
    {0x5e035041, "sha256h2 q1, q2, v3.4s"}, {0xce638041, "sha512h q1, q2, v3.2d"},
    {0xce638841, "sha512su1 v1.2d, v2.2d, v3.2d"}, {0xcec08041, "sha512su0 v1.2d, v2.2d"},
    {0xce031041, "eor3 v1.16b, v2.16b, v3.16b, v4.16b"}, {0xce231041, "bcax v1.16b, v2.16b, v3.16b, v4.16b"},
    {0xce638c41, "rax1 v1.2d, v2.2d, v3.2d"}, {0xce831441, "xar v1.2d, v2.2d, v3.2d, #5"},
    {0x0ee3e041, "pmull v1.1q, v2.1d, v3.1d"}, {0x4ee3e041, "pmull2 v1.1q, v2.2d, v3.2d"},
    {0xce431041, "sm3ss1 v1.4s, v2.4s, v3.4s, v4.4s"}, {0xce439041, "sm3tt1a v1.4s, v2.4s, v3.s[1]"},
    {0xce63c441, "sm3partw2 v1.4s, v2.4s, v3.4s"}, {0xcec08441, "sm4e v1.4s, v2.4s"},
    {0x4e839441, "sdot v1.4s, v2.16b, v3.16b"}, {0x4fa3e041, "sdot v1.4s, v2.16b, v3.4b[1]"},
    {0x4f03f841, "sudot v1.4s, v2.16b, v3.4b[2]"}, {0x4e83a441, "smmla v1.4s, v2.16b, v3.16b"},
    {0x6e438441, "sqrdmlah v1.8h, v2.8h, v3.8h"}, {0x7fa3d841, "sqrdmlah s1, s2, v3.s[3]"},
    {0x6e43fc41, "bfdot v1.4s, v2.8h, v3.8h"}, {0x6e43ec41, "bfmmla v1.4s, v2.8h, v3.8h"},
    {0x0ff3f841, "bfmlalb v1.4s, v2.8h, v3.h[7]"}, {0x1e634041, "bfcvt h1, s2"},
    {0x4ea16841, "bfcvtn2 v1.8h, v2.4s"},  {0x6ec3dc41, "fcmla v1.2d, v2.2d, v3.2d, #270"},
    {0x6f633841, "fcmla v1.8h, v2.8h, v3.h[3], #90"}, {0x6ec3f441, "fcadd v1.2d, v2.2d, v3.2d, #270"},
    {0x4e23ec41, "fmlal v1.4s, v2.4h, v3.4h"}, {0x4fb30041, "fmlal v1.4s, v2.4h, v3.h[3]"},
    {0x1e7e0041, "fjcvtzs w1, d2"},         {0x1e68c041, "frint32x d1, d2"},
    {0x6e61f841, "frint64x v1.2d, v2.2d"},  {0xd500401f, "cfinv"},
    {0xba018425, "rmif x1, #3, #5"},        {0x3a00482d, "setf16 w1"},
    {0x1ee32841, "fadd h1, h2, h3"},        {0x1fe39041, "fnmsub h1, h2, h3, h4"},
    {0x1ee24041, "fcvt s1, h2"},            {0x1e63c041, "fcvt h1, d2"},
    {0x9ee60041, "fmov x1, h2"},            {0x9ec2ec41, "scvtf h1, x2, #5"},
    {0x4e431441, "fadd v1.8h, v2.8h, v3.8h"}, {0x7ec31441, "fabd h1, h2, h3"},
    {0x4ef9b841, "fcvtzs v1.8h, v2.8h"},    {0x7ef9d841, "frsqrte h1, h2"},
    {0x4f331841, "fmla v1.8h, v2.8h, v3.h[7]"}, {0x4e30c841, "fmaxnmv h1, v2.8h"},
    {0x5e30d841, "faddp h1, v2.2h"},        {0x4f00fc01, "fmov v1.8h, #2.0"},
    {0x4f1cfc41, "fcvtzs v1.8h, v2.8h, #4"},
    {0x19221061, "ldclrp x1, x2, [x3]"},    {0x19e28061, "swppal x1, x2, [x3]"},
    {0x19010440, "cpyfp [x0]!, [x1]!, x2!"}, {0x1d810440, "cpye [x0]!, [x1]!, x2!"},
    {0x19c24420, "setm [x0]!, x1!, x2"},    {0xdac02041, "abs x1, x2"},
    {0x5ac01841, "ctz w1, w2"},             {0x9ac36041, "smax x1, x2, x3"},
    {0x91c3ec41, "smax x1, x2, #-5"},       {0xf8ffec20, "ldrab x0, [x1, #-16]!"},
    {0xdac10041, "pacia x1, x2"},           {0x9ac33041, "pacga x1, x2, x3"},
    {0xd9421861, "ldiapp x1, x2, [x3]"},    {0xd9c00841, "ldapr x1, [x2], #8"},
    {0x1dc04841, "ldapur q1, [x2, #4]"},    {0x4d418441, "ldap1 {v1.d}[1], [x2]"},
    {0xd5031001, "wfet x1"},                {0xf5058105, "cbgt x5, #11, .+0x20"},
    {0x74c28041, "cbbeq w1, w2, .+8"},      {0x9a032fe1, "addpt x1, sp, x3, lsl #3"},
    {0x9b639041, "msubpt x1, x2, x3, x4"},  {0xe8ff0861, "ldtp x1, x2, [x3], #-16"},
    {0xed400861, "ldtp q1, q2, [x3]"},      {0xc95f7c41, "ldtxr x1, [x2]"},
    {0xc9c1fc62, "casalt x1, x2, [x3]"},    {0x49827cc4, "caspt x2, x3, x4, x5, [x6]"},
    {0x59210462, "ldtadd x1, x2, [x3]"},    {0xd9427861, "ldapp x1, x2, [x3]"},
    {0x5500005f, "retaasppc .-8"},          {0xd65f0fe1, "retabsppcr x1"},
    {0xf380005f, "autiasppc .-8"},          {0xdac1903e, "autiasppcr x1"},
    {0x1eea0041, "fcvtns s1, h2"},          {0x9e3c0041, "scvtf s1, d2"},
    {0x4ea3dc41, "famax v1.4s, v2.4s, v3.4s"}, {0x6ec31c41, "famin v1.8h, v2.8h, v3.8h"},
    {0x5ebcd1cd, "sqdmull d13, s14, s28"},  {0x4e603996, "suqadd v22.8h, v12.8h"},
    {0x2ea1ca2c, "ursqrte v12.2s, v17.2s"}, {0xd53be021, "mrs x1, cntpct_el0"},
    {0xd53b2401, "mrs x1, rndr"},           {0xd51b42a1, "msr dit, x1"},
};

}  // namespace

TEST(decoder_accepts_common_instructions) {
  for (const Sample& s : kSupported) {
    Instruction i = decode(s.word, 0x1000);
    if (i.op == Op::Invalid || i.op == Op::Unsupported)
      juice::test::fail(__FILE__, __LINE__, std::format("{:08x} ({}) decoded as {}", s.word, s.text, mnemonic(i.op)));
    // The disassembler must handle everything the decoder produces.
    CHECK(!disassemble(i).empty());
  }
}

TEST(decoder_add_sub) {
  Instruction i = decode(0x8b020020, 0);
  CHECK(i.op == Op::AddShift);
  CHECK_EQ(i.rd, 0);
  CHECK_EQ(i.rn, 1);
  CHECK_EQ(i.rm, 2);
  CHECK(i.sf);
  CHECK(!i.set_flags);

  i = decode(0xd14083e0, 0);  // sub x0, sp, #0x20, lsl #12
  CHECK(i.op == Op::SubImm);
  CHECK_EQ(i.imm, 0x20000);
  CHECK_EQ(i.rn, 31);

  i = decode(0x8b224820, 0);  // add x0, x1, w2, uxtw #2
  CHECK(i.op == Op::AddExt);
  CHECK_EQ(i.shift, static_cast<uint8_t>(Extend::Uxtw));
  CHECK_EQ(i.amount, 2);
}

TEST(decoder_logical_immediate) {
  Instruction i = decode(0x92089c20, 0);
  CHECK(i.op == Op::AndImm);
  CHECK_EQ(static_cast<uint64_t>(i.imm), 0xff00ff00ff00ff00ull);

  uint64_t v = 0;
  CHECK(decode_logical_immediate(true, 1, 0, 0, v));  // 0x1
  CHECK_EQ(v, 1u);
  CHECK(decode_logical_immediate(false, 0, 0, 0b111100, v));  // 0x55555555
  CHECK_EQ(v, 0x55555555u);
  CHECK(!decode_logical_immediate(true, 1, 0, 0b111111, v));  // all ones: reserved
  CHECK(!decode_logical_immediate(false, 1, 0, 0, v));        // N=1 with 32-bit
}

TEST(decoder_branch_targets) {
  CHECK_EQ(static_cast<uint64_t>(decode(0x94000040, 0x1000).imm), 0x1100u);   // bl .+0x100
  CHECK_EQ(static_cast<uint64_t>(decode(0x54ffffc1, 0x1000).imm), 0xff8u);    // b.ne .-8
  CHECK_EQ(decode(0x54ffffc1, 0x1000).cond, 1);
  CHECK_EQ(static_cast<uint64_t>(decode(0x35ffffe0, 0x1000).imm), 0xffcu);    // cbnz .-4
  Instruction tbz = decode(0xb6400060, 0x1000);
  CHECK(tbz.op == Op::Tbz);
  CHECK_EQ(tbz.amount, 40);
  CHECK_EQ(static_cast<uint64_t>(tbz.imm), 0x100cu);
  CHECK_EQ(static_cast<uint64_t>(decode(0x90028a80, 0x1234).imm), 0x5151000u);  // adrp
  CHECK_EQ(static_cast<uint64_t>(decode(0x10000081, 0x1000).imm), 0x1010u);     // adr
  CHECK_EQ(static_cast<uint64_t>(decode(0x58000100, 0x1000).imm), 0x1020u);     // ldr literal
}

TEST(decoder_loads_stores) {
  Instruction i = decode(0xf8408c20, 0);  // ldr x0, [x1, #8]!
  CHECK(i.op == Op::Ldr);
  CHECK(i.mode == AddrMode::PreIndex);
  CHECK_EQ(i.imm, 8);
  CHECK_EQ(i.mem_size, 8);

  i = decode(0xb81fc422, 0);  // str w2, [x1], #-4
  CHECK(i.op == Op::Str);
  CHECK(i.mode == AddrMode::PostIndex);
  CHECK_EQ(i.imm, -4);

  i = decode(0x79c00420, 0);  // ldrsh w0, [x1, #2]
  CHECK(i.mem_signed);
  CHECK(!i.mem_to_64);
  CHECK_EQ(i.mem_size, 2);
  CHECK_EQ(i.imm, 2);

  i = decode(0xadff0440, 0);  // ldp q0, q1, [x2, #-32]!
  CHECK(i.op == Op::Ldp);
  CHECK(i.vector);
  CHECK_EQ(i.mem_size, 16);
  CHECK_EQ(i.imm, -32);

  i = decode(0xb862d820, 0);  // ldr w0, [x1, w2, sxtw #2]
  CHECK(i.mode == AddrMode::RegOffset);
  CHECK_EQ(i.shift, static_cast<uint8_t>(Extend::Sxtw));
  CHECK_EQ(i.amount, 2);

  CHECK(decode(0xd50b7420, 0).op == Op::DcZva);  // dc zva
  CHECK(decode(0xd50b7520, 0).op == Op::IcIvau);  // ic ivau, x0
  CHECK(decode(0xd50b7b20, 0).op == Op::Nop);     // dc cvau, x0
}

TEST(decoder_simd_immediates) {
  CHECK_EQ(expand_simd_immediate(0, 0b0010, 0xff), 0x0000ff000000ff00ull);
  CHECK_EQ(expand_simd_immediate(1, 0b1110, 0b10000001), 0xff000000000000ffull);
  CHECK_EQ(expand_simd_immediate(0, 0b1110, 0x2a), 0x2a2a2a2a2a2a2a2aull);
  CHECK_EQ(expand_simd_immediate(1, 0b1111, 0x70), 0x3ff0000000000000ull);  // fmov #1.0 (double)
}

TEST(decoder_rejects_garbage) {
  CHECK(decode(0x00000000, 0).op == Op::Udf);
  CHECK(decode(0xffffffff, 0).op == Op::Invalid || decode(0xffffffff, 0).op == Op::Unsupported);
}
