#pragma once

// JUICE intermediate representation.
//
// A Block is a straight-line list of instructions in SSA form (each Inst
// defines the value whose id is its index) followed by one Terminator.
//
// The IR is independent of the guest ISA: guest state is an array of 64-bit
// "slots" accessed by GetReg/SetReg, and guest memory is accessed through
// host pointers (the guest shares the host address space).
//
// Width rules: ALU ops carry a size of 4 or 8 bytes. A 4-byte op only looks at
// the low 32 bits of its operands and always produces a zero-extended result.

#include <array>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace juice::ir {

using ValueId = uint32_t;
inline constexpr ValueId kNoValue = 0xFFFF'FFFFu;

enum class Opcode : uint8_t {
  Nop,
  Const,           // imm
  GetReg,          // imm = slot                                     -> value
  SetReg,          // imm = slot, a = value
  Load,            // a = address; size = 1/2/4/8; aux = sign-extend  -> 64-bit value
  Store,           // a = address, b = value; size = 1/2/4/8
  LoadToState,     // a = address; copy `size` bytes into slots starting at imm, zero-fill to aux bytes
  StoreFromState,  // a = address; copy `size` bytes from slots starting at imm to memory

  Add, Sub, Mul, UMulH, SMulH, UDiv, SDiv,
  And, Or, Xor, Shl, LShr, AShr, Ror,
  Not, Neg, Clz, Bswap,
  SExt,            // aux = source bit width (8, 16, 32)
  ZExt,            // aux = source bit width (8, 16, 32)
  Cmp,             // aux = Predicate                                -> 0 / 1
  Select,          // a ? b : c
  Adc,             // a + b + C(c), c = packed flags
  Sbc,             // a - b - !C(c)
  FlagsAdd,        // packed NZCV of a + b
  FlagsSub,        // packed NZCV of a - b
  FlagsAdc,        // packed NZCV of a + b + C(c)
  FlagsSbc,        // packed NZCV of a - b - !C(c)
  FlagsLogic,      // packed NZCV for a logical result a (C = V = 0)
  CondHolds,       // aux = condition code, a = packed flags          -> 0 / 1

  // --- Memory ordering and atomics (side effects; see atomics.cpp) -------------
  StateAddr,       // imm = slot                                     -> host address of that state slot
  Fence,           // full memory barrier
  AtomicRmw,       // a = address, b = operand; size = 1/2/4/8; aux = AtomicOp -> old value (zero-extended)
  AtomicCas,       // a = address, b = expected, c = desired; size    -> old value (zero-extended)
  Counter,         // the virtual counter (CNTVCT_EL0): nanoseconds of a monotonic clock; aux = 1: a
                   //   random number instead (RNDR)
  AtomicCasPair,   // a = address, b = pointer to {expected lo, hi, desired lo, hi}
                   //   (128-bit compare-and-swap)                    -> 0 if swapped, 1 if not
  AtomicRmwPair,   // a = address, b = pointer to the 128-bit operand {lo, hi}, which receives the
                   //   old value; aux = AtomicOp (Clr, Set or Swap)
  MemOp,           // a = destination, b = source (or the byte value), c = byte count; aux =
                   //   0 memmove, 1 forward byte-by-byte copy, 2 memset

  // --- Operations on 128-bit values held in pairs of state slots (lo, hi) ---------
  StateOp,         // imm = StateOpKind | d << 8 | n << 16 | m << 24, the first slots of the
                   //   destination and source pairs; aux as the kind describes. Reads and
                   //   writes guest state directly (see state_ops.cpp)

  // --- Vector lane operations on 64-bit vector halves --------------------------
  // Low nibble of aux = element size in bytes (1, 2, 4, 8). size is always 8.
  VAdd, VSub, VMul,
  VCmp,            // aux high nibble = VecPred; lanes become all ones / zero
  VMax, VMin,      // aux bit 4 = signed
  VAbs,
  VShl, VLShr, VAShr,  // b = shift amount (same for every lane)
  VUnzip,          // even (bit 4 clear) or odd lanes of the 128-bit value b:a
  VZip,            // interleave lanes of a and b, from the low (bit 4 clear) or high half of each
  VTrn,            // transpose: lanes a[2i], b[2i] (bit 4 clear) or a[2i+1], b[2i+1]
  VWiden,          // widen lanes of the low (bit 5 clear) or high 32 bits of a; bit 4 = signed
  VReduce,         // fold all lanes of a into a scalar; aux high nibble = VecReduce
  VCnt,            // population count of each byte
  VRev,            // reverse lanes within containers of (aux high nibble) bytes
  VLane,           // imm = VecOp: the lane operation; aux and arguments as VecOp describes

  // --- Scalar floating point: values hold IEEE bits; size = 4 (single) or 8 (double) ---
  FAdd, FSub, FMul, FDiv,
  FMax, FMin, FMaxNm, FMinNm,
  FSqrt,
  FMadd,           // a * b + c, fused
  FCvt,            // convert from aux (source size) to size
  FToInt,          // size = integer size; aux = FpRound | signed << 3 | (source is double) << 4
  IntToF,          // size = fp size; aux = signed | (source is 64-bit) << 1
  FRint,           // round to integral; aux = FpRound | 8 (int32 range) / 16 (int64 range): FRINT32/64
  FCmp,            // packed NZCV of the comparison a ? b

  Count_
};

enum class Predicate : uint8_t { Eq, Ne, Ult, Ule, Ugt, Uge, Slt, Sle, Sgt, Sge };

// Read-modify-write operation for AtomicRmw.
enum class AtomicOp : uint8_t { Add, Clr, Eor, Set, SMax, SMin, UMax, UMin, Swap };

// Lane comparison for VCmp.
enum class VecPred : uint8_t { Eq, Gt, Ge, Hi, Hs, Tst };  // Gt/Ge signed, Hi/Hs unsigned

// Reduction kinds for VReduce.
enum class VecReduce : uint8_t { Add, UMax, UMin, SMax, SMin, UAddLong, SAddLong };

// Lane operations of VLane, on 64-bit vector halves. Unless noted, the low
// nibble of aux is the element size in bytes and bit 4 means signed.
enum class VecOp : uint8_t {
  // --- integer: a, b lanes -> lanes ---
  SatAdd, SatSub,        // saturating
  Abd,                   // absolute difference
  HAdd, RHAdd, HSub,     // halving (RHAdd rounds)
  ShlReg,                // shift each lane of a by the signed low byte of b's lane (negative: right)
  RShlReg,               // the same, rounding right shifts
  SatShlReg,             // the same, saturating left shifts
  SatRShlReg,            // rounding right shifts, saturating left shifts
  RShr,                  // rounding right shift by b (1..bits)
  SatShlImm,             // saturating left shift by b; aux bits 4-5: 0 signed, 1 unsigned, 2 signed to unsigned
  SatNarrow,             // a = lanes of twice the element size -> narrowed lanes in the low 32 bits;
                         //   aux bits 4-5 as SatShlImm (the element size is the narrow one)
  AddLongPairwise,       // pairs of lanes -> lanes of twice the size
  PMul,                  // polynomial (carry-less) multiply of bytes, low 8 bits
  PMulLong,              // bytes of the low (aux bit 5 clear) or high 32 bits of a, b -> 16-bit products
  SatDMulHigh,           // signed saturating doubling multiply high; aux bit 5 = rounding
  TblPart,               // bytes: index b in [8k, 8k+8), k = aux, selects a byte of c; else a's byte
  Clz, Cls, Rbit,        // per lane (Rbit: bytes)
  SatAbs, SatNeg,        // signed saturating
  Crc32,                 // scalar: CRC-32 of the low aux & 0xF bytes of b into the accumulator a
                         //   (bit-reflected, no inversion); aux bit 4 = Castagnoli polynomial
  Dot,                   // 32-bit lanes of c plus the dot products of the 4 bytes of a and b in each
                         //   lane; aux bit 4 = a signed, bit 5 = b signed
  SatRdmAcc,             // SQRDMLAH / SQRDMLSH: c + (2 * a * b + rounding) >> bits, saturated;
                         //   aux bit 5 = subtract the product
  SatAccMixed,           // SUQADD (aux bit 4 clear): signed a + unsigned b, saturated signed;
                         //   USQADD (bit 4 set): unsigned a + signed b, saturated unsigned
  URecpe, URsqrte,       // unsigned reciprocal (square root) estimates of 32-bit lanes
  // --- floating point: element size 4 or 8 (2: half precision, conversions only) ---
  FAdd, FSub, FMul, FDiv, FMax, FMin, FMaxNm, FMinNm,
  FAbd,                  // |a - b|
  FMulX,                 // as FMul, but 0 * inf = 2 with the product's sign
  FMla, FMls,            // c + a * b, c - a * b (fused)
  FCmEq, FCmGe, FCmGt,   // lanes become all ones / zero
  FAcGe, FAcGt,          // compares of absolute values
  FRecps, FRsqrts,       // 2 - a * b, (3 - a * b) / 2 (fused)
  FSqrt,
  FRecpe, FRsqrte,       // Arm's reciprocal (square root) estimates
  FRint,                 // aux bits 4-6 = FpRound
  FToInt,                // aux bits 4-6 = FpRound, bit 7 = signed; b = fraction bits (fixed point)
  IntToF,                // bit 4 = signed; b = fraction bits
  FCvtUp,                // the low (aux bit 4 clear) or high 32 bits of a, converted to lanes of
                         //   the element size (from half to single, or single to double)
  FCvtDown,              // lanes of a and b (twice the element size) -> the element size; a's in
                         //   the low 32 bits, b's in the high
  FRint32, FRint64,      // FRINT32* / FRINT64*: as FRint, out of range gives the most negative integer
  FCmla,                 // complex pairs: c + a * b rotated by aux bits 4-5 (x 90 degrees), fused
  FCadd,                 // complex pairs: a + b rotated by 90 (aux bits 4-5 = 1) or 270 (3) degrees
  FJcvt,                 // scalar FJCVTZS of the double a: the 32-bit result (aux bit 4 clear) or
                         //   the packed flags (Z = exact) (aux bit 4 set)
  // --- BFloat16 ---
  BfDot,                 // 32-bit float lanes of c plus the dot products of the bf16 pairs of a, b
                         //   (round to odd, denormals flushed: Arm's BFDOT)
  BfMlal,                // float lanes of c + bf16 even (aux bit 4 clear) or odd elements of a * b
  BfCvt,                 // float lanes of a (and b) -> bf16, a's in the low 32 bits, b's next
  Count_
};

// Operations of StateOp (each 128-bit operand is a slot pair).
enum class StateOpKind : uint8_t {
  AesE, AesD,            // d = SubBytes(ShiftRows(d ^ n)) / inverse
  AesMc, AesImc,         // d = MixColumns(n) / inverse
  Sha1C, Sha1P, Sha1M,   // four SHA-1 rounds: d = hash d (abcd), low 32 bits of n (e), m (w + k)
  Sha1Su0, Sha1Su1,      // SHA-1 message schedule
  Sha256H, Sha256H2,     // four SHA-256 rounds on d with the other half of the state in n, w + k in m
  Sha256Su0, Sha256Su1,  // SHA-256 message schedule
  Sha512H, Sha512H2,     // two SHA-512 rounds (Arm's SHA512H / SHA512H2)
  Sha512Su0, Sha512Su1,  // SHA-512 message schedule
  PMull64,               // d = 128-bit carry-less product of the 64-bit halves (aux) of n and m
  Mmla,                  // d (2x2 32-bit) += n (2x8 bytes) * m (2x8 bytes) transposed; aux bit 0 =
                         //   n signed, bit 1 = m signed
  BfMmla,                // d (2x2 float) += n (2x4 bf16) * m (2x4 bf16) transposed
  Sm3Ss1,                // d = SM3SS1(n, m, a), aux = first slot of a
  Sm3Tt1a, Sm3Tt1b, Sm3Tt2a, Sm3Tt2b,  // aux = word index of m
  Sm3PartW1, Sm3PartW2,
  Sm4E,                  // four SM4 rounds of the data d with the round keys n
  Sm4EKey,               // four SM4 round keys from the key words n and constants m
};

// Floating point rounding modes for FToInt / FRint.
enum class FpRound : uint8_t { NearestEven, PlusInf, MinusInf, Zero, NearestAway };

// Packed flag layout: N = bit 31, Z = bit 30, C = bit 29, V = bit 28.
inline constexpr uint64_t kFlagN = 1ull << 31;
inline constexpr uint64_t kFlagZ = 1ull << 30;
inline constexpr uint64_t kFlagC = 1ull << 29;
inline constexpr uint64_t kFlagV = 1ull << 28;

struct Inst {
  Opcode op = Opcode::Nop;
  uint8_t size = 8;  // operation width (4/8) or memory access size
  uint8_t aux = 0;
  std::array<ValueId, 3> args{kNoValue, kNoValue, kNoValue};
  uint64_t imm = 0;
};

struct Terminator {
  enum class Kind : uint8_t {
    Jump,          // pc = target
    JumpIndirect,  // pc = value
    Branch,        // pc = value ? target : fallthrough
    Exit,          // pc = target; exit_reason/exit_info set; leave to the dispatcher
  };
  Kind kind = Kind::Exit;
  ValueId value = kNoValue;
  uint64_t target = 0;
  uint64_t fallthrough = 0;
  uint32_t exit_reason = 0;
  uint32_t exit_info = 0;
};

struct Block {
  uint64_t guest_pc = 0;    // first guest instruction
  uint64_t guest_end = 0;   // one past the last guest byte covered
  uint32_t guest_insns = 0;
  std::vector<Inst> insts;
  Terminator term;
  // Index of the first IR instruction of each guest instruction (4 bytes
  // each, from guest_pc), for finding the guest instruction that faulted.
  std::vector<uint32_t> insn_starts;
};

// The guest pc of the instruction that IR instruction `inst` belongs to.
uint64_t guest_pc_of(const Block& block, size_t inst);

// Where the backend finds the program counter and exit fields in guest state.
struct StateLayout {
  uint16_t pc_slot = 0;
  uint32_t exit_reason_offset = 0;  // byte offset of a uint32
  uint32_t exit_info_offset = 0;    // byte offset of a uint32
  uint16_t slot_count = 0;
};

// --- Construction ------------------------------------------------------------

class Builder {
 public:
  explicit Builder(Block& block) : block_(block) {}

  ValueId emit(const Inst& inst);
  ValueId emit(Opcode op, uint8_t size, ValueId a = kNoValue, ValueId b = kNoValue, ValueId c = kNoValue,
               uint64_t imm = 0, uint8_t aux = 0);

  ValueId constant(uint64_t value);
  ValueId get(uint16_t slot);
  void set(uint16_t slot, ValueId value);
  ValueId load(ValueId addr, uint8_t bytes, bool sign_extend);
  void store(ValueId addr, ValueId value, uint8_t bytes);
  void load_to_state(ValueId addr, uint16_t slot, uint8_t bytes, uint8_t zero_to);
  void store_from_state(ValueId addr, uint16_t slot, uint8_t bytes);

  ValueId binary(Opcode op, ValueId a, ValueId b, uint8_t size) { return emit(op, size, a, b); }
  ValueId add(ValueId a, ValueId b, uint8_t size = 8) { return emit(Opcode::Add, size, a, b); }
  ValueId sub(ValueId a, ValueId b, uint8_t size = 8) { return emit(Opcode::Sub, size, a, b); }
  ValueId and_(ValueId a, ValueId b, uint8_t size = 8) { return emit(Opcode::And, size, a, b); }
  ValueId or_(ValueId a, ValueId b, uint8_t size = 8) { return emit(Opcode::Or, size, a, b); }
  ValueId xor_(ValueId a, ValueId b, uint8_t size = 8) { return emit(Opcode::Xor, size, a, b); }
  ValueId shl(ValueId a, ValueId b, uint8_t size = 8) { return emit(Opcode::Shl, size, a, b); }
  ValueId lshr(ValueId a, ValueId b, uint8_t size = 8) { return emit(Opcode::LShr, size, a, b); }
  ValueId ashr(ValueId a, ValueId b, uint8_t size = 8) { return emit(Opcode::AShr, size, a, b); }
  ValueId not_(ValueId a, uint8_t size = 8) { return emit(Opcode::Not, size, a); }
  ValueId neg(ValueId a, uint8_t size = 8) { return emit(Opcode::Neg, size, a); }
  ValueId sext(ValueId a, uint8_t from_bits, uint8_t size = 8) {
    return emit(Opcode::SExt, size, a, kNoValue, kNoValue, 0, from_bits);
  }
  ValueId zext(ValueId a, uint8_t from_bits) { return emit(Opcode::ZExt, 8, a, kNoValue, kNoValue, 0, from_bits); }
  ValueId cmp(Predicate p, ValueId a, ValueId b, uint8_t size = 8) {
    return emit(Opcode::Cmp, size, a, b, kNoValue, 0, static_cast<uint8_t>(p));
  }
  ValueId select(ValueId cond, ValueId t, ValueId f, uint8_t size = 8) {
    return emit(Opcode::Select, size, cond, t, f);
  }
  ValueId cond_holds(ValueId flags, uint8_t cond) {
    return emit(Opcode::CondHolds, 8, flags, kNoValue, kNoValue, 0, cond);
  }

  void jump(uint64_t target);
  void jump_indirect(ValueId target);
  void branch(ValueId cond, uint64_t target, uint64_t fallthrough);
  void exit(uint32_t reason, uint32_t info, uint64_t pc);

  Block& block() { return block_; }

 private:
  Block& block_;
};

// --- Semantics shared by the optimizer, interpreter and tests ----------------

bool is_pure(Opcode op);           // no side effects, result depends only on args
bool has_side_effects(Opcode op);  // must be kept even if its result is unused
// Accesses guest memory, so may fault: guest state must be exact before it
// (the optimizer keeps earlier guest-register stores).
bool may_fault(Opcode op);
bool is_vector_or_fp(Opcode op);   // the SIMD/FP opcodes above
bool has_result(Opcode op);
unsigned arg_count(Opcode op);
const char* opcode_name(Opcode op);

// Evaluate a pure instruction given its argument values.
uint64_t evaluate(const Inst& inst, uint64_t a, uint64_t b, uint64_t c);

// Does `cond` (A64 condition code) hold for packed flags?
bool condition_holds(uint8_t cond, uint64_t flags);
// Bit i set <=> condition holds when (flags >> 28) == i.
uint16_t condition_mask(uint8_t cond);

uint64_t flags_add(uint64_t a, uint64_t b, uint64_t carry_in, unsigned size);

// Execute an atomic opcode (AtomicRmw, AtomicCas, AtomicCasPair) on host memory,
// or read the counter (Counter).
uint64_t execute_atomic(const Inst& inst, uint64_t a, uint64_t b, uint64_t c);

// Execute a StateOp against guest state (an array of slots).
void execute_state_op(const Inst& inst, uint64_t* state);

// --- Debugging -----------------------------------------------------------------

using SlotNamer = std::function<std::string(uint16_t)>;
std::string to_string(const Block& block, const SlotNamer& namer = {});

// --- Optimization ----------------------------------------------------------------

struct OptimizeStats {
  uint32_t folded = 0;
  uint32_t forwarded = 0;
  uint32_t dead_stores = 0;
  uint32_t dead_values = 0;
};

OptimizeStats optimize(Block& block);

// --- Reference interpreter ---------------------------------------------------------

// Executes `block` against guest state `state` (an array of slots). Memory is
// accessed through host pointers. Used for testing the JIT and as a fallback
// execution mode.
// `current`, if given, tracks the instruction being executed (for faults).
void interpret(const Block& block, uint64_t* state, const StateLayout& layout, volatile size_t* current = nullptr);

}  // namespace juice::ir
