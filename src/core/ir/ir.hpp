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
  AtomicCasPair,   // a = address, b = pointer to {expected lo, hi, desired lo, hi}
                   //   (128-bit compare-and-swap)                    -> 0 if swapped, 1 if not

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

  // --- Scalar floating point: values hold IEEE bits; size = 4 (single) or 8 (double) ---
  FAdd, FSub, FMul, FDiv,
  FMax, FMin, FMaxNm, FMinNm,
  FSqrt,
  FMadd,           // a * b + c, fused
  FCvt,            // convert from aux (source size) to size
  FToInt,          // size = integer size; aux = FpRound | signed << 3 | (source is double) << 4
  IntToF,          // size = fp size; aux = signed | (source is 64-bit) << 1
  FRint,           // round to integral; aux = FpRound
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
};

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

// Execute an atomic opcode (AtomicRmw, AtomicCas, AtomicCasPair) on host memory.
uint64_t execute_atomic(const Inst& inst, uint64_t a, uint64_t b, uint64_t c);

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
void interpret(const Block& block, uint64_t* state, const StateLayout& layout);

}  // namespace juice::ir
