#pragma once

// Decoded form of a single A64 instruction.
//
// The decoder is purely a function of (instruction word, pc); it performs no
// memory access and has no OS dependencies, so it can be reused by analysis
// tools as well as by the translator.

#include <cstdint>
#include <string>

namespace juice::arm64 {

enum class Op : uint16_t {
  Invalid,      // unallocated encoding
  Unsupported,  // allocated, but not handled by JUICE yet

  // Data processing - immediate
  Adr, Adrp,
  AddImm, SubImm,
  AndImm, OrrImm, EorImm,          // ANDS = AndImm + set_flags
  Movn, Movz, Movk,
  Sbfm, Bfm, Ubfm,
  Extr,

  // Branches, exceptions, system
  B, Bl, BCond, Cbz, Cbnz, Tbz, Tbnz,
  Br, Blr, Ret,
  Svc, Brk, Hlt, Udf,
  Nop, Clrex,
  Barrier,         // DMB / DSB ordering all accesses (the x86-64 store->load fence)
  Mrs, Msr,

  // Data processing - register
  AndReg, BicReg, OrrReg, OrnReg, EorReg, EonReg,   // ANDS/BICS via set_flags
  AddShift, SubShift,
  AddExt, SubExt,
  Adc, Sbc,
  Ccmn, Ccmp,
  Csel, Csinc, Csinv, Csneg,
  Rbit, Rev16, Rev32, Rev, Clz, Cls,
  Udiv, Sdiv, Lslv, Lsrv, Asrv, Rorv,
  Madd, Msub, Smaddl, Smsubl, Umaddl, Umsubl, Smulh, Umulh,

  // Loads and stores
  Ldr, Str,        // single register (integer or SIMD&FP)
  Ldp, Stp,        // register pair
  Prfm,            // prefetch (no-op)
  DcZva,           // DC ZVA Xt: zero the 64-byte block containing Xt
  Ldxr, Stxr,      // exclusive (also acquire/release forms)
  Ldxp, Stxp,
  Cas,
  Casp,            // CASP: rm = Rs (even), rd = Rt (even); sf = 64-bit registers
  Swp,
  Ldadd, Ldclr, Ldeor, Ldset, Ldsmax, Ldsmin, Ldumax, Ldumin,

  // SIMD & FP (small subset used for data movement)
  FmovToGp,        // FMOV Wd/Xd, Sn/Dn/Vn.D[1]
  FmovFromGp,      // FMOV Sd/Dd/Vd.D[1], Wn/Xn
  FmovReg,         // FMOV Hd/Sd/Dd, Hn/Sn/Dn
  VMovImm,         // MOVI / MVNI / FMOV (vector, immediate)
  VOrrImm, VBicImm,
  VDupGp,          // DUP Vd.T, Rn
  VDupElem,        // DUP Vd.T, Vn.Ts[i]
  VDupScalar,      // DUP (MOV) Bd/Hd/Sd/Dd, Vn.Ts[i]
  VUmov, VSmov,    // UMOV/SMOV Rd, Vn.Ts[i]
  VInsGp,          // INS Vd.Ts[i], Rn
  VInsElem,        // INS Vd.Ts[i], Vn.Ts[j]
  VAnd, VBic, VOrr, VOrn, VEor,

  // SIMD structure loads/stores
  VLdMulti, VStMulti,  // LD1-LD4 / ST1-ST4 (multiple structures): ra = registers, amount = interleave
  VLdLane, VStLane,    // LD1-LD4 / ST1-ST4 (single structure): index = lane, amount = registers
  VLdRep,              // LD1R-LD4R: amount = registers
  // (post-index: mode = PostIndex; imm_form = immediate increment `imm`, else register rm)

  // AdvSIMD integer (esize = element size, q = 128-bit)
  VecAdd, VecSub, VecMul,
  VecCmp,              // shift = ir::VecPred
  VecCmpZero,          // shift = VecZeroCmp
  VecMax, VecMin,      // mem_signed
  VecMaxP, VecMinP, VecAddP,
  VecAddAcross, VecMaxAcross, VecMinAcross, VecAddLongAcross,
  VecAddPScalar,       // ADDP Dd, Vn.2D
  VecShl, VecShr,      // by immediate `imm`; VecShr: mem_signed
  VecShrn, VecXtn,     // narrowing; index = 1 for the "2" (upper half) forms
  VecShll,             // SSHLL/USHLL (SXTL/UXTL): index = 1 for the "2" forms, imm = shift
  VecCnt, VecNot, VecNeg, VecAbs,
  VecRev,              // amount = container size in bytes
  VecUzp, VecZip, VecTrn,  // index = 1 for the "2" forms
  VecExt,              // imm = byte position
  VecBsl, VecBit, VecBif,
  VecIntOp,            // three same, integer: shift = VecInt
  VecFpOp,             // three same, floating point (and FP pairwise): shift = VecFp, esize 4/8
  VecIntUnary,         // two-register misc, integer: shift = VecIntUn, amount = narrowing mode
  VecFpUnary,          // two-register misc, floating point: shift = VecFpUn, amount = rounding / compare
  VecLong,             // three different: shift = VecLongKind, esize = narrow size, index = "2" form
  VecShiftOp,          // shift by immediate: shift = VecShiftKind, imm = amount / fraction bits,
                       //   amount = narrowing mode (bit 2: rounding)
  VecElemOp,           // by element: shift = VecElemKind, index2 = element index
  VecTbl,              // TBL / TBX: amount = table registers, index = 1 for TBX
  VecFpAcross,         // FMAXV / FMINV / FMAXNMV / FMINNMV: shift = VecFp
  FpFixedToFp,         // SCVTF / UCVTF (fixed point, from Wn/Xn): imm = fraction bits
  FpToFixed,           // FCVTZS / FCVTZU (fixed point, to Wd/Xd): imm = fraction bits

  // Scalar floating point (mem_size = 4 single / 8 double)
  FpBinary,            // shift = FpBinaryOp
  FpUnary,             // shift = FpUnaryOp
  FpCvt,               // FCVT: mem_size = destination, esize = source
  FpRint,              // shift = ir::FpRound
  FpFma,               // shift = 0 FMADD, 1 FMSUB, 2 FNMADD, 3 FNMSUB
  FpCmp,               // imm_form = compare with zero
  FpCcmp,              // cond, nzcv
  FpCsel,              // cond
  FpMovImm,            // imm = bits
  FpToInt,             // shift = ir::FpRound, mem_signed, sf = 64-bit result
  IntToFp,             // mem_signed, sf = 64-bit source

  Count_
};

enum class VecZeroCmp : uint8_t { Gt, Ge, Eq, Le, Lt };
enum class VecInt : uint8_t {
  SatAdd, SatSub, Abd, Aba, HAdd, RHAdd, HSub, ShlReg, SatShlReg, RShlReg, SatRShlReg, Mla, Mls, PMul, SqDMulH,
  SqRDMulH
};
enum class VecFp : uint8_t {
  Add, Sub, Mul, Div, Max, Min, MaxNm, MinNm, Abd, MulX, Mla, Mls, CmEq, CmGe, CmGt, AcGe, AcGt, Recps, Rsqrts,
  AddP, MaxP, MinP, MaxNmP, MinNmP
};
enum class VecIntUn : uint8_t { Clz, Cls, Rbit, AddLP, AdaLP, SatAbs, SatNeg, SatXtn, Shll };
enum class VecFpUn : uint8_t { Abs, Neg, Sqrt, Rint, ToInt, FromInt, CmpZero, Recpe, Rsqrte, CvtLong, CvtNarrow };
enum class VecLongKind : uint8_t {
  AddL, AddW, SubL, SubW, AddHN, RAddHN, SubHN, RSubHN, AbaL, AbdL, MlaL, MlsL, MulL, PMulL, SqDMulL, SqDMlaL,
  SqDMlsL
};
enum class VecShiftKind : uint8_t { Sra, RShr, RSra, Sri, Sli, SatShl, Rshrn, SatShrn, FixedToFp, FpToFixed };
enum class VecElemKind : uint8_t {
  Mul, Mla, Mls, MulL, MlaL, MlsL, FMul, FMla, FMls, FMulX, SqDMulH, SqRDMulH, SqDMulL, SqDMlaL, SqDMlsL
};
enum class FpBinaryOp : uint8_t { Mul, Div, Add, Sub, Max, Min, MaxNm, MinNm, NMul };
enum class FpUnaryOp : uint8_t { Abs = 1, Neg = 2, Sqrt = 3 };

enum class ShiftType : uint8_t { Lsl = 0, Lsr = 1, Asr = 2, Ror = 3 };

// Extend option for extended-register forms (encoding order).
enum class Extend : uint8_t { Uxtb, Uxth, Uxtw, Uxtx, Sxtb, Sxth, Sxtw, Sxtx };

enum class AddrMode : uint8_t {
  Offset,     // [Xn, #imm]
  PreIndex,   // [Xn, #imm]!
  PostIndex,  // [Xn], #imm
  RegOffset,  // [Xn, Rm, extend #amount]
  Literal,    // pc-relative; address in `imm`
};

// System registers JUICE understands (op0:op1:CRn:CRm:op2 packed as in MRS).
namespace sysreg {
constexpr uint16_t make(unsigned op0, unsigned op1, unsigned crn, unsigned crm, unsigned op2) {
  return static_cast<uint16_t>((op0 << 14) | (op1 << 11) | (crn << 7) | (crm << 3) | op2);
}
inline constexpr uint16_t NZCV = make(3, 3, 4, 2, 0);
inline constexpr uint16_t FPCR = make(3, 3, 4, 4, 0);
inline constexpr uint16_t FPSR = make(3, 3, 4, 4, 1);
inline constexpr uint16_t TPIDR_EL0 = make(3, 3, 13, 0, 2);
inline constexpr uint16_t TPIDRRO_EL0 = make(3, 3, 13, 0, 3);
inline constexpr uint16_t DCZID_EL0 = make(3, 3, 0, 0, 7);
inline constexpr uint16_t CTR_EL0 = make(3, 3, 0, 0, 1);
inline constexpr uint16_t MIDR_EL1 = make(3, 0, 0, 0, 0);
inline constexpr uint16_t CurrentEL = make(3, 0, 4, 2, 2);
inline constexpr uint16_t CNTFRQ_EL0 = make(3, 3, 14, 0, 0);
inline constexpr uint16_t CNTVCT_EL0 = make(3, 3, 14, 0, 2);
}  // namespace sysreg

struct Instruction {
  Op op = Op::Invalid;
  uint32_t raw = 0;
  uint64_t pc = 0;

  bool sf = true;           // 64-bit operation (X registers)
  bool set_flags = false;   // S bit (ADDS, ANDS, ...)

  uint8_t rd = 0;           // destination, also Rt for loads/stores
  uint8_t rn = 0;           // first source, also base register
  uint8_t rm = 0;           // second source, also Rs for atomics/exclusives
  uint8_t ra = 0;           // third source, also Rt2 for pairs

  uint8_t cond = 0;         // condition code (B.cond, CSEL, CCMP)
  uint8_t shift = 0;        // ShiftType or Extend
  uint8_t amount = 0;       // shift amount / bit number (TBZ) / MOVK shift
  uint8_t immr = 0;         // bitfield immr, or EXTR lsb
  uint8_t imms = 0;
  uint8_t nzcv = 0;         // CCMP fallback flags (4 bits)
  bool imm_form = false;    // CCMP immediate form

  // Memory access
  uint8_t mem_size = 0;     // bytes per register (1, 2, 4, 8, 16)
  bool mem_signed = false;  // sign-extending load
  bool mem_to_64 = true;    // signed load destination is Xt (else Wt)
  bool vector = false;      // SIMD&FP register transfer
  bool release = false;     // store-release (STLR, STLUR): ordered before later acquires
  AddrMode mode = AddrMode::Offset;

  // SIMD
  bool q = false;           // 128-bit vector
  bool scalar = false;      // AdvSIMD scalar form: one element in the low lane, the rest zeroed
  uint8_t esize = 0;        // element size in bytes
  uint8_t index = 0;        // element index (destination for INS)
  uint8_t index2 = 0;       // source element index

  uint16_t sysreg = 0;
  int64_t imm = 0;          // immediate, offset, or absolute branch/literal target
};

// Decode one instruction located at `pc`.
Instruction decode(uint32_t word, uint64_t pc);

// True if the instruction always ends a basic block.
bool is_block_terminator(const Instruction& insn);

const char* mnemonic(Op op);

// Human readable disassembly (approximately LLVM syntax).
std::string disassemble(const Instruction& insn);

// DecodeBitMasks() from the Arm ARM, for logical immediates. Returns false for
// reserved encodings.
bool decode_logical_immediate(bool sf, unsigned n, unsigned immr, unsigned imms, uint64_t& out);

// AdvSIMDExpandImm() from the Arm ARM.
uint64_t expand_simd_immediate(unsigned op, unsigned cmode, unsigned imm8);

}  // namespace juice::arm64
