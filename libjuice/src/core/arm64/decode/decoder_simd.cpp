// Decoding of scalar floating point and Advanced SIMD instructions.

#include <bit>

#include "core/arm64/decode/decoder_detail.hpp"

// Instruction fields are extracted with bits() and stored in narrow members;
// every field fits its member by construction.
#ifdef _MSC_VER
#pragma warning(disable : 4244 4805)
#endif

namespace juice::arm64::detail {
namespace {

// Values stored in Instruction::shift, in the order of ir::VecPred / ir::FpRound.
enum VecPredCode : uint8_t { kEq, kGt, kGe, kHi, kHs, kTst };
enum RoundCode : uint8_t { kNearestEven, kPlusInf, kMinusInf, kZero, kNearestAway };

// Size in bytes for an FP `ftype` field (0 if unsupported: half precision / reserved).
uint8_t fp_size(unsigned ftype) { return ftype == 0 ? 4 : ftype == 1 ? 8 : 0; }

void decode_fp_int_conversion(Instruction& i, uint32_t w) {
  i.sf = bit(w, 31);
  const unsigned ftype = bits(w, 23, 22);
  const unsigned rmode = bits(w, 20, 19);
  const unsigned opcode = bits(w, 18, 16);

  if (opcode == 6 || opcode == 7) {  // FMOV (general)
    if (rmode == 0 && ((!i.sf && ftype == 0) || (i.sf && ftype == 1))) {
      i.mem_size = i.sf ? 8 : 4;
      i.index = 0;
    } else if (rmode == 1 && i.sf && ftype == 2) {
      i.mem_size = 8;
      i.index = 1;  // Vn.D[1]
    } else {
      return;
    }
    i.op = opcode == 6 ? Op::FmovToGp : Op::FmovFromGp;
    return;
  }

  i.mem_size = fp_size(ftype);
  if (!i.mem_size) return;
  if (opcode <= 1) {  // FCVTNS/FCVTPS/FCVTMS/FCVTZS and unsigned forms
    i.op = Op::FpToInt;
    i.shift = static_cast<uint8_t>(rmode);
    i.mem_signed = opcode == 0;
  } else if ((opcode == 4 || opcode == 5) && rmode == 0) {  // FCVTAS / FCVTAU
    i.op = Op::FpToInt;
    i.shift = kNearestAway;
    i.mem_signed = opcode == 4;
  } else if ((opcode == 2 || opcode == 3) && rmode == 0) {  // SCVTF / UCVTF
    i.op = Op::IntToFp;
    i.mem_signed = opcode == 2;
  }
}

void decode_fp_data(Instruction& i, uint32_t w) {
  i.mem_size = fp_size(bits(w, 23, 22));
  if (!i.mem_size) return;

  if ((w & 0x7C00) == 0x4000) {  // 1 source
    const unsigned opcode = bits(w, 20, 15);
    switch (opcode) {
      case 0b000000: i.op = Op::FmovReg; return;
      case 0b000001: i.op = Op::FpUnary; i.shift = static_cast<uint8_t>(FpUnaryOp::Abs); return;
      case 0b000010: i.op = Op::FpUnary; i.shift = static_cast<uint8_t>(FpUnaryOp::Neg); return;
      case 0b000011: i.op = Op::FpUnary; i.shift = static_cast<uint8_t>(FpUnaryOp::Sqrt); return;
      case 0b000100:
      case 0b000101:
        i.op = Op::FpCvt;
        i.esize = i.mem_size;
        i.mem_size = opcode == 0b000100 ? 4 : 8;
        if (i.esize == i.mem_size) i.op = Op::Invalid;
        return;
      case 0b001000: i.op = Op::FpRint; i.shift = kNearestEven; return;
      case 0b001001: i.op = Op::FpRint; i.shift = kPlusInf; return;
      case 0b001010: i.op = Op::FpRint; i.shift = kMinusInf; return;
      case 0b001011: i.op = Op::FpRint; i.shift = kZero; return;
      case 0b001100: i.op = Op::FpRint; i.shift = kNearestAway; return;
      case 0b001110:  // FRINTX
      case 0b001111:  // FRINTI (current rounding mode: round to nearest)
        i.op = Op::FpRint;
        i.shift = kNearestEven;
        return;
      default:
        return;
    }
  }
  if ((w & 0x3C00) == 0x2000) {  // compare
    if (bits(w, 15, 14) != 0 || (w & 7) != 0) return;
    i.op = Op::FpCmp;
    i.imm_form = bit(w, 3);
    return;
  }
  if ((w & 0x1C00) == 0x1000) {  // FMOV (scalar, immediate)
    if (bits(w, 9, 5) != 0) return;
    const unsigned imm8 = bits(w, 20, 13);
    uint64_t value = expand_simd_immediate(i.mem_size == 8 ? 1 : 0, 0b1111, imm8);
    if (i.mem_size == 4) value &= 0xFFFF'FFFFu;
    i.op = Op::FpMovImm;
    i.imm = static_cast<int64_t>(value);
    return;
  }
  switch (bits(w, 11, 10)) {
    case 0b01:  // conditional compare
      i.op = Op::FpCcmp;
      i.cond = bits(w, 15, 12);
      i.nzcv = bits(w, 3, 0);
      return;
    case 0b10: {  // 2 source
      const unsigned opcode = bits(w, 15, 12);
      if (opcode > 8) return;
      i.op = Op::FpBinary;
      i.shift = static_cast<uint8_t>(opcode);
      return;
    }
    case 0b11:  // conditional select
      i.op = Op::FpCsel;
      i.cond = bits(w, 15, 12);
      return;
    default:
      return;
  }
}

void decode_three_same(Instruction& i, uint32_t w) {
  const bool u = bit(w, 29);
  const unsigned size = bits(w, 23, 22);
  const unsigned opcode = bits(w, 15, 11);
  i.esize = static_cast<uint8_t>(1u << size);

  if (opcode == 0b00011) {  // logical
    if (!u) {
      static constexpr Op ops[4] = {Op::VAnd, Op::VBic, Op::VOrr, Op::VOrn};
      i.op = ops[size];
    } else {
      static constexpr Op ops[4] = {Op::VEor, Op::VecBsl, Op::VecBit, Op::VecBif};
      i.op = ops[size];
    }
    return;
  }
  if (opcode >= 0b11000) {  // floating point: size<1> selects the operation, size<0> the precision
    const unsigned a = size >> 1;
    i.esize = (size & 1) ? 8 : 4;
    if (i.esize == 8 && !i.q && !i.scalar) return;
    const unsigned key = (u << 6) | (a << 5) | (opcode & 0x1F);
    auto fp = [&](VecFp f) {
      i.op = Op::VecFpOp;
      i.shift = static_cast<uint8_t>(f);
    };
    switch (key) {
      case 0b0011000: fp(VecFp::MaxNm); break;
      case 0b0011001: fp(VecFp::Mla); break;
      case 0b0011010: fp(VecFp::Add); break;
      case 0b0011011: fp(VecFp::MulX); break;
      case 0b0011100: fp(VecFp::CmEq); break;
      case 0b0011110: fp(VecFp::Max); break;
      case 0b0011111: fp(VecFp::Recps); break;
      case 0b0111000: fp(VecFp::MinNm); break;
      case 0b0111001: fp(VecFp::Mls); break;
      case 0b0111010: fp(VecFp::Sub); break;
      case 0b0111110: fp(VecFp::Min); break;
      case 0b0111111: fp(VecFp::Rsqrts); break;
      case 0b1011000: fp(VecFp::MaxNmP); break;
      case 0b1011010: fp(VecFp::AddP); break;
      case 0b1011011: fp(VecFp::Mul); break;
      case 0b1011100: fp(VecFp::CmGe); break;
      case 0b1011101: fp(VecFp::AcGe); break;
      case 0b1011110: fp(VecFp::MaxP); break;
      case 0b1011111: fp(VecFp::Div); break;
      case 0b1111000: fp(VecFp::MinNmP); break;
      case 0b1111010: fp(VecFp::Abd); break;
      case 0b1111100: fp(VecFp::CmGt); break;
      case 0b1111101: fp(VecFp::AcGt); break;
      case 0b1111110: fp(VecFp::MinP); break;
      default: break;
    }
    return;
  }
  if (size == 3 && !i.q && !i.scalar) return;

  auto cmp = [&](uint8_t pred) {
    i.op = Op::VecCmp;
    i.shift = pred;
  };
  auto int_op = [&](VecInt k, bool no_64 = true) {
    if (no_64 && size == 3) return;
    i.op = Op::VecIntOp;
    i.shift = static_cast<uint8_t>(k);
    i.mem_signed = !u;
  };
  switch (opcode) {
    case 0b00000: int_op(VecInt::HAdd); break;
    case 0b00001: int_op(VecInt::SatAdd, false); break;
    case 0b00010: int_op(VecInt::RHAdd); break;
    case 0b00100: int_op(VecInt::HSub); break;
    case 0b00101: int_op(VecInt::SatSub, false); break;
    case 0b01000: int_op(VecInt::ShlReg, false); break;
    case 0b01001: int_op(VecInt::SatShlReg, false); break;
    case 0b01010: int_op(VecInt::RShlReg, false); break;
    case 0b01011: int_op(VecInt::SatRShlReg, false); break;
    case 0b01110: int_op(VecInt::Abd); break;
    case 0b01111: int_op(VecInt::Aba); break;
    case 0b10010: int_op(u ? VecInt::Mls : VecInt::Mla); break;
    case 0b10110:
      if (size == 1 || size == 2) int_op(u ? VecInt::SqRDMulH : VecInt::SqDMulH);
      break;
    case 0b10000: i.op = u ? Op::VecSub : Op::VecAdd; break;
    case 0b10001: cmp(u ? kEq : kTst); break;
    case 0b00110: cmp(u ? kHi : kGt); break;
    case 0b00111: cmp(u ? kHs : kGe); break;
    case 0b01100: i.op = Op::VecMax; i.mem_signed = !u; break;
    case 0b01101: i.op = Op::VecMin; i.mem_signed = !u; break;
    case 0b10100: i.op = Op::VecMaxP; i.mem_signed = !u; break;
    case 0b10101: i.op = Op::VecMinP; i.mem_signed = !u; break;
    case 0b10111: if (!u) i.op = Op::VecAddP; break;
    case 0b10011:
      if (!u && size != 3) i.op = Op::VecMul;
      if (u && size == 0) int_op(VecInt::PMul);
      break;
    default: break;
  }
}

// Floating point two-register misc (and its scalar form).
void decode_two_reg_misc_fp(Instruction& i, uint32_t w) {
  const bool u = bit(w, 29);
  const unsigned size = bits(w, 23, 22);
  const unsigned opcode = bits(w, 16, 12);
  const unsigned a = size >> 1, sz = size & 1;
  auto fp = [&](VecFpUn k, uint8_t amount = 0, bool sign = false) {
    i.esize = sz ? 8 : 4;
    if (i.esize == 8 && !i.q && !i.scalar) return;
    i.op = Op::VecFpUnary;
    i.shift = static_cast<uint8_t>(k);
    i.amount = amount;
    i.mem_signed = sign;
  };
  const unsigned key = (u << 6) | (a << 5) | opcode;
  switch (key) {
    case 0b0010110:  // FCVTN / FCVTN2: esize = destination size
      if (i.scalar) return;
      i.op = Op::VecFpUnary;
      i.shift = static_cast<uint8_t>(VecFpUn::CvtNarrow);
      i.esize = sz ? 4 : 2;
      i.index = i.q;
      return;
    case 0b0010111:  // FCVTL / FCVTL2: esize = destination size
      if (i.scalar) return;
      i.op = Op::VecFpUnary;
      i.shift = static_cast<uint8_t>(VecFpUn::CvtLong);
      i.esize = sz ? 8 : 4;
      i.index = i.q;
      return;
    case 0b0011000: fp(VecFpUn::Rint, kNearestEven); return;  // FRINTN
    case 0b0011001: fp(VecFpUn::Rint, kMinusInf); return;     // FRINTM
    case 0b0011010: fp(VecFpUn::ToInt, kNearestEven, true); return;
    case 0b0011011: fp(VecFpUn::ToInt, kMinusInf, true); return;
    case 0b0011100: fp(VecFpUn::ToInt, kNearestAway, true); return;
    case 0b0011101: fp(VecFpUn::FromInt, 0, true); return;
    case 0b0101100: fp(VecFpUn::CmpZero, static_cast<uint8_t>(VecZeroCmp::Gt)); return;
    case 0b0101101: fp(VecFpUn::CmpZero, static_cast<uint8_t>(VecZeroCmp::Eq)); return;
    case 0b0101110: fp(VecFpUn::CmpZero, static_cast<uint8_t>(VecZeroCmp::Lt)); return;
    case 0b0101111: fp(VecFpUn::Abs); return;
    case 0b0111000: fp(VecFpUn::Rint, kPlusInf); return;      // FRINTP
    case 0b0111001: fp(VecFpUn::Rint, kZero); return;         // FRINTZ
    case 0b0111010: fp(VecFpUn::ToInt, kPlusInf, true); return;
    case 0b0111011: fp(VecFpUn::ToInt, kZero, true); return;
    case 0b0111101: fp(VecFpUn::Recpe); return;
    case 0b1011000: fp(VecFpUn::Rint, kNearestAway); return;  // FRINTA
    case 0b1011001: fp(VecFpUn::Rint, kNearestEven); return;  // FRINTX
    case 0b1011010: fp(VecFpUn::ToInt, kNearestEven); return;
    case 0b1011011: fp(VecFpUn::ToInt, kMinusInf); return;
    case 0b1011100: fp(VecFpUn::ToInt, kNearestAway); return;
    case 0b1011101: fp(VecFpUn::FromInt); return;
    case 0b1101100: fp(VecFpUn::CmpZero, static_cast<uint8_t>(VecZeroCmp::Ge)); return;
    case 0b1101101: fp(VecFpUn::CmpZero, static_cast<uint8_t>(VecZeroCmp::Le)); return;
    case 0b1101111: fp(VecFpUn::Neg); return;
    case 0b1111001: fp(VecFpUn::Rint, kNearestEven); return;  // FRINTI
    case 0b1111010: fp(VecFpUn::ToInt, kPlusInf); return;
    case 0b1111011: fp(VecFpUn::ToInt, kZero); return;
    case 0b1111101: fp(VecFpUn::Rsqrte); return;
    case 0b1111111: fp(VecFpUn::Sqrt); return;
    default: return;
  }
}

void decode_two_reg_misc(Instruction& i, uint32_t w) {
  const bool u = bit(w, 29);
  const unsigned size = bits(w, 23, 22);
  const unsigned opcode = bits(w, 16, 12);
  i.esize = static_cast<uint8_t>(1u << size);
  if (opcode >= 0b10110 || (opcode >= 0b01100 && opcode <= 0b01111 && size >= 2)) {
    decode_two_reg_misc_fp(i, w);
    return;
  }
  auto int_un = [&](VecIntUn k, uint8_t amount = 0) {
    i.op = Op::VecIntUnary;
    i.shift = static_cast<uint8_t>(k);
    i.amount = amount;
    i.mem_signed = !u;
  };
  auto zero_cmp = [&](VecZeroCmp c) {
    if (size == 3 && !i.q && !i.scalar) return;
    i.op = Op::VecCmpZero;
    i.shift = static_cast<uint8_t>(c);
  };
  switch (opcode) {
    case 0b00000:  // REV64 / REV32
      i.amount = u ? 4 : 8;
      if (i.esize < i.amount) i.op = Op::VecRev;
      break;
    case 0b00001:  // REV16
      if (!u && size == 0) {
        i.op = Op::VecRev;
        i.amount = 2;
      }
      break;
    case 0b00101:
      if (size == 0) i.op = u ? Op::VecNot : Op::VecCnt;
      if (size == 1 && u) int_un(VecIntUn::Rbit);
      break;
    case 0b00010: if (size != 3) int_un(VecIntUn::AddLP); break;
    case 0b00110: if (size != 3) int_un(VecIntUn::AdaLP); break;
    case 0b00100: if (size != 3) int_un(u ? VecIntUn::Clz : VecIntUn::Cls); break;
    case 0b00111: if (size != 3 || i.q || i.scalar) int_un(u ? VecIntUn::SatNeg : VecIntUn::SatAbs); break;
    case 0b10011: if (u && size != 3 && !i.scalar) { int_un(VecIntUn::Shll); i.index = i.q; } break;
    case 0b10100:  // SQXTN / UQXTN (esize = narrow size)
      if (size != 3) {
        int_un(VecIntUn::SatXtn, u ? 1 : 0);
        i.index = i.q;
      }
      break;
    case 0b01000: zero_cmp(u ? VecZeroCmp::Ge : VecZeroCmp::Gt); break;
    case 0b01001: zero_cmp(u ? VecZeroCmp::Le : VecZeroCmp::Eq); break;
    case 0b01010: if (!u) zero_cmp(VecZeroCmp::Lt); break;
    case 0b01011:
      if (size != 3 || i.q || i.scalar) i.op = u ? Op::VecNeg : Op::VecAbs;
      break;
    case 0b10010:  // XTN / XTN2: esize is the narrow (destination) size; SQXTUN
      if (!u && size != 3 && !i.scalar) {
        i.op = Op::VecXtn;
        i.index = i.q;
      } else if (u && size != 3) {
        int_un(VecIntUn::SatXtn, 2);
        i.index = i.q;
      }
      break;
    default:
      break;
  }
}

void decode_across_lanes(Instruction& i, uint32_t w) {
  const bool u = bit(w, 29);
  const unsigned size = bits(w, 23, 22);
  const unsigned opcode = bits(w, 16, 12);
  if (u && (opcode == 0b01100 || opcode == 0b01111)) {  // FMAXNMV / FMINNMV / FMAXV / FMINV (4S)
    if ((size & 1) || !i.q) return;
    i.op = Op::VecFpAcross;
    i.esize = 4;
    const bool min = size >> 1;
    i.shift = static_cast<uint8_t>(opcode == 0b01100 ? (min ? VecFp::MinNm : VecFp::MaxNm)
                                                     : (min ? VecFp::Min : VecFp::Max));
    return;
  }
  if (size == 3 || (size == 2 && !i.q)) return;
  i.esize = static_cast<uint8_t>(1u << size);
  switch (opcode) {
    case 0b11011: if (!u) i.op = Op::VecAddAcross; break;
    case 0b01010: i.op = Op::VecMaxAcross; i.mem_signed = !u; break;
    case 0b11010: i.op = Op::VecMinAcross; i.mem_signed = !u; break;
    case 0b00011: i.op = Op::VecAddLongAcross; i.mem_signed = !u; break;
    default: break;
  }
}

void decode_shift_immediate(Instruction& i, uint32_t w) {
  const bool u = bit(w, 29);
  const unsigned immh = bits(w, 22, 19);
  const unsigned immhb = bits(w, 22, 16);
  const unsigned opcode = bits(w, 15, 11);
  const unsigned hb = 31 - static_cast<unsigned>(std::countl_zero(immh));
  i.esize = static_cast<uint8_t>(1u << hb);
  const unsigned ebits = i.esize * 8u;
  const bool wide_ok = i.esize != 8 || i.q || i.scalar;
  auto shift_op = [&](VecShiftKind k, int64_t imm, uint8_t amount = 0) {
    i.op = Op::VecShiftOp;
    i.shift = static_cast<uint8_t>(k);
    i.imm = imm;
    i.amount = amount;
    i.mem_signed = !u;
  };
  switch (opcode) {
    case 0b00000:  // SSHR / USHR
      if (!wide_ok) return;
      i.op = Op::VecShr;
      i.mem_signed = !u;
      i.imm = 2 * ebits - immhb;
      break;
    case 0b01010:  // SHL / SLI
      if (!wide_ok) return;
      if (u) {
        shift_op(VecShiftKind::Sli, immhb - ebits);
        break;
      }
      i.op = Op::VecShl;
      i.imm = immhb - ebits;
      break;
    case 0b00010: if (wide_ok) shift_op(VecShiftKind::Sra, 2 * ebits - immhb); break;
    case 0b00100: if (wide_ok) shift_op(VecShiftKind::RShr, 2 * ebits - immhb); break;
    case 0b00110: if (wide_ok) shift_op(VecShiftKind::RSra, 2 * ebits - immhb); break;
    case 0b01000: if (wide_ok && u) shift_op(VecShiftKind::Sri, 2 * ebits - immhb); break;
    case 0b01100: if (wide_ok && u) shift_op(VecShiftKind::SatShl, immhb - ebits, 2); break;  // SQSHLU
    case 0b01110: if (wide_ok) shift_op(VecShiftKind::SatShl, immhb - ebits, u ? 1 : 0); break;
    case 0b10001:  // RSHRN / SQRSHRUN (esize = destination size)
    case 0b10000:  // SHRN (handled below) / SQSHRUN
    case 0b10010:  // SQSHRN / UQSHRN
    case 0b10011:  // SQRSHRN / UQRSHRN
      if (i.esize == 8) return;
      if (opcode == 0b10000 && !u) {
        if (i.scalar) return;
        i.op = Op::VecShrn;
        i.imm = 2 * ebits - immhb;
        i.index = i.q;
        break;
      }
      if (opcode == 0b10001 && !u) {
        if (i.scalar) return;
        shift_op(VecShiftKind::Rshrn, 2 * ebits - immhb);
      } else {
        const uint8_t mode = (opcode == 0b10000 || opcode == 0b10001) ? 2 : (u ? 1 : 0);
        const uint8_t rounding = (opcode & 1) ? 4 : 0;
        shift_op(VecShiftKind::SatShrn, 2 * ebits - immhb, mode | rounding);
      }
      i.index = i.q;
      break;
    case 0b11100:  // SCVTF / UCVTF (fixed point)
    case 0b11111:  // FCVTZS / FCVTZU (fixed point)
      if (i.esize < 4 || !wide_ok) return;
      shift_op(opcode == 0b11100 ? VecShiftKind::FixedToFp : VecShiftKind::FpToFixed, 2 * ebits - immhb);
      break;
    case 0b10100:  // SSHLL / USHLL (esize = source element size)
      if (i.esize == 8 || i.scalar) return;
      i.op = Op::VecShll;
      i.mem_signed = !u;
      i.imm = immhb - ebits;
      i.index = i.q;
      break;
    default:
      break;
  }
}

void decode_three_different(Instruction& i, uint32_t w) {
  const bool u = bit(w, 29);
  const unsigned size = bits(w, 23, 22);
  const unsigned opcode = bits(w, 15, 12);
  if (size == 3) return;  // (PMULL 1Q needs the crypto extension)
  i.esize = static_cast<uint8_t>(1u << size);
  i.index = i.q;
  i.mem_signed = !u;
  static constexpr VecLongKind kinds[16] = {
      VecLongKind::AddL,  VecLongKind::AddW, VecLongKind::SubL, VecLongKind::SubW,    VecLongKind::AddHN,
      VecLongKind::AbaL,  VecLongKind::SubHN, VecLongKind::AbdL, VecLongKind::MlaL,   VecLongKind::SqDMlaL,
      VecLongKind::MlsL,  VecLongKind::SqDMlsL, VecLongKind::MulL, VecLongKind::SqDMulL, VecLongKind::PMulL,
      VecLongKind::MulL};
  if (opcode == 0b1111) return;
  VecLongKind k = kinds[opcode];
  if (u && opcode == 0b0100) k = VecLongKind::RAddHN;
  if (u && opcode == 0b0110) k = VecLongKind::RSubHN;
  if (u && (opcode == 0b1001 || opcode == 0b1011 || opcode == 0b1101 || opcode == 0b1110)) return;
  if ((k == VecLongKind::SqDMlaL || k == VecLongKind::SqDMlsL || k == VecLongKind::SqDMulL) && size == 0) return;
  if (k == VecLongKind::PMulL && size != 0) return;
  i.op = Op::VecLong;
  i.shift = static_cast<uint8_t>(k);
}

void decode_by_element(Instruction& i, uint32_t w) {
  const bool u = bit(w, 29);
  const unsigned size = bits(w, 23, 22);
  const unsigned opcode = bits(w, 15, 12);
  const unsigned l = bit(w, 21), m = bit(w, 20), h = bit(w, 11);
  const bool fp = (opcode == 0b0001 || opcode == 0b0101 || opcode == 0b1001) && size >= 2;
  if (fp) {
    if (opcode != 0b1001 && u) return;
    i.esize = (size & 1) ? 8 : 4;
    if (i.esize == 8) {
      if (l || (!i.q && !i.scalar)) return;
      i.index2 = static_cast<uint8_t>(h);
    } else {
      i.index2 = static_cast<uint8_t>((h << 1) | l);
    }
    i.rm = static_cast<uint8_t>((m << 4) | bits(w, 19, 16));
    i.op = Op::VecElemOp;
    i.shift = static_cast<uint8_t>(opcode == 0b0001 ? VecElemKind::FMla
                                   : opcode == 0b0101 ? VecElemKind::FMls
                                   : u              ? VecElemKind::FMulX
                                                    : VecElemKind::FMul);
    return;
  }
  if (size != 1 && size != 2) return;
  i.esize = static_cast<uint8_t>(1u << size);
  if (size == 1) {
    i.index2 = static_cast<uint8_t>((h << 2) | (l << 1) | m);
    i.rm = static_cast<uint8_t>(bits(w, 19, 16));
  } else {
    i.index2 = static_cast<uint8_t>((h << 1) | l);
    i.rm = static_cast<uint8_t>((m << 4) | bits(w, 19, 16));
  }
  i.mem_signed = !u;
  i.index = i.q;
  VecElemKind k;
  switch ((u << 4) | opcode) {
    case 0b10000: k = VecElemKind::Mla; break;
    case 0b10100: k = VecElemKind::Mls; break;
    case 0b01000: k = VecElemKind::Mul; break;
    case 0b00010: case 0b10010: k = VecElemKind::MlaL; break;
    case 0b00110: case 0b10110: k = VecElemKind::MlsL; break;
    case 0b01010: case 0b11010: k = VecElemKind::MulL; break;
    case 0b00011: k = VecElemKind::SqDMlaL; break;
    case 0b00111: k = VecElemKind::SqDMlsL; break;
    case 0b01011: k = VecElemKind::SqDMulL; break;
    case 0b01100: k = VecElemKind::SqDMulH; break;
    case 0b01101: k = VecElemKind::SqRDMulH; break;
    default: return;
  }
  if (i.scalar && (k == VecElemKind::Mla || k == VecElemKind::Mls || k == VecElemKind::Mul || k == VecElemKind::MlaL ||
                   k == VecElemKind::MlsL || k == VecElemKind::MulL))
    return;
  i.op = Op::VecElemOp;
  i.shift = static_cast<uint8_t>(k);
}

void decode_fp_fixed_conversion(Instruction& i, uint32_t w) {
  i.sf = bit(w, 31);
  const unsigned ftype = bits(w, 23, 22);
  const unsigned rmode = bits(w, 20, 19);
  const unsigned opcode = bits(w, 18, 16);
  const unsigned scale = bits(w, 15, 10);
  i.mem_size = fp_size(ftype);
  if (!i.mem_size || (!i.sf && scale < 32)) return;
  i.imm = 64 - scale;
  if (rmode == 0 && (opcode == 2 || opcode == 3)) {
    i.op = Op::FpFixedToFp;
    i.mem_signed = opcode == 2;
  } else if (rmode == 3 && (opcode == 0 || opcode == 1)) {
    i.op = Op::FpToFixed;
    i.mem_signed = opcode == 0;
  }
}

}  // namespace

bool decode_simd_structure(Instruction& i, uint32_t w) {
  const bool multi_post = (w & 0xBFA00000u) == 0x0C800000u;
  const bool multi = (w & 0xBFBF0000u) == 0x0C000000u || multi_post;
  const bool single_post = (w & 0xBF800000u) == 0x0D800000u;
  const bool single = (w & 0xBF9F0000u) == 0x0D000000u || single_post;
  if (!multi && !single) return false;

  i.q = bit(w, 30);
  i.rd = bits(w, 4, 0);
  i.rn = bits(w, 9, 5);
  i.vector = true;
  const bool load = bit(w, 22);
  const unsigned size = bits(w, 11, 10);

  if (multi) {
    unsigned rpt = 0, selem = 0;
    switch (bits(w, 15, 12)) {
      case 0b0000: rpt = 1; selem = 4; break;
      case 0b0010: rpt = 4; selem = 1; break;
      case 0b0100: rpt = 1; selem = 3; break;
      case 0b0110: rpt = 3; selem = 1; break;
      case 0b0111: rpt = 1; selem = 1; break;
      case 0b1000: rpt = 1; selem = 2; break;
      case 0b1010: rpt = 2; selem = 1; break;
      default: return true;  // Invalid
    }
    if (size == 3 && !i.q && selem > 1) return true;
    i.op = load ? Op::VLdMulti : Op::VStMulti;
    i.esize = static_cast<uint8_t>(1u << size);
    i.ra = static_cast<uint8_t>(rpt * selem);
    i.amount = static_cast<uint8_t>(selem);
    i.mem_size = i.q ? 16 : 8;
    i.imm = i.ra * i.mem_size;
    if (multi_post) {
      i.mode = AddrMode::PostIndex;
      i.rm = bits(w, 20, 16);
      i.imm_form = i.rm == 31;
    }
    return true;
  }

  const unsigned opcode = bits(w, 15, 13);
  const bool s = bit(w, 12);
  const unsigned selem = (((opcode & 1) << 1) | bit(w, 21)) + 1;
  i.amount = static_cast<uint8_t>(selem);
  switch (opcode >> 1) {
    case 0:
      i.esize = 1;
      i.index = static_cast<uint8_t>((i.q << 3) | (s << 2) | size);
      break;
    case 1:
      if (size & 1) return true;
      i.esize = 2;
      i.index = static_cast<uint8_t>((i.q << 2) | (s << 1) | (size >> 1));
      break;
    case 2:
      if (size & 2) return true;
      if (size & 1) {
        if (s) return true;
        i.esize = 8;
        i.index = i.q;
      } else {
        i.esize = 4;
        i.index = static_cast<uint8_t>((i.q << 1) | s);
      }
      break;
    default:  // replicate
      if (!load || s) return true;
      i.esize = static_cast<uint8_t>(1u << size);
      break;
  }
  i.op = (opcode >> 1) == 3 ? Op::VLdRep : load ? Op::VLdLane : Op::VStLane;
  i.imm = selem * i.esize;
  if (single_post) {
    i.mode = AddrMode::PostIndex;
    i.rm = bits(w, 20, 16);
    i.imm_form = i.rm == 31;
  }
  return true;
}

void decode_simd_fp(Instruction& i, uint32_t w) {
  i.rd = bits(w, 4, 0);
  i.rn = bits(w, 9, 5);
  i.rm = bits(w, 20, 16);
  i.q = bit(w, 30);
  i.op = Op::Unsupported;

  // --- scalar floating point ---
  if ((w & 0x7F200000u) == 0x1E000000u) {  // conversion between FP and fixed point
    decode_fp_fixed_conversion(i, w);
    return;
  }
  if ((w & 0x7F20FC00u) == 0x1E200000u) {
    decode_fp_int_conversion(i, w);
    return;
  }
  if ((w & 0xFF000000u) == 0x1F000000u) {  // 3 source
    i.mem_size = fp_size(bits(w, 23, 22));
    if (!i.mem_size) return;
    i.op = Op::FpFma;
    i.ra = bits(w, 14, 10);
    i.shift = static_cast<uint8_t>((bit(w, 21) << 1) | bit(w, 15));
    return;
  }
  if ((w & 0xFF200000u) == 0x1E200000u) {
    decode_fp_data(i, w);
    return;
  }

  // --- Advanced SIMD ---
  if ((w & 0xFFE0FC00u) == 0x5E000400u) {  // scalar copy: DUP Vd, Vn.T[i] (MOV scalar)
    unsigned imm5 = bits(w, 20, 16);
    if ((imm5 & 0xF) == 0) return;
    unsigned size = static_cast<unsigned>(std::countr_zero(imm5));
    i.esize = static_cast<uint8_t>(1u << size);
    i.index2 = static_cast<uint8_t>(imm5 >> (size + 1));
    i.op = Op::VDupScalar;
    return;
  }

  if ((w & 0xFFFFFC00u) == 0x5EF1B800u) {  // ADDP Dd, Vn.2D
    i.op = Op::VecAddPScalar;
    return;
  }
  if ((w & 0xDF3E0C00u) == 0x5E300800u) {  // scalar pairwise, floating point: FADDP / FMAXP / ... (2 lanes)
    const unsigned opcode = bits(w, 16, 12), size = bits(w, 23, 22);
    if (!bit(w, 29)) return;  // (half precision forms)
    i.scalar = true;
    i.esize = (size & 1) ? 8 : 4;
    const bool min = size >> 1;
    VecFp f;
    switch (opcode) {
      case 0b01100: f = min ? VecFp::MinNmP : VecFp::MaxNmP; break;
      case 0b01101: if (min) return; f = VecFp::AddP; break;
      case 0b01111: f = min ? VecFp::MinP : VecFp::MaxP; break;
      default: return;
    }
    i.op = Op::VecFpOp;
    i.shift = static_cast<uint8_t>(f);
    return;
  }
  if ((w & 0xDF200400u) == 0x5E200400u) {  // scalar three same
    i.scalar = true;
    i.q = false;
    decode_three_same(i, w);
    return;
  }
  if ((w & 0xDF3E0C00u) == 0x5E200800u) {  // scalar two-register miscellaneous
    i.scalar = true;
    i.q = false;
    decode_two_reg_misc(i, w);
    return;
  }
  if ((w & 0xDF800400u) == 0x5F000400u && bits(w, 22, 19) != 0) {  // scalar shift by immediate
    i.scalar = true;
    i.q = false;
    decode_shift_immediate(i, w);
    return;
  }
  if ((w & 0xDF000400u) == 0x5F000000u) {  // scalar by element
    i.scalar = true;
    i.q = false;
    decode_by_element(i, w);
    return;
  }
  if ((w & 0xBFE08C00u) == 0x0E000000u) {  // TBL / TBX
    i.op = Op::VecTbl;
    i.esize = 1;
    i.amount = static_cast<uint8_t>(bits(w, 14, 13) + 1);
    i.index = bit(w, 12);
    return;
  }
  if ((w & 0x9F200C00u) == 0x0E200000u) {  // three different
    decode_three_different(i, w);
    return;
  }
  if ((w & 0x9F000400u) == 0x0F000000u) {  // by element
    decode_by_element(i, w);
    return;
  }

  if ((w & 0x9FF80400u) == 0x0F000400u) {  // modified immediate
    unsigned op = bit(w, 29);
    unsigned cmode = bits(w, 15, 12);
    unsigned imm8 = (bits(w, 18, 16) << 5) | bits(w, 9, 5);
    if (bit(w, 11)) return;  // FMOV (half precision)
    if (op == 1 && cmode == 0b1111 && !i.q) { i.op = Op::Invalid; return; }
    uint64_t value = expand_simd_immediate(op, cmode, imm8);
    bool is_orr_bic = (cmode & 1) && cmode < 0b1100;
    if (is_orr_bic) {
      i.op = op ? Op::VBicImm : Op::VOrrImm;
    } else {
      bool inverted = op && cmode != 0b1110 && cmode != 0b1111;  // MVNI
      i.op = Op::VMovImm;
      if (inverted) value = ~value;
    }
    i.imm = static_cast<int64_t>(value);
    return;
  }

  if ((w & 0x9F800400u) == 0x0F000400u) {  // shift by immediate (immh != 0)
    decode_shift_immediate(i, w);
    return;
  }

  if ((w & 0x9FE08400u) == 0x0E000400u) {  // copy
    unsigned op = bit(w, 29);
    unsigned imm5 = bits(w, 20, 16);
    unsigned imm4 = bits(w, 14, 11);
    if ((imm5 & 0xF) == 0) return;
    unsigned size = static_cast<unsigned>(std::countr_zero(imm5));
    i.esize = static_cast<uint8_t>(1u << size);
    i.index = static_cast<uint8_t>(imm5 >> (size + 1));
    if (op == 1) {
      if (!i.q) return;
      i.op = Op::VInsElem;
      i.index2 = static_cast<uint8_t>(imm4 >> size);
      return;
    }
    switch (imm4) {
      case 0b0000:
        if (size == 3 && !i.q) return;
        i.op = Op::VDupElem;
        i.index2 = i.index;
        return;
      case 0b0001:
        if (size == 3 && !i.q) return;
        i.op = Op::VDupGp;
        return;
      case 0b0011:
        i.op = Op::VInsGp;
        return;
      case 0b0101:  // SMOV
        if (size >= 2 && !(size == 2 && i.q)) return;
        i.op = Op::VSmov;
        i.sf = i.q;
        return;
      case 0b0111:  // UMOV
        if ((size == 3) != i.q) return;
        i.op = Op::VUmov;
        i.sf = i.q;
        return;
      default:
        return;
    }
  }

  if ((w & 0x9F200400u) == 0x0E200400u) {  // three same
    decode_three_same(i, w);
    return;
  }
  if ((w & 0x9F3E0C00u) == 0x0E200800u) {  // two-register miscellaneous
    decode_two_reg_misc(i, w);
    return;
  }
  if ((w & 0x9F3E0C00u) == 0x0E300800u) {  // across lanes
    decode_across_lanes(i, w);
    return;
  }
  if ((w & 0xBF208C00u) == 0x0E000800u) {  // permute
    static constexpr Op ops[8] = {Op::Unsupported, Op::VecUzp, Op::VecTrn, Op::VecZip,
                                  Op::Unsupported, Op::VecUzp, Op::VecTrn, Op::VecZip};
    unsigned opcode = bits(w, 14, 12);
    unsigned size = bits(w, 23, 22);
    if (size == 3 && !i.q) return;
    i.op = ops[opcode];
    i.esize = static_cast<uint8_t>(1u << size);
    i.index = static_cast<uint8_t>(opcode >> 2);
    return;
  }
  if ((w & 0xBFE08400u) == 0x2E000000u) {  // EXT
    i.imm = bits(w, 14, 11);
    if (!i.q && i.imm >= 8) return;
    i.op = Op::VecExt;
    return;
  }
}

}  // namespace juice::arm64::detail
