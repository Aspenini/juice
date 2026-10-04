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
  if (size == 3 && !i.q) return;

  auto cmp = [&](uint8_t pred) {
    i.op = Op::VecCmp;
    i.shift = pred;
  };
  switch (opcode) {
    case 0b10000: i.op = u ? Op::VecSub : Op::VecAdd; break;
    case 0b10001: cmp(u ? kEq : kTst); break;
    case 0b00110: cmp(u ? kHi : kGt); break;
    case 0b00111: cmp(u ? kHs : kGe); break;
    case 0b01100: i.op = Op::VecMax; i.mem_signed = !u; break;
    case 0b01101: i.op = Op::VecMin; i.mem_signed = !u; break;
    case 0b10100: i.op = Op::VecMaxP; i.mem_signed = !u; break;
    case 0b10101: i.op = Op::VecMinP; i.mem_signed = !u; break;
    case 0b10111: if (!u) i.op = Op::VecAddP; break;
    case 0b10011: if (!u && size != 3) i.op = Op::VecMul; break;
    default: break;
  }
}

void decode_two_reg_misc(Instruction& i, uint32_t w) {
  const bool u = bit(w, 29);
  const unsigned size = bits(w, 23, 22);
  const unsigned opcode = bits(w, 16, 12);
  i.esize = static_cast<uint8_t>(1u << size);
  auto zero_cmp = [&](VecZeroCmp c) {
    if (size == 3 && !i.q) return;
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
      break;
    case 0b01000: zero_cmp(u ? VecZeroCmp::Ge : VecZeroCmp::Gt); break;
    case 0b01001: zero_cmp(u ? VecZeroCmp::Le : VecZeroCmp::Eq); break;
    case 0b01010: if (!u) zero_cmp(VecZeroCmp::Lt); break;
    case 0b01011:
      if (size != 3 || i.q) i.op = u ? Op::VecNeg : Op::VecAbs;
      break;
    case 0b10010:  // XTN / XTN2: esize is the narrow (destination) size
      if (!u && size != 3) {
        i.op = Op::VecXtn;
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
  switch (opcode) {
    case 0b00000:  // SSHR / USHR
      if (i.esize == 8 && !i.q) return;
      i.op = Op::VecShr;
      i.mem_signed = !u;
      i.imm = 2 * ebits - immhb;
      break;
    case 0b01010:  // SHL
      if (u || (i.esize == 8 && !i.q)) return;
      i.op = Op::VecShl;
      i.imm = immhb - ebits;
      break;
    case 0b10000:  // SHRN / SHRN2 (esize = destination element size)
      if (u || i.esize == 8) return;
      i.op = Op::VecShrn;
      i.imm = 2 * ebits - immhb;
      i.index = i.q;
      break;
    case 0b10100:  // SSHLL / USHLL (esize = source element size)
      if (i.esize == 8) return;
      i.op = Op::VecShll;
      i.mem_signed = !u;
      i.imm = immhb - ebits;
      i.index = i.q;
      break;
    default:
      break;
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
