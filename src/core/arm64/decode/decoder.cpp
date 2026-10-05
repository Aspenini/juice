#include "core/arm64/decode/instruction.hpp"

#include <bit>

#include "core/arm64/decode/decoder_detail.hpp"

// Instruction fields are extracted with bits() and stored in narrow members;
// every field fits its member by construction.
#ifdef _MSC_VER
#pragma warning(disable : 4244 4805)
#endif

namespace juice::arm64 {
namespace {

constexpr uint32_t bits(uint32_t v, unsigned hi, unsigned lo) {
  return (v >> lo) & ((hi - lo == 31) ? 0xFFFFFFFFu : ((1u << (hi - lo + 1)) - 1));
}
constexpr bool bit(uint32_t v, unsigned n) { return (v >> n) & 1; }
constexpr int64_t sext(uint64_t v, unsigned width) {
  return static_cast<int64_t>(v << (64 - width)) >> (64 - width);
}

uint64_t replicate(uint64_t value, unsigned esize) {
  uint64_t out = 0;
  for (unsigned i = 0; i < 64; i += esize) out |= value << i;
  return out;
}

// --- Data processing (immediate) ------------------------------------------

void decode_dp_imm(Instruction& i, uint32_t w) {
  i.sf = bit(w, 31);
  i.rd = bits(w, 4, 0);
  i.rn = bits(w, 9, 5);

  switch (bits(w, 25, 23)) {
    case 0b000:
    case 0b001: {  // PC-relative addressing
      int64_t imm = sext((uint64_t{bits(w, 23, 5)} << 2) | bits(w, 30, 29), 21);
      if (bit(w, 31)) {
        i.op = Op::Adrp;
        i.imm = static_cast<int64_t>((i.pc & ~uint64_t{0xFFF}) + (static_cast<uint64_t>(imm) << 12));
      } else {
        i.op = Op::Adr;
        i.imm = static_cast<int64_t>(i.pc + static_cast<uint64_t>(imm));
      }
      i.sf = true;
      return;
    }
    case 0b010: {  // Add/subtract (immediate)
      uint64_t imm = bits(w, 21, 10);
      if (bit(w, 22)) imm <<= 12;
      i.op = bit(w, 30) ? Op::SubImm : Op::AddImm;
      i.set_flags = bit(w, 29);
      i.imm = static_cast<int64_t>(imm);
      return;
    }
    case 0b100: {  // Logical (immediate)
      unsigned opc = bits(w, 30, 29);
      uint64_t mask;
      if (!decode_logical_immediate(i.sf, bit(w, 22), bits(w, 21, 16), bits(w, 15, 10), mask)) return;
      static constexpr Op ops[4] = {Op::AndImm, Op::OrrImm, Op::EorImm, Op::AndImm};
      i.op = ops[opc];
      i.set_flags = opc == 3;
      i.imm = static_cast<int64_t>(mask);
      return;
    }
    case 0b101: {  // Move wide (immediate)
      unsigned opc = bits(w, 30, 29);
      unsigned hw = bits(w, 22, 21);
      if (opc == 1 || (!i.sf && hw > 1)) return;
      i.op = opc == 0 ? Op::Movn : opc == 2 ? Op::Movz : Op::Movk;
      i.imm = bits(w, 20, 5);
      i.amount = static_cast<uint8_t>(hw * 16);
      return;
    }
    case 0b110: {  // Bitfield
      unsigned opc = bits(w, 30, 29);
      if (opc == 3 || bit(w, 22) != i.sf) return;
      i.immr = bits(w, 21, 16);
      i.imms = bits(w, 15, 10);
      if (!i.sf && (i.immr >= 32 || i.imms >= 32)) return;
      static constexpr Op ops[3] = {Op::Sbfm, Op::Bfm, Op::Ubfm};
      i.op = ops[opc];
      return;
    }
    case 0b111: {  // Extract
      if (bits(w, 30, 29) != 0 || bit(w, 21) || bit(w, 22) != i.sf) return;
      i.rm = bits(w, 20, 16);
      i.immr = bits(w, 15, 10);
      if (!i.sf && i.immr >= 32) return;
      i.op = Op::Extr;
      return;
    }
    default:
      i.op = Op::Unsupported;  // add/sub with tags (MTE)
      return;
  }
}

// --- Branches, exception generation and system ------------------------------

void decode_system(Instruction& i, uint32_t w) {
  bool l = bit(w, 21);
  unsigned op0 = bits(w, 20, 19);
  unsigned op1 = bits(w, 18, 16);
  unsigned crn = bits(w, 15, 12);
  unsigned crm = bits(w, 11, 8);
  unsigned op2 = bits(w, 7, 5);
  i.rd = bits(w, 4, 0);

  if (op0 == 0) {
    if (l) return;
    if (crn == 2 && op1 == 3 && i.rd == 31) {  // HINT: NOP, YIELD, BTI, PAC*SP, ...
      i.op = Op::Nop;
    } else if (crn == 3 && op1 == 3 && i.rd == 31) {  // barriers
      // x86-64 already orders loads and stores except a store followed by a
      // load, so only DMB/DSB covering both reads and writes need a fence.
      // ISB/SB and the load-only / store-only variants are free.
      if (op2 == 2) i.op = Op::Clrex;
      else if ((op2 == 4 || op2 == 5) && (crm & 3) == 3) i.op = Op::Barrier;
      else i.op = Op::Nop;
    } else if (crn == 4 && i.rd == 31) {  // MSR (immediate) to PSTATE fields
      i.op = Op::Nop;
    }
    return;
  }
  if (op0 == 1) {  // SYS / SYSL (cache maintenance, TLBI, ...)
    if (!l && op1 == 3 && crn == 7 && crm == 4 && op2 == 1) {
      i.op = Op::DcZva;  // block size 64 bytes, as DCZID_EL0 reports
    } else if (!l) {
      i.op = Op::Nop;  // DC CVAU, IC IVAU, ...: no-op for a translator with coherent caches
    } else {
      i.op = Op::Unsupported;
    }
    return;
  }
  i.op = l ? Op::Mrs : Op::Msr;
  i.sysreg = sysreg::make(op0, op1, crn, crm, op2);
}

void decode_branch_reg(Instruction& i, uint32_t w) {
  unsigned opc = bits(w, 24, 21);
  unsigned op2 = bits(w, 20, 16);
  unsigned op3 = bits(w, 15, 10);
  unsigned op4 = bits(w, 4, 0);
  i.rn = bits(w, 9, 5);
  if (op2 != 31) return;

  bool plain = op3 == 0 && op4 == 0;
  bool pac_zero = (op3 == 2 || op3 == 3) && op4 == 31;  // BRAAZ, RETAA, ...
  switch (opc) {
    case 0b0000:
      if (plain || pac_zero) i.op = Op::Br;
      break;
    case 0b0001:
      if (plain || pac_zero) i.op = Op::Blr;
      break;
    case 0b0010:
      if (plain) {
        i.op = Op::Ret;
      } else if ((op3 == 2 || op3 == 3) && i.rn == 31 && op4 == 31) {
        i.op = Op::Ret;  // RETAA / RETAB: pointer authentication is not modelled
        i.rn = 30;
      }
      break;
    case 0b1000:  // BRAA / BRAB
      if (op3 == 2 || op3 == 3) i.op = Op::Br;
      break;
    case 0b1001:  // BLRAA / BLRAB
      if (op3 == 2 || op3 == 3) i.op = Op::Blr;
      break;
    default:
      break;
  }
}

void decode_branch(Instruction& i, uint32_t w) {
  if (bits(w, 30, 26) == 0b00101) {
    i.op = bit(w, 31) ? Op::Bl : Op::B;
    i.imm = static_cast<int64_t>(i.pc + static_cast<uint64_t>(sext(uint64_t{bits(w, 25, 0)} << 2, 28)));
  } else if (bits(w, 30, 25) == 0b011010) {
    i.op = bit(w, 24) ? Op::Cbnz : Op::Cbz;
    i.sf = bit(w, 31);
    i.rd = bits(w, 4, 0);
    i.imm = static_cast<int64_t>(i.pc + static_cast<uint64_t>(sext(uint64_t{bits(w, 23, 5)} << 2, 21)));
  } else if (bits(w, 30, 25) == 0b011011) {
    i.op = bit(w, 24) ? Op::Tbnz : Op::Tbz;
    i.rd = bits(w, 4, 0);
    i.amount = static_cast<uint8_t>((bit(w, 31) << 5) | bits(w, 23, 19));
    i.sf = bit(w, 31);
    i.imm = static_cast<int64_t>(i.pc + static_cast<uint64_t>(sext(uint64_t{bits(w, 18, 5)} << 2, 16)));
  } else if (bits(w, 31, 25) == 0b0101010 && !bit(w, 24)) {
    i.op = Op::BCond;  // bit 4 set is BC.cond, which behaves identically here
    i.cond = bits(w, 3, 0);
    i.imm = static_cast<int64_t>(i.pc + static_cast<uint64_t>(sext(uint64_t{bits(w, 23, 5)} << 2, 21)));
  } else if (bits(w, 31, 24) == 0b11010100) {
    unsigned opc = bits(w, 23, 21);
    unsigned ll = bits(w, 1, 0);
    i.imm = bits(w, 20, 5);
    if (bits(w, 4, 2) != 0) return;
    if (opc == 0 && ll == 1) i.op = Op::Svc;
    else if (opc == 1 && ll == 0) i.op = Op::Brk;
    else if (opc == 2 && ll == 0) i.op = Op::Hlt;
    else if (opc == 0 && (ll == 2 || ll == 3)) i.op = Op::Unsupported;  // HVC / SMC
  } else if (bits(w, 31, 22) == 0b1101010100) {
    decode_system(i, w);
  } else if (bits(w, 31, 25) == 0b1101011) {
    decode_branch_reg(i, w);
  }
}

// --- Loads and stores ------------------------------------------------------

// Fill in size/sign/direction for single-register load/store encodings.
bool set_single_reg(Instruction& i, unsigned size, bool v, unsigned opc) {
  i.vector = v;
  if (v) {
    unsigned scale = ((opc & 2) << 1) | size;
    if (scale > 4) return false;
    i.mem_size = static_cast<uint8_t>(1u << scale);
    i.op = (opc & 1) ? Op::Ldr : Op::Str;
    return true;
  }
  i.mem_size = static_cast<uint8_t>(1u << size);
  switch (opc) {
    case 0: i.op = Op::Str; break;
    case 1: i.op = Op::Ldr; break;
    case 2:
      if (size == 3) {
        i.op = Op::Prfm;
      } else {
        i.op = Op::Ldr;
        i.mem_signed = true;
        i.mem_to_64 = true;
      }
      break;
    case 3:
      if (size >= 2) return false;
      i.op = Op::Ldr;
      i.mem_signed = true;
      i.mem_to_64 = false;
      break;
  }
  i.sf = i.mem_size == 8 || (i.mem_signed && i.mem_to_64);
  return true;
}

void decode_exclusive(Instruction& i, uint32_t w) {
  unsigned size = bits(w, 31, 30);
  bool o2 = bit(w, 23), l = bit(w, 22), o1 = bit(w, 21);
  i.rm = bits(w, 20, 16);  // Rs
  i.ra = bits(w, 14, 10);  // Rt2
  i.mem_size = static_cast<uint8_t>(1u << size);
  i.sf = size == 3;

  if (!o2 && !o1) {
    i.op = l ? Op::Ldxr : Op::Stxr;
  } else if (!o2 && o1) {
    if (size < 2) {  // CASP / CASPA / CASPL / CASPAL: size<0> selects 64-bit register pairs
      if (i.ra != 31 || (i.rm & 1) || (bits(w, 4, 0) & 1)) return;
      i.op = Op::Casp;
      i.sf = size == 1;
      i.mem_size = size == 1 ? 16 : 8;
      return;
    }
    i.op = l ? Op::Ldxp : Op::Stxp;
  } else if (o2 && !o1) {
    i.op = l ? Op::Ldr : Op::Str;  // LDAR / STLR (and LDLAR / STLLR)
    i.mode = AddrMode::Offset;
    i.imm = 0;
    i.release = !l;
  } else {
    if (i.ra != 31) return;
    i.op = Op::Cas;
  }
}

void decode_atomic(Instruction& i, uint32_t w) {
  unsigned size = bits(w, 31, 30);
  i.rm = bits(w, 20, 16);  // Rs
  i.mem_size = static_cast<uint8_t>(1u << size);
  i.sf = size == 3;
  bool o3 = bit(w, 15);
  unsigned opc = bits(w, 14, 12);
  if (!o3) {
    static constexpr Op ops[8] = {Op::Ldadd, Op::Ldclr, Op::Ldeor, Op::Ldset,
                                  Op::Ldsmax, Op::Ldsmin, Op::Ldumax, Op::Ldumin};
    i.op = ops[opc];
  } else if (opc == 0) {
    i.op = Op::Swp;
  } else if (opc == 4) {  // LDAPR
    i.op = Op::Ldr;
    i.mode = AddrMode::Offset;
    i.imm = 0;
    i.rm = 0;
  }
}

void decode_ldst(Instruction& i, uint32_t w) {
  unsigned size = bits(w, 31, 30);
  bool v = bit(w, 26);
  i.rd = bits(w, 4, 0);
  i.rn = bits(w, 9, 5);

  if (bits(w, 29, 24) == 0b001000 && !v) {
    decode_exclusive(i, w);
    return;
  }

  if (detail::decode_simd_structure(i, w)) return;

  if (bits(w, 29, 27) == 0b011 && bits(w, 25, 24) == 0) {  // load register (literal)
    unsigned opc = size;
    i.mode = AddrMode::Literal;
    i.imm = static_cast<int64_t>(i.pc + static_cast<uint64_t>(sext(uint64_t{bits(w, 23, 5)} << 2, 21)));
    i.op = Op::Ldr;
    if (v) {
      if (opc == 3) { i.op = Op::Invalid; return; }
      i.vector = true;
      i.mem_size = static_cast<uint8_t>(4u << opc);
    } else if (opc == 3) {
      i.op = Op::Prfm;
    } else {
      i.mem_size = opc == 0 ? 4 : opc == 1 ? 8 : 4;
      i.mem_signed = opc == 2;
      i.sf = opc != 0;
    }
    return;
  }

  if (bits(w, 29, 27) == 0b101) {  // load/store pair
    unsigned opc = size;
    bool l = bit(w, 22);
    unsigned m = bits(w, 25, 23);
    i.ra = bits(w, 14, 10);
    i.vector = v;
    if (v) {
      if (opc == 3) return;
      i.mem_size = static_cast<uint8_t>(4u << opc);
    } else if (opc == 0) {
      i.mem_size = 4;
      i.sf = false;
    } else if (opc == 1) {
      if (!l) { i.op = Op::Unsupported; return; }  // STGP
      i.mem_size = 4;
      i.mem_signed = true;  // LDPSW
      i.sf = true;
    } else if (opc == 2) {
      i.mem_size = 8;
    } else {
      return;
    }
    i.mode = m == 1 ? AddrMode::PostIndex : m == 3 ? AddrMode::PreIndex : AddrMode::Offset;
    i.imm = sext(bits(w, 21, 15), 7) * i.mem_size;
    i.op = l ? Op::Ldp : Op::Stp;
    return;
  }

  if (bits(w, 29, 24) == 0b011001 && !bit(w, 21) && bits(w, 11, 10) == 0 && !v) {
    // LDAPUR / STLUR family: unscaled offset with release/acquire semantics.
    if (!set_single_reg(i, size, false, bits(w, 23, 22))) { i.op = Op::Invalid; return; }
    i.mode = AddrMode::Offset;
    i.imm = sext(bits(w, 20, 12), 9);
    i.release = i.op == Op::Str;
    return;
  }

  if (bits(w, 29, 27) != 0b111) return;

  unsigned opc = bits(w, 23, 22);
  if (bits(w, 25, 24) == 0b01) {  // unsigned immediate offset
    if (!set_single_reg(i, size, v, opc)) { i.op = Op::Invalid; return; }
    i.mode = AddrMode::Offset;
    i.imm = static_cast<int64_t>(uint64_t{bits(w, 21, 10)} * (i.op == Op::Prfm ? 8 : i.mem_size));
    return;
  }
  if (bits(w, 25, 24) != 0) return;

  if (!bit(w, 21)) {  // unscaled / pre / post / unprivileged
    if (!set_single_reg(i, size, v, opc)) { i.op = Op::Invalid; return; }
    i.imm = sext(bits(w, 20, 12), 9);
    switch (bits(w, 11, 10)) {
      case 0: i.mode = AddrMode::Offset; break;    // LDUR / STUR
      case 1: i.mode = AddrMode::PostIndex; break;
      case 2: i.mode = AddrMode::Offset; break;    // LDTR / STTR
      case 3: i.mode = AddrMode::PreIndex; break;
    }
    return;
  }

  if (bits(w, 11, 10) == 0b10) {  // register offset
    unsigned option = bits(w, 15, 13);
    if (!(option & 2)) return;
    if (!set_single_reg(i, size, v, opc)) { i.op = Op::Invalid; return; }
    i.mode = AddrMode::RegOffset;
    i.rm = bits(w, 20, 16);
    i.shift = static_cast<uint8_t>(option);
    unsigned scale = static_cast<unsigned>(std::countr_zero(unsigned{i.mem_size ? i.mem_size : 8u}));
    i.amount = bit(w, 12) ? static_cast<uint8_t>(scale) : 0;
    return;
  }

  if (bits(w, 11, 10) == 0 && !v) {
    decode_atomic(i, w);
    return;
  }
  i.op = Op::Unsupported;
}

// --- Data processing (register) ---------------------------------------------

void decode_dp_reg(Instruction& i, uint32_t w) {
  i.sf = bit(w, 31);
  i.rd = bits(w, 4, 0);
  i.rn = bits(w, 9, 5);
  i.rm = bits(w, 20, 16);
  bool op0 = bit(w, 30);
  bool op1 = bit(w, 28);
  unsigned op2 = bits(w, 24, 21);

  if (!op1) {
    if (!(op2 & 0b1000)) {  // logical (shifted register)
      unsigned opc = bits(w, 30, 29);
      bool n = bit(w, 21);
      i.shift = bits(w, 23, 22);
      i.amount = bits(w, 15, 10);
      if (!i.sf && i.amount >= 32) return;
      static constexpr Op ops[4][2] = {{Op::AndReg, Op::BicReg},
                                       {Op::OrrReg, Op::OrnReg},
                                       {Op::EorReg, Op::EonReg},
                                       {Op::AndReg, Op::BicReg}};
      i.op = ops[opc][n];
      i.set_flags = opc == 3;
      return;
    }
    i.set_flags = bit(w, 29);
    bool sub = bit(w, 30);
    if (!(op2 & 1)) {  // add/subtract (shifted register)
      i.shift = bits(w, 23, 22);
      i.amount = bits(w, 15, 10);
      if (i.shift == 3 || (!i.sf && i.amount >= 32)) return;
      i.op = sub ? Op::SubShift : Op::AddShift;
    } else {  // add/subtract (extended register)
      if (bits(w, 23, 22) != 0) return;
      i.shift = bits(w, 15, 13);
      i.amount = bits(w, 12, 10);
      if (i.amount > 4) return;
      i.op = sub ? Op::SubExt : Op::AddExt;
    }
    return;
  }

  switch (op2) {
    case 0b0000:  // add/subtract with carry
      if (bits(w, 15, 10) != 0) return;
      i.set_flags = bit(w, 29);
      i.op = op0 ? Op::Sbc : Op::Adc;
      return;
    case 0b0010:  // conditional compare
      if (!bit(w, 29) || bit(w, 10) || bit(w, 4)) return;
      i.op = op0 ? Op::Ccmp : Op::Ccmn;
      i.cond = bits(w, 15, 12);
      i.nzcv = bits(w, 3, 0);
      i.imm_form = bit(w, 11);
      i.imm = i.rm;
      return;
    case 0b0100: {  // conditional select
      if (bit(w, 29)) return;
      unsigned o2 = bits(w, 11, 10);
      if (o2 > 1) return;
      static constexpr Op ops[2][2] = {{Op::Csel, Op::Csinc}, {Op::Csinv, Op::Csneg}};
      i.op = ops[op0][o2];
      i.cond = bits(w, 15, 12);
      return;
    }
    case 0b0110: {
      if (bit(w, 29)) return;
      unsigned opcode = bits(w, 15, 10);
      if (!op0) {  // data processing (2 source)
        switch (opcode) {
          case 0b000010: i.op = Op::Udiv; break;
          case 0b000011: i.op = Op::Sdiv; break;
          case 0b001000: i.op = Op::Lslv; break;
          case 0b001001: i.op = Op::Lsrv; break;
          case 0b001010: i.op = Op::Asrv; break;
          case 0b001011: i.op = Op::Rorv; break;
          default: i.op = Op::Unsupported; break;  // CRC32, PAC, ...
        }
      } else {  // data processing (1 source)
        if (i.rm != 0) { i.op = Op::Unsupported; return; }
        switch (opcode) {
          case 0b000000: i.op = Op::Rbit; break;
          case 0b000001: i.op = Op::Rev16; break;
          case 0b000010: i.op = i.sf ? Op::Rev32 : Op::Rev; break;
          case 0b000011: if (i.sf) i.op = Op::Rev; break;
          case 0b000100: i.op = Op::Clz; break;
          case 0b000101: i.op = Op::Cls; break;
          default: i.op = Op::Unsupported; break;
        }
      }
      return;
    }
    default:
      break;
  }

  if (op2 & 0b1000) {  // data processing (3 source)
    if (bits(w, 30, 29) != 0) return;
    unsigned op31 = bits(w, 23, 21);
    bool o0 = bit(w, 15);
    i.ra = bits(w, 14, 10);
    switch (op31) {
      case 0b000: i.op = o0 ? Op::Msub : Op::Madd; break;
      case 0b001: if (i.sf) i.op = o0 ? Op::Smsubl : Op::Smaddl; break;
      case 0b010: if (i.sf && !o0) i.op = Op::Smulh; break;
      case 0b101: if (i.sf) i.op = o0 ? Op::Umsubl : Op::Umaddl; break;
      case 0b110: if (i.sf && !o0) i.op = Op::Umulh; break;
      default: break;
    }
    return;
  }
  i.op = Op::Unsupported;
}

}  // namespace

bool decode_logical_immediate(bool sf, unsigned n, unsigned immr, unsigned imms, uint64_t& out) {
  if (!sf && n) return false;
  unsigned combined = (n << 6) | (~imms & 0x3F);
  if (combined == 0) return false;
  int len = 31 - std::countl_zero(combined);
  if (len < 1) return false;
  unsigned esize = 1u << len;
  unsigned levels = esize - 1;
  unsigned s = imms & levels;
  unsigned r = immr & levels;
  if (s == levels) return false;
  uint64_t welem = (s + 1 == 64) ? ~uint64_t{0} : ((uint64_t{1} << (s + 1)) - 1);
  uint64_t emask = esize == 64 ? ~uint64_t{0} : ((uint64_t{1} << esize) - 1);
  uint64_t rotated = r == 0 ? welem : (((welem >> r) | (welem << (esize - r))) & emask);
  uint64_t result = replicate(rotated, esize);
  if (!sf) result &= 0xFFFFFFFFu;
  out = result;
  return true;
}

uint64_t expand_simd_immediate(unsigned op, unsigned cmode, unsigned imm8) {
  uint64_t imm = imm8;
  switch (cmode >> 1) {
    case 0: return replicate(imm, 32);
    case 1: return replicate(imm << 8, 32);
    case 2: return replicate(imm << 16, 32);
    case 3: return replicate(imm << 24, 32);
    case 4: return replicate(imm, 16);
    case 5: return replicate(imm << 8, 16);
    case 6:
      if (cmode & 1) return replicate((imm << 16) | 0xFFFF, 32);
      return replicate((imm << 8) | 0xFF, 32);
    default:
      break;
  }
  if (!(cmode & 1)) {
    if (!op) return replicate(imm, 8);
    uint64_t out = 0;
    for (unsigned b = 0; b < 8; ++b)
      if (imm8 & (1u << b)) out |= uint64_t{0xFF} << (8 * b);
    return out;
  }
  uint64_t a = (imm8 >> 7) & 1, b = (imm8 >> 6) & 1, cdefgh = imm8 & 0x3F;
  if (!op) {  // single precision
    uint64_t f = (a << 31) | ((b ^ 1) << 30) | ((b ? 0x1FULL : 0) << 25) | (cdefgh << 19);
    return replicate(f, 32);
  }
  // double precision
  return (a << 63) | ((b ^ 1) << 62) | ((b ? 0xFFULL : 0) << 54) | (cdefgh << 48);
}

Instruction decode(uint32_t w, uint64_t pc) {
  Instruction i;
  i.raw = w;
  i.pc = pc;

  unsigned op0 = bits(w, 28, 25);
  if ((op0 & 0b1110) == 0b1000) {
    decode_dp_imm(i, w);
  } else if ((op0 & 0b1110) == 0b1010) {
    decode_branch(i, w);
  } else if ((op0 & 0b0101) == 0b0100) {
    decode_ldst(i, w);
  } else if ((op0 & 0b0111) == 0b0101) {
    decode_dp_reg(i, w);
  } else if ((op0 & 0b0111) == 0b0111) {
    detail::decode_simd_fp(i, w);
  } else if (op0 == 0 && (w >> 16) == 0) {
    i.op = Op::Udf;
    i.imm = w & 0xFFFF;
  }
  return i;
}

bool is_block_terminator(const Instruction& insn) {
  switch (insn.op) {
    case Op::B: case Op::Bl: case Op::BCond: case Op::Cbz: case Op::Cbnz:
    case Op::Tbz: case Op::Tbnz: case Op::Br: case Op::Blr: case Op::Ret:
    case Op::Svc: case Op::Brk: case Op::Hlt: case Op::Udf:
    case Op::Invalid: case Op::Unsupported:
      return true;
    default:
      return false;
  }
}

}  // namespace juice::arm64
