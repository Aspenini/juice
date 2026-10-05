#include <format>

#include "core/arm64/decode/instruction.hpp"

namespace juice::arm64 {

const char* mnemonic(Op op) {
  switch (op) {
    case Op::Invalid: return "<invalid>";
    case Op::Unsupported: return "<unsupported>";
    case Op::Adr: return "adr";
    case Op::Adrp: return "adrp";
    case Op::AddImm: return "add";
    case Op::SubImm: return "sub";
    case Op::AndImm: return "and";
    case Op::OrrImm: return "orr";
    case Op::EorImm: return "eor";
    case Op::Movn: return "movn";
    case Op::Movz: return "movz";
    case Op::Movk: return "movk";
    case Op::Sbfm: return "sbfm";
    case Op::Bfm: return "bfm";
    case Op::Ubfm: return "ubfm";
    case Op::Extr: return "extr";
    case Op::B: return "b";
    case Op::Bl: return "bl";
    case Op::BCond: return "b.";
    case Op::Cbz: return "cbz";
    case Op::Cbnz: return "cbnz";
    case Op::Tbz: return "tbz";
    case Op::Tbnz: return "tbnz";
    case Op::Br: return "br";
    case Op::Blr: return "blr";
    case Op::Ret: return "ret";
    case Op::Svc: return "svc";
    case Op::Brk: return "brk";
    case Op::Hlt: return "hlt";
    case Op::Udf: return "udf";
    case Op::Nop: return "nop";
    case Op::Clrex: return "clrex";
    case Op::Barrier: return "dmb";
    case Op::Mrs: return "mrs";
    case Op::Msr: return "msr";
    case Op::AndReg: return "and";
    case Op::BicReg: return "bic";
    case Op::OrrReg: return "orr";
    case Op::OrnReg: return "orn";
    case Op::EorReg: return "eor";
    case Op::EonReg: return "eon";
    case Op::AddShift: return "add";
    case Op::SubShift: return "sub";
    case Op::AddExt: return "add";
    case Op::SubExt: return "sub";
    case Op::Adc: return "adc";
    case Op::Sbc: return "sbc";
    case Op::Ccmn: return "ccmn";
    case Op::Ccmp: return "ccmp";
    case Op::Csel: return "csel";
    case Op::Csinc: return "csinc";
    case Op::Csinv: return "csinv";
    case Op::Csneg: return "csneg";
    case Op::Rbit: return "rbit";
    case Op::Rev16: return "rev16";
    case Op::Rev32: return "rev32";
    case Op::Rev: return "rev";
    case Op::Clz: return "clz";
    case Op::Cls: return "cls";
    case Op::Udiv: return "udiv";
    case Op::Sdiv: return "sdiv";
    case Op::Lslv: return "lsl";
    case Op::Lsrv: return "lsr";
    case Op::Asrv: return "asr";
    case Op::Rorv: return "ror";
    case Op::Madd: return "madd";
    case Op::Msub: return "msub";
    case Op::Smaddl: return "smaddl";
    case Op::Smsubl: return "smsubl";
    case Op::Umaddl: return "umaddl";
    case Op::Umsubl: return "umsubl";
    case Op::Smulh: return "smulh";
    case Op::Umulh: return "umulh";
    case Op::Ldr: return "ldr";
    case Op::Str: return "str";
    case Op::Ldp: return "ldp";
    case Op::Stp: return "stp";
    case Op::Prfm: return "prfm";
    case Op::DcZva: return "dc zva";
    case Op::IcIvau: return "ic ivau";
    case Op::Casp: return "casp";
    case Op::Ldxr: return "ldxr";
    case Op::Stxr: return "stxr";
    case Op::Ldxp: return "ldxp";
    case Op::Stxp: return "stxp";
    case Op::Cas: return "cas";
    case Op::Swp: return "swp";
    case Op::Ldadd: return "ldadd";
    case Op::Ldclr: return "ldclr";
    case Op::Ldeor: return "ldeor";
    case Op::Ldset: return "ldset";
    case Op::Ldsmax: return "ldsmax";
    case Op::Ldsmin: return "ldsmin";
    case Op::Ldumax: return "ldumax";
    case Op::Ldumin: return "ldumin";
    case Op::FmovToGp: return "fmov";
    case Op::FmovFromGp: return "fmov";
    case Op::FmovReg: return "fmov";
    case Op::VMovImm: return "movi";
    case Op::VOrrImm: return "orr";
    case Op::VBicImm: return "bic";
    case Op::VDupGp: return "dup";
    case Op::VDupElem: return "dup";
    case Op::VDupScalar: return "mov";
    case Op::VUmov: return "umov";
    case Op::VSmov: return "smov";
    case Op::VInsGp: return "ins";
    case Op::VInsElem: return "ins";
    case Op::VAnd: return "and";
    case Op::VBic: return "bic";
    case Op::VOrr: return "orr";
    case Op::VOrn: return "orn";
    case Op::VEor: return "eor";
    case Op::VLdMulti: return "ld";
    case Op::VStMulti: return "st";
    case Op::VLdLane: return "ld1";
    case Op::VStLane: return "st1";
    case Op::VLdRep: return "ld1r";
    case Op::VecAdd: return "add";
    case Op::VecSub: return "sub";
    case Op::VecMul: return "mul";
    case Op::VecCmp: return "cm";
    case Op::VecCmpZero: return "cm";
    case Op::VecMax: return "max";
    case Op::VecMin: return "min";
    case Op::VecMaxP: return "maxp";
    case Op::VecMinP: return "minp";
    case Op::VecAddP: return "addp";
    case Op::VecAddAcross: return "addv";
    case Op::VecMaxAcross: return "maxv";
    case Op::VecMinAcross: return "minv";
    case Op::VecAddLongAcross: return "addlv";
    case Op::VecAddPScalar: return "addp";
    case Op::VecShl: return "shl";
    case Op::VecShr: return "shr";
    case Op::VecShrn: return "shrn";
    case Op::VecXtn: return "xtn";
    case Op::VecShll: return "shll";
    case Op::VecCnt: return "cnt";
    case Op::VecNot: return "not";
    case Op::VecNeg: return "neg";
    case Op::VecAbs: return "abs";
    case Op::VecRev: return "rev";
    case Op::VecUzp: return "uzp";
    case Op::VecZip: return "zip";
    case Op::VecTrn: return "trn";
    case Op::VecExt: return "ext";
    case Op::VecBsl: return "bsl";
    case Op::VecBit: return "bit";
    case Op::VecBif: return "bif";
    case Op::VecIntOp: return "simd.int";
    case Op::VecFpOp: return "simd.fp";
    case Op::VecIntUnary: return "simd.int1";
    case Op::VecFpUnary: return "simd.fp1";
    case Op::VecLong: return "simd.long";
    case Op::VecShiftOp: return "simd.shift";
    case Op::VecElemOp: return "simd.elem";
    case Op::VecTbl: return "tbl";
    case Op::VecFpAcross: return "simd.fpv";
    case Op::FpFixedToFp: return "cvtf.fixed";
    case Op::FpToFixed: return "fcvtz.fixed";
    case Op::FpBinary: return "fp";
    case Op::FpUnary: return "fp";
    case Op::FpCvt: return "fcvt";
    case Op::FpRint: return "frint";
    case Op::FpFma: return "fmadd";
    case Op::FpCmp: return "fcmp";
    case Op::FpCcmp: return "fccmp";
    case Op::FpCsel: return "fcsel";
    case Op::FpMovImm: return "fmov";
    case Op::FpToInt: return "fcvtz";
    case Op::IntToFp: return "cvtf";
    case Op::Count_: break;
  }
  return "?";
}

namespace {

constexpr const char* kCond[16] = {"eq", "ne", "hs", "lo", "mi", "pl", "vs", "vc",
                                   "hi", "ls", "ge", "lt", "gt", "le", "al", "nv"};
constexpr const char* kShift[4] = {"lsl", "lsr", "asr", "ror"};
constexpr const char* kExtend[8] = {"uxtb", "uxth", "uxtw", "uxtx", "sxtb", "sxth", "sxtw", "sxtx"};

// General register name. `sp_ok` selects SP/WSP for register 31, otherwise XZR/WZR.
std::string gpr(unsigned r, bool x, bool sp_ok = false) {
  if (r == 31) return sp_ok ? (x ? "sp" : "wsp") : (x ? "xzr" : "wzr");
  return std::format("{}{}", x ? 'x' : 'w', r);
}

std::string fpr(unsigned r, unsigned bytes) {
  static constexpr char prefix[17] = {0, 'b', 'h', 0, 's', 0, 0, 0, 'd', 0, 0, 0, 0, 0, 0, 0, 'q'};
  return std::format("{}{}", prefix[bytes], r);
}

std::string hex(int64_t v) {
  if (v < 0) return std::format("#-0x{:x}", static_cast<uint64_t>(-v));
  return std::format("#0x{:x}", static_cast<uint64_t>(v));
}

std::string mem_operand(const Instruction& i) {
  std::string base = gpr(i.rn, true, true);
  switch (i.mode) {
    case AddrMode::Offset:
      return i.imm ? std::format("[{}, {}]", base, hex(i.imm)) : std::format("[{}]", base);
    case AddrMode::PreIndex:
      return std::format("[{}, {}]!", base, hex(i.imm));
    case AddrMode::PostIndex:
      return std::format("[{}], {}", base, hex(i.imm));
    case AddrMode::RegOffset: {
      bool x = (i.shift & 1) != 0;  // UXTX / SXTX / LSL use an X index register
      std::string ext = i.shift == static_cast<uint8_t>(Extend::Uxtx) ? "lsl" : kExtend[i.shift];
      if (i.amount == 0 && i.shift == static_cast<uint8_t>(Extend::Uxtx))
        return std::format("[{}, {}]", base, gpr(i.rm, x));
      return std::format("[{}, {}, {} #{}]", base, gpr(i.rm, x), ext, i.amount);
    }
    case AddrMode::Literal:
      return std::format("0x{:x}", static_cast<uint64_t>(i.imm));
  }
  return "?";
}

std::string data_reg(const Instruction& i, unsigned r) {
  if (i.vector) return fpr(r, i.mem_size);
  bool x = i.mem_signed ? i.mem_to_64 : i.mem_size == 8;
  return gpr(r, x);
}

std::string vreg_arrangement(unsigned r, bool q, unsigned esize) {
  static constexpr char suffix[9] = {0, 'b', 'h', 0, 's', 0, 0, 0, 'd'};
  unsigned lanes = (q ? 16 : 8) / esize;
  return std::format("v{}.{}{}", r, lanes, suffix[esize]);
}

}  // namespace

std::string disassemble(const Instruction& i) {
  const bool x = i.sf;
  std::string m = mnemonic(i.op);
  auto rd = [&](bool sp = false) { return gpr(i.rd, x, sp); };
  auto rn = [&](bool sp = false) { return gpr(i.rn, x, sp); };
  auto rm = [&] { return gpr(i.rm, x); };

  switch (i.op) {
    case Op::Invalid:
    case Op::Unsupported:
      return std::format("{} (0x{:08x})", m, i.raw);
    case Op::Adr:
    case Op::Adrp:
      return std::format("{} {}, 0x{:x}", m, gpr(i.rd, true), static_cast<uint64_t>(i.imm));
    case Op::AddImm:
    case Op::SubImm:
      return std::format("{}{} {}, {}, {}", m, i.set_flags ? "s" : "", rd(!i.set_flags), rn(true), hex(i.imm));
    case Op::AndImm:
    case Op::OrrImm:
    case Op::EorImm:
      return std::format("{}{} {}, {}, {}", m, i.set_flags ? "s" : "", rd(!i.set_flags), rn(), hex(i.imm));
    case Op::Movn:
    case Op::Movz:
    case Op::Movk:
      return i.amount ? std::format("{} {}, {}, lsl #{}", m, rd(), hex(i.imm), i.amount)
                      : std::format("{} {}, {}", m, rd(), hex(i.imm));
    case Op::Sbfm:
    case Op::Bfm:
    case Op::Ubfm:
      return std::format("{} {}, {}, #{}, #{}", m, rd(), rn(), i.immr, i.imms);
    case Op::Extr:
      return std::format("{} {}, {}, {}, #{}", m, rd(), rn(), rm(), i.immr);
    case Op::B:
    case Op::Bl:
      return std::format("{} 0x{:x}", m, static_cast<uint64_t>(i.imm));
    case Op::BCond:
      return std::format("b.{} 0x{:x}", kCond[i.cond], static_cast<uint64_t>(i.imm));
    case Op::Cbz:
    case Op::Cbnz:
      return std::format("{} {}, 0x{:x}", m, gpr(i.rd, x), static_cast<uint64_t>(i.imm));
    case Op::Tbz:
    case Op::Tbnz:
      return std::format("{} {}, #{}, 0x{:x}", m, gpr(i.rd, x), i.amount, static_cast<uint64_t>(i.imm));
    case Op::Br:
    case Op::Blr:
      return std::format("{} {}", m, gpr(i.rn, true));
    case Op::Ret:
      return i.rn == 30 ? m : std::format("{} {}", m, gpr(i.rn, true));
    case Op::Svc:
    case Op::Brk:
    case Op::Hlt:
    case Op::Udf:
      return std::format("{} {}", m, hex(i.imm));
    case Op::Nop:
    case Op::Clrex:
    case Op::Barrier:
      return m;
    case Op::Mrs:
      return std::format("mrs {}, s{}_{}_c{}_c{}_{}", gpr(i.rd, true), i.sysreg >> 14, (i.sysreg >> 11) & 7,
                         (i.sysreg >> 7) & 15, (i.sysreg >> 3) & 15, i.sysreg & 7);
    case Op::Msr:
      return std::format("msr s{}_{}_c{}_c{}_{}, {}", i.sysreg >> 14, (i.sysreg >> 11) & 7, (i.sysreg >> 7) & 15,
                         (i.sysreg >> 3) & 15, i.sysreg & 7, gpr(i.rd, true));
    case Op::AndReg: case Op::BicReg: case Op::OrrReg: case Op::OrnReg: case Op::EorReg: case Op::EonReg:
    case Op::AddShift: case Op::SubShift: {
      std::string s = std::format("{}{} {}, {}, {}", m, i.set_flags ? "s" : "", rd(), rn(), rm());
      if (i.amount) s += std::format(", {} #{}", kShift[i.shift], i.amount);
      return s;
    }
    case Op::AddExt:
    case Op::SubExt: {
      bool xm = (i.shift & 3) == 3;
      return std::format("{}{} {}, {}, {}, {} #{}", m, i.set_flags ? "s" : "", rd(!i.set_flags), rn(true),
                         gpr(i.rm, xm), kExtend[i.shift], i.amount);
    }
    case Op::Adc:
    case Op::Sbc:
      return std::format("{}{} {}, {}, {}", m, i.set_flags ? "s" : "", rd(), rn(), rm());
    case Op::Ccmn:
    case Op::Ccmp:
      return std::format("{} {}, {}, #{}, {}", m, rn(), i.imm_form ? hex(i.imm) : rm(), i.nzcv, kCond[i.cond]);
    case Op::Csel: case Op::Csinc: case Op::Csinv: case Op::Csneg:
      return std::format("{} {}, {}, {}, {}", m, rd(), rn(), rm(), kCond[i.cond]);
    case Op::Rbit: case Op::Rev16: case Op::Rev32: case Op::Rev: case Op::Clz: case Op::Cls:
      return std::format("{} {}, {}", m, rd(), rn());
    case Op::Udiv: case Op::Sdiv: case Op::Lslv: case Op::Lsrv: case Op::Asrv: case Op::Rorv:
    case Op::Smulh: case Op::Umulh:
      return std::format("{} {}, {}, {}", m, rd(), rn(), rm());
    case Op::Madd:
    case Op::Msub:
      return std::format("{} {}, {}, {}, {}", m, rd(), rn(), rm(), gpr(i.ra, x));
    case Op::Smaddl: case Op::Smsubl: case Op::Umaddl: case Op::Umsubl:
      return std::format("{} {}, {}, {}, {}", m, gpr(i.rd, true), gpr(i.rn, false), gpr(i.rm, false),
                         gpr(i.ra, true));
    case Op::Ldr:
    case Op::Str: {
      const char* suffix = "";
      if (!i.vector) {
        if (i.mem_size == 1) suffix = i.mem_signed ? "sb" : "b";
        else if (i.mem_size == 2) suffix = i.mem_signed ? "sh" : "h";
        else if (i.mem_size == 4 && i.mem_signed) suffix = "sw";
      }
      if (i.release) m = "stlr";
      return std::format("{}{} {}, {}", m, suffix, data_reg(i, i.rd), mem_operand(i));
    }
    case Op::Ldp:
    case Op::Stp:
      return std::format("{}{} {}, {}, {}", m, i.mem_signed ? "sw" : "", data_reg(i, i.rd), data_reg(i, i.ra),
                         mem_operand(i));
    case Op::Prfm:
      return std::format("prfm {}", mem_operand(i));
    case Op::DcZva:
      return std::format("dc zva, x{}", i.rd);
    case Op::IcIvau:
      return std::format("ic ivau, x{}", i.rd);
    case Op::Casp: {
      const char r = i.sf ? 'x' : 'w';
      return std::format("casp {}{}, {}{}, {}{}, {}{}, [x{}]", r, i.rm, r, i.rm + 1, r, i.rd, r, i.rd + 1, i.rn);
    }
    case Op::Ldxr:
      return std::format("{} {}, [{}]", m, gpr(i.rd, i.mem_size == 8), gpr(i.rn, true, true));
    case Op::Stxr:
      return std::format("{} {}, {}, [{}]", m, gpr(i.rm, false), gpr(i.rd, i.mem_size == 8), gpr(i.rn, true, true));
    case Op::Ldxp:
      return std::format("{} {}, {}, [{}]", m, gpr(i.rd, i.mem_size == 8), gpr(i.ra, i.mem_size == 8),
                         gpr(i.rn, true, true));
    case Op::Stxp:
      return std::format("{} {}, {}, {}, [{}]", m, gpr(i.rm, false), gpr(i.rd, i.mem_size == 8),
                         gpr(i.ra, i.mem_size == 8), gpr(i.rn, true, true));
    case Op::Cas: case Op::Swp: case Op::Ldadd: case Op::Ldclr: case Op::Ldeor: case Op::Ldset:
    case Op::Ldsmax: case Op::Ldsmin: case Op::Ldumax: case Op::Ldumin: {
      static constexpr const char* sz[9] = {"", "b", "h", "", "", "", "", "", ""};
      return std::format("{}{} {}, {}, [{}]", m, sz[i.mem_size], gpr(i.rm, i.mem_size == 8),
                         gpr(i.rd, i.mem_size == 8), gpr(i.rn, true, true));
    }
    case Op::FmovToGp:
      return i.index ? std::format("fmov {}, v{}.d[1]", gpr(i.rd, true), i.rn)
                     : std::format("fmov {}, {}", gpr(i.rd, x), fpr(i.rn, i.mem_size));
    case Op::FmovFromGp:
      return i.index ? std::format("fmov v{}.d[1], {}", i.rd, gpr(i.rn, true))
                     : std::format("fmov {}, {}", fpr(i.rd, i.mem_size), gpr(i.rn, x));
    case Op::FmovReg:
      return std::format("fmov {}, {}", fpr(i.rd, i.mem_size), fpr(i.rn, i.mem_size));
    case Op::VMovImm:
    case Op::VOrrImm:
    case Op::VBicImm:
      return std::format("{} v{}.{}, #0x{:x}", m, i.rd, i.q ? "2d" : "1d", static_cast<uint64_t>(i.imm));
    case Op::VDupGp:
      return std::format("dup {}, {}", vreg_arrangement(i.rd, i.q, i.esize), gpr(i.rn, i.esize == 8));
    case Op::VDupElem:
      return std::format("dup {}, v{}[{}]", vreg_arrangement(i.rd, i.q, i.esize), i.rn, i.index2);
    case Op::VDupScalar:
      return std::format("mov {}, v{}[{}]", fpr(i.rd, i.esize), i.rn, i.index2);
    case Op::VUmov:
    case Op::VSmov:
      return std::format("{} {}, v{}[{}]", m, gpr(i.rd, x), i.rn, i.index);
    case Op::VInsGp:
      return std::format("ins v{}[{}], {}", i.rd, i.index, gpr(i.rn, i.esize == 8));
    case Op::VInsElem:
      return std::format("ins v{}[{}], v{}[{}]", i.rd, i.index, i.rn, i.index2);
    case Op::VAnd: case Op::VBic: case Op::VOrr: case Op::VOrn: case Op::VEor:
      return std::format("{} {}, {}, {}", m, vreg_arrangement(i.rd, i.q, 1), vreg_arrangement(i.rn, i.q, 1),
                         vreg_arrangement(i.rm, i.q, 1));
    case Op::VLdMulti:
    case Op::VStMulti: {
      std::string regs;
      for (unsigned r = 0; r < i.ra; ++r)
        regs += (r ? ", " : "") + vreg_arrangement((i.rd + r) % 32, i.q, i.esize);
      std::string s = std::format("{}{} {{{}}}, [{}]", m, i.amount, regs, gpr(i.rn, true, true));
      if (i.mode == AddrMode::PostIndex) s += i.imm_form ? std::format(", {}", hex(i.imm)) : ", " + gpr(i.rm, true);
      return s;
    }
    case Op::VLdLane:
    case Op::VStLane:
    case Op::VLdRep:
      return std::format("{} {{v{}}}[{}], [{}]", m, i.rd, i.index, gpr(i.rn, true, true));
    case Op::VecAddAcross: case Op::VecMaxAcross: case Op::VecMinAcross: case Op::VecAddLongAcross:
      return std::format("{} {}, {}", m, fpr(i.rd, i.esize), vreg_arrangement(i.rn, i.q, i.esize));
    case Op::VecAddPScalar:
      return std::format("addp d{}, v{}.2d", i.rd, i.rn);
    case Op::VecShl: case Op::VecShr: case Op::VecShrn: case Op::VecShll:
      return std::format("{} {}, {}, #{}", m, vreg_arrangement(i.rd, i.q, i.esize),
                         vreg_arrangement(i.rn, i.q, i.esize), i.imm);
    case Op::VecCnt: case Op::VecNot: case Op::VecNeg: case Op::VecAbs: case Op::VecRev: case Op::VecXtn:
    case Op::VecCmpZero:
      return std::format("{} {}, {}", m, vreg_arrangement(i.rd, i.q, i.esize), vreg_arrangement(i.rn, i.q, i.esize));
    case Op::VecExt:
      return std::format("ext {}, {}, {}, #{}", vreg_arrangement(i.rd, i.q, 1), vreg_arrangement(i.rn, i.q, 1),
                         vreg_arrangement(i.rm, i.q, 1), i.imm);
    case Op::VecAdd: case Op::VecSub: case Op::VecMul: case Op::VecCmp: case Op::VecMax: case Op::VecMin:
    case Op::VecMaxP: case Op::VecMinP: case Op::VecAddP: case Op::VecUzp: case Op::VecZip: case Op::VecTrn:
    case Op::VecBsl: case Op::VecBit: case Op::VecBif:
      return std::format("{} {}, {}, {}", m, vreg_arrangement(i.rd, i.q, i.esize),
                         vreg_arrangement(i.rn, i.q, i.esize), vreg_arrangement(i.rm, i.q, i.esize));
    // The groups below print their operation number (the Vec* enums of instruction.hpp).
    case Op::VecIntOp: case Op::VecFpOp: case Op::VecLong: case Op::VecElemOp: case Op::VecTbl:
      return std::format("{}.{}{} {}, {}, {}", m, i.shift, i.scalar ? " scalar" : "",
                         vreg_arrangement(i.rd, i.q, i.esize), vreg_arrangement(i.rn, i.q, i.esize),
                         vreg_arrangement(i.rm, i.q, i.esize));
    case Op::VecIntUnary: case Op::VecFpUnary: case Op::VecFpAcross:
      return std::format("{}.{}{} {}, {}", m, i.shift, i.scalar ? " scalar" : "", vreg_arrangement(i.rd, i.q, i.esize),
                         vreg_arrangement(i.rn, i.q, i.esize));
    case Op::VecShiftOp:
      return std::format("{}.{}{} {}, {}, #{}", m, i.shift, i.scalar ? " scalar" : "",
                         vreg_arrangement(i.rd, i.q, i.esize), vreg_arrangement(i.rn, i.q, i.esize), i.imm);
    case Op::FpFixedToFp:
      return std::format("{} {}, {}{}, #{}", m, fpr(i.rd, i.mem_size), i.sf ? "x" : "w", i.rn, i.imm);
    case Op::FpToFixed:
      return std::format("{} {}{}, {}, #{}", m, i.sf ? "x" : "w", i.rd, fpr(i.rn, i.mem_size), i.imm);
    case Op::FpBinary: {
      static constexpr const char* names[9] = {"fmul", "fdiv", "fadd", "fsub", "fmax", "fmin", "fmaxnm", "fminnm",
                                               "fnmul"};
      return std::format("{} {}, {}, {}", names[i.shift], fpr(i.rd, i.mem_size), fpr(i.rn, i.mem_size),
                         fpr(i.rm, i.mem_size));
    }
    case Op::FpUnary: {
      static constexpr const char* names[4] = {"fmov", "fabs", "fneg", "fsqrt"};
      return std::format("{} {}, {}", names[i.shift & 3], fpr(i.rd, i.mem_size), fpr(i.rn, i.mem_size));
    }
    case Op::FpCvt:
      return std::format("fcvt {}, {}", fpr(i.rd, i.mem_size), fpr(i.rn, i.esize));
    case Op::FpRint:
      return std::format("frint{} {}, {}", "npmza"[i.shift % 5], fpr(i.rd, i.mem_size), fpr(i.rn, i.mem_size));
    case Op::FpFma: {
      static constexpr const char* names[4] = {"fmadd", "fmsub", "fnmadd", "fnmsub"};
      return std::format("{} {}, {}, {}, {}", names[i.shift & 3], fpr(i.rd, i.mem_size), fpr(i.rn, i.mem_size),
                         fpr(i.rm, i.mem_size), fpr(i.ra, i.mem_size));
    }
    case Op::FpCmp:
      return std::format("fcmp {}, {}", fpr(i.rn, i.mem_size), i.imm_form ? "#0.0" : fpr(i.rm, i.mem_size));
    case Op::FpCcmp:
      return std::format("fccmp {}, {}, #{}, {}", fpr(i.rn, i.mem_size), fpr(i.rm, i.mem_size), i.nzcv,
                         kCond[i.cond]);
    case Op::FpCsel:
      return std::format("fcsel {}, {}, {}, {}", fpr(i.rd, i.mem_size), fpr(i.rn, i.mem_size), fpr(i.rm, i.mem_size),
                         kCond[i.cond]);
    case Op::FpMovImm:
      return std::format("fmov {}, #0x{:x}", fpr(i.rd, i.mem_size), static_cast<uint64_t>(i.imm));
    case Op::FpToInt:
      return std::format("fcvt{}{} {}, {}", "npmza"[i.shift % 5], i.mem_signed ? 's' : 'u', gpr(i.rd, i.sf),
                         fpr(i.rn, i.mem_size));
    case Op::IntToFp:
      return std::format("{}cvtf {}, {}", i.mem_signed ? 's' : 'u', fpr(i.rd, i.mem_size), gpr(i.rn, i.sf));
    case Op::Count_:
      break;
  }
  return m;
}

}  // namespace juice::arm64
