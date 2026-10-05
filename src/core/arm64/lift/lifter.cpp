#include "core/arm64/lift/lifter.hpp"

#include <bit>
#include <cmath>
#include <cstddef>
#include <vector>

#include "core/arm64/state/cpu_state.hpp"

namespace juice::arm64 {
namespace {

using ir::Opcode;
using ir::Predicate;
using V = ir::ValueId;

constexpr uint64_t low_mask(unsigned width) { return width >= 64 ? ~0ull : ((1ull << width) - 1); }

class Lifter {
 public:
  explicit Lifter(ir::Builder& b, const LiftOptions& options = {}) : b_(b), tls_vector_offset_(options.tls_vector_offset) {}

  bool lift(const Instruction& i);

 private:
  // --- helpers ---------------------------------------------------------------
  V c(uint64_t v) { return b_.constant(v); }
  V x(unsigned r) { return r == 31 ? c(0) : b_.get(slot::X(r)); }       // XZR for 31
  V xsp(unsigned r) { return b_.get(r == 31 ? slot::SP : slot::X(r)); }  // SP for 31
  void set_x(unsigned r, V v) {
    if (r != 31) b_.set(slot::X(r), v);
  }
  void set_xsp(unsigned r, V v) { b_.set(r == 31 ? slot::SP : slot::X(r), v); }
  V flags() { return b_.get(slot::NZCV); }
  void set_flags(V v) { b_.set(slot::NZCV, v); }
  V op(Opcode o, V a, V b, uint8_t size) { return b_.binary(o, a, b, size); }

  V shifted(V v, ShiftType type, unsigned amount, uint8_t size);
  V extended(V v, Extend ext, unsigned shift);
  V address(const Instruction& i, V& writeback);
  V vector_element(unsigned reg, unsigned index, unsigned esize);
  void vector_insert(unsigned reg, unsigned index, unsigned esize, V value);

  bool unsupported(const Instruction& i) {
    b_.exit(static_cast<uint32_t>(ExitReason::Unsupported), i.raw, i.pc);
    return true;
  }

  void lift_bitfield(const Instruction& i);
  void lift_load_store(const Instruction& i);
  void lift_pair(const Instruction& i);
  void lift_atomic(const Instruction& i);
  void lift_exclusive(const Instruction& i);
  bool lift_mrs(const Instruction& i);
  bool lift_msr(const Instruction& i);
  void lift_simd(const Instruction& i);
  void lift_simd_memory(const Instruction& i);
  void lift_vector(const Instruction& i);
  void lift_fp(const Instruction& i);
  void lift_vector_ext(const Instruction& i);

  // Vector helpers: lane ops on 64-bit halves (see ir::Opcode::VAdd and friends).
  V vop(Opcode o, V a, V b, unsigned esize, unsigned high = 0) {
    return b_.emit(o, 8, a, b, ir::kNoValue, 0, static_cast<uint8_t>(esize | (high << 4)));
  }
  V vlo(unsigned r) { return b_.get(slot::VLo(r)); }
  V vhi(unsigned r) { return b_.get(slot::VHi(r)); }
  void set_v(unsigned r, V lo, V hi) {
    b_.set(slot::VLo(r), lo);
    b_.set(slot::VHi(r), hi);
  }

  ir::Builder& b_;
  uint32_t tls_vector_offset_;
};

V Lifter::shifted(V v, ShiftType type, unsigned amount, uint8_t size) {
  if (amount == 0) return v;
  static constexpr Opcode ops[4] = {Opcode::Shl, Opcode::LShr, Opcode::AShr, Opcode::Ror};
  return op(ops[static_cast<unsigned>(type)], v, c(amount), size);
}

V Lifter::extended(V v, Extend ext, unsigned shift) {
  switch (ext) {
    case Extend::Uxtb: v = b_.zext(v, 8); break;
    case Extend::Uxth: v = b_.zext(v, 16); break;
    case Extend::Uxtw: v = b_.zext(v, 32); break;
    case Extend::Sxtb: v = b_.sext(v, 8); break;
    case Extend::Sxth: v = b_.sext(v, 16); break;
    case Extend::Sxtw: v = b_.sext(v, 32); break;
    case Extend::Uxtx:
    case Extend::Sxtx: break;
  }
  if (shift) v = b_.shl(v, c(shift));
  return v;
}

V Lifter::address(const Instruction& i, V& writeback) {
  writeback = ir::kNoValue;
  if (i.mode == AddrMode::Literal) return c(static_cast<uint64_t>(i.imm));
  V base = xsp(i.rn);
  switch (i.mode) {
    case AddrMode::Offset:
      return i.imm ? b_.add(base, c(static_cast<uint64_t>(i.imm))) : base;
    case AddrMode::PreIndex:
      writeback = b_.add(base, c(static_cast<uint64_t>(i.imm)));
      return writeback;
    case AddrMode::PostIndex:
      writeback = b_.add(base, c(static_cast<uint64_t>(i.imm)));
      return base;
    case AddrMode::RegOffset:
      return b_.add(base, extended(x(i.rm), static_cast<Extend>(i.shift), i.amount));
    case AddrMode::Literal:
      break;
  }
  return base;
}

void Lifter::lift_bitfield(const Instruction& i) {
  const uint8_t s = i.sf ? 8 : 4;
  const unsigned datasize = s * 8u;
  const unsigned r = i.immr, imms = i.imms;
  V src = x(i.rn);
  V result;

  if (imms >= r) {  // extract bits [imms:r] to the bottom
    unsigned width = imms - r + 1;
    switch (i.op) {
      case Op::Ubfm:
        result = op(Opcode::LShr, src, c(r), s);
        if (width < datasize) result = op(Opcode::And, result, c(low_mask(width)), s);
        break;
      case Op::Sbfm:
        result = op(Opcode::AShr, op(Opcode::Shl, src, c(datasize - 1 - imms), s), c(datasize - width), s);
        break;
      default: {  // BFXIL
        V field = op(Opcode::And, op(Opcode::LShr, src, c(r), s), c(low_mask(width)), s);
        V keep = op(Opcode::And, x(i.rd), c(~low_mask(width)), s);
        result = op(Opcode::Or, keep, field, s);
        break;
      }
    }
  } else {  // insert bits [imms:0] at position datasize - r
    unsigned width = imms + 1;
    unsigned pos = datasize - r;
    switch (i.op) {
      case Op::Ubfm:
        result = op(Opcode::Shl, op(Opcode::And, src, c(low_mask(width)), s), c(pos), s);
        break;
      case Op::Sbfm: {
        V ext = op(Opcode::AShr, op(Opcode::Shl, src, c(datasize - width), s), c(datasize - width), s);
        result = op(Opcode::Shl, ext, c(pos), s);
        break;
      }
      default: {  // BFI
        V field = op(Opcode::Shl, op(Opcode::And, src, c(low_mask(width)), s), c(pos), s);
        V keep = op(Opcode::And, x(i.rd), c(~(low_mask(width) << pos)), s);
        result = op(Opcode::Or, keep, field, s);
        break;
      }
    }
  }
  set_x(i.rd, result);
}

void Lifter::lift_load_store(const Instruction& i) {
  if (tls_vector_offset_ && i.op == Op::Ldr && !i.vector && i.mem_size == 8 && i.mode == AddrMode::Offset &&
      i.rn == 18 && i.imm == tls_vector_offset_) {
    set_x(i.rd, b_.get(slot::TlsVector));
    return;
  }
  V wb;
  V addr = address(i, wb);
  if (i.op == Op::Ldr) {
    if (i.vector) {
      b_.load_to_state(addr, slot::VLo(i.rd), i.mem_size, 16);
    } else {
      V v = b_.load(addr, i.mem_size, i.mem_signed);
      if (i.mem_signed && !i.mem_to_64) v = b_.zext(v, 32);
      set_x(i.rd, v);
    }
  } else {
    if (i.vector) {
      b_.store_from_state(addr, slot::VLo(i.rd), i.mem_size);
    } else if (i.release) {
      // A plain x86 store may pass a later load; STLR must not pass a later
      // LDAR, so make it a sequentially consistent (locked) store.
      b_.emit(Opcode::AtomicRmw, i.mem_size, addr, x(i.rd), ir::kNoValue, 0,
              static_cast<uint8_t>(ir::AtomicOp::Swap));
    } else {
      b_.store(addr, x(i.rd), i.mem_size);
    }
  }
  if (wb != ir::kNoValue) set_xsp(i.rn, wb);
}

void Lifter::lift_pair(const Instruction& i) {
  V wb;
  V addr = address(i, wb);
  V addr2 = b_.add(addr, c(i.mem_size));
  if (i.op == Op::Ldp) {
    if (i.vector) {
      b_.load_to_state(addr, slot::VLo(i.rd), i.mem_size, 16);
      b_.load_to_state(addr2, slot::VLo(i.ra), i.mem_size, 16);
    } else {
      V v1 = b_.load(addr, i.mem_size, i.mem_signed);
      V v2 = b_.load(addr2, i.mem_size, i.mem_signed);
      set_x(i.rd, v1);
      set_x(i.ra, v2);
    }
  } else {
    if (i.vector) {
      b_.store_from_state(addr, slot::VLo(i.rd), i.mem_size);
      b_.store_from_state(addr2, slot::VLo(i.ra), i.mem_size);
    } else {
      V v1 = x(i.rd);
      V v2 = x(i.ra);
      b_.store(addr, v1, i.mem_size);
      b_.store(addr2, v2, i.mem_size);
    }
  }
  if (wb != ir::kNoValue) set_xsp(i.rn, wb);
}

// LSE atomics (CAS, SWP, LDADD, ...): one atomic host operation each.
void Lifter::lift_atomic(const Instruction& i) {
  const uint8_t sz = i.mem_size;
  const V addr = xsp(i.rn);
  const V operand = x(i.rm);
  if (i.op == Op::Casp) {
    // Compare the pair Rs:Rs+1 with memory and store Rt:Rt+1 if equal; Rs:Rs+1
    // receive the old value either way.
    if (i.sf) {  // 128-bit: CMPXCHG16B on {expected, desired} staged in guest state
      b_.set(slot::ExclValue, x(i.rm));
      b_.set(slot::ExclValueHi, x(i.rm + 1));
      b_.set(slot::ExclNew, x(i.rd));
      b_.set(slot::ExclNewHi, x(i.rd + 1));
      V operands = b_.emit(Opcode::StateAddr, 8, ir::kNoValue, ir::kNoValue, ir::kNoValue, slot::ExclValue);
      b_.emit(Opcode::AtomicCasPair, 8, addr, operands);
      V old_lo = b_.get(slot::ExclValue), old_hi = b_.get(slot::ExclValueHi);
      set_x(i.rm, old_lo);
      set_x(i.rm + 1, old_hi);
    } else {  // two 32-bit registers: one 64-bit compare-and-swap
      auto pack = [&](unsigned r) { return b_.or_(b_.zext(x(r), 32), b_.shl(x(r + 1), c(32))); };
      V old = b_.emit(Opcode::AtomicCas, 8, addr, pack(i.rm), pack(i.rd));
      set_x(i.rm, b_.zext(old, 32));
      set_x(i.rm + 1, b_.lshr(old, c(32)));
    }
    return;
  }
  if (i.op == Op::Cas) {
    V expected = sz < 8 ? b_.zext(operand, static_cast<uint8_t>(sz * 8)) : operand;
    set_x(i.rm, b_.emit(Opcode::AtomicCas, sz, addr, expected, x(i.rd)));
    return;
  }
  ir::AtomicOp kind;
  switch (i.op) {
    case Op::Swp: kind = ir::AtomicOp::Swap; break;
    case Op::Ldadd: kind = ir::AtomicOp::Add; break;
    case Op::Ldclr: kind = ir::AtomicOp::Clr; break;
    case Op::Ldeor: kind = ir::AtomicOp::Eor; break;
    case Op::Ldset: kind = ir::AtomicOp::Set; break;
    case Op::Ldsmax: kind = ir::AtomicOp::SMax; break;
    case Op::Ldsmin: kind = ir::AtomicOp::SMin; break;
    case Op::Ldumax: kind = ir::AtomicOp::UMax; break;
    default: kind = ir::AtomicOp::UMin; break;
  }
  set_x(i.rd, b_.emit(Opcode::AtomicRmw, sz, addr, operand, ir::kNoValue, 0, static_cast<uint8_t>(kind)));
}

// Exclusives. The monitor is emulated by value: LDXR/LDXP record what they
// loaded, and STXR/STXP store with an atomic compare-and-swap against that
// value, failing (status 1) if memory changed in between. Like other
// translators this accepts an A-B-A change as unchanged.
void Lifter::lift_exclusive(const Instruction& i) {
  const uint8_t sz = i.mem_size;
  const V addr = xsp(i.rn);
  switch (i.op) {
    case Op::Ldxr: {
      V v = b_.load(addr, sz, false);
      b_.set(slot::ExclValue, v);
      set_x(i.rd, v);
      break;
    }
    case Op::Stxr: {
      V expected = b_.get(slot::ExclValue);
      V old = b_.emit(Opcode::AtomicCas, sz, addr, expected, x(i.rd));
      set_x(i.rm, b_.cmp(Predicate::Ne, old, expected));
      break;
    }
    case Op::Ldxp: {
      V v1 = b_.load(addr, sz, false);
      V v2 = b_.load(b_.add(addr, c(sz)), sz, false);
      if (sz == 4) {
        b_.set(slot::ExclValue, b_.or_(v1, b_.shl(v2, c(32))));
      } else {
        b_.set(slot::ExclValue, v1);
        b_.set(slot::ExclValueHi, v2);
      }
      set_x(i.rd, v1);
      set_x(i.ra, v2);
      break;
    }
    case Op::Stxp: {
      V status;
      if (sz == 4) {  // 2 x 32 bits: one 64-bit compare-and-swap
        V desired = b_.or_(b_.zext(x(i.rd), 32), b_.shl(x(i.ra), c(32)));
        V expected = b_.get(slot::ExclValue);
        V old = b_.emit(Opcode::AtomicCas, 8, addr, expected, desired);
        status = b_.cmp(Predicate::Ne, old, expected);
      } else {  // 2 x 64 bits: 128-bit compare-and-swap on {excl_value, excl_value_hi, excl_new, excl_new_hi}
        b_.set(slot::ExclNew, x(i.rd));
        b_.set(slot::ExclNewHi, x(i.ra));
        V operands = b_.emit(Opcode::StateAddr, 8, ir::kNoValue, ir::kNoValue, ir::kNoValue, slot::ExclValue);
        status = b_.emit(Opcode::AtomicCasPair, 8, addr, operands);
      }
      set_x(i.rm, status);
      break;
    }
    default:
      break;
  }
}

bool Lifter::lift_mrs(const Instruction& i) {
  V v;
  switch (i.sysreg) {
    case sysreg::NZCV: v = flags(); break;
    case sysreg::FPCR: v = b_.get(slot::FPCR); break;
    case sysreg::FPSR: v = b_.get(slot::FPSR); break;
    case sysreg::TPIDR_EL0: v = b_.get(slot::TPIDR_EL0); break;
    case sysreg::TPIDRRO_EL0: v = b_.get(slot::TPIDRRO_EL0); break;
    case sysreg::DCZID_EL0: v = c(4); break;             // DC ZVA allowed, 2^4 words = 64-byte blocks
    case sysreg::CTR_EL0: v = c(0x8444C004); break;      // 64-byte cache lines
    case sysreg::MIDR_EL1: v = c(0x410FD0C0); break;     // generic Arm Cortex
    case sysreg::CurrentEL: v = c(0); break;             // user mode (EL0)
    default:
      // ID_* feature registers (op0=3, op1=0, CRn=0): report no optional features.
      if ((i.sysreg >> 7) == (sysreg::make(3, 0, 0, 0, 0) >> 7)) {
        v = c(0);
        break;
      }
      return unsupported(i);
  }
  set_x(i.rd, v);
  return false;
}

bool Lifter::lift_msr(const Instruction& i) {
  switch (i.sysreg) {
    case sysreg::NZCV: set_flags(b_.and_(x(i.rd), c(0xF000'0000u))); break;
    case sysreg::FPCR: b_.set(slot::FPCR, x(i.rd)); break;
    case sysreg::FPSR: b_.set(slot::FPSR, x(i.rd)); break;
    case sysreg::TPIDR_EL0: b_.set(slot::TPIDR_EL0, x(i.rd)); break;
    default: return unsupported(i);
  }
  return false;
}

V Lifter::vector_element(unsigned reg, unsigned index, unsigned esize) {
  unsigned bitpos = index * esize * 8;
  V v = b_.get(bitpos >= 64 ? slot::VHi(reg) : slot::VLo(reg));
  unsigned sh = bitpos % 64;
  if (sh) v = b_.lshr(v, c(sh));
  if (esize < 8) v = b_.and_(v, c(low_mask(esize * 8)));
  return v;
}

void Lifter::vector_insert(unsigned reg, unsigned index, unsigned esize, V value) {
  unsigned bitpos = index * esize * 8;
  uint16_t s = bitpos >= 64 ? slot::VHi(reg) : slot::VLo(reg);
  if (esize == 8) {
    b_.set(s, value);
    return;
  }
  unsigned sh = bitpos % 64;
  uint64_t m = low_mask(esize * 8) << sh;
  V keep = b_.and_(b_.get(s), c(~m));
  V field = b_.shl(b_.and_(value, c(low_mask(esize * 8))), c(sh));
  b_.set(s, b_.or_(keep, field));
}

void Lifter::lift_simd(const Instruction& i) {
  static constexpr uint64_t kReplicate[9] = {0, 0x0101010101010101ull, 0x0001000100010001ull, 0,
                                             0x0000000100000001ull, 0, 0, 0, 1};
  switch (i.op) {
    case Op::FmovToGp: {
      V v = b_.get(i.index ? slot::VHi(i.rn) : slot::VLo(i.rn));
      if (i.mem_size == 4) v = b_.zext(v, 32);
      set_x(i.rd, v);
      break;
    }
    case Op::FmovFromGp:
      if (i.index) {
        b_.set(slot::VHi(i.rd), x(i.rn));
      } else {
        V v = x(i.rn);
        if (i.mem_size == 4) v = b_.zext(v, 32);
        b_.set(slot::VLo(i.rd), v);
        b_.set(slot::VHi(i.rd), c(0));
      }
      break;
    case Op::FmovReg: {
      V v = b_.get(slot::VLo(i.rn));
      if (i.mem_size < 8) v = b_.zext(v, static_cast<uint8_t>(i.mem_size * 8));
      b_.set(slot::VLo(i.rd), v);
      b_.set(slot::VHi(i.rd), c(0));
      break;
    }
    case Op::VMovImm:
      b_.set(slot::VLo(i.rd), c(static_cast<uint64_t>(i.imm)));
      b_.set(slot::VHi(i.rd), c(i.q ? static_cast<uint64_t>(i.imm) : 0));
      break;
    case Op::VOrrImm:
    case Op::VBicImm: {
      auto apply = [&](uint16_t s) {
        V old = b_.get(s);
        return i.op == Op::VOrrImm ? b_.or_(old, c(static_cast<uint64_t>(i.imm)))
                                   : b_.and_(old, c(~static_cast<uint64_t>(i.imm)));
      };
      V lo = apply(slot::VLo(i.rd));
      V hi = i.q ? apply(slot::VHi(i.rd)) : c(0);
      b_.set(slot::VLo(i.rd), lo);
      b_.set(slot::VHi(i.rd), hi);
      break;
    }
    case Op::VDupGp:
    case Op::VDupElem: {
      V e = i.op == Op::VDupGp ? x(i.rn) : vector_element(i.rn, i.index2, i.esize);
      if (i.esize < 8) e = b_.and_(e, c(low_mask(i.esize * 8)));
      V rep = i.esize == 8 ? e : b_.binary(Opcode::Mul, e, c(kReplicate[i.esize]), 8);
      b_.set(slot::VLo(i.rd), rep);
      b_.set(slot::VHi(i.rd), i.q ? rep : c(0));
      break;
    }
    case Op::VDupScalar: {
      V e = vector_element(i.rn, i.index2, i.esize);
      b_.set(slot::VLo(i.rd), e);
      b_.set(slot::VHi(i.rd), c(0));
      break;
    }
    case Op::VUmov:
      set_x(i.rd, vector_element(i.rn, i.index, i.esize));
      break;
    case Op::VSmov: {
      V e = b_.sext(vector_element(i.rn, i.index, i.esize), static_cast<uint8_t>(i.esize * 8));
      if (!i.sf) e = b_.zext(e, 32);
      set_x(i.rd, e);
      break;
    }
    case Op::VInsGp:
      vector_insert(i.rd, i.index, i.esize, x(i.rn));
      break;
    case Op::VInsElem:
      vector_insert(i.rd, i.index, i.esize, vector_element(i.rn, i.index2, i.esize));
      break;
    case Op::VAnd: case Op::VBic: case Op::VOrr: case Op::VOrn: case Op::VEor: {
      auto apply = [&](V a, V m) {
        switch (i.op) {
          case Op::VAnd: return b_.and_(a, m);
          case Op::VBic: return b_.and_(a, b_.not_(m));
          case Op::VOrr: return b_.or_(a, m);
          case Op::VOrn: return b_.or_(a, b_.not_(m));
          default: return b_.xor_(a, m);
        }
      };
      V lo = apply(b_.get(slot::VLo(i.rn)), b_.get(slot::VLo(i.rm)));
      V hi = i.q ? apply(b_.get(slot::VHi(i.rn)), b_.get(slot::VHi(i.rm))) : c(0);
      b_.set(slot::VLo(i.rd), lo);
      b_.set(slot::VHi(i.rd), hi);
      break;
    }
    default:
      break;
  }
}

// LD1-LD4 / ST1-ST4 and the single-lane forms.
void Lifter::lift_simd_memory(const Instruction& i) {
  static constexpr uint64_t kReplicate[9] = {0, 0x0101010101010101ull, 0x0001000100010001ull, 0,
                                             0x0000000100000001ull, 0, 0, 0, 1};
  const V base = xsp(i.rn);
  const unsigned e = i.esize;
  auto at = [&](uint64_t offset) { return offset ? b_.add(base, c(offset)) : base; };

  switch (i.op) {
    case Op::VLdMulti:
    case Op::VStMulti: {
      const unsigned regs = i.ra, selem = i.amount, bytes = i.mem_size;
      const bool load = i.op == Op::VLdMulti;
      if (selem == 1) {  // consecutive registers, no interleaving
        for (unsigned r = 0; r < regs; ++r) {
          const uint16_t s = slot::VLo((i.rd + r) % 32);
          if (load) b_.load_to_state(at(uint64_t{r} * bytes), s, static_cast<uint8_t>(bytes), 16);
          else b_.store_from_state(at(uint64_t{r} * bytes), s, static_cast<uint8_t>(bytes));
        }
        break;
      }
      const unsigned lanes = bytes / e;
      if (load) {
        std::vector<V> halves(selem * 2, ir::kNoValue);
        for (unsigned lane = 0; lane < lanes; ++lane) {
          for (unsigned s = 0; s < selem; ++s) {
            V v = b_.load(at(uint64_t{lane * selem + s} * e), static_cast<uint8_t>(e), false);
            const unsigned bitpos = lane * e * 8;
            if (bitpos % 64) v = b_.shl(v, c(bitpos % 64));
            V& h = halves[s * 2 + bitpos / 64];
            h = h == ir::kNoValue ? v : b_.or_(h, v);
          }
        }
        for (unsigned s = 0; s < selem; ++s)
          set_v((i.rd + s) % 32, halves[s * 2], halves[s * 2 + 1] == ir::kNoValue ? c(0) : halves[s * 2 + 1]);
      } else {
        for (unsigned lane = 0; lane < lanes; ++lane)
          for (unsigned s = 0; s < selem; ++s)
            b_.store(at(uint64_t{lane * selem + s} * e), vector_element((i.rd + s) % 32, lane, e),
                     static_cast<uint8_t>(e));
      }
      break;
    }
    case Op::VLdLane: {
      std::vector<V> elems;
      for (unsigned s = 0; s < i.amount; ++s) elems.push_back(b_.load(at(uint64_t{s} * e), static_cast<uint8_t>(e), false));
      for (unsigned s = 0; s < i.amount; ++s) vector_insert((i.rd + s) % 32, i.index, e, elems[s]);
      break;
    }
    case Op::VStLane:
      for (unsigned s = 0; s < i.amount; ++s)
        b_.store(at(uint64_t{s} * e), vector_element((i.rd + s) % 32, i.index, e), static_cast<uint8_t>(e));
      break;
    case Op::VLdRep: {
      std::vector<V> reps;
      for (unsigned s = 0; s < i.amount; ++s) {
        V v = b_.load(at(uint64_t{s} * e), static_cast<uint8_t>(e), false);
        reps.push_back(e == 8 ? v : b_.binary(Opcode::Mul, v, c(kReplicate[e]), 8));
      }
      for (unsigned s = 0; s < i.amount; ++s) set_v((i.rd + s) % 32, reps[s], i.q ? reps[s] : c(0));
      break;
    }
    default:
      break;
  }
  if (i.mode == AddrMode::PostIndex)
    set_xsp(i.rn, b_.add(base, i.imm_form ? c(static_cast<uint64_t>(i.imm)) : x(i.rm)));
}

void Lifter::lift_vector(const Instruction& i) {
  const unsigned e = i.esize;
  const bool q = i.q;
  // Operands are read before the destination is written (rd may alias rn/rm).
  auto unary = [&](auto f) {
    V lo = f(vlo(i.rn));
    V hi = q ? f(vhi(i.rn)) : c(0);
    set_v(i.rd, lo, hi);
  };
  auto binary = [&](auto f) {
    V lo = f(vlo(i.rn), vlo(i.rm));
    V hi = q ? f(vhi(i.rn), vhi(i.rm)) : c(0);
    set_v(i.rd, lo, hi);
  };
  // Pairwise: adjacent lanes of the concatenation Vm:Vn.
  auto pairwise = [&](auto f) {
    V nlo = vlo(i.rn), mlo = vlo(i.rm);
    if (q) {
      V nhi = vhi(i.rn), mhi = vhi(i.rm);
      V lo = f(vop(Opcode::VUnzip, nlo, nhi, e, 0), vop(Opcode::VUnzip, nlo, nhi, e, 1));
      V hi = f(vop(Opcode::VUnzip, mlo, mhi, e, 0), vop(Opcode::VUnzip, mlo, mhi, e, 1));
      set_v(i.rd, lo, hi);
    } else {
      set_v(i.rd, f(vop(Opcode::VUnzip, nlo, mlo, e, 0), vop(Opcode::VUnzip, nlo, mlo, e, 1)), c(0));
    }
  };
  auto across = [&](Opcode lanewise, unsigned high, ir::VecReduce kind) {
    V v = vlo(i.rn);
    if (q) v = vop(lanewise, v, vhi(i.rn), e, high);
    set_v(i.rd, vop(Opcode::VReduce, v, ir::kNoValue, e, static_cast<unsigned>(kind)), c(0));
  };
  const unsigned sign = i.mem_signed ? 1 : 0;

  switch (i.op) {
    case Op::VecAdd: binary([&](V a, V b) { return vop(Opcode::VAdd, a, b, e); }); break;
    case Op::VecSub: binary([&](V a, V b) { return vop(Opcode::VSub, a, b, e); }); break;
    case Op::VecMul: binary([&](V a, V b) { return vop(Opcode::VMul, a, b, e); }); break;
    case Op::VecCmp: binary([&](V a, V b) { return vop(Opcode::VCmp, a, b, e, i.shift); }); break;
    case Op::VecCmpZero: {
      using ir::VecPred;
      const auto z = static_cast<VecZeroCmp>(i.shift);
      unary([&](V a) {
        V zero = c(0);
        switch (z) {
          case VecZeroCmp::Gt: return vop(Opcode::VCmp, a, zero, e, static_cast<unsigned>(VecPred::Gt));
          case VecZeroCmp::Ge: return vop(Opcode::VCmp, a, zero, e, static_cast<unsigned>(VecPred::Ge));
          case VecZeroCmp::Eq: return vop(Opcode::VCmp, a, zero, e, static_cast<unsigned>(VecPred::Eq));
          case VecZeroCmp::Le: return vop(Opcode::VCmp, zero, a, e, static_cast<unsigned>(VecPred::Ge));
          default: return vop(Opcode::VCmp, zero, a, e, static_cast<unsigned>(VecPred::Gt));
        }
      });
      break;
    }
    case Op::VecMax: binary([&](V a, V b) { return vop(Opcode::VMax, a, b, e, sign); }); break;
    case Op::VecMin: binary([&](V a, V b) { return vop(Opcode::VMin, a, b, e, sign); }); break;
    case Op::VecMaxP: pairwise([&](V a, V b) { return vop(Opcode::VMax, a, b, e, sign); }); break;
    case Op::VecMinP: pairwise([&](V a, V b) { return vop(Opcode::VMin, a, b, e, sign); }); break;
    case Op::VecAddP: pairwise([&](V a, V b) { return vop(Opcode::VAdd, a, b, e); }); break;
    case Op::VecAddAcross: across(Opcode::VAdd, 0, ir::VecReduce::Add); break;
    case Op::VecMaxAcross:
      across(Opcode::VMax, sign, i.mem_signed ? ir::VecReduce::SMax : ir::VecReduce::UMax);
      break;
    case Op::VecMinAcross:
      across(Opcode::VMin, sign, i.mem_signed ? ir::VecReduce::SMin : ir::VecReduce::UMin);
      break;
    case Op::VecAddLongAcross: {
      const auto kind = static_cast<unsigned>(i.mem_signed ? ir::VecReduce::SAddLong : ir::VecReduce::UAddLong);
      V sum = vop(Opcode::VReduce, vlo(i.rn), ir::kNoValue, e, kind);
      if (q) sum = b_.add(sum, vop(Opcode::VReduce, vhi(i.rn), ir::kNoValue, e, kind));
      set_v(i.rd, b_.and_(sum, c(low_mask(e * 16))), c(0));
      break;
    }
    case Op::VecAddPScalar:
      set_v(i.rd, b_.add(vlo(i.rn), vhi(i.rn)), c(0));
      break;
    case Op::VecShl:
      unary([&](V a) { return vop(Opcode::VShl, a, c(static_cast<uint64_t>(i.imm)), e); });
      break;
    case Op::VecShr:
      unary([&](V a) {
        return vop(i.mem_signed ? Opcode::VAShr : Opcode::VLShr, a, c(static_cast<uint64_t>(i.imm)), e);
      });
      break;
    case Op::VecShrn:
    case Op::VecXtn: {
      V lo = vlo(i.rn), hi = vhi(i.rn);
      if (i.op == Op::VecShrn) {
        lo = vop(Opcode::VLShr, lo, c(static_cast<uint64_t>(i.imm)), e * 2);
        hi = vop(Opcode::VLShr, hi, c(static_cast<uint64_t>(i.imm)), e * 2);
      }
      V narrow = vop(Opcode::VUnzip, lo, hi, e, 0);
      if (i.index) b_.set(slot::VHi(i.rd), narrow);  // "2" form: upper half, lower half kept
      else set_v(i.rd, narrow, c(0));
      break;
    }
    case Op::VecShll: {
      V src = i.index ? vhi(i.rn) : vlo(i.rn);
      V lo = vop(Opcode::VWiden, src, ir::kNoValue, e, sign);
      V hi = vop(Opcode::VWiden, src, ir::kNoValue, e, sign | 2);
      if (i.imm) {
        lo = vop(Opcode::VShl, lo, c(static_cast<uint64_t>(i.imm)), e * 2);
        hi = vop(Opcode::VShl, hi, c(static_cast<uint64_t>(i.imm)), e * 2);
      }
      set_v(i.rd, lo, hi);
      break;
    }
    case Op::VecCnt: unary([&](V a) { return vop(Opcode::VCnt, a, ir::kNoValue, 1); }); break;
    case Op::VecNot: unary([&](V a) { return b_.not_(a); }); break;
    case Op::VecNeg: unary([&](V a) { return vop(Opcode::VSub, c(0), a, e); }); break;
    case Op::VecAbs: unary([&](V a) { return vop(Opcode::VAbs, a, ir::kNoValue, e); }); break;
    case Op::VecRev: unary([&](V a) { return vop(Opcode::VRev, a, ir::kNoValue, e, i.amount); }); break;
    case Op::VecUzp: {
      V nlo = vlo(i.rn), mlo = vlo(i.rm);
      if (q) {
        V nhi = vhi(i.rn), mhi = vhi(i.rm);
        set_v(i.rd, vop(Opcode::VUnzip, nlo, nhi, e, i.index), vop(Opcode::VUnzip, mlo, mhi, e, i.index));
      } else {
        set_v(i.rd, vop(Opcode::VUnzip, nlo, mlo, e, i.index), c(0));
      }
      break;
    }
    case Op::VecZip:
    case Op::VecTrn: {
      if (e == 8) {  // 2D: whole halves
        V a = i.index ? vhi(i.rn) : vlo(i.rn);
        V b = i.index ? vhi(i.rm) : vlo(i.rm);
        set_v(i.rd, a, b);
      } else if (i.op == Op::VecZip) {
        if (q) {
          V a = i.index ? vhi(i.rn) : vlo(i.rn);
          V b = i.index ? vhi(i.rm) : vlo(i.rm);
          set_v(i.rd, vop(Opcode::VZip, a, b, e, 0), vop(Opcode::VZip, a, b, e, 1));
        } else {
          set_v(i.rd, vop(Opcode::VZip, vlo(i.rn), vlo(i.rm), e, i.index), c(0));
        }
      } else {
        binary([&](V a, V b) { return vop(Opcode::VTrn, a, b, e, i.index); });
      }
      break;
    }
    case Op::VecExt: {
      std::vector<V> words = {vlo(i.rn)};
      if (q) words.push_back(vhi(i.rn));
      words.push_back(vlo(i.rm));
      if (q) words.push_back(vhi(i.rm));
      auto extract = [&](unsigned byte) {
        unsigned j = byte / 8, s = (byte % 8) * 8;
        if (s == 0) return words[j];
        return b_.or_(b_.lshr(words[j], c(s)), b_.shl(words[j + 1], c(64 - s)));
      };
      const unsigned k = static_cast<unsigned>(i.imm);
      V lo = extract(k);
      V hi = q ? extract(k + 8) : c(0);
      set_v(i.rd, lo, hi);
      break;
    }
    case Op::VecBsl:
    case Op::VecBit:
    case Op::VecBif: {
      auto select = [&](V d, V n, V m) {
        switch (i.op) {
          case Op::VecBsl: return b_.or_(b_.and_(d, n), b_.and_(b_.not_(d), m));
          case Op::VecBit: return b_.or_(b_.and_(n, m), b_.and_(d, b_.not_(m)));
          default: return b_.or_(b_.and_(d, m), b_.and_(n, b_.not_(m)));
        }
      };
      V lo = select(vlo(i.rd), vlo(i.rn), vlo(i.rm));
      V hi = q ? select(vhi(i.rd), vhi(i.rn), vhi(i.rm)) : c(0);
      set_v(i.rd, lo, hi);
      break;
    }
    default:
      break;
  }
}

void Lifter::lift_fp(const Instruction& i) {
  const uint8_t fs = i.mem_size;
  const uint64_t sign_bit = fs == 8 ? 0x8000'0000'0000'0000ull : 0x8000'0000ull;
  auto negate = [&](V v) { return b_.xor_(v, c(sign_bit), fs); };
  auto fp = [&](Opcode o, V a, V b = ir::kNoValue, V cc = ir::kNoValue, uint8_t aux = 0) {
    return b_.emit(o, fs, a, b, cc, 0, aux);
  };

  switch (i.op) {
    case Op::FpBinary: {
      static constexpr Opcode ops[9] = {Opcode::FMul, Opcode::FDiv,   Opcode::FAdd,   Opcode::FSub, Opcode::FMax,
                                        Opcode::FMin, Opcode::FMaxNm, Opcode::FMinNm, Opcode::FMul};
      V r = fp(ops[i.shift], vlo(i.rn), vlo(i.rm));
      if (static_cast<FpBinaryOp>(i.shift) == FpBinaryOp::NMul) r = negate(r);
      set_v(i.rd, r, c(0));
      break;
    }
    case Op::FpUnary: {
      V n = vlo(i.rn);
      V r;
      switch (static_cast<FpUnaryOp>(i.shift)) {
        case FpUnaryOp::Abs: r = b_.and_(n, c(~sign_bit), fs); break;
        case FpUnaryOp::Neg: r = negate(n); break;
        default: r = fp(Opcode::FSqrt, n); break;
      }
      set_v(i.rd, r, c(0));
      break;
    }
    case Op::FpCvt:
      set_v(i.rd, fp(Opcode::FCvt, vlo(i.rn), ir::kNoValue, ir::kNoValue, i.esize), c(0));
      break;
    case Op::FpRint:
      set_v(i.rd, fp(Opcode::FRint, vlo(i.rn), ir::kNoValue, ir::kNoValue, i.shift), c(0));
      break;
    case Op::FpFma: {
      // FMADD: n*m + a, FMSUB: -n*m + a, FNMADD: -n*m - a, FNMSUB: n*m - a
      V n = vlo(i.rn), m = vlo(i.rm), a = vlo(i.ra);
      if (i.shift == 1 || i.shift == 2) n = negate(n);
      if (i.shift >= 2) a = negate(a);
      set_v(i.rd, fp(Opcode::FMadd, n, m, a), c(0));
      break;
    }
    case Op::FpCmp:
      set_flags(fp(Opcode::FCmp, vlo(i.rn), i.imm_form ? c(0) : vlo(i.rm)));
      break;
    case Op::FpCcmp: {
      V held = b_.cond_holds(flags(), i.cond);
      V cmp = fp(Opcode::FCmp, vlo(i.rn), vlo(i.rm));
      set_flags(b_.select(held, cmp, c(uint64_t{i.nzcv} << 28)));
      break;
    }
    case Op::FpCsel: {
      V r = b_.select(b_.cond_holds(flags(), i.cond), vlo(i.rn), vlo(i.rm), fs == 8 ? 8 : 4);
      set_v(i.rd, r, c(0));
      break;
    }
    case Op::FpMovImm:
      set_v(i.rd, c(static_cast<uint64_t>(i.imm)), c(0));
      break;
    case Op::FpToInt: {
      const auto aux = static_cast<uint8_t>(i.shift | (i.mem_signed ? 8 : 0) | (fs == 8 ? 16 : 0));
      set_x(i.rd, b_.emit(Opcode::FToInt, i.sf ? 8 : 4, vlo(i.rn), ir::kNoValue, ir::kNoValue, 0, aux));
      break;
    }
    case Op::IntToFp: {
      const auto aux = static_cast<uint8_t>((i.mem_signed ? 1 : 0) | (i.sf ? 2 : 0));
      set_v(i.rd, fp(Opcode::IntToF, x(i.rn), ir::kNoValue, ir::kNoValue, aux), c(0));
      break;
    }
    default:
      break;
  }
}

// The Advanced SIMD groups built on VLane (integer saturating/halving/rounding
// operations, floating point vectors, widening and narrowing, by element,
// table lookups) and the fixed-point conversions.
void Lifter::lift_vector_ext(const Instruction& i) {
  static constexpr uint64_t kReplicate[9] = {0, 0x0101010101010101ull, 0x0001000100010001ull, 0,
                                             0x0000000100000001ull, 0, 0, 0, 1};
  const unsigned e = i.esize;
  const bool q = i.q && !i.scalar;
  const unsigned sign = i.mem_signed ? 1 : 0;
  using ir::VecOp;
  const V none = ir::kNoValue;
  auto lane = [&](VecOp o, V a, V b = ir::kNoValue, V cc = ir::kNoValue, unsigned aux = 0) {
    return b_.emit(Opcode::VLane, 8, a, b, cc, static_cast<uint64_t>(o), static_cast<uint8_t>(aux));
  };
  auto half = [&](unsigned reg, unsigned h) { return h ? vhi(reg) : vlo(reg); };
  auto rep = [&](uint64_t lane_value, unsigned esize) {  // a constant in every lane
    return c(esize == 8 ? lane_value : (lane_value & low_mask(esize * 8)) * kReplicate[esize]);
  };
  // Write the result halves (computed from both halves before writing: rd may alias the sources).
  auto write = [&](auto f) {
    if (i.scalar) {
      V r = f(0u);
      if (e < 8) r = b_.and_(r, c(low_mask(e * 8)));
      set_v(i.rd, r, c(0));
      return;
    }
    V lo = f(0u);
    V hi = q ? f(1u) : c(0);
    set_v(i.rd, lo, hi);
  };
  // Narrow results (64 bits from both source halves) go to the low half, or
  // the high half for the "2" forms (keeping the low one).
  auto write_narrow = [&](V narrow) {
    if (i.scalar) {
      set_v(i.rd, b_.and_(narrow, c(low_mask(e * 8))), c(0));
    } else if (i.index) {
      b_.set(slot::VHi(i.rd), narrow);
    } else {
      set_v(i.rd, narrow, c(0));
    }
  };
  auto join32 = [&](V lo, V hi) {  // two 32-bit results into one half
    return b_.or_(b_.and_(lo, c(0xFFFF'FFFFu)), b_.shl(hi, c(32)));
  };
  auto widen = [&](V src, unsigned part, unsigned esize, unsigned s) {
    return vop(Opcode::VWiden, src, ir::kNoValue, esize, s | (part << 1));
  };
  // The element `index` of register `reg`, replicated across a half.
  auto element = [&](unsigned reg, unsigned index, unsigned esize) {
    V v = vector_element(reg, index, esize);
    if (esize < 8) v = b_.and_(v, c(low_mask(esize * 8)));
    return esize == 8 ? v : b_.binary(Opcode::Mul, v, c(kReplicate[esize]), 8);
  };

  switch (i.op) {
    case Op::VecIntOp: {
      const auto k = static_cast<VecInt>(i.shift);
      const unsigned aux = e | (sign << 4);
      switch (k) {
        case VecInt::SatAdd: write([&](unsigned h) { return lane(VecOp::SatAdd, half(i.rn, h), half(i.rm, h), none, aux); }); break;
        case VecInt::SatSub: write([&](unsigned h) { return lane(VecOp::SatSub, half(i.rn, h), half(i.rm, h), none, aux); }); break;
        case VecInt::Abd: write([&](unsigned h) { return lane(VecOp::Abd, half(i.rn, h), half(i.rm, h), none, aux); }); break;
        case VecInt::Aba:
          write([&](unsigned h) {
            return vop(Opcode::VAdd, half(i.rd, h), lane(VecOp::Abd, half(i.rn, h), half(i.rm, h), none, aux), e);
          });
          break;
        case VecInt::HAdd: write([&](unsigned h) { return lane(VecOp::HAdd, half(i.rn, h), half(i.rm, h), none, aux); }); break;
        case VecInt::RHAdd: write([&](unsigned h) { return lane(VecOp::RHAdd, half(i.rn, h), half(i.rm, h), none, aux); }); break;
        case VecInt::HSub: write([&](unsigned h) { return lane(VecOp::HSub, half(i.rn, h), half(i.rm, h), none, aux); }); break;
        case VecInt::ShlReg: write([&](unsigned h) { return lane(VecOp::ShlReg, half(i.rn, h), half(i.rm, h), none, aux); }); break;
        case VecInt::SatShlReg: write([&](unsigned h) { return lane(VecOp::SatShlReg, half(i.rn, h), half(i.rm, h), none, aux); }); break;
        case VecInt::RShlReg: write([&](unsigned h) { return lane(VecOp::RShlReg, half(i.rn, h), half(i.rm, h), none, aux); }); break;
        case VecInt::SatRShlReg: write([&](unsigned h) { return lane(VecOp::SatRShlReg, half(i.rn, h), half(i.rm, h), none, aux); }); break;
        case VecInt::Mla:
          write([&](unsigned h) { return vop(Opcode::VAdd, half(i.rd, h), vop(Opcode::VMul, half(i.rn, h), half(i.rm, h), e), e); });
          break;
        case VecInt::Mls:
          write([&](unsigned h) { return vop(Opcode::VSub, half(i.rd, h), vop(Opcode::VMul, half(i.rn, h), half(i.rm, h), e), e); });
          break;
        case VecInt::PMul: write([&](unsigned h) { return lane(VecOp::PMul, half(i.rn, h), half(i.rm, h), none, 1); }); break;
        case VecInt::SqDMulH:
        case VecInt::SqRDMulH: {
          const unsigned a = e | (1u << 4) | (k == VecInt::SqRDMulH ? 1u << 5 : 0u);
          write([&](unsigned h) { return lane(VecOp::SatDMulHigh, half(i.rn, h), half(i.rm, h), none, a); });
          break;
        }
      }
      break;
    }

    case Op::VecFpOp: {
      const auto k = static_cast<VecFp>(i.shift);
      static constexpr VecOp kOps[] = {VecOp::FAdd,  VecOp::FSub,  VecOp::FMul,  VecOp::FDiv,   VecOp::FMax,  VecOp::FMin,
                                       VecOp::FMaxNm, VecOp::FMinNm, VecOp::FAbd, VecOp::FMulX, VecOp::FMla, VecOp::FMls,
                                       VecOp::FCmEq, VecOp::FCmGe, VecOp::FCmGt, VecOp::FAcGe, VecOp::FAcGt,
                                       VecOp::FRecps, VecOp::FRsqrts};
      if (k >= VecFp::AddP) {  // pairwise: adjacent lanes of Vm:Vn (scalar: of Vn's two lanes)
        static constexpr VecOp kPair[] = {VecOp::FAdd, VecOp::FMax, VecOp::FMin, VecOp::FMaxNm, VecOp::FMinNm};
        const VecOp o = kPair[static_cast<unsigned>(k) - static_cast<unsigned>(VecFp::AddP)];
        if (i.scalar) {
          V r = e == 8 ? lane(o, vlo(i.rn), vhi(i.rn), none, e) : lane(o, vlo(i.rn), b_.lshr(vlo(i.rn), c(32)), none, e);
          set_v(i.rd, e == 8 ? r : b_.and_(r, c(0xFFFF'FFFFu)), c(0));
          break;
        }
        V nlo = vlo(i.rn), mlo = vlo(i.rm);
        if (q) {
          V nhi = vhi(i.rn), mhi = vhi(i.rm);
          V lo = lane(o, vop(Opcode::VUnzip, nlo, nhi, e, 0), vop(Opcode::VUnzip, nlo, nhi, e, 1), none, e);
          V hi = lane(o, vop(Opcode::VUnzip, mlo, mhi, e, 0), vop(Opcode::VUnzip, mlo, mhi, e, 1), none, e);
          set_v(i.rd, lo, hi);
        } else {
          set_v(i.rd, lane(o, vop(Opcode::VUnzip, nlo, mlo, e, 0), vop(Opcode::VUnzip, nlo, mlo, e, 1), none, e), c(0));
        }
        break;
      }
      const VecOp o = kOps[static_cast<unsigned>(k)];
      if (o == VecOp::FMla || o == VecOp::FMls) {
        write([&](unsigned h) { return lane(o, half(i.rn, h), half(i.rm, h), half(i.rd, h), e); });
      } else {
        write([&](unsigned h) { return lane(o, half(i.rn, h), half(i.rm, h), none, e); });
      }
      break;
    }

    case Op::VecFpAcross: {  // 4 single lanes: op(op(l0, l1), op(l2, l3))
      static constexpr VecOp kOps[] = {VecOp::FAdd, VecOp::FSub, VecOp::FMul, VecOp::FDiv, VecOp::FMax, VecOp::FMin,
                                       VecOp::FMaxNm, VecOp::FMinNm};
      const VecOp o = kOps[i.shift];
      V lo = vlo(i.rn), hi = vhi(i.rn);
      V a = lane(o, lo, b_.lshr(lo, c(32)), none, 4);
      V b = lane(o, hi, b_.lshr(hi, c(32)), none, 4);
      set_v(i.rd, b_.and_(lane(o, a, b, none, 4), c(0xFFFF'FFFFu)), c(0));
      break;
    }

    case Op::VecIntUnary: {
      const auto k = static_cast<VecIntUn>(i.shift);
      const unsigned aux = e | (sign << 4);
      switch (k) {
        case VecIntUn::Clz: write([&](unsigned h) { return lane(VecOp::Clz, half(i.rn, h), none, none, e); }); break;
        case VecIntUn::Cls: write([&](unsigned h) { return lane(VecOp::Cls, half(i.rn, h), none, none, e); }); break;
        case VecIntUn::Rbit: write([&](unsigned h) { return lane(VecOp::Rbit, half(i.rn, h), none, none, 1); }); break;
        case VecIntUn::SatAbs: write([&](unsigned h) { return lane(VecOp::SatAbs, half(i.rn, h), none, none, aux); }); break;
        case VecIntUn::SatNeg: write([&](unsigned h) { return lane(VecOp::SatNeg, half(i.rn, h), none, none, aux); }); break;
        case VecIntUn::AddLP: write([&](unsigned h) { return lane(VecOp::AddLongPairwise, half(i.rn, h), none, none, aux); }); break;
        case VecIntUn::AdaLP:
          write([&](unsigned h) {
            return vop(Opcode::VAdd, half(i.rd, h), lane(VecOp::AddLongPairwise, half(i.rn, h), none, none, aux), e * 2);
          });
          break;
        case VecIntUn::SatXtn: {  // esize = narrow size; amount = mode
          const unsigned a = e | (static_cast<unsigned>(i.amount) << 4);
          if (i.scalar) {
            write_narrow(lane(VecOp::SatNarrow, vlo(i.rn), none, none, a));
          } else {
            write_narrow(join32(lane(VecOp::SatNarrow, vlo(i.rn), none, none, a), lane(VecOp::SatNarrow, vhi(i.rn), none, none, a)));
          }
          break;
        }
        case VecIntUn::Shll: {  // SHLL: widen and shift by the element size
          V src = i.index ? vhi(i.rn) : vlo(i.rn);
          V lo = vop(Opcode::VShl, widen(src, 0, e, 0), c(e * 8), e * 2);
          V hi = vop(Opcode::VShl, widen(src, 1, e, 0), c(e * 8), e * 2);
          set_v(i.rd, lo, hi);
          break;
        }
      }
      break;
    }

    case Op::VecFpUnary: {
      const auto k = static_cast<VecFpUn>(i.shift);
      const uint64_t sign_bits = e == 8 ? 1ull << 63 : (1ull << (e * 8 - 1)) * kReplicate[e];
      switch (k) {
        case VecFpUn::Abs: write([&](unsigned h) { return b_.and_(half(i.rn, h), b_.not_(c(sign_bits))); }); break;
        case VecFpUn::Neg: write([&](unsigned h) { return b_.xor_(half(i.rn, h), c(sign_bits)); }); break;
        case VecFpUn::Sqrt: write([&](unsigned h) { return lane(VecOp::FSqrt, half(i.rn, h), none, none, e); }); break;
        case VecFpUn::Recpe: write([&](unsigned h) { return lane(VecOp::FRecpe, half(i.rn, h), none, none, e); }); break;
        case VecFpUn::Rsqrte: write([&](unsigned h) { return lane(VecOp::FRsqrte, half(i.rn, h), none, none, e); }); break;
        case VecFpUn::Rint:
          write([&](unsigned h) { return lane(VecOp::FRint, half(i.rn, h), none, none, e | (i.amount << 4)); });
          break;
        case VecFpUn::ToInt:
          write([&](unsigned h) { return lane(VecOp::FToInt, half(i.rn, h), c(0), none, e | (i.amount << 4) | (sign << 7)); });
          break;
        case VecFpUn::FromInt:
          write([&](unsigned h) { return lane(VecOp::IntToF, half(i.rn, h), c(0), none, e | (sign << 4)); });
          break;
        case VecFpUn::CmpZero: {
          const auto z = static_cast<VecZeroCmp>(i.amount);
          write([&](unsigned h) {
            V n = half(i.rn, h), zero = c(0);
            switch (z) {
              case VecZeroCmp::Gt: return lane(VecOp::FCmGt, n, zero, none, e);
              case VecZeroCmp::Ge: return lane(VecOp::FCmGe, n, zero, none, e);
              case VecZeroCmp::Eq: return lane(VecOp::FCmEq, n, zero, none, e);
              case VecZeroCmp::Le: return lane(VecOp::FCmGe, zero, n, none, e);
              default: return lane(VecOp::FCmGt, zero, n, none, e);
            }
          });
          break;
        }
        case VecFpUn::CvtLong: {  // esize = destination size
          V src = i.index ? vhi(i.rn) : vlo(i.rn);
          set_v(i.rd, lane(VecOp::FCvtUp, src, none, none, e), lane(VecOp::FCvtUp, src, none, none, e | 16));
          break;
        }
        case VecFpUn::CvtNarrow:  // esize = destination size
          write_narrow(lane(VecOp::FCvtDown, vlo(i.rn), vhi(i.rn), none, e));
          break;
      }
      break;
    }

    case Op::VecLong: {  // esize = narrow size; wide lanes are 2e
      const auto k = static_cast<VecLongKind>(i.shift);
      const unsigned w2 = e * 2;
      V n_src = i.index ? vhi(i.rn) : vlo(i.rn);
      V m_src = i.index ? vhi(i.rm) : vlo(i.rm);
      auto wn = [&](unsigned p) { return widen(n_src, p, e, sign); };
      auto wm = [&](unsigned p) { return widen(m_src, p, e, sign); };
      auto both = [&](auto f) {
        V lo = f(0u), hi = f(1u);
        set_v(i.rd, lo, hi);
      };
      switch (k) {
        case VecLongKind::AddL: both([&](unsigned p) { return vop(Opcode::VAdd, wn(p), wm(p), w2); }); break;
        case VecLongKind::SubL: both([&](unsigned p) { return vop(Opcode::VSub, wn(p), wm(p), w2); }); break;
        case VecLongKind::AddW: both([&](unsigned p) { return vop(Opcode::VAdd, half(i.rn, p), wm(p), w2); }); break;
        case VecLongKind::SubW: both([&](unsigned p) { return vop(Opcode::VSub, half(i.rn, p), wm(p), w2); }); break;
        case VecLongKind::AbdL: both([&](unsigned p) { return lane(VecOp::Abd, wn(p), wm(p), none, w2 | (sign << 4)); }); break;
        case VecLongKind::AbaL:
          both([&](unsigned p) {
            return vop(Opcode::VAdd, half(i.rd, p), lane(VecOp::Abd, wn(p), wm(p), none, w2 | (sign << 4)), w2);
          });
          break;
        case VecLongKind::MulL: both([&](unsigned p) { return vop(Opcode::VMul, wn(p), wm(p), w2); }); break;
        case VecLongKind::MlaL:
          both([&](unsigned p) { return vop(Opcode::VAdd, half(i.rd, p), vop(Opcode::VMul, wn(p), wm(p), w2), w2); });
          break;
        case VecLongKind::MlsL:
          both([&](unsigned p) { return vop(Opcode::VSub, half(i.rd, p), vop(Opcode::VMul, wn(p), wm(p), w2), w2); });
          break;
        case VecLongKind::PMulL:
          both([&](unsigned p) { return lane(VecOp::PMulLong, n_src, m_src, none, 1 | (p << 5)); });
          break;
        case VecLongKind::SqDMulL:
        case VecLongKind::SqDMlaL:
        case VecLongKind::SqDMlsL: {
          const unsigned a = w2 | (1u << 4);
          both([&](unsigned p) {
            V prod = vop(Opcode::VMul, widen(n_src, p, e, 1), widen(m_src, p, e, 1), w2);
            V doubled = lane(VecOp::SatAdd, prod, prod, none, a);
            if (k == VecLongKind::SqDMulL) return doubled;
            return lane(k == VecLongKind::SqDMlaL ? VecOp::SatAdd : VecOp::SatSub, half(i.rd, p), doubled, none, a);
          });
          break;
        }
        case VecLongKind::AddHN:
        case VecLongKind::RAddHN:
        case VecLongKind::SubHN:
        case VecLongKind::RSubHN: {  // here e is the narrow (destination) size
          const bool sub = k == VecLongKind::SubHN || k == VecLongKind::RSubHN;
          const bool round = k == VecLongKind::RAddHN || k == VecLongKind::RSubHN;
          V sums[2];
          for (unsigned p = 0; p < 2; ++p) {
            V s = vop(sub ? Opcode::VSub : Opcode::VAdd, half(i.rn, p), half(i.rm, p), w2);
            if (round) s = vop(Opcode::VAdd, s, rep(1ull << (e * 8 - 1), w2), w2);
            sums[p] = s;
          }
          write_narrow(vop(Opcode::VUnzip, sums[0], sums[1], e, 1));
          break;
        }
      }
      break;
    }

    case Op::VecShiftOp: {
      const auto k = static_cast<VecShiftKind>(i.shift);
      const unsigned n = static_cast<unsigned>(i.imm);
      const unsigned aux = e | (sign << 4);
      auto shr = [&](V v) { return vop(i.mem_signed ? Opcode::VAShr : Opcode::VLShr, v, c(n), e); };
      switch (k) {
        case VecShiftKind::Sra: write([&](unsigned h) { return vop(Opcode::VAdd, half(i.rd, h), shr(half(i.rn, h)), e); }); break;
        case VecShiftKind::RShr: write([&](unsigned h) { return lane(VecOp::RShr, half(i.rn, h), c(n), none, aux); }); break;
        case VecShiftKind::RSra:
          write([&](unsigned h) { return vop(Opcode::VAdd, half(i.rd, h), lane(VecOp::RShr, half(i.rn, h), c(n), none, aux), e); });
          break;
        case VecShiftKind::Sri: {
          const uint64_t keep = n >= e * 8 ? low_mask(e * 8) : ~(low_mask(e * 8) >> n) & low_mask(e * 8);
          write([&](unsigned h) {
            V shifted = vop(Opcode::VLShr, half(i.rn, h), c(n), e);
            return b_.or_(b_.and_(half(i.rd, h), rep(keep, e)), shifted);
          });
          break;
        }
        case VecShiftKind::Sli: {
          const uint64_t keep = low_mask(n);
          write([&](unsigned h) {
            V shifted = vop(Opcode::VShl, half(i.rn, h), c(n), e);
            return b_.or_(b_.and_(half(i.rd, h), rep(keep, e)), shifted);
          });
          break;
        }
        case VecShiftKind::SatShl:
          write([&](unsigned h) { return lane(VecOp::SatShlImm, half(i.rn, h), c(n), none, e | (i.amount << 4)); });
          break;
        case VecShiftKind::Rshrn: {  // e = destination size
          V lo = lane(VecOp::RShr, vlo(i.rn), c(n), none, e * 2);
          V hi = lane(VecOp::RShr, vhi(i.rn), c(n), none, e * 2);
          write_narrow(vop(Opcode::VUnzip, lo, hi, e, 0));
          break;
        }
        case VecShiftKind::SatShrn: {  // e = destination size; amount: mode | rounding << 2
          const unsigned mode = i.amount & 3;
          const bool rounding = i.amount & 4;
          const bool source_signed = mode != 1;
          auto narrow_half = [&](V v) {
            V shifted = rounding ? lane(VecOp::RShr, v, c(n), none, e * 2 | (source_signed ? 16u : 0u))
                                 : vop(source_signed ? Opcode::VAShr : Opcode::VLShr, v, c(n), e * 2);
            return lane(VecOp::SatNarrow, shifted, none, none, e | (mode << 4));
          };
          if (i.scalar) {
            write_narrow(narrow_half(vlo(i.rn)));
          } else {
            write_narrow(join32(narrow_half(vlo(i.rn)), narrow_half(vhi(i.rn))));
          }
          break;
        }
        case VecShiftKind::FixedToFp:
          write([&](unsigned h) { return lane(VecOp::IntToF, half(i.rn, h), c(n), none, aux); });
          break;
        case VecShiftKind::FpToFixed: {
          const unsigned a = e | (static_cast<unsigned>(ir::FpRound::Zero) << 4) | (sign << 7);
          write([&](unsigned h) { return lane(VecOp::FToInt, half(i.rn, h), c(n), none, a); });
          break;
        }
      }
      break;
    }

    case Op::VecElemOp: {
      const auto k = static_cast<VecElemKind>(i.shift);
      V el = element(i.rm, i.index2, e);  // read before any write
      switch (k) {
        case VecElemKind::Mul: write([&](unsigned h) { return vop(Opcode::VMul, half(i.rn, h), el, e); }); break;
        case VecElemKind::Mla:
          write([&](unsigned h) { return vop(Opcode::VAdd, half(i.rd, h), vop(Opcode::VMul, half(i.rn, h), el, e), e); });
          break;
        case VecElemKind::Mls:
          write([&](unsigned h) { return vop(Opcode::VSub, half(i.rd, h), vop(Opcode::VMul, half(i.rn, h), el, e), e); });
          break;
        case VecElemKind::FMul: write([&](unsigned h) { return lane(VecOp::FMul, half(i.rn, h), el, none, e); }); break;
        case VecElemKind::FMulX: write([&](unsigned h) { return lane(VecOp::FMulX, half(i.rn, h), el, none, e); }); break;
        case VecElemKind::FMla: write([&](unsigned h) { return lane(VecOp::FMla, half(i.rn, h), el, half(i.rd, h), e); }); break;
        case VecElemKind::FMls: write([&](unsigned h) { return lane(VecOp::FMls, half(i.rn, h), el, half(i.rd, h), e); }); break;
        case VecElemKind::SqDMulH:
        case VecElemKind::SqRDMulH: {
          const unsigned a = e | (1u << 4) | (k == VecElemKind::SqRDMulH ? 1u << 5 : 0u);
          write([&](unsigned h) { return lane(VecOp::SatDMulHigh, half(i.rn, h), el, none, a); });
          break;
        }
        default: {  // long forms: e = narrow size
          const unsigned w2 = e * 2;
          V src = i.index ? vhi(i.rn) : vlo(i.rn);
          const unsigned s = (k == VecElemKind::SqDMulL || k == VecElemKind::SqDMlaL || k == VecElemKind::SqDMlsL) ? 1 : sign;
          auto product = [&](unsigned p) { return vop(Opcode::VMul, widen(src, p, e, s), widen(el, p, e, s), w2); };
          auto compute = [&](unsigned p) -> V {
            switch (k) {
              case VecElemKind::MulL: return product(p);
              case VecElemKind::MlaL: return vop(Opcode::VAdd, half(i.rd, p), product(p), w2);
              case VecElemKind::MlsL: return vop(Opcode::VSub, half(i.rd, p), product(p), w2);
              default: {
                const unsigned a = w2 | (1u << 4);
                V pr = product(p);
                V doubled = lane(VecOp::SatAdd, pr, pr, none, a);
                if (k == VecElemKind::SqDMulL) return doubled;
                return lane(k == VecElemKind::SqDMlaL ? VecOp::SatAdd : VecOp::SatSub, half(i.rd, p), doubled, none, a);
              }
            }
          };
          if (i.scalar) {
            set_v(i.rd, b_.and_(compute(0), c(low_mask(w2 * 8))), c(0));
          } else {
            V lo = compute(0), hi = compute(1);
            set_v(i.rd, lo, hi);
          }
          break;
        }
      }
      break;
    }

    case Op::VecTbl: {
      const unsigned regs = i.amount;
      V tables[8];
      for (unsigned t = 0; t < regs; ++t) {
        tables[2 * t] = vlo((i.rn + t) % 32);
        tables[2 * t + 1] = vhi((i.rn + t) % 32);
      }
      auto lookup = [&](unsigned h) {
        V acc = i.index ? half(i.rd, h) : c(0);  // TBX keeps the destination's bytes
        V idx = half(i.rm, h);
        for (unsigned part = 0; part < 2 * regs; ++part) acc = lane(VecOp::TblPart, acc, idx, tables[part], part);
        return acc;
      };
      V lo = lookup(0);
      V hi = i.q ? lookup(1) : c(0);
      set_v(i.rd, lo, hi);
      break;
    }

    case Op::FpFixedToFp: {  // integer register / 2^fbits
      const uint8_t fs = i.mem_size;
      const auto aux = static_cast<uint8_t>((i.mem_signed ? 1 : 0) | (i.sf ? 2 : 0));
      V v = b_.emit(Opcode::IntToF, fs, x(i.rn), ir::kNoValue, ir::kNoValue, 0, aux);
      const int fbits = static_cast<int>(i.imm);
      const uint64_t scale = fs == 8 ? std::bit_cast<uint64_t>(std::ldexp(1.0, -fbits))
                                     : std::bit_cast<uint32_t>(std::ldexp(1.0f, -fbits));
      set_v(i.rd, b_.emit(Opcode::FMul, fs, v, c(scale)), c(0));
      break;
    }
    case Op::FpToFixed: {  // truncate(value * 2^fbits)
      const uint8_t fs = i.mem_size;
      const int fbits = static_cast<int>(i.imm);
      const uint64_t scale = fs == 8 ? std::bit_cast<uint64_t>(std::ldexp(1.0, fbits))
                                     : std::bit_cast<uint32_t>(std::ldexp(1.0f, fbits));
      V scaled = b_.emit(Opcode::FMul, fs, vlo(i.rn), c(scale));
      const auto aux = static_cast<uint8_t>(static_cast<unsigned>(ir::FpRound::Zero) | (i.mem_signed ? 8 : 0) |
                                            (fs == 8 ? 16 : 0));
      set_x(i.rd, b_.emit(Opcode::FToInt, i.sf ? 8 : 4, scaled, ir::kNoValue, ir::kNoValue, 0, aux));
      break;
    }
    default:
      break;
  }
}

bool Lifter::lift(const Instruction& i) {
  const uint8_t s = i.sf ? 8 : 4;
  const uint64_t next = i.pc + 4;
  const uint64_t imm = static_cast<uint64_t>(i.imm);

  switch (i.op) {
    case Op::Invalid:
    case Op::Udf:
      b_.exit(static_cast<uint32_t>(ExitReason::Undefined), i.raw, i.pc);
      return true;
    case Op::Unsupported:
    case Op::Count_:
      return unsupported(i);

    // --- data processing (immediate) ---
    case Op::Adr:
    case Op::Adrp:
      set_x(i.rd, c(imm));
      return false;
    case Op::AddImm:
    case Op::SubImm: {
      bool add = i.op == Op::AddImm;
      V a = xsp(i.rn), b = c(imm);
      V r = op(add ? Opcode::Add : Opcode::Sub, a, b, s);
      if (i.set_flags) {
        set_flags(b_.emit(add ? Opcode::FlagsAdd : Opcode::FlagsSub, s, a, b));
        set_x(i.rd, r);
      } else {
        set_xsp(i.rd, r);
      }
      return false;
    }
    case Op::AndImm:
    case Op::OrrImm:
    case Op::EorImm: {
      Opcode o = i.op == Op::AndImm ? Opcode::And : i.op == Op::OrrImm ? Opcode::Or : Opcode::Xor;
      V r = op(o, x(i.rn), c(imm), s);
      if (i.set_flags) {
        set_flags(b_.emit(Opcode::FlagsLogic, s, r));
        set_x(i.rd, r);
      } else {
        set_xsp(i.rd, r);
      }
      return false;
    }
    case Op::Movz:
      set_x(i.rd, c(imm << i.amount));
      return false;
    case Op::Movn: {
      uint64_t v = ~(imm << i.amount);
      set_x(i.rd, c(i.sf ? v : (v & 0xFFFF'FFFFu)));
      return false;
    }
    case Op::Movk: {
      V keep = op(Opcode::And, x(i.rd), c(~(0xFFFFull << i.amount)), s);
      set_x(i.rd, op(Opcode::Or, keep, c(imm << i.amount), s));
      return false;
    }
    case Op::Sbfm:
    case Op::Bfm:
    case Op::Ubfm:
      lift_bitfield(i);
      return false;
    case Op::Extr: {
      const unsigned lsb = i.immr;
      V r;
      if (lsb == 0) r = i.sf ? x(i.rm) : b_.zext(x(i.rm), 32);
      else if (i.rn == i.rm) r = op(Opcode::Ror, x(i.rn), c(lsb), s);
      else r = op(Opcode::Or, op(Opcode::LShr, x(i.rm), c(lsb), s), op(Opcode::Shl, x(i.rn), c(s * 8u - lsb), s), s);
      set_x(i.rd, r);
      return false;
    }

    // --- branches / system ---
    case Op::B:
      b_.jump(imm);
      return true;
    case Op::Bl:
      set_x(30, c(next));
      b_.jump(imm);
      return true;
    case Op::BCond:
      if (i.cond >= 14) b_.jump(imm);
      else b_.branch(b_.cond_holds(flags(), i.cond), imm, next);
      return true;
    case Op::Cbz:
    case Op::Cbnz:
      b_.branch(b_.cmp(i.op == Op::Cbz ? Predicate::Eq : Predicate::Ne, x(i.rd), c(0), s), imm, next);
      return true;
    case Op::Tbz:
    case Op::Tbnz: {
      V bitv = b_.and_(b_.lshr(x(i.rd), c(i.amount)), c(1));
      V cond = i.op == Op::Tbz ? b_.cmp(Predicate::Eq, bitv, c(0)) : bitv;
      b_.branch(cond, imm, next);
      return true;
    }
    case Op::Br:
    case Op::Ret:
      b_.jump_indirect(x(i.rn));
      return true;
    case Op::Blr: {
      V target = x(i.rn);
      set_x(30, c(next));
      b_.jump_indirect(target);
      return true;
    }
    case Op::Svc:
      b_.exit(static_cast<uint32_t>(ExitReason::Svc), static_cast<uint32_t>(imm), next);
      return true;
    case Op::Brk:
      b_.exit(static_cast<uint32_t>(ExitReason::Brk), static_cast<uint32_t>(imm), i.pc);
      return true;
    case Op::Hlt:
      b_.exit(static_cast<uint32_t>(ExitReason::Hlt), static_cast<uint32_t>(imm), i.pc);
      return true;
    case Op::DcZva: {
      V base = b_.and_(x(i.rd), c(~uint64_t{63}));
      for (unsigned k = 0; k < 64; k += 8) b_.store(k ? b_.add(base, c(k)) : base, c(0), 8);
      return false;
    }
    case Op::Nop:
    case Op::Clrex:
    case Op::Prfm:
      return false;
    case Op::Barrier:
      b_.emit(Opcode::Fence, 8);
      return false;
    case Op::Mrs:
      return lift_mrs(i);
    case Op::Msr:
      return lift_msr(i);

    // --- data processing (register) ---
    case Op::AndReg: case Op::BicReg: case Op::OrrReg: case Op::OrnReg: case Op::EorReg: case Op::EonReg: {
      V m = shifted(x(i.rm), static_cast<ShiftType>(i.shift), i.amount, s);
      if (i.op == Op::BicReg || i.op == Op::OrnReg || i.op == Op::EonReg) m = b_.not_(m, s);
      Opcode o = (i.op == Op::AndReg || i.op == Op::BicReg) ? Opcode::And
               : (i.op == Op::OrrReg || i.op == Op::OrnReg) ? Opcode::Or
                                                            : Opcode::Xor;
      V r = op(o, x(i.rn), m, s);
      if (i.set_flags) set_flags(b_.emit(Opcode::FlagsLogic, s, r));
      set_x(i.rd, r);
      return false;
    }
    case Op::AddShift:
    case Op::SubShift:
    case Op::AddExt:
    case Op::SubExt: {
      bool ext = i.op == Op::AddExt || i.op == Op::SubExt;
      bool add = i.op == Op::AddShift || i.op == Op::AddExt;
      V a = ext ? xsp(i.rn) : x(i.rn);
      V m = ext ? extended(x(i.rm), static_cast<Extend>(i.shift), i.amount)
                : shifted(x(i.rm), static_cast<ShiftType>(i.shift), i.amount, s);
      V r = op(add ? Opcode::Add : Opcode::Sub, a, m, s);
      if (i.set_flags) {
        set_flags(b_.emit(add ? Opcode::FlagsAdd : Opcode::FlagsSub, s, a, m));
        set_x(i.rd, r);
      } else if (ext) {
        set_xsp(i.rd, r);
      } else {
        set_x(i.rd, r);
      }
      return false;
    }
    case Op::Adc:
    case Op::Sbc: {
      bool adc = i.op == Op::Adc;
      V f = flags(), a = x(i.rn), m = x(i.rm);
      V r = b_.emit(adc ? Opcode::Adc : Opcode::Sbc, s, a, m, f);
      if (i.set_flags) set_flags(b_.emit(adc ? Opcode::FlagsAdc : Opcode::FlagsSbc, s, a, m, f));
      set_x(i.rd, r);
      return false;
    }
    case Op::Ccmn:
    case Op::Ccmp: {
      V f = flags();
      V a = x(i.rn);
      V m = i.imm_form ? c(imm) : x(i.rm);
      V cmp = b_.emit(i.op == Op::Ccmp ? Opcode::FlagsSub : Opcode::FlagsAdd, s, a, m);
      V held = b_.cond_holds(f, i.cond);
      set_flags(b_.select(held, cmp, c(uint64_t{i.nzcv} << 28)));
      return false;
    }
    case Op::Csel: case Op::Csinc: case Op::Csinv: case Op::Csneg: {
      V held = b_.cond_holds(flags(), i.cond);
      V n = x(i.rn);
      V m = x(i.rm);
      V alt = m;
      if (i.op == Op::Csinc) alt = op(Opcode::Add, m, c(1), s);
      else if (i.op == Op::Csinv) alt = b_.not_(m, s);
      else if (i.op == Op::Csneg) alt = b_.neg(m, s);
      set_x(i.rd, b_.select(held, n, alt, s));
      return false;
    }
    case Op::Rbit: {
      V v = x(i.rn);
      static constexpr uint64_t masks[3] = {0x5555555555555555ull, 0x3333333333333333ull, 0x0F0F0F0F0F0F0F0Full};
      for (unsigned k = 0; k < 3; ++k) {
        unsigned sh = 1u << k;
        V hi = op(Opcode::And, op(Opcode::LShr, v, c(sh), s), c(masks[k]), s);
        V lo = op(Opcode::Shl, op(Opcode::And, v, c(masks[k]), s), c(sh), s);
        v = op(Opcode::Or, hi, lo, s);
      }
      set_x(i.rd, b_.emit(Opcode::Bswap, s, v));
      return false;
    }
    case Op::Rev16: {
      V v = x(i.rn);
      const uint64_t m = 0x00FF00FF00FF00FFull;
      V hi = op(Opcode::And, op(Opcode::LShr, v, c(8), s), c(m), s);
      V lo = op(Opcode::Shl, op(Opcode::And, v, c(m), s), c(8), s);
      set_x(i.rd, op(Opcode::Or, hi, lo, s));
      return false;
    }
    case Op::Rev32:
      set_x(i.rd, op(Opcode::Ror, b_.emit(Opcode::Bswap, 8, x(i.rn)), c(32), 8));
      return false;
    case Op::Rev:
      set_x(i.rd, b_.emit(Opcode::Bswap, s, x(i.rn)));
      return false;
    case Op::Clz:
      set_x(i.rd, b_.emit(Opcode::Clz, s, x(i.rn)));
      return false;
    case Op::Cls: {
      V v = x(i.rn);
      V t = op(Opcode::Xor, v, op(Opcode::AShr, v, c(1), s), s);
      set_x(i.rd, op(Opcode::Sub, b_.emit(Opcode::Clz, s, t), c(1), s));
      return false;
    }
    case Op::Udiv: case Op::Sdiv: case Op::Lslv: case Op::Lsrv: case Op::Asrv: case Op::Rorv: {
      Opcode o = i.op == Op::Udiv ? Opcode::UDiv
               : i.op == Op::Sdiv ? Opcode::SDiv
               : i.op == Op::Lslv ? Opcode::Shl
               : i.op == Op::Lsrv ? Opcode::LShr
               : i.op == Op::Asrv ? Opcode::AShr
                                  : Opcode::Ror;
      set_x(i.rd, op(o, x(i.rn), x(i.rm), s));
      return false;
    }
    case Op::Madd:
    case Op::Msub: {
      V prod = op(Opcode::Mul, x(i.rn), x(i.rm), s);
      set_x(i.rd, op(i.op == Op::Madd ? Opcode::Add : Opcode::Sub, x(i.ra), prod, s));
      return false;
    }
    case Op::Smaddl: case Op::Smsubl: case Op::Umaddl: case Op::Umsubl: {
      bool sign = i.op == Op::Smaddl || i.op == Op::Smsubl;
      V a = sign ? b_.sext(x(i.rn), 32) : b_.zext(x(i.rn), 32);
      V m = sign ? b_.sext(x(i.rm), 32) : b_.zext(x(i.rm), 32);
      V prod = op(Opcode::Mul, a, m, 8);
      bool add = i.op == Op::Smaddl || i.op == Op::Umaddl;
      set_x(i.rd, op(add ? Opcode::Add : Opcode::Sub, x(i.ra), prod, 8));
      return false;
    }
    case Op::Smulh:
    case Op::Umulh:
      set_x(i.rd, op(i.op == Op::Smulh ? Opcode::SMulH : Opcode::UMulH, x(i.rn), x(i.rm), 8));
      return false;

    // --- loads and stores ---
    case Op::Ldr:
    case Op::Str:
      lift_load_store(i);
      return false;
    case Op::Ldp:
    case Op::Stp:
      lift_pair(i);
      return false;
    case Op::Ldxr:
    case Op::Stxr:
    case Op::Ldxp:
    case Op::Stxp:
      lift_exclusive(i);
      return false;
    case Op::Cas: case Op::Casp: case Op::Swp: case Op::Ldadd: case Op::Ldclr: case Op::Ldeor: case Op::Ldset:
    case Op::Ldsmax: case Op::Ldsmin: case Op::Ldumax: case Op::Ldumin:
      lift_atomic(i);
      return false;

    // --- SIMD & FP data movement ---
    case Op::FmovToGp: case Op::FmovFromGp: case Op::FmovReg: case Op::VMovImm: case Op::VOrrImm: case Op::VBicImm:
    case Op::VDupGp: case Op::VDupElem: case Op::VDupScalar: case Op::VUmov: case Op::VSmov: case Op::VInsGp: case Op::VInsElem:
    case Op::VAnd: case Op::VBic: case Op::VOrr: case Op::VOrn: case Op::VEor:
      lift_simd(i);
      return false;

    case Op::VLdMulti: case Op::VStMulti: case Op::VLdLane: case Op::VStLane: case Op::VLdRep:
      lift_simd_memory(i);
      return false;

    case Op::VecAdd: case Op::VecSub: case Op::VecMul: case Op::VecCmp: case Op::VecCmpZero: case Op::VecMax:
    case Op::VecMin: case Op::VecMaxP: case Op::VecMinP: case Op::VecAddP: case Op::VecAddAcross:
    case Op::VecMaxAcross: case Op::VecMinAcross: case Op::VecAddLongAcross: case Op::VecAddPScalar:
    case Op::VecShl: case Op::VecShr: case Op::VecShrn: case Op::VecXtn: case Op::VecShll: case Op::VecCnt:
    case Op::VecNot: case Op::VecNeg: case Op::VecAbs: case Op::VecRev: case Op::VecUzp: case Op::VecZip:
    case Op::VecTrn: case Op::VecExt: case Op::VecBsl: case Op::VecBit: case Op::VecBif:
      lift_vector(i);
      return false;

    case Op::VecIntOp: case Op::VecFpOp: case Op::VecIntUnary: case Op::VecFpUnary: case Op::VecLong:
    case Op::VecShiftOp: case Op::VecElemOp: case Op::VecTbl: case Op::VecFpAcross: case Op::FpFixedToFp:
    case Op::FpToFixed:
      lift_vector_ext(i);
      return false;

    case Op::FpBinary: case Op::FpUnary: case Op::FpCvt: case Op::FpRint: case Op::FpFma: case Op::FpCmp:
    case Op::FpCcmp: case Op::FpCsel: case Op::FpMovImm: case Op::FpToInt: case Op::IntToFp:
      lift_fp(i);
      return false;
  }
  return unsupported(i);
}

}  // namespace

bool lift_instruction(const Instruction& insn, ir::Builder& builder) { return Lifter(builder).lift(insn); }

ir::Block lift_block(uint64_t pc, const CodeReader& read, const LiftOptions& options) {
  ir::Block block;
  block.guest_pc = pc;
  ir::Builder builder(block);
  Lifter lifter(builder, options);

  uint64_t cur = pc;
  for (uint32_t n = 0;; ++n) {
    if (n >= options.max_insns) {
      builder.jump(cur);
      break;
    }
    uint32_t word = 0;
    if ((cur & 3) != 0 || !read(cur, word)) {
      if (n == 0) builder.exit(static_cast<uint32_t>(ExitReason::FetchFault), 0, cur);
      else builder.jump(cur);
      break;
    }
    Instruction insn = decode(word, cur);
    ++block.guest_insns;
    cur += 4;
    if (lifter.lift(insn)) break;
  }
  block.guest_end = cur;
  return block;
}

ir::StateLayout state_layout() {
  ir::StateLayout layout;
  layout.pc_slot = slot::PC;
  layout.exit_reason_offset = offsetof(CpuState, exit_reason);
  layout.exit_info_offset = offsetof(CpuState, exit_info);
  layout.slot_count = slot::Count;
  return layout;
}

}  // namespace juice::arm64
