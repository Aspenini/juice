#include "core/ir/ir.hpp"

#include <bit>
#include <format>

#include "core/ir/eval_simd.hpp"

namespace juice::ir {

// --- Builder -------------------------------------------------------------------

ValueId Builder::emit(const Inst& inst) {
  block_.insts.push_back(inst);
  return static_cast<ValueId>(block_.insts.size() - 1);
}

ValueId Builder::emit(Opcode op, uint8_t size, ValueId a, ValueId b, ValueId c, uint64_t imm, uint8_t aux) {
  Inst inst;
  inst.op = op;
  inst.size = size;
  inst.aux = aux;
  inst.args = {a, b, c};
  inst.imm = imm;
  return emit(inst);
}

ValueId Builder::constant(uint64_t value) { return emit(Opcode::Const, 8, kNoValue, kNoValue, kNoValue, value); }
ValueId Builder::get(uint16_t slot) { return emit(Opcode::GetReg, 8, kNoValue, kNoValue, kNoValue, slot); }
void Builder::set(uint16_t slot, ValueId value) { emit(Opcode::SetReg, 8, value, kNoValue, kNoValue, slot); }

ValueId Builder::load(ValueId addr, uint8_t bytes, bool sign_extend) {
  return emit(Opcode::Load, bytes, addr, kNoValue, kNoValue, 0, sign_extend ? 1 : 0);
}

void Builder::store(ValueId addr, ValueId value, uint8_t bytes) { emit(Opcode::Store, bytes, addr, value); }

void Builder::load_to_state(ValueId addr, uint16_t slot, uint8_t bytes, uint8_t zero_to) {
  emit(Opcode::LoadToState, bytes, addr, kNoValue, kNoValue, slot, zero_to);
}

void Builder::store_from_state(ValueId addr, uint16_t slot, uint8_t bytes) {
  emit(Opcode::StoreFromState, bytes, addr, kNoValue, kNoValue, slot);
}

void Builder::jump(uint64_t target) {
  block_.term = {};
  block_.term.kind = Terminator::Kind::Jump;
  block_.term.target = target;
}

void Builder::jump_indirect(ValueId target) {
  block_.term = {};
  block_.term.kind = Terminator::Kind::JumpIndirect;
  block_.term.value = target;
}

void Builder::branch(ValueId cond, uint64_t target, uint64_t fallthrough) {
  block_.term = {};
  block_.term.kind = Terminator::Kind::Branch;
  block_.term.value = cond;
  block_.term.target = target;
  block_.term.fallthrough = fallthrough;
}

void Builder::exit(uint32_t reason, uint32_t info, uint64_t pc) {
  block_.term = {};
  block_.term.kind = Terminator::Kind::Exit;
  block_.term.exit_reason = reason;
  block_.term.exit_info = info;
  block_.term.target = pc;
}

// --- Opcode properties --------------------------------------------------------------

bool has_side_effects(Opcode op) {
  switch (op) {
    case Opcode::SetReg:
    case Opcode::Store:
    case Opcode::LoadToState:
    case Opcode::StoreFromState:
    case Opcode::Fence:
    case Opcode::AtomicRmw:
    case Opcode::AtomicCas:
    case Opcode::AtomicCasPair:
    case Opcode::Counter:  // not removable: each read must see the time it runs at
      return true;
    default:
      return false;
  }
}

bool is_pure(Opcode op) {
  switch (op) {
    case Opcode::Counter:
    case Opcode::StateAddr:
    case Opcode::Fence:
    case Opcode::AtomicRmw:
    case Opcode::AtomicCas:
    case Opcode::AtomicCasPair:
    case Opcode::Nop:
    case Opcode::GetReg:
    case Opcode::SetReg:
    case Opcode::Load:
    case Opcode::Store:
    case Opcode::LoadToState:
    case Opcode::StoreFromState:
    case Opcode::Count_:
      return false;
    default:
      return true;
  }
}

bool has_result(Opcode op) {
  switch (op) {
    case Opcode::Fence:
    case Opcode::Nop:
    case Opcode::SetReg:
    case Opcode::Store:
    case Opcode::LoadToState:
    case Opcode::StoreFromState:
    case Opcode::Count_:
      return false;
    default:
      return true;
  }
}

bool is_vector_or_fp(Opcode op) {
  return static_cast<unsigned>(op) >= static_cast<unsigned>(Opcode::VAdd) &&
         static_cast<unsigned>(op) < static_cast<unsigned>(Opcode::Count_);
}

unsigned arg_count(Opcode op) {
  switch (op) {
    case Opcode::Nop:
    case Opcode::Const:
    case Opcode::GetReg:
    case Opcode::StateAddr:
    case Opcode::Fence:
    case Opcode::Counter:
    case Opcode::Count_:
      return 0;
    case Opcode::SetReg:
    case Opcode::Load:
    case Opcode::LoadToState:
    case Opcode::StoreFromState:
    case Opcode::Not:
    case Opcode::Neg:
    case Opcode::Clz:
    case Opcode::Bswap:
    case Opcode::SExt:
    case Opcode::ZExt:
    case Opcode::FlagsLogic:
    case Opcode::CondHolds:
    case Opcode::VAbs:
    case Opcode::VWiden:
    case Opcode::VReduce:
    case Opcode::VCnt:
    case Opcode::VRev:
    case Opcode::FSqrt:
    case Opcode::FCvt:
    case Opcode::FToInt:
    case Opcode::IntToF:
    case Opcode::FRint:
      return 1;
    case Opcode::FMadd:
    case Opcode::VLane:
    case Opcode::AtomicCas:
    case Opcode::Select:
    case Opcode::Adc:
    case Opcode::Sbc:
    case Opcode::FlagsAdc:
    case Opcode::FlagsSbc:
      return 3;
    default:
      return 2;
  }
}

const char* opcode_name(Opcode op) {
  switch (op) {
    case Opcode::Nop: return "nop";
    case Opcode::Const: return "const";
    case Opcode::GetReg: return "get";
    case Opcode::SetReg: return "set";
    case Opcode::Load: return "load";
    case Opcode::Store: return "store";
    case Opcode::LoadToState: return "load_state";
    case Opcode::StoreFromState: return "store_state";
    case Opcode::Add: return "add";
    case Opcode::Sub: return "sub";
    case Opcode::Mul: return "mul";
    case Opcode::UMulH: return "umulh";
    case Opcode::SMulH: return "smulh";
    case Opcode::UDiv: return "udiv";
    case Opcode::SDiv: return "sdiv";
    case Opcode::And: return "and";
    case Opcode::Or: return "or";
    case Opcode::Xor: return "xor";
    case Opcode::Shl: return "shl";
    case Opcode::LShr: return "lshr";
    case Opcode::AShr: return "ashr";
    case Opcode::Ror: return "ror";
    case Opcode::Not: return "not";
    case Opcode::Neg: return "neg";
    case Opcode::Clz: return "clz";
    case Opcode::Bswap: return "bswap";
    case Opcode::SExt: return "sext";
    case Opcode::ZExt: return "zext";
    case Opcode::Cmp: return "cmp";
    case Opcode::Select: return "select";
    case Opcode::Adc: return "adc";
    case Opcode::Sbc: return "sbc";
    case Opcode::FlagsAdd: return "flags.add";
    case Opcode::FlagsSub: return "flags.sub";
    case Opcode::FlagsAdc: return "flags.adc";
    case Opcode::FlagsSbc: return "flags.sbc";
    case Opcode::FlagsLogic: return "flags.logic";
    case Opcode::CondHolds: return "cond";
    case Opcode::StateAddr: return "state_addr";
    case Opcode::Fence: return "fence";
    case Opcode::AtomicRmw: return "atomic.rmw";
    case Opcode::AtomicCas: return "atomic.cas";
    case Opcode::AtomicCasPair: return "atomic.cas_pair";
    case Opcode::Counter: return "counter";
    case Opcode::VAdd: return "v.add";
    case Opcode::VSub: return "v.sub";
    case Opcode::VMul: return "v.mul";
    case Opcode::VCmp: return "v.cmp";
    case Opcode::VMax: return "v.max";
    case Opcode::VMin: return "v.min";
    case Opcode::VAbs: return "v.abs";
    case Opcode::VShl: return "v.shl";
    case Opcode::VLShr: return "v.lshr";
    case Opcode::VAShr: return "v.ashr";
    case Opcode::VUnzip: return "v.unzip";
    case Opcode::VZip: return "v.zip";
    case Opcode::VTrn: return "v.trn";
    case Opcode::VWiden: return "v.widen";
    case Opcode::VReduce: return "v.reduce";
    case Opcode::VCnt: return "v.cnt";
    case Opcode::VRev: return "v.rev";
    case Opcode::VLane: return "v.lane";
    case Opcode::FAdd: return "f.add";
    case Opcode::FSub: return "f.sub";
    case Opcode::FMul: return "f.mul";
    case Opcode::FDiv: return "f.div";
    case Opcode::FMax: return "f.max";
    case Opcode::FMin: return "f.min";
    case Opcode::FMaxNm: return "f.maxnm";
    case Opcode::FMinNm: return "f.minnm";
    case Opcode::FSqrt: return "f.sqrt";
    case Opcode::FMadd: return "f.madd";
    case Opcode::FCvt: return "f.cvt";
    case Opcode::FToInt: return "f.toint";
    case Opcode::IntToF: return "f.fromint";
    case Opcode::FRint: return "f.rint";
    case Opcode::FCmp: return "f.cmp";
    case Opcode::Count_: break;
  }
  return "?";
}

// --- Semantics ---------------------------------------------------------------------

namespace {

uint64_t mask_to(uint64_t v, unsigned size) { return size == 4 ? (v & 0xFFFF'FFFFu) : v; }

uint64_t umulh(uint64_t a, uint64_t b) {
  uint64_t a_lo = a & 0xFFFF'FFFFu, a_hi = a >> 32;
  uint64_t b_lo = b & 0xFFFF'FFFFu, b_hi = b >> 32;
  uint64_t lo_lo = a_lo * b_lo;
  uint64_t hi_lo = a_hi * b_lo;
  uint64_t lo_hi = a_lo * b_hi;
  uint64_t hi_hi = a_hi * b_hi;
  uint64_t cross = (lo_lo >> 32) + (hi_lo & 0xFFFF'FFFFu) + lo_hi;
  return hi_hi + (hi_lo >> 32) + (cross >> 32);
}

uint64_t smulh(uint64_t a, uint64_t b) {
  uint64_t r = umulh(a, b);
  if (static_cast<int64_t>(a) < 0) r -= b;
  if (static_cast<int64_t>(b) < 0) r -= a;
  return r;
}

int64_t sign_extend(uint64_t v, unsigned bits) {
  if (bits >= 64) return static_cast<int64_t>(v);
  return static_cast<int64_t>(v << (64 - bits)) >> (64 - bits);
}

uint64_t pack(uint64_t n, uint64_t z, uint64_t c, uint64_t v) {
  return (n << 31) | (z << 30) | (c << 29) | (v << 28);
}

}  // namespace

uint64_t flags_add(uint64_t a, uint64_t b, uint64_t carry_in, unsigned size) {
  carry_in &= 1;
  if (size == 8) {
    uint64_t t = a + b;
    uint64_t c1 = t < a;
    uint64_t r = t + carry_in;
    uint64_t c2 = r < t;
    uint64_t v = ((~(a ^ b) & (a ^ r)) >> 63) & 1;
    return pack(r >> 63, r == 0, c1 | c2, v);
  }
  uint64_t a32 = a & 0xFFFF'FFFFu, b32 = b & 0xFFFF'FFFFu;
  uint64_t wide = a32 + b32 + carry_in;
  uint64_t r = wide & 0xFFFF'FFFFu;
  uint64_t v = ((~(a32 ^ b32) & (a32 ^ r)) >> 31) & 1;
  return pack(r >> 31, r == 0, (wide >> 32) & 1, v);
}

bool condition_holds(uint8_t cond, uint64_t flags) {
  bool n = flags & kFlagN, z = flags & kFlagZ, c = flags & kFlagC, v = flags & kFlagV;
  bool result = false;
  switch (cond >> 1) {
    case 0: result = z; break;
    case 1: result = c; break;
    case 2: result = n; break;
    case 3: result = v; break;
    case 4: result = c && !z; break;
    case 5: result = n == v; break;
    case 6: result = n == v && !z; break;
    case 7: return true;  // AL / NV
  }
  return (cond & 1) ? !result : result;
}

uint16_t condition_mask(uint8_t cond) {
  uint16_t mask = 0;
  for (unsigned i = 0; i < 16; ++i)
    if (condition_holds(cond, uint64_t{i} << 28)) mask |= static_cast<uint16_t>(1u << i);
  return mask;
}

uint64_t evaluate(const Inst& in, uint64_t a, uint64_t b, uint64_t c) {
  const unsigned size = in.size;
  const unsigned width = size * 8;
  const uint64_t shift_mask = width - 1;
  uint64_t r = 0;
  switch (in.op) {
    case Opcode::Const: return in.imm;
    case Opcode::Add: r = a + b; break;
    case Opcode::Sub: r = a - b; break;
    case Opcode::Mul: r = a * b; break;
    case Opcode::UMulH: r = umulh(a, b); break;
    case Opcode::SMulH: r = smulh(a, b); break;
    case Opcode::UDiv: {
      uint64_t x = mask_to(a, size), y = mask_to(b, size);
      r = y == 0 ? 0 : x / y;
      break;
    }
    case Opcode::SDiv: {
      int64_t x = sign_extend(a, width), y = sign_extend(b, width);
      if (y == 0) r = 0;
      else if (y == -1) r = 0 - static_cast<uint64_t>(x);
      else r = static_cast<uint64_t>(x / y);
      break;
    }
    case Opcode::And: r = a & b; break;
    case Opcode::Or: r = a | b; break;
    case Opcode::Xor: r = a ^ b; break;
    case Opcode::Shl: r = a << (b & shift_mask); break;
    case Opcode::LShr: r = mask_to(a, size) >> (b & shift_mask); break;
    case Opcode::AShr: r = static_cast<uint64_t>(sign_extend(a, width) >> (b & shift_mask)); break;
    case Opcode::Ror: {
      uint64_t x = mask_to(a, size);
      unsigned s = static_cast<unsigned>(b & shift_mask);
      r = s == 0 ? x : (x >> s) | (x << (width - s));
      break;
    }
    case Opcode::Not: r = ~a; break;
    case Opcode::Neg: r = 0 - a; break;
    case Opcode::Clz:
      r = size == 4 ? static_cast<uint64_t>(std::countl_zero(static_cast<uint32_t>(a)))
                    : static_cast<uint64_t>(std::countl_zero(a));
      break;
    case Opcode::Bswap:
      r = size == 4 ? std::byteswap(static_cast<uint32_t>(a)) : std::byteswap(a);
      break;
    case Opcode::SExt: r = static_cast<uint64_t>(sign_extend(a, in.aux)); break;
    case Opcode::ZExt: r = in.aux >= 64 ? a : a & ((uint64_t{1} << in.aux) - 1); break;
    case Opcode::Cmp: {
      uint64_t x = mask_to(a, size), y = mask_to(b, size);
      int64_t sx = sign_extend(a, width), sy = sign_extend(b, width);
      switch (static_cast<Predicate>(in.aux)) {
        case Predicate::Eq: return x == y;
        case Predicate::Ne: return x != y;
        case Predicate::Ult: return x < y;
        case Predicate::Ule: return x <= y;
        case Predicate::Ugt: return x > y;
        case Predicate::Uge: return x >= y;
        case Predicate::Slt: return sx < sy;
        case Predicate::Sle: return sx <= sy;
        case Predicate::Sgt: return sx > sy;
        case Predicate::Sge: return sx >= sy;
      }
      return 0;
    }
    case Opcode::Select: r = a ? b : c; break;
    case Opcode::Adc: r = a + b + ((c & kFlagC) ? 1 : 0); break;
    case Opcode::Sbc: r = a + ~b + ((c & kFlagC) ? 1 : 0); break;
    case Opcode::FlagsAdd: return flags_add(a, b, 0, size);
    case Opcode::FlagsSub: return flags_add(a, ~b, 1, size);
    case Opcode::FlagsAdc: return flags_add(a, b, (c & kFlagC) ? 1 : 0, size);
    case Opcode::FlagsSbc: return flags_add(a, ~b, (c & kFlagC) ? 1 : 0, size);
    case Opcode::FlagsLogic: {
      uint64_t x = mask_to(a, size);
      return pack((x >> (width - 1)) & 1, x == 0, 0, 0);
    }
    case Opcode::CondHolds: return condition_holds(in.aux, a) ? 1 : 0;
    default:
      if (is_vector_or_fp(in.op)) return mask_to(evaluate_simd(in, a, b, c), size);
      return 0;
  }
  return mask_to(r, size);
}

// --- Printing ------------------------------------------------------------------------

std::string to_string(const Block& block, const SlotNamer& namer) {
  auto slot = [&](uint64_t s) {
    return namer ? namer(static_cast<uint16_t>(s)) : std::format("slot{}", s);
  };
  auto val = [](ValueId v) { return std::format("%{}", v); };

  std::string out = std::format("block 0x{:x} ({} guest insns)\n", block.guest_pc, block.guest_insns);
  for (size_t i = 0; i < block.insts.size(); ++i) {
    const Inst& in = block.insts[i];
    if (in.op == Opcode::Nop) continue;
    std::string line = has_result(in.op) ? std::format("  %{} = ", i) : std::string("  ");
    line += opcode_name(in.op);
    switch (in.op) {
      case Opcode::Const:
        line += std::format(" 0x{:x}", in.imm);
        break;
      case Opcode::GetReg:
      case Opcode::StateAddr:
        line += " " + slot(in.imm);
        break;
      case Opcode::SetReg:
        line += std::format(" {}, {}", slot(in.imm), val(in.args[0]));
        break;
      case Opcode::Load:
        line += std::format("{}{} [{}]", in.size * 8, in.aux ? "s" : "", val(in.args[0]));
        break;
      case Opcode::Store:
        line += std::format("{} [{}], {}", in.size * 8, val(in.args[0]), val(in.args[1]));
        break;
      case Opcode::LoadToState:
        line += std::format(" {}, [{}], {} bytes", slot(in.imm), val(in.args[0]), in.size);
        break;
      case Opcode::StoreFromState:
        line += std::format(" [{}], {}, {} bytes", val(in.args[0]), slot(in.imm), in.size);
        break;
      default: {
        line += in.size == 4 ? "32" : "";
        if (in.op == Opcode::SExt || in.op == Opcode::ZExt) line += std::format(".{}", in.aux);
        if (in.op == Opcode::Cmp) {
          static constexpr const char* preds[] = {"eq", "ne", "ult", "ule", "ugt", "uge", "slt", "sle", "sgt", "sge"};
          line += std::format(".{}", preds[in.aux]);
        }
        if (in.op == Opcode::VLane) line += std::format(".op{}", in.imm);
        if (in.op == Opcode::CondHolds || is_vector_or_fp(in.op)) line += std::format(".{:x}", in.aux);
        for (unsigned k = 0; k < arg_count(in.op); ++k) line += (k ? ", " : " ") + val(in.args[k]);
        break;
      }
    }
    out += line + "\n";
  }
  const Terminator& t = block.term;
  switch (t.kind) {
    case Terminator::Kind::Jump:
      out += std::format("  jump 0x{:x}\n", t.target);
      break;
    case Terminator::Kind::JumpIndirect:
      out += std::format("  jump {}\n", val(t.value));
      break;
    case Terminator::Kind::Branch:
      out += std::format("  branch {} ? 0x{:x} : 0x{:x}\n", val(t.value), t.target, t.fallthrough);
      break;
    case Terminator::Kind::Exit:
      out += std::format("  exit reason={} info=0x{:x} pc=0x{:x}\n", t.exit_reason, t.exit_info, t.target);
      break;
  }
  return out;
}

}  // namespace juice::ir
