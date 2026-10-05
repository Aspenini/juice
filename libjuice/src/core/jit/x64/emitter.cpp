#include "core/jit/x64/emitter.hpp"

#include "core/jit/x64/assembler.hpp"

namespace juice::x64 {
namespace {

using ir::Inst;
using ir::Opcode;
using ir::ValueId;

#if defined(_WIN32)
constexpr Reg kArg0 = RCX;
constexpr Reg kArg1 = RDX;
constexpr Reg kCallArgs[4] = {RCX, RDX, R8, R9};
#else
constexpr Reg kArg0 = RDI;
constexpr Reg kArg1 = RSI;
constexpr Reg kCallArgs[4] = {RDI, RSI, RDX, RCX};
#endif

// Stack space reserved by the block prologue: 32 bytes of home space for
// helper calls (Win64) plus 8 to keep RSP 16-byte aligned at the call.
constexpr int32_t kFrameSize = 40;

// Out-of-line implementation of the vector and floating point opcodes: the
// generated code calls the IR evaluator, so the JIT and the interpreter share
// one definition of these semantics.
uint64_t evaluate_helper(uint64_t a, uint64_t b, uint64_t c, uint64_t packed) {
  ir::Inst in;
  in.op = static_cast<Opcode>(packed & 0xFF);
  in.size = static_cast<uint8_t>(packed >> 8);
  in.aux = static_cast<uint8_t>(packed >> 16);
  in.imm = packed >> 32;  // VLane's operation
  return ir::evaluate(in, a, b, c);
}

uint64_t atomic_helper(uint64_t a, uint64_t b, uint64_t c, uint64_t packed) {
  ir::Inst in;
  in.op = static_cast<Opcode>(packed & 0xFF);
  in.size = static_cast<uint8_t>(packed >> 8);
  in.aux = static_cast<uint8_t>(packed >> 16);
  return ir::execute_atomic(in, a, b, c);
}

constexpr Reg kState = RBX;    // guest state base
constexpr Reg kScratch = RBP;  // IR value slots

Cond predicate_cond(ir::Predicate p) {
  switch (p) {
    case ir::Predicate::Eq: return Cond::E;
    case ir::Predicate::Ne: return Cond::NE;
    case ir::Predicate::Ult: return Cond::B;
    case ir::Predicate::Ule: return Cond::BE;
    case ir::Predicate::Ugt: return Cond::A;
    case ir::Predicate::Uge: return Cond::AE;
    case ir::Predicate::Slt: return Cond::L;
    case ir::Predicate::Sle: return Cond::LE;
    case ir::Predicate::Sgt: return Cond::G;
    case ir::Predicate::Sge: return Cond::GE;
  }
  return Cond::E;
}

class Compiler {
 public:
  Compiler(const ir::Block& block, const ir::StateLayout& layout) : block_(block), layout_(layout) {}

  std::vector<uint8_t> run() {
    a_.push(kState);
    a_.push(kScratch);
    a_.alu_imm(Alu::Sub, RSP, kFrameSize);
    a_.mov(kState, kArg0);
    a_.mov(kScratch, kArg1);
    for (size_t i = 0; i < block_.insts.size(); ++i) emit(static_cast<ValueId>(i), block_.insts[i]);
    terminator();
    return a_.code();
  }

 private:
  // --- operand helpers --------------------------------------------------------

  Mem value_mem(ValueId v) const { return Mem{kScratch, static_cast<int32_t>(8 * v)}; }
  Mem state_mem(uint64_t byte_offset) const { return Mem{kState, static_cast<int32_t>(byte_offset)}; }
  Mem slot_mem(uint64_t slot) const { return state_mem(8 * slot); }

  bool is_const(ValueId v) const { return block_.insts[v].op == Opcode::Const; }
  uint64_t const_value(ValueId v) const { return block_.insts[v].imm; }

  // Can v be used as a sign-extended imm32 for an operation of `size` bytes?
  bool imm32_ok(ValueId v, unsigned size) const {
    if (!is_const(v)) return false;
    if (size == 4) return true;
    int64_t s = static_cast<int64_t>(const_value(v));
    return s >= INT32_MIN && s <= INT32_MAX;
  }
  int32_t imm32(ValueId v) const { return static_cast<int32_t>(static_cast<uint32_t>(const_value(v))); }

  void get(Reg r, ValueId v) {
    if (is_const(v)) a_.mov_imm(r, const_value(v));
    else a_.load(r, value_mem(v));
  }
  void put(ValueId v, Reg r) { a_.store(value_mem(v), r, 8); }

  // Pack EFLAGS (after an arithmetic op) into NZCV format in RAX.
  void pack_flags(bool invert_carry) {
    a_.setcc(Cond::S, RAX);
    a_.setcc(Cond::E, RCX);
    a_.setcc(invert_carry ? Cond::AE : Cond::B, RDX);
    a_.setcc(Cond::O, R8);
    a_.movzx8(RAX, RAX);
    a_.movzx8(RCX, RCX);
    a_.movzx8(RDX, RDX);
    a_.movzx8(R8, R8);
    a_.shift_imm(Shift::Shl, RAX, 1, false);
    a_.alu(Alu::Or, RAX, RCX, false);
    a_.shift_imm(Shift::Shl, RAX, 1, false);
    a_.alu(Alu::Or, RAX, RDX, false);
    a_.shift_imm(Shift::Shl, RAX, 1, false);
    a_.alu(Alu::Or, RAX, R8, false);
    a_.shift_imm(Shift::Shl, RAX, 28, false);
  }

  // RAX = a <op> b, flags set by the x86 instruction.
  void alu_op(Alu op, const Inst& in) {
    bool w = in.size == 8;
    get(RAX, in.args[0]);
    if (imm32_ok(in.args[1], in.size)) {
      a_.alu_imm(op, RAX, imm32(in.args[1]), w);
    } else {
      get(RCX, in.args[1]);
      a_.alu(op, RAX, RCX, w);
    }
  }

  // Load the carry flag of packed flags `flags` into CF (inverted for SBC).
  void carry_in(ValueId flags, bool invert) {
    get(RDX, flags);
    a_.bt_imm(RDX, 29, false);
    if (invert) a_.cmc();
  }

  void shift(Shift op, ValueId v, const Inst& in) {
    bool w = in.size == 8;
    unsigned width = in.size * 8u;
    get(RAX, in.args[0]);
    if (is_const(in.args[1])) {
      uint8_t amount = static_cast<uint8_t>(const_value(in.args[1]) & (width - 1));
      if (amount) a_.shift_imm(op, RAX, amount, w);
      else if (!w) a_.mov(RAX, RAX, false);
    } else {
      get(RCX, in.args[1]);
      a_.shift_cl(op, RAX, w);
    }
    put(v, RAX);
  }

  void divide(ValueId v, const Inst& in, bool sign) {
    bool w = in.size == 8;
    get(RAX, in.args[0]);
    get(RCX, in.args[1]);
    a_.test(RCX, RCX, w);
    auto zero = a_.jcc(Cond::E);
    Assembler::Label minus_one{};
    if (sign) {
      a_.alu_imm(Alu::Cmp, RCX, -1, w);
      auto normal = a_.jcc(Cond::NE);
      a_.neg(RAX, w);  // x / -1 == -x, and avoids the INT_MIN / -1 trap
      minus_one = a_.jmp();
      a_.bind(normal);
      if (w) a_.cqo();
      else a_.cdq();
      a_.idiv(RCX, w);
    } else {
      a_.alu(Alu::Xor, RDX, RDX, false);
      a_.div(RCX, w);
    }
    auto done = a_.jmp();
    a_.bind(zero);
    a_.alu(Alu::Xor, RAX, RAX, false);
    a_.bind(done);
    if (sign) a_.bind(minus_one);
    put(v, RAX);
  }

  void call_helper(ValueId v, const Inst& in, uint64_t (*helper)(uint64_t, uint64_t, uint64_t, uint64_t)) {
    for (unsigned k = 0; k < 3; ++k)
      if (in.args[k] != ir::kNoValue) get(kCallArgs[k], in.args[k]);
    a_.mov_imm(kCallArgs[3], static_cast<uint64_t>(in.op) | (uint64_t{in.size} << 8) | (uint64_t{in.aux} << 16) |
                                 ((in.imm & 0xFFFF'FFFFu) << 32));
    a_.mov_imm(RAX, reinterpret_cast<uint64_t>(helper));
    a_.call(RAX);
    put(v, RAX);
  }

  void emit(ValueId v, const Inst& in) {
    const bool w = in.size == 8;
    if (ir::is_vector_or_fp(in.op)) {
      call_helper(v, in, &evaluate_helper);
      return;
    }
    switch (in.op) {
      case Opcode::Nop:
      case Opcode::Const:
        return;  // constants are materialized at their uses

      case Opcode::GetReg:
        a_.load(RAX, slot_mem(in.imm));
        put(v, RAX);
        return;
      case Opcode::StateAddr:
        a_.lea(RAX, slot_mem(in.imm));
        put(v, RAX);
        return;
      case Opcode::Fence:
        a_.mfence();
        return;
      case Opcode::AtomicRmw:
      case Opcode::AtomicCas:
      case Opcode::AtomicCasPair:
      case Opcode::Counter:
        call_helper(v, in, &atomic_helper);
        return;
      case Opcode::SetReg:
        if (imm32_ok(in.args[0], 8)) {
          a_.store_imm32(slot_mem(in.imm), imm32(in.args[0]), true);
        } else {
          get(RAX, in.args[0]);
          a_.store(slot_mem(in.imm), RAX, 8);
        }
        return;

      case Opcode::Load: {
        get(RAX, in.args[0]);
        Mem m{RAX, 0};
        bool sign = in.aux != 0;
        switch (in.size) {
          case 1: sign ? a_.movsx8(RAX, m) : a_.movzx8(RAX, m); break;
          case 2: sign ? a_.movsx16(RAX, m) : a_.movzx16(RAX, m); break;
          case 4: sign ? a_.movsxd(RAX, m) : a_.load(RAX, m, false); break;
          default: a_.load(RAX, m, true); break;
        }
        put(v, RAX);
        return;
      }
      case Opcode::Store:
        get(RAX, in.args[0]);
        get(RCX, in.args[1]);
        a_.store(Mem{RAX, 0}, RCX, in.size);
        return;
      case Opcode::LoadToState: {
        get(RAX, in.args[0]);
        const uint64_t off = 8 * in.imm;
        unsigned written = 8;
        switch (in.size) {
          case 16:
            a_.load(RCX, Mem{RAX, 0});
            a_.store(state_mem(off), RCX, 8);
            a_.load(RCX, Mem{RAX, 8});
            a_.store(state_mem(off + 8), RCX, 8);
            written = 16;
            break;
          case 8: a_.load(RCX, Mem{RAX, 0}); a_.store(state_mem(off), RCX, 8); break;
          case 4: a_.load(RCX, Mem{RAX, 0}, false); a_.store(state_mem(off), RCX, 8); break;
          case 2: a_.movzx16(RCX, Mem{RAX, 0}); a_.store(state_mem(off), RCX, 8); break;
          default: a_.movzx8(RCX, Mem{RAX, 0}); a_.store(state_mem(off), RCX, 8); break;
        }
        for (unsigned k = written; k < in.aux; k += 8) a_.store_imm32(state_mem(off + k), 0, true);
        return;
      }
      case Opcode::StoreFromState: {
        get(RAX, in.args[0]);
        const uint64_t off = 8 * in.imm;
        if (in.size == 16) {
          a_.load(RCX, state_mem(off));
          a_.store(Mem{RAX, 0}, RCX, 8);
          a_.load(RCX, state_mem(off + 8));
          a_.store(Mem{RAX, 8}, RCX, 8);
        } else {
          a_.load(RCX, state_mem(off), in.size == 8);
          a_.store(Mem{RAX, 0}, RCX, in.size);
        }
        return;
      }

      case Opcode::Add: alu_op(Alu::Add, in); put(v, RAX); return;
      case Opcode::Sub: alu_op(Alu::Sub, in); put(v, RAX); return;
      case Opcode::And: alu_op(Alu::And, in); put(v, RAX); return;
      case Opcode::Or: alu_op(Alu::Or, in); put(v, RAX); return;
      case Opcode::Xor: alu_op(Alu::Xor, in); put(v, RAX); return;
      case Opcode::Mul:
        get(RAX, in.args[0]);
        get(RCX, in.args[1]);
        a_.imul(RAX, RCX, w);
        put(v, RAX);
        return;
      case Opcode::UMulH:
      case Opcode::SMulH:
        get(RAX, in.args[0]);
        get(RCX, in.args[1]);
        if (in.op == Opcode::UMulH) a_.mul(RCX, true);
        else a_.imul1(RCX, true);
        put(v, RDX);
        return;
      case Opcode::UDiv: divide(v, in, false); return;
      case Opcode::SDiv: divide(v, in, true); return;
      case Opcode::Shl: shift(Shift::Shl, v, in); return;
      case Opcode::LShr: shift(Shift::Shr, v, in); return;
      case Opcode::AShr: shift(Shift::Sar, v, in); return;
      case Opcode::Ror: shift(Shift::Ror, v, in); return;
      case Opcode::Not:
        get(RAX, in.args[0]);
        a_.not_(RAX, w);
        put(v, RAX);
        return;
      case Opcode::Neg:
        get(RAX, in.args[0]);
        a_.neg(RAX, w);
        put(v, RAX);
        return;
      case Opcode::Clz: {
        get(RCX, in.args[0]);
        a_.bsr(RAX, RCX, w);
        auto nonzero = a_.jcc(Cond::NE);
        a_.mov_imm(RAX, ~0ull);
        a_.bind(nonzero);
        a_.neg(RAX, true);
        a_.alu_imm(Alu::Add, RAX, static_cast<int32_t>(in.size * 8 - 1), true);
        put(v, RAX);
        return;
      }
      case Opcode::Bswap:
        get(RAX, in.args[0]);
        a_.bswap(RAX, w);
        put(v, RAX);
        return;
      case Opcode::SExt:
        get(RAX, in.args[0]);
        if (in.aux == 8) a_.movsx8(RAX, RAX);
        else if (in.aux == 16) a_.movsx16(RAX, RAX);
        else if (in.aux == 32) a_.movsxd(RAX, RAX);
        if (!w) a_.mov(RAX, RAX, false);
        put(v, RAX);
        return;
      case Opcode::ZExt:
        get(RAX, in.args[0]);
        if (in.aux == 8) a_.movzx8(RAX, RAX);
        else if (in.aux == 16) a_.movzx16(RAX, RAX);
        else if (in.aux == 32) a_.mov(RAX, RAX, false);
        put(v, RAX);
        return;
      case Opcode::Cmp:
        alu_op(Alu::Cmp, in);
        a_.setcc(predicate_cond(static_cast<ir::Predicate>(in.aux)), RAX);
        a_.movzx8(RAX, RAX);
        put(v, RAX);
        return;
      case Opcode::Select:
        get(RAX, in.args[1]);
        get(RCX, in.args[2]);
        get(RDX, in.args[0]);
        a_.test(RDX, RDX, true);
        a_.cmov(Cond::E, RAX, RCX, w);
        if (!w) a_.mov(RAX, RAX, false);
        put(v, RAX);
        return;
      case Opcode::Adc:
      case Opcode::Sbc:
      case Opcode::FlagsAdc:
      case Opcode::FlagsSbc: {
        bool sbc = in.op == Opcode::Sbc || in.op == Opcode::FlagsSbc;
        bool flags = in.op == Opcode::FlagsAdc || in.op == Opcode::FlagsSbc;
        get(RAX, in.args[0]);
        get(RCX, in.args[1]);
        carry_in(in.args[2], sbc);
        a_.alu(sbc ? Alu::Sbb : Alu::Adc, RAX, RCX, w);
        if (flags) pack_flags(sbc);
        put(v, RAX);
        return;
      }
      case Opcode::FlagsAdd:
        alu_op(Alu::Add, in);
        pack_flags(false);
        put(v, RAX);
        return;
      case Opcode::FlagsSub:
        alu_op(Alu::Cmp, in);
        pack_flags(true);
        put(v, RAX);
        return;
      case Opcode::FlagsLogic:
        get(RAX, in.args[0]);
        a_.test(RAX, RAX, w);
        pack_flags(false);
        put(v, RAX);
        return;
      case Opcode::CondHolds:
        get(RAX, in.args[0]);
        a_.shift_imm(Shift::Shr, RAX, 28, false);
        a_.mov_imm(RCX, ir::condition_mask(in.aux));
        a_.bt(RCX, RAX, false);
        a_.setcc(Cond::B, RAX);
        a_.movzx8(RAX, RAX);
        put(v, RAX);
        return;
      default:
        return;
    }
  }

  void store_pc(Reg r) { a_.store(slot_mem(layout_.pc_slot), r, 8); }

  void epilogue() {
    a_.alu_imm(Alu::Add, RSP, kFrameSize);
    a_.pop(kScratch);
    a_.pop(kState);
    a_.ret();
  }

  void terminator() {
    const ir::Terminator& t = block_.term;
    switch (t.kind) {
      case ir::Terminator::Kind::Jump:
        a_.mov_imm(RAX, t.target);
        store_pc(RAX);
        break;
      case ir::Terminator::Kind::JumpIndirect:
        get(RAX, t.value);
        store_pc(RAX);
        break;
      case ir::Terminator::Kind::Branch:
        get(RDX, t.value);
        a_.mov_imm(RAX, t.target);
        a_.mov_imm(RCX, t.fallthrough);
        a_.test(RDX, RDX, true);
        a_.cmov(Cond::E, RAX, RCX, true);
        store_pc(RAX);
        break;
      case ir::Terminator::Kind::Exit:
        a_.store_imm32(state_mem(layout_.exit_reason_offset), static_cast<int32_t>(t.exit_reason), false);
        a_.store_imm32(state_mem(layout_.exit_info_offset), static_cast<int32_t>(t.exit_info), false);
        a_.mov_imm(RAX, t.target);
        store_pc(RAX);
        break;
    }
    epilogue();
  }

  const ir::Block& block_;
  const ir::StateLayout& layout_;
  Assembler a_;
};

}  // namespace

std::vector<uint8_t> Emitter::compile(const ir::Block& block) const {
  if (block.insts.size() > kMaxBlockValues) return {};
  return Compiler(block, layout_).run();
}

}  // namespace juice::x64
