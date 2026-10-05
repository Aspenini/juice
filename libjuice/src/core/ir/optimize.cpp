// Simple block-local optimizations:
//
//   1. forward pass: register-read forwarding, constant folding and algebraic
//      simplification
//   2. backward pass: dead guest-register store elimination
//   3. backward pass: dead value elimination
//
// Removed instructions become Nop so that value ids stay stable.

#include <algorithm>
#include <numeric>

#include "core/ir/ir.hpp"

namespace juice::ir {
namespace {

// Number of 64-bit state slots touched by a state transfer instruction.
// LoadToState always writes these slots completely.
unsigned state_slots(const Inst& in) {
  unsigned bytes = std::max<unsigned>(in.size, in.aux);
  return (bytes + 7) / 8;
}

class Optimizer {
 public:
  explicit Optimizer(Block& block) : block_(block), insts_(block.insts) {}

  OptimizeStats run() {
    uint64_t max_slot = 0;
    for (const Inst& in : insts_) {
      if (in.op == Opcode::GetReg || in.op == Opcode::SetReg) max_slot = std::max(max_slot, in.imm);
      if (in.op == Opcode::LoadToState || in.op == Opcode::StoreFromState)
        max_slot = std::max<uint64_t>(max_slot, in.imm + state_slots(in));
    }
    slot_count_ = static_cast<size_t>(max_slot) + 1;

    forward();
    dead_stores();
    dead_values();
    return stats_;
  }

 private:
  bool is_const(ValueId v) const { return v != kNoValue && insts_[v].op == Opcode::Const; }
  uint64_t const_value(ValueId v) const { return insts_[v].imm; }

  // True if the value is known to have its upper 32 bits clear.
  bool is_clean32(ValueId v) const {
    const Inst& in = insts_[v];
    switch (in.op) {
      case Opcode::Const: return in.imm <= 0xFFFF'FFFFu;
      case Opcode::Load: return in.size <= 4 && !in.aux;
      case Opcode::ZExt: return in.aux <= 32;
      case Opcode::Cmp:
      case Opcode::CondHolds:
      case Opcode::FlagsAdd:
      case Opcode::FlagsSub:
      case Opcode::FlagsAdc:
      case Opcode::FlagsSbc:
      case Opcode::FlagsLogic:
        return true;
      default:
        return is_pure(in.op) && in.size == 4;
    }
  }

  // Can `inst` (of width size) be replaced by its operand v unchanged?
  bool passthrough_ok(const Inst& inst, ValueId v) const { return inst.size == 8 || is_clean32(v); }

  void make_alias(size_t i, ValueId to) {
    alias_[i] = to;
    insts_[i].op = Opcode::Nop;
    ++stats_.folded;
  }

  void make_const(size_t i, uint64_t value) {
    Inst& in = insts_[i];
    in = Inst{};
    in.op = Opcode::Const;
    in.imm = value;
    ++stats_.folded;
  }

  void simplify(size_t i) {
    Inst& in = insts_[i];
    ValueId a = in.args[0], b = in.args[1];

    // Canonicalize constants to the right-hand side of commutative operations.
    switch (in.op) {
      case Opcode::Add: case Opcode::Mul: case Opcode::And: case Opcode::Or: case Opcode::Xor:
        if (is_const(a) && !is_const(b)) {
          std::swap(in.args[0], in.args[1]);
          std::swap(a, b);
        }
        break;
      default:
        break;
    }

    const uint64_t ones = in.size == 4 ? 0xFFFF'FFFFull : ~0ull;
    switch (in.op) {
      case Opcode::Add: case Opcode::Sub: case Opcode::Or: case Opcode::Xor:
      case Opcode::Shl: case Opcode::LShr: case Opcode::AShr: case Opcode::Ror:
        if (is_const(b) && (const_value(b) & ones) == 0 && passthrough_ok(in, a)) make_alias(i, a);
        break;
      case Opcode::And:
        if (is_const(b) && (const_value(b) & ones) == 0) make_const(i, 0);
        else if (is_const(b) && (const_value(b) & ones) == ones && passthrough_ok(in, a)) make_alias(i, a);
        else if (a == b && passthrough_ok(in, a)) make_alias(i, a);
        break;
      case Opcode::Mul:
        if (is_const(b) && (const_value(b) & ones) == 0) make_const(i, 0);
        else if (is_const(b) && (const_value(b) & ones) == 1 && passthrough_ok(in, a)) make_alias(i, a);
        break;
      case Opcode::Select:
        if (is_const(a)) {
          ValueId chosen = const_value(a) ? b : in.args[2];
          if (passthrough_ok(in, chosen)) make_alias(i, chosen);
        } else if (b == in.args[2] && passthrough_ok(in, b)) {
          make_alias(i, b);
        }
        break;
      case Opcode::ZExt:
        if (in.aux == 32 && is_clean32(a)) make_alias(i, a);
        break;
      default:
        break;
    }
  }

  void forward() {
    const size_t n = insts_.size();
    alias_.resize(n);
    std::iota(alias_.begin(), alias_.end(), ValueId{0});
    std::vector<ValueId> known(slot_count_, kNoValue);

    for (size_t i = 0; i < n; ++i) {
      Inst& in = insts_[i];
      for (ValueId& arg : in.args)
        if (arg != kNoValue) arg = alias_[arg];

      switch (in.op) {
        case Opcode::Nop:
        case Opcode::Const:
          break;
        case Opcode::GetReg: {
          ValueId& k = known[in.imm];
          if (k != kNoValue) {
            alias_[i] = k;
            in.op = Opcode::Nop;
            ++stats_.forwarded;
          } else {
            k = static_cast<ValueId>(i);
          }
          break;
        }
        case Opcode::SetReg:
          known[in.imm] = in.args[0];
          break;
        case Opcode::LoadToState:
          for (unsigned s = 0; s < state_slots(in); ++s) known[in.imm + s] = kNoValue;
          break;
        case Opcode::AtomicCasPair:  // writes guest state through a StateAddr pointer
          std::fill(known.begin(), known.end(), kNoValue);
          break;
        case Opcode::Load:
        case Opcode::Store:
        case Opcode::StoreFromState:
          break;
        default: {
          if (!is_pure(in.op)) break;
          unsigned count = arg_count(in.op);
          bool all_const = true;
          uint64_t v[3] = {0, 0, 0};
          for (unsigned k = 0; k < count; ++k) {
            if (!is_const(in.args[k])) {
              all_const = false;
              break;
            }
            v[k] = const_value(in.args[k]);
          }
          if (all_const) make_const(i, evaluate(in, v[0], v[1], v[2]));
          else simplify(i);
          break;
        }
      }
    }

    Terminator& t = block_.term;
    if (t.value != kNoValue) t.value = alias_[t.value];
    if (t.kind == Terminator::Kind::Branch && is_const(t.value)) {
      t.kind = Terminator::Kind::Jump;
      if (!const_value(t.value)) t.target = t.fallthrough;
      t.value = kNoValue;
    } else if (t.kind == Terminator::Kind::JumpIndirect && is_const(t.value)) {
      t.kind = Terminator::Kind::Jump;
      t.target = const_value(t.value);
      t.value = kNoValue;
    }
  }

  void dead_stores() {
    std::vector<uint8_t> overwritten(slot_count_, 0);
    for (size_t i = insts_.size(); i-- > 0;) {
      Inst& in = insts_[i];
      switch (in.op) {
        case Opcode::SetReg:
          if (overwritten[in.imm]) {
            in.op = Opcode::Nop;
            ++stats_.dead_stores;
          } else {
            overwritten[in.imm] = 1;
          }
          break;
        case Opcode::GetReg:
          overwritten[in.imm] = 0;
          break;
        case Opcode::LoadToState:
          for (unsigned s = 0; s < state_slots(in); ++s) overwritten[in.imm + s] = 1;
          break;
        case Opcode::StoreFromState:
          for (unsigned s = 0; s < state_slots(in); ++s) overwritten[in.imm + s] = 0;
          break;
        case Opcode::AtomicCasPair:
          // Reads guest state through a StateAddr pointer: keep every earlier store.
          std::fill(overwritten.begin(), overwritten.end(), uint8_t{0});
          break;
        default:
          break;
      }
    }
  }

  void dead_values() {
    std::vector<uint8_t> live(insts_.size(), 0);
    if (block_.term.value != kNoValue) live[block_.term.value] = 1;
    for (size_t i = insts_.size(); i-- > 0;) {
      Inst& in = insts_[i];
      if (in.op == Opcode::Nop) continue;
      bool needed = !has_result(in.op) || has_side_effects(in.op) || live[i];
      if (!needed) {
        in.op = Opcode::Nop;
        ++stats_.dead_values;
        continue;
      }
      for (unsigned k = 0; k < arg_count(in.op); ++k)
        if (in.args[k] != kNoValue) live[in.args[k]] = 1;
    }
  }

  Block& block_;
  std::vector<Inst>& insts_;
  std::vector<ValueId> alias_;
  size_t slot_count_ = 0;
  OptimizeStats stats_;
};

}  // namespace

OptimizeStats optimize(Block& block) { return Optimizer(block).run(); }

}  // namespace juice::ir
