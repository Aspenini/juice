#include "core/jit/x64/emitter.hpp"

#include "core/jit/x64/assembler.hpp"

#include <algorithm>
#include <bit>
#include <cstddef>
#include <unordered_map>

#if defined(_MSC_VER)
#include <intrin.h>
#else
#include <cpuid.h>
#endif

namespace juice::x64 {
namespace {

// Host instruction set extensions the generated code may use (SSE2 is baseline).
struct HostFeatures {
  bool ssse3 = false;   // pshufb, pabs*
  bool sse41 = false;   // pmulld, pmin/pmax*, pmovzx/sx, pcmpeqq
  bool sse42 = false;   // pcmpgtq
  bool fma = false;     // FMA3, with the AVX state it needs
};

HostFeatures detect_host_features() {
  HostFeatures f;
  unsigned ecx = 0;
#if defined(_MSC_VER)
  int regs[4];
  __cpuid(regs, 1);
  ecx = static_cast<unsigned>(regs[2]);
#else
  unsigned eax, ebx, edx;
  if (!__get_cpuid(1, &eax, &ebx, &ecx, &edx)) return f;
#endif
  f.ssse3 = (ecx >> 9) & 1;
  f.sse41 = (ecx >> 19) & 1;
  f.sse42 = (ecx >> 20) & 1;
  const bool fma = (ecx >> 12) & 1, osxsave = (ecx >> 27) & 1, avx = (ecx >> 28) & 1;
  if (fma && osxsave && avx) {
#if defined(__clang__) || defined(__GNUC__)
    unsigned lo, hi;
    __asm__("xgetbv" : "=a"(lo), "=d"(hi) : "c"(0));
    f.fma = (lo & 6) == 6;  // XMM and YMM state enabled by the OS
#else
    f.fma = (_xgetbv(0) & 6) == 6;
#endif
  }
  return f;
}

const HostFeatures kHost = detect_host_features();
const bool kHasFma = kHost.fma;

// The sign bit of each lane of a 64-bit vector half, for unsigned compares.
constexpr uint64_t lane_sign_bits(unsigned esize) {
  return esize == 1 ? 0x8080808080808080ull
         : esize == 2 ? 0x8000800080008000ull
         : esize == 4 ? 0x8000000080000000ull
                      : 0x8000000000000000ull;
}

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
constexpr int32_t kFrameSize = kBlockFrameSize;

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

void state_helper(uint64_t* state, uint64_t packed) {
  ir::Inst in;
  in.op = Opcode::StateOp;
  in.aux = static_cast<uint8_t>(packed >> 16);
  in.imm = packed >> 32;
  ir::execute_state_op(in, state);
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
  Compiler(const ir::Block& block, const ir::StateLayout& layout, const ChainLayout& chain,
           std::vector<FaultSite>* faults, std::vector<LinkSite>* links)
      : block_(block), layout_(layout), chain_(chain), faults_(faults), links_(links) {}

  size_t body() const { return body_; }

  std::vector<uint8_t> run() {
    find_lazy_flags();
    find_loop_slots();
    allocate_registers();
    for (Reg r : kBlockSavedRegs) a_.push(r);
    a_.alu_imm(Alu::Sub, RSP, kFrameSize);
    for (unsigned k = 0; k < kBlockSavedXmmCount; ++k)  // movdqu [rsp + area + 16k], xmm
      a_.sse(0xF3, {0x7F}, kBlockSavedXmmFirst + k, Mem{RSP, kBlockXmmSaveArea + 16 * static_cast<int32_t>(k)});
    a_.mov(kState, kArg0);
    a_.mov(kScratch, kArg1);
    body_ = a_.size();
    for (const LoopSlot& l : loop_slots_) emit(l.get, block_.insts[l.get]);  // hoisted: see find_loop_slots
    loop_head_ = a_.size();
    for (size_t i = 0; i < block_.insts.size(); ++i) {
      if (hoisted_[i]) continue;
      if (faults_ && ir::may_fault(block_.insts[i].op)) {
        faults_->push_back({static_cast<uint32_t>(a_.size()),
                            static_cast<uint32_t>(ir::guest_pc_of(block_, i) - block_.guest_pc)});
      }
      emit(static_cast<ValueId>(i), block_.insts[i]);
    }
    terminator();
    emit_cold();
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

  // --- loops -------------------------------------------------------------------------
  //
  // A block that jumps back to itself keeps the guest registers it reads in
  // host registers across iterations: their reads (GetReg) move to the top of
  // the block, and the back edge puts the values the block stored in them
  // (its last SetReg; the stores to guest state still happen, so the state in
  // memory stays exact) into those registers and jumps past the reads. This
  // takes the store -> load round trip through memory off the loop's
  // critical path. Registers the block only reads stay in their registers.

  struct LoopSlot {
    ValueId get;    // the GetReg (its register holds the slot at the loop head)
    ValueId value;  // the value the block leaves in the slot (kNoValue: unchanged)
  };
  static constexpr size_t kMaxLoopSlots = 4;  // the back edge moves them through RAX, RCX, RDX, R8

  bool self_edge() const {
    const ir::Terminator& t = block_.term;
    if (!chain_.link_helper) return false;
    return (t.kind == ir::Terminator::Kind::Jump && t.target == block_.guest_pc) ||
           (t.kind == ir::Terminator::Kind::Branch && (t.target == block_.guest_pc || t.fallthrough == block_.guest_pc));
  }

  void find_loop_slots() {
    const size_t n = block_.insts.size();
    hoisted_.assign(n, 0);
    if (!self_edge()) return;
    std::vector<std::pair<uint64_t, ValueId>> gets;           // slot, GetReg
    std::unordered_map<uint64_t, ValueId> last_set;           // slot -> last value stored
    std::unordered_map<uint64_t, size_t> first_set;           // slot -> index of the first store
    std::vector<uint64_t> written;                            // slots written directly from memory
    for (size_t i = 0; i < n; ++i) {
      const Inst& in = block_.insts[i];
      switch (in.op) {
        case Opcode::LoadToState:
          for (unsigned k = 0; k < (std::max<unsigned>(in.size, in.aux) + 7) / 8; ++k) written.push_back(in.imm + k);
          break;
        case Opcode::StateOp:
        case Opcode::StateAddr:
        case Opcode::AtomicCasPair:
        case Opcode::AtomicRmwPair:
          return;  // write guest state other than through SetReg
        case Opcode::GetReg:
          gets.emplace_back(in.imm, static_cast<ValueId>(i));
          break;
        case Opcode::SetReg:
          last_set[in.imm] = in.args[0];
          first_set.try_emplace(in.imm, i);
          break;
        default:
          break;
      }
    }
    auto dead = [&](uint64_t slot) {
      return std::find(block_.dead_at_exit.begin(), block_.dead_at_exit.end(), slot) != block_.dead_at_exit.end();
    };
    // Loop-carried registers first, then the ones only read.
    for (int pass = 0; pass < 2; ++pass) {
      for (const auto& [slot, get] : gets) {
        if (loop_slots_.size() == kMaxLoopSlots) return;
        if (std::find(written.begin(), written.end(), slot) != written.end()) continue;
        const auto set = last_set.find(slot);
        if ((set != last_set.end()) != (pass == 0)) continue;
        if (set != last_set.end() && (first_set[slot] < get || dead(slot))) continue;
        loop_slots_.push_back({get, set != last_set.end() ? set->second : ir::kNoValue});
        hoisted_[get] = 1;
      }
    }
  }

  // The back edge: the new values into the slots' registers, then the loop head.
  void back_edge() {
    a_.load(RCX, state_mem(chain_.interrupt_offset));
    a_.test(RCX, RCX);
    const Assembler::Label go_on = a_.jcc(Cond::E);
    a_.mov_imm(RAX, block_.guest_pc);
    store_pc(RAX);
    epilogue();
    a_.bind(go_on);
    static constexpr Reg temps[kMaxLoopSlots] = {RAX, RCX, RDX, R8};
    for (size_t k = 0; k < loop_slots_.size(); ++k)
      if (loop_slots_[k].value != ir::kNoValue) get(temps[k], loop_slots_[k].value);
    for (size_t k = 0; k < loop_slots_.size(); ++k)
      if (loop_slots_[k].value != ir::kNoValue) put(loop_slots_[k].get, temps[k]);
    a_.jmp_to(loop_head_);
  }

  // --- register allocation -----------------------------------------------------------
  //
  // IR values live in callee-saved host registers (kBlockSavedRegs after RBX
  // and RBP) from their definition to their last use, as many as there are
  // registers for; the rest in the scratch array. Helper calls preserve them,
  // and every other register the code uses is a temporary within one IR
  // instruction. A value's register is only reused after the instruction that
  // last uses it (so its operands stay readable on every path).

  static constexpr Reg kNoReg = RSP;  // never allocated

  void allocate_registers() {
    const size_t n = block_.insts.size();
    reg_.assign(n, kNoReg);
    std::vector<size_t> last_use(n, 0);
    std::vector<uint8_t> used(n, 0);
    auto use = [&](ValueId a, size_t at) {
      if (a == ir::kNoValue || a >= n) return;
      last_use[a] = std::max(last_use[a], at);
      used[a] = 1;
    };
    for (size_t i = 0; i < n; ++i) {
      const Inst& in = block_.insts[i];
      if (in.op == Opcode::Nop) continue;
      for (unsigned k = 0; k < ir::arg_count(in.op); ++k) use(in.args[k], i);
      // A select on a fused condition repeats the flag operation.
      if (in.op == Opcode::Select && in.args[0] < n && select_cond_[in.args[0]]) {
        const Inst& flags = block_.insts[block_.insts[in.args[0]].args[0]];
        for (unsigned k = 0; k < ir::arg_count(flags.op); ++k) use(flags.args[k], i);
      }
      // A condition fused with its flag operation repeats it: its operands are used here too.
      if (in.op == Opcode::CondHolds && in.args[0] < n) {
        const Inst& flags = block_.insts[in.args[0]];
        Cond x86;
        int constant;
        if (fusable(flags.op) && fused_condition(flags, in.aux, x86, constant))
          for (unsigned k = 0; k < ir::arg_count(flags.op); ++k) use(flags.args[k], i);
      }
    }
    if (branch_cond_) {
      const Inst& flags = block_.insts[block_.insts[block_.term.value].args[0]];
      for (unsigned k = 0; k < ir::arg_count(flags.op); ++k) use(flags.args[k], n);
    } else {
      use(block_.term.value, n);
    }
    for (const LoopSlot& l : loop_slots_) {
      if (l.value != ir::kNoValue) use(l.value, n + 1);  // read by the back edge
      else use(l.get, n + 1);                             // read again by the next iteration
      used[l.get] = 1;
    }

    std::vector<Reg> pool;
    for (Reg r : kBlockSavedRegs)
      if (r != kState && r != kScratch) pool.push_back(r);
    // Floating point and vector values (results of scalar FP and vector
    // operations, and guest registers only those operations and stores read)
    // go to XMM registers.
    xreg_.assign(n, -1);
    std::vector<int8_t> xpool;
    for (unsigned k = kBlockSavedXmmCount; k-- > 0;) xpool.push_back(static_cast<int8_t>(kBlockSavedXmmFirst + k));
    auto scalar_fp = [](const Inst& in) {
      return in.op >= Opcode::FAdd && in.op <= Opcode::FCmp && (in.size == 4 || in.size == 8);
    };
    std::vector<uint8_t> fp_value(n, 0);
    if (!xpool.empty()) {
      std::vector<uint8_t> other_reader(n, 0);
      for (size_t i = 0; i < n; ++i) {
        const Inst& in = block_.insts[i];
        if (in.op == Opcode::Nop) continue;
        const bool fp_reader = (ir::is_vector_or_fp(in.op) && in.op != Opcode::IntToF) || in.op == Opcode::SetReg;
        for (unsigned k = 0; k < ir::arg_count(in.op); ++k)
          if (in.args[k] < n && !fp_reader) other_reader[in.args[k]] = 1;
      }
      if (block_.term.value < n) other_reader[block_.term.value] = 1;
      for (size_t i = 0; i < n; ++i) {
        const Inst& in = block_.insts[i];
        const bool produces_fp = (scalar_fp(in) || ir::is_vector_or_fp(in.op)) && in.op != Opcode::FCmp &&
                                 in.op != Opcode::FToInt;
        const bool fp_load = in.op == Opcode::Load && (in.size == 4 || in.size == 8) && in.aux == 0;
        fp_value[i] = produces_fp || ((in.op == Opcode::GetReg || fp_load) && !other_reader[i]);
      }
    }
    // The hoisted reads are defined first, and need registers.
    for (const LoopSlot& l : loop_slots_) {
      if (fp_value[l.get] && !xpool.empty()) {
        xreg_[l.get] = xpool.back();
        xpool.pop_back();
      } else {
        reg_[l.get] = pool.back();
        pool.pop_back();
      }
    }
    std::vector<uint8_t> freed(n, 0);
    for (size_t i = 0; i < n; ++i) {
      const Inst& in = block_.insts[i];
      if (in.op == Opcode::Nop) continue;
      if (ir::has_result(in.op) && in.op != Opcode::Const && !lazy_[i] && !(branch_cond_ && i == lazy_cond_) &&
          !hoisted_[i] && !select_cond_[i] && used[i]) {
        if (fp_value[i] && !xpool.empty()) {
          xreg_[i] = xpool.back();
          xpool.pop_back();
        } else if (!pool.empty()) {
          reg_[i] = pool.back();
          pool.pop_back();
        }
      }
      auto release = [&](ValueId a) {
        if (a == ir::kNoValue || a >= n || freed[a] || last_use[a] != i) return;
        if (reg_[a] != kNoReg) {
          freed[a] = 1;
          pool.push_back(reg_[a]);
        } else if (xreg_[a] >= 0) {
          freed[a] = 1;
          xpool.push_back(xreg_[a]);
        }
      };
      for (unsigned k = 0; k < ir::arg_count(in.op); ++k) release(in.args[k]);
      if (in.op == Opcode::Select && in.args[0] < n && select_cond_[in.args[0]])
        for (unsigned k = 0; k < ir::arg_count(block_.insts[block_.insts[in.args[0]].args[0]].op); ++k)
          release(block_.insts[block_.insts[in.args[0]].args[0]].args[k]);
      if (in.op == Opcode::CondHolds && in.args[0] < n)
        for (unsigned k = 0; k < ir::arg_count(block_.insts[in.args[0]].op); ++k)
          release(block_.insts[in.args[0]].args[k]);
    }
  }

  void get(Reg r, ValueId v) {
    if (is_const(v)) a_.mov_imm(r, const_value(v));
    else if (reg_[v] != kNoReg) a_.mov(r, reg_[v]);
    else if (xreg_[v] >= 0) a_.sse(0x66, {0x7E}, static_cast<unsigned>(xreg_[v]), r, true);  // movq r, xmm
    else a_.load(r, value_mem(v));
  }
  void put(ValueId v, Reg r) {
    if (reg_[v] != kNoReg) a_.mov(reg_[v], r);
    else if (xreg_[v] >= 0) a_.sse(0x66, {0x6E}, static_cast<unsigned>(xreg_[v]), r, true);  // movq xmm, r
    else a_.store(value_mem(v), r, 8);
  }
  // The register holding v: its own, or `tmp` loaded with it.
  Reg src(ValueId v, Reg tmp) {  // (an XMM-held value is moved to tmp)
    if (!is_const(v) && reg_[v] != kNoReg) return reg_[v];
    get(tmp, v);
    return tmp;
  }
  // Where to compute v: its own register, or `tmp` (then put(v, tmp)).
  Reg dst(ValueId v, Reg tmp) const { return reg_[v] != kNoReg ? reg_[v] : tmp; }
  void finish(ValueId v, Reg r) {
    if (r != reg_[v]) put(v, r);
  }

  // The same for the low 64 bits of an XMM register.
  void get_xmm(unsigned xmm, ValueId v) {
    if (reg_[v] != kNoReg) a_.sse(0x66, {0x6E}, xmm, reg_[v], true);  // movq xmm, r64
    else if (xreg_[v] >= 0) {
      if (static_cast<unsigned>(xreg_[v]) != xmm) a_.sse(0, {0x28}, xmm, static_cast<unsigned>(xreg_[v]));  // movaps
    } else {
      a_.movsd_load(xmm, value_mem(v));
    }
  }
  void put_xmm(ValueId v, unsigned xmm) {
    if (reg_[v] != kNoReg) a_.sse(0x66, {0x7E}, xmm, reg_[v], true);  // movq r64, xmm
    else if (xreg_[v] >= 0) a_.sse(0xF3, {0x7E}, static_cast<unsigned>(xreg_[v]), xmm);  // movq xmm, xmm (upper half cleared)
    else a_.movsd_store(value_mem(v), xmm);
  }

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
  void alu_op(Alu op, const Inst& in, Reg d = RAX) {
    bool w = in.size == 8;
    if (op == Alu::Cmp && d == RAX && !is_const(in.args[0]) && reg_[in.args[0]] != kNoReg) {
      d = reg_[in.args[0]];  // a compare changes nothing: use a's register as it is
    } else {
      get(d, in.args[0]);
    }
    if (imm32_ok(in.args[1], in.size)) {
      a_.alu_imm(op, d, imm32(in.args[1]), w);
    } else {
      a_.alu(op, d, src(in.args[1], RCX), w);
    }
  }

  // An ALU operation whose result is v, computed in v's register if it has one.
  // (No operand shares that register: operands' registers are released only
  // after the instruction that last uses them.)
  void alu_value(ValueId v, Alu op, const Inst& in) {
    const Reg d = dst(v, RAX);
    alu_op(op, in, d);
    finish(v, d);
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
    const Reg d = dst(v, RAX);
    if (is_const(in.args[1])) {
      get(d, in.args[0]);
      uint8_t amount = static_cast<uint8_t>(const_value(in.args[1]) & (width - 1));
      if (amount) a_.shift_imm(op, d, amount, w);
      else if (!w) a_.mov(d, d, false);
    } else {
      get(RCX, in.args[1]);
      get(d, in.args[0]);
      a_.shift_cl(op, d, w);
    }
    finish(v, d);
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

  // --- scalar floating point -------------------------------------------------------
  //
  // Single and double precision arithmetic, compares and conversions run as
  // SSE instructions. The evaluator computes them with the same host
  // operations (round to nearest, no flush to zero), so the results agree
  // except for NaNs, where ARM's rules (which NaN propagates, the default NaN)
  // differ from x86's: a NaN result takes the helper instead.

  void fp_get(unsigned xmm, ValueId v) {
    if (is_const(v)) {
      a_.mov_imm(RAX, const_value(v));
      a_.sse(0x66, {0x6E}, xmm, RAX, true);  // movq xmm, rax
    } else {
      get_xmm(xmm, v);
    }
  }

  void fp_put(ValueId v, unsigned xmm, unsigned size) {
    if (size == 8) {
      put_xmm(v, xmm);
    } else if (xreg_[v] >= 0) {  // the single, with the rest of the register clear
      const auto x = static_cast<unsigned>(xreg_[v]);
      a_.sse(0, {0x57}, x, x);    // xorps
      a_.sse(0xF3, {0x10}, x, xmm);  // movss
    } else {
      a_.sse(0x66, {0x7E}, xmm, RAX, false);  // movd eax, xmm (upper half cleared)
      put(v, RAX);
    }
  }

  // Slow paths (the helper, for NaN results and the like) go after the
  // block's code, so that the fast path falls through: `from` jumps there,
  // and the slow path continues where the fast one ends (now).
  struct ColdHelper {
    Assembler::Label from;
    ValueId v;
    Inst in;
    size_t done;
  };
  void cold_helper(Assembler::Label from, ValueId v, const Inst& in) { cold_.push_back({from, v, in, a_.size()}); }
  void emit_cold() {
    for (const ColdHelper& c : cold_) {
      a_.bind(c.from);
      call_helper(c.v, c.in, &evaluate_helper);
      a_.jmp_to(c.done);
    }
  }

  // XMM registers for an operation computing v: v's own (doubles and vector
  // halves; singles go through XMM0 for fp_put to clear the upper bits), or XMM0.
  unsigned xdst(ValueId v, bool direct) const { return direct && xreg_[v] >= 0 ? static_cast<unsigned>(xreg_[v]) : 0; }
  // The register holding v for reading: its own, or `tmp` loaded with it.
  unsigned xsrc(ValueId v, unsigned tmp) {
    if (!is_const(v) && xreg_[v] >= 0) return static_cast<unsigned>(xreg_[v]);
    fp_get(tmp, v);
    return tmp;
  }
  // The result is in XMM `d`: keep it unless it is a NaN.
  void fp_finish(ValueId v, const Inst& in, unsigned d = 0) {
    a_.sse(in.size == 8 ? 0x66 : 0, {0x2E}, d, d);  // ucomisd/ucomiss: PF = unordered
    const Assembler::Label nan = a_.jcc(Cond::P);
    if (d == 0) fp_put(v, 0, in.size);
    cold_helper(nan, v, in);
  }

  bool emit_scalar_fp(ValueId v, const Inst& in) {
    const unsigned size = in.size;
    const uint8_t sd = size == 8 ? 0xF2 : 0xF3;  // the sd/ss prefix
    switch (in.op) {
      case Opcode::FAdd:
      case Opcode::FSub:
      case Opcode::FMul:
      case Opcode::FDiv: {
        if (size != 4 && size != 8) return false;
        const uint8_t op = in.op == Opcode::FAdd ? 0x58 : in.op == Opcode::FMul ? 0x59 : in.op == Opcode::FSub ? 0x5C : 0x5E;
        const unsigned d = xdst(v, size == 8);
        fp_get(d, in.args[0]);
        a_.sse(sd, {op}, d, xsrc(in.args[1], 1));
        fp_finish(v, in, d);
        return true;
      }
      case Opcode::FSqrt:
        if (size != 4 && size != 8) return false;
        fp_get(0, in.args[0]);
        a_.sse(sd, {0x51}, 0, 0u);
        fp_finish(v, in);
        return true;
      case Opcode::FMadd:  // a * b + c, fused: vfmadd231 xmm0(c), xmm1(a), xmm2(b)
        if ((size != 4 && size != 8) || !kHasFma) return false;
        fp_get(0, in.args[2]);
        fp_get(1, in.args[0]);
        fp_get(2, in.args[1]);
        a_.vex_0f38(0xB9, size == 8, 0, 1, 2);
        fp_finish(v, in);
        return true;
      case Opcode::FCmp: {  // packed NZCV: unordered 0011, equal 0110, less 1000, greater 0010
        if (size != 4 && size != 8) return false;
        if (lazy_[v]) return true;  // only fused conditions use it
        fp_get(0, in.args[0]);
        fp_get(1, in.args[1]);
        a_.sse(size == 8 ? 0x66 : 0, {0x2E}, 0, 1u);  // ucomis xmm0, xmm1
        a_.mov_imm(RAX, ir::kFlagC);
        a_.mov_imm(RCX, ir::kFlagN);
        a_.cmov(Cond::B, RAX, RCX, false);  // less (or unordered)
        a_.mov_imm(RCX, ir::kFlagZ | ir::kFlagC);
        a_.cmov(Cond::E, RAX, RCX, false);  // equal (or unordered)
        a_.mov_imm(RCX, ir::kFlagC | ir::kFlagV);
        a_.cmov(Cond::P, RAX, RCX, false);  // unordered
        put(v, RAX);
        return true;
      }
      case Opcode::FCvt:
        if (in.aux == 8 && size == 4) {
          fp_get(0, in.args[0]);
          a_.sse(0xF2, {0x5A}, 0, 0u);  // cvtsd2ss
        } else if (in.aux == 4 && size == 8) {
          fp_get(0, in.args[0]);
          a_.sse(0xF3, {0x5A}, 0, 0u);  // cvtss2sd
        } else {
          return false;
        }
        fp_finish(v, in);
        return true;
      case Opcode::FRint: {  // round to integral (FRINT32/64 and half precision: the helper)
        if ((size != 4 && size != 8) || (in.aux & 0x18) || !kHost.sse41) return false;
        const auto mode = static_cast<ir::FpRound>(in.aux & 7);
        const uint8_t pd = size == 8 ? 0x66 : 0;  // the packed-op prefix (andpd / andps, ...)
        const uint8_t round = size == 8 ? 0x0B : 0x0A;  // roundsd / roundss (66 0F 3A)
        auto round_imm = [&](unsigned dst, unsigned src_xmm, uint8_t imm) {
          a_.sse(0x66, {0x3A, round}, dst, src_xmm);
          a_.imm8(imm | 8);  // the given mode, inexact suppressed
        };
        auto fconst = [&](unsigned xmm, double d) {
          if (size == 8) vconst(xmm, std::bit_cast<uint64_t>(d));
          else vconst(xmm, std::bit_cast<uint32_t>(static_cast<float>(d)));
        };
        fp_get(0, in.args[0]);
        switch (mode) {
          case ir::FpRound::NearestEven: round_imm(0, 0, 0); break;
          case ir::FpRound::MinusInf: round_imm(0, 0, 1); break;
          case ir::FpRound::PlusInf: round_imm(0, 0, 2); break;
          case ir::FpRound::Zero: round_imm(0, 0, 3); break;
          case ir::FpRound::NearestAway: {
            // t = trunc(x); t += copysign(1, x) if |x - t| >= 0.5 (x - t is exact)
            round_imm(1, 0, 3);
            a_.sse(0, {0x28}, 2, 0u);          // movaps xmm2, xmm0
            a_.sse(sd, {0x5C}, 2, 1u);         // sub: x - t
            vconst(3, size == 8 ? 0x7FFF'FFFF'FFFF'FFFFull : 0x7FFF'FFFFull);
            a_.sse(pd, {0x54}, 2, 3u);         // and: |x - t|
            fconst(4, 0.5);
            a_.sse(sd, {0xC2}, 2, 4u);         // cmpnlt: >= 0.5 (all ones)
            a_.imm8(5);
            vconst(5, size == 8 ? 0x8000'0000'0000'0000ull : 0x8000'0000ull);
            a_.sse(pd, {0x54}, 5, 0u);         // and: x's sign
            fconst(3, 1.0);
            a_.sse(pd, {0x56}, 3, 5u);         // or: copysign(1, x)
            a_.sse(0, {0x28}, 4, 1u);          // movaps xmm4, xmm1
            a_.sse(sd, {0x58}, 4, 3u);         // add: t + copysign(1, x)
            a_.sse(pd, {0x54}, 4, 2u);         // and: where >= 0.5 ...
            a_.sse(pd, {0x55}, 2, 1u);         // andn: ... else t (not t + 0, which loses -0)
            a_.sse(pd, {0x56}, 4, 2u);         // or
            a_.sse(0, {0x28}, 0, 4u);          // movaps xmm0, xmm4
            break;
          }
        }
        fp_finish(v, in);
        return true;
      }
      case Opcode::IntToF: {
        if (size != 4 && size != 8) return false;
        const bool sign = in.aux & 1, wide = (in.aux >> 1) & 1;
        if (!sign && wide) return false;  // unsigned 64-bit: no SSE instruction
        get(RAX, in.args[0]);
        if (!sign) a_.mov(RAX, RAX, false);  // unsigned 32-bit: zero-extend, convert as 64-bit
        a_.sse(0, {0x57}, 0, 0u);           // xorps xmm0, xmm0 (no false dependency)
        a_.sse(sd, {0x2A}, 0, RAX, wide || !sign);  // cvtsi2sd/ss xmm0, r
        fp_put(v, 0, size);
        return true;
      }
      case Opcode::FToInt: {
        const auto mode = static_cast<ir::FpRound>(in.aux & 7);
        const bool sign = (in.aux >> 3) & 1, from_double = (in.aux >> 4) & 1;
        if ((in.aux >> 5) & 1) return false;  // from half precision
        if (mode != ir::FpRound::Zero && mode != ir::FpRound::NearestEven) return false;
        const uint8_t op = mode == ir::FpRound::Zero ? 0x2C : 0x2D;  // cvtt / cvt (MXCSR: nearest even)
        const uint8_t prefix = from_double ? 0xF2 : 0xF3;
        fp_get(0, in.args[0]);
        Assembler::Label slow;
        if (sign) {
          a_.sse(prefix, {op}, RAX, 0u, size == 8);
          // NaN and out of range give the "integer indefinite" (INT_MIN): ARM saturates instead.
          if (size == 8) {
            a_.mov_imm(RCX, 0x8000'0000'0000'0000ull);
            a_.alu(Alu::Cmp, RAX, RCX, true);
          } else {
            a_.alu_imm(Alu::Cmp, RAX, INT32_MIN, false);
          }
          slow = a_.jcc(Cond::E);
        } else if (size == 4) {
          a_.sse(prefix, {op}, RAX, 0u, true);  // as a 64-bit signed value: in range if 0..2^32-1
          a_.mov(RCX, RAX);
          a_.shift_imm(Shift::Shr, RCX, 32);
          slow = a_.jcc(Cond::NE);
        } else {
          a_.sse(prefix, {op}, RAX, 0u, true);  // 0..2^63-1 fit; the rest (negative, large, NaN) don't
          a_.test(RAX, RAX);
          slow = a_.jcc(Cond::S);
        }
        put(v, RAX);
        cold_helper(slow, v, in);
        return true;
      }
      default:
        return false;
    }
  }

  // --- vector halves ------------------------------------------------------------------
  //
  // Lane operations on 64-bit vector halves run in the low half of an XMM
  // register (movq clears the upper half), for the element sizes SSE has the
  // instruction for; floating point lanes take the helper if a lane is NaN.

  void vconst(unsigned xmm, uint64_t k) {
    a_.mov_imm(RAX, k);
    a_.sse(0x66, {0x6E}, xmm, RAX, true);  // movq xmm, rax
  }
  void vput(ValueId v, unsigned xmm) { put_xmm(v, xmm); }
  void pop66(std::initializer_list<uint8_t> opcode, unsigned dst, unsigned src) { a_.sse(0x66, opcode, dst, src); }

  // packed-int opcode for element size `esize` from {b, w, d, q} (0 = none).
  static const uint8_t* by_size(const uint8_t (&ops)[4], unsigned esize) {
    const unsigned i = esize == 1 ? 0 : esize == 2 ? 1 : esize == 4 ? 2 : 3;
    return ops[i] ? &ops[i] : nullptr;
  }

  // XMM0 = lanes compared (all ones / zero); false if not available inline.
  bool emit_vcmp(ir::VecPred pred, unsigned esize) {
    // pcmpeq b/w/d (q: 0F38 29, SSE4.1), pcmpgt b/w/d (q: 0F38 37, SSE4.2)
    auto eq = [&](unsigned dst, unsigned src) {
      if (esize == 8) pop66({0x38, 0x29}, dst, src);
      else pop66({static_cast<uint8_t>(esize == 1 ? 0x74 : esize == 2 ? 0x75 : 0x76)}, dst, src);
    };
    auto gt = [&](unsigned dst, unsigned src) {
      if (esize == 8) pop66({0x38, 0x37}, dst, src);
      else pop66({static_cast<uint8_t>(esize == 1 ? 0x64 : esize == 2 ? 0x65 : 0x66)}, dst, src);
    };
    if (esize == 8 && ((pred == ir::VecPred::Eq || pred == ir::VecPred::Tst) ? !kHost.sse41 : !kHost.sse42)) return false;
    auto invert = [&](unsigned xmm) {  // xmm = ~xmm
      pop66({0x76}, 3, 3);               // pcmpeqd xmm3, xmm3: all ones
      pop66({0xEF}, xmm, 3);             // pxor
    };
    switch (pred) {
      case ir::VecPred::Eq:
        eq(0, 1);
        return true;
      case ir::VecPred::Tst:
        pop66({0xDB}, 0, 1);  // pand
        pop66({0xEF}, 1, 1);  // pxor xmm1, xmm1
        eq(0, 1);             // (a & b) == 0
        invert(0);
        return true;
      case ir::VecPred::Hi:
      case ir::VecPred::Hs:
        vconst(2, lane_sign_bits(esize));
        pop66({0xEF}, 0, 2);
        pop66({0xEF}, 1, 2);
        [[fallthrough]];
      case ir::VecPred::Gt:
      case ir::VecPred::Ge:
        if (pred == ir::VecPred::Gt || pred == ir::VecPred::Hi) {
          gt(0, 1);
        } else {  // a >= b: !(b > a)
          gt(1, 0);
          invert(1);
          a_.sse(0xF3, {0x7E}, 0, 1u);  // movq xmm0, xmm1
        }
        return true;
    }
    return false;
  }

  bool emit_vector(ValueId v, const Inst& in) {
    const unsigned esize = in.aux & 0xF;
    switch (in.op) {
      case Opcode::VAdd:
      case Opcode::VSub: {
        static constexpr uint8_t add[4] = {0xFC, 0xFD, 0xFE, 0xD4}, sub[4] = {0xF8, 0xF9, 0xFA, 0xFB};
        const unsigned d = xdst(v, true);
        fp_get(d, in.args[0]);
        pop66({*by_size(in.op == Opcode::VAdd ? add : sub, esize)}, d, xsrc(in.args[1], 1));
        if (d == 0) vput(v, 0);
        return true;
      }
      case Opcode::VMul:
        if (esize != 2 && !(esize == 4 && kHost.sse41)) return false;
        fp_get(0, in.args[0]);
        fp_get(1, in.args[1]);
        if (esize == 2) pop66({0xD5}, 0, 1);  // pmullw
        else pop66({0x38, 0x40}, 0, 1);      // pmulld
        vput(v, 0);
        return true;
      case Opcode::VCmp:
        fp_get(0, in.args[0]);
        fp_get(1, in.args[1]);
        if (!emit_vcmp(static_cast<ir::VecPred>(in.aux >> 4), esize)) return false;
        vput(v, 0);
        return true;
      case Opcode::VMax:
      case Opcode::VMin: {
        const bool sign = (in.aux >> 4) & 1, max = in.op == Opcode::VMax;
        // {opcode bytes, needs SSE4.1}
        uint8_t op1 = 0, op2 = 0;
        bool sse41 = true;
        if (esize == 1 && !sign) { op1 = max ? 0xDE : 0xDA; sse41 = false; }
        else if (esize == 1) { op1 = 0x38; op2 = max ? 0x3C : 0x38; }
        else if (esize == 2 && sign) { op1 = max ? 0xEE : 0xEA; sse41 = false; }
        else if (esize == 2) { op1 = 0x38; op2 = max ? 0x3E : 0x3A; }
        else if (esize == 4) { op1 = 0x38; op2 = sign ? (max ? 0x3D : 0x39) : (max ? 0x3F : 0x3B); }
        else return false;
        if (sse41 && !kHost.sse41) return false;
        fp_get(0, in.args[0]);
        fp_get(1, in.args[1]);
        if (op2) pop66({op1, op2}, 0, 1);
        else pop66({op1}, 0, 1);
        vput(v, 0);
        return true;
      }
      case Opcode::VAbs:
        if (esize == 8 || !kHost.ssse3) return false;
        fp_get(1, in.args[0]);
        pop66({0x38, static_cast<uint8_t>(esize == 1 ? 0x1C : esize == 2 ? 0x1D : 0x1E)}, 0, 1);  // pabs
        vput(v, 0);
        return true;
      case Opcode::VShl:
      case Opcode::VLShr:
      case Opcode::VAShr: {
        // Shifts by the 64-bit count in XMM1 (counts of the lane width or more
        // give 0, or the sign for arithmetic shifts, as the IR defines).
        static constexpr uint8_t shl[4] = {0, 0xF1, 0xF2, 0xF3}, shr[4] = {0, 0xD1, 0xD2, 0xD3},
                                 sar[4] = {0, 0xE1, 0xE2, 0};
        const uint8_t* op = by_size(in.op == Opcode::VShl ? shl : in.op == Opcode::VLShr ? shr : sar, esize);
        if (!op) return false;
        fp_get(0, in.args[0]);
        fp_get(1, in.args[1]);
        pop66({*op}, 0, 1);
        vput(v, 0);
        return true;
      }
      case Opcode::VWiden: {
        if (esize == 8 || !kHost.sse41) return false;
        const bool sign = (in.aux >> 4) & 1, high = (in.aux >> 5) & 1;
        fp_get(1, in.args[0]);
        if (high) {
          vconst(2, 32);
          pop66({0xD3}, 1, 2);  // psrlq xmm1, 32
        }
        const uint8_t op = static_cast<uint8_t>((sign ? 0x20 : 0x30) + (esize == 1 ? 0 : esize == 2 ? 3 : 5));
        pop66({0x38, op}, 0, 1);  // pmovsx/zx bw, wd, dq
        vput(v, 0);
        return true;
      }
      case Opcode::VLane:
        return emit_vlane(v, in);
      default:
        return false;
    }
  }

  // A jump taken if a floating point lane of the low 64 bits of XMM `x` is a
  // NaN (the upper half may hold NaNs of its own, from 0 / 0).
  Assembler::Label lanes_nan(unsigned x, unsigned esize) {
    if (esize == 8) {
      a_.sse(0x66, {0x2E}, x, x);  // ucomisd
      return a_.jcc(Cond::P);
    }
    a_.sse(0xF3, {0x7E}, 3, x);    // movq xmm3, x
    a_.sse(0, {0xC2}, 3, 3u);      // cmpunordps xmm3, xmm3
    a_.imm8(3);
    a_.sse(0, {0x50}, RAX, 3u);    // movmskps eax, xmm3
    a_.alu_imm(Alu::And, RAX, 3, false);
    return a_.jcc(Cond::NE);
  }

  bool emit_vlane(ValueId v, const Inst& in) {
    const auto op = static_cast<ir::VecOp>(in.imm);
    const unsigned esize = in.aux & 0xF;
    switch (op) {
      case ir::VecOp::TblPart: {  // bytes of b in [8k, 8k + 8) select a byte of c, others keep a's
        if (!kHost.ssse3) return false;
        if (in.aux * 8u >= 256) {  // no byte index reaches this part: a unchanged
          get(RAX, in.args[0]);
          put(v, RAX);
          return true;
        }
        fp_get(0, in.args[0]);  // a: the bytes so far
        fp_get(1, in.args[1]);  // b: the indices
        fp_get(2, in.args[2]);  // c: the table part
        if (in.aux) {
          vconst(3, 0x0101010101010101ull * (in.aux * 8u));
          pop66({0xF8}, 1, 3);  // psubb: indices relative to the part
        }
        a_.sse(0xF3, {0x7E}, 4, 1u);           // movq xmm4, xmm1
        vconst(3, 0xF8F8F8F8F8F8F8F8ull);
        pop66({0xDB}, 4, 3);                   // pand: bits outside 0..7
        pop66({0xEF}, 3, 3);                   // pxor xmm3, xmm3
        pop66({0x74}, 4, 3);                   // pcmpeqb: in this part
        pop66({0x38, 0x00}, 2, 1);             // pshufb xmm2, xmm1: the table bytes
        pop66({0xDB}, 2, 4);                   // pand: where in range
        pop66({0xDF}, 4, 0);                   // pandn xmm4, xmm0: a's bytes elsewhere
        pop66({0xEB}, 2, 4);                   // por
        vput(v, 2);
        return true;
      }
      case ir::VecOp::FAdd:
      case ir::VecOp::FSub:
      case ir::VecOp::FMul:
      case ir::VecOp::FDiv:
      case ir::VecOp::FMla:
      case ir::VecOp::FMls: {
        if (esize != 4 && esize != 8) return false;
        const bool fused = op == ir::VecOp::FMla || op == ir::VecOp::FMls;
        if (fused && !kHasFma) return false;
        const uint8_t pd = esize == 8 ? 0x66 : 0;
        if (fused) {  // c + a * b, c - a * b: vfmadd231 / vfnmadd231 xmm0(c), xmm1(a), xmm2(b)
          fp_get(0, in.args[2]);
          fp_get(1, in.args[0]);
          fp_get(2, in.args[1]);
          a_.vex_0f38(op == ir::VecOp::FMla ? 0xB8 : 0xBC, esize == 8, 0, 1, 2);
          // NaN in a lane of the half: the helper (ARM's NaN rules).
          const Assembler::Label nan = lanes_nan(0, esize);
          vput(v, 0);
          cold_helper(nan, v, in);
          return true;
        }
        const uint8_t code = op == ir::VecOp::FAdd ? 0x58 : op == ir::VecOp::FMul ? 0x59 : op == ir::VecOp::FSub ? 0x5C : 0x5E;
        const unsigned d = xdst(v, true);
        fp_get(d, in.args[0]);
        a_.sse(pd, {code}, d, xsrc(in.args[1], 1));
        const Assembler::Label nan = lanes_nan(d, esize);
        if (d == 0) vput(v, 0);
        cold_helper(nan, v, in);
        return true;
      }
      case ir::VecOp::FCmEq:
      case ir::VecOp::FCmGe:
      case ir::VecOp::FCmGt: {  // unordered lanes compare false, as cmpps has it
        if (esize != 4 && esize != 8) return false;
        const uint8_t pd = esize == 8 ? 0x66 : 0;
        fp_get(0, in.args[0]);
        fp_get(1, in.args[1]);
        if (op == ir::VecOp::FCmEq) {
          a_.sse(pd, {0xC2}, 0, 1u);  // cmpeq xmm0, xmm1
          a_.imm8(0);
          vput(v, 0);
        } else {  // a >= b: b <= a; a > b: b < a
          a_.sse(pd, {0xC2}, 1, 0u);
          a_.imm8(op == ir::VecOp::FCmGe ? 2 : 1);
          vput(v, 1);
        }
        return true;
      }
      default:
        return false;
    }
  }

  void emit(ValueId v, const Inst& in) {
    const bool w = in.size == 8;
    if (ir::is_vector_or_fp(in.op)) {
      if (!emit_scalar_fp(v, in) && !emit_vector(v, in)) call_helper(v, in, &evaluate_helper);
      return;
    }
    switch (in.op) {
      case Opcode::Nop:
      case Opcode::Const:
        return;  // constants are materialized at their uses

      case Opcode::GetReg: {
        if (xreg_[v] >= 0) {
          a_.movsd_load(static_cast<unsigned>(xreg_[v]), slot_mem(in.imm));
          return;
        }
        const Reg d = dst(v, RAX);
        a_.load(d, slot_mem(in.imm));
        finish(v, d);
        return;
      }
      case Opcode::StateAddr:
        a_.lea(RAX, slot_mem(in.imm));
        put(v, RAX);
        return;
      case Opcode::Fence:
        a_.mfence();
        return;
      case Opcode::StateOp:
        a_.mov(kCallArgs[0], kState);
        a_.mov_imm(kCallArgs[1], (uint64_t{in.aux} << 16) | ((in.imm & 0xFFFF'FFFFu) << 32));
        a_.mov_imm(RAX, reinterpret_cast<uint64_t>(&state_helper));
        a_.call(RAX);
        return;
      case Opcode::AtomicRmw:
      case Opcode::AtomicCas:
      case Opcode::AtomicCasPair:
      case Opcode::AtomicRmwPair:
      case Opcode::MemOp:
      case Opcode::Counter:
        call_helper(v, in, &atomic_helper);
        return;
      case Opcode::SetReg:
        if (imm32_ok(in.args[0], 8)) {
          a_.store_imm32(slot_mem(in.imm), imm32(in.args[0]), true);
        } else if (!is_const(in.args[0]) && xreg_[in.args[0]] >= 0) {
          a_.movsd_store(slot_mem(in.imm), static_cast<unsigned>(xreg_[in.args[0]]));
        } else {
          a_.store(slot_mem(in.imm), src(in.args[0], RAX), 8);
        }
        return;

      case Opcode::Load: {
        if (xreg_[v] >= 0) {  // straight into an XMM register (movd / movq, the rest cleared)
          const Mem m{src(in.args[0], RAX), 0};
          if (in.size == 8) a_.sse(0xF3, {0x7E}, static_cast<unsigned>(xreg_[v]), m);
          else a_.sse(0x66, {0x6E}, static_cast<unsigned>(xreg_[v]), m);
          return;
        }
        const Mem m{src(in.args[0], RAX), 0};
        const Reg d = dst(v, RAX);
        bool sign = in.aux != 0;
        switch (in.size) {
          case 1: sign ? a_.movsx8(d, m) : a_.movzx8(d, m); break;
          case 2: sign ? a_.movsx16(d, m) : a_.movzx16(d, m); break;
          case 4: sign ? a_.movsxd(d, m) : a_.load(d, m, false); break;
          default: a_.load(d, m, true); break;
        }
        finish(v, d);
        return;
      }
      case Opcode::Store: {
        const Reg base = src(in.args[0], RAX);
        a_.store(Mem{base, 0}, src(in.args[1], RCX), in.size);
        return;
      }
      case Opcode::LoadToState: {
        const Reg base = src(in.args[0], RAX);
        const uint64_t off = 8 * in.imm;
        unsigned written = 8;
        switch (in.size) {
          case 16:
            a_.load(RCX, Mem{base, 0});
            a_.store(state_mem(off), RCX, 8);
            a_.load(RCX, Mem{base, 8});
            a_.store(state_mem(off + 8), RCX, 8);
            written = 16;
            break;
          case 8: a_.load(RCX, Mem{base, 0}); a_.store(state_mem(off), RCX, 8); break;
          case 4: a_.load(RCX, Mem{base, 0}, false); a_.store(state_mem(off), RCX, 8); break;
          case 2: a_.movzx16(RCX, Mem{base, 0}); a_.store(state_mem(off), RCX, 8); break;
          default: a_.movzx8(RCX, Mem{base, 0}); a_.store(state_mem(off), RCX, 8); break;
        }
        for (unsigned k = written; k < in.aux; k += 8) a_.store_imm32(state_mem(off + k), 0, true);
        return;
      }
      case Opcode::StoreFromState: {
        const Reg base = src(in.args[0], RAX);
        const uint64_t off = 8 * in.imm;
        if (in.size == 16) {
          a_.load(RCX, state_mem(off));
          a_.store(Mem{base, 0}, RCX, 8);
          a_.load(RCX, state_mem(off + 8));
          a_.store(Mem{base, 8}, RCX, 8);
        } else {
          a_.load(RCX, state_mem(off), in.size == 8);
          a_.store(Mem{base, 0}, RCX, in.size);
        }
        return;
      }

      case Opcode::Add: alu_value(v, Alu::Add, in); return;
      case Opcode::Sub: alu_value(v, Alu::Sub, in); return;
      case Opcode::And: alu_value(v, Alu::And, in); return;
      case Opcode::Or: alu_value(v, Alu::Or, in); return;
      case Opcode::Xor: alu_value(v, Alu::Xor, in); return;
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
      case Opcode::Select: {
        if (select_cond_[in.args[0]]) {  // on the x86 flags of the condition's flag operation
          const Inst& cond = block_.insts[in.args[0]];
          const Inst& flags = block_.insts[cond.args[0]];
          Cond x86;
          int constant;
          fused_condition(flags, cond.aux, x86, constant);
          // The values first (loading 0 may clear flags), away from RAX and RCX
          // (the flag operation's temporaries).
          const Reg d = dst(v, RDX);
          get(d, in.args[1]);
          const Reg f = src(in.args[2], R8);
          redo_flags(flags, cond.aux);
          a_.cmov(static_cast<Cond>(static_cast<uint8_t>(x86) ^ 1), d, f, w);
          if (!w) a_.mov(d, d, false);
          finish(v, d);
          return;
        }
        const Reg d = dst(v, RAX);
        get(d, in.args[1]);
        const Reg f = src(in.args[2], RCX);
        const Reg c = src(in.args[0], RDX);
        a_.test(c, c, true);
        a_.cmov(Cond::E, d, f, w);
        if (!w) a_.mov(d, d, false);
        finish(v, d);
        return;
      }
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
        if (lazy_[v]) return;
        alu_op(Alu::Add, in);
        pack_flags(false);
        put(v, RAX);
        return;
      case Opcode::FlagsSub:
        if (lazy_[v]) return;
        alu_op(Alu::Cmp, in);
        pack_flags(true);
        put(v, RAX);
        return;
      case Opcode::FlagsLogic:
        if (lazy_[v]) return;
        get(RAX, in.args[0]);
        a_.test(RAX, RAX, w);
        pack_flags(false);
        put(v, RAX);
        return;
      case Opcode::CondHolds:
        if (branch_cond_ && v == lazy_cond_) return;  // the terminator branches on the flags
        if (select_cond_[v]) return;                   // the selects use the flags
        if (fused_cond_holds(v, in)) return;
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
    for (unsigned k = 0; k < kBlockSavedXmmCount; ++k)  // movdqu xmm, [rsp + area + 16k]
      a_.sse(0xF3, {0x6F}, kBlockSavedXmmFirst + k, Mem{RSP, kBlockXmmSaveArea + 16 * static_cast<int32_t>(k)});
    a_.alu_imm(Alu::Add, RSP, kFrameSize);
    for (size_t k = std::size(kBlockSavedRegs); k-- > 0;) a_.pop(kBlockSavedRegs[k]);
    a_.ret();
  }

  // --- flags ---------------------------------------------------------------------------
  //
  // A condition on the flags of a compare (FlagsSub), CMN (FlagsAdd) or test
  // (FlagsLogic) repeats the x86 compare and reads the x86 flags directly. The
  // packed NZCV value is then only computed if something other than
  // conditions uses it (such as the store of NZCV to guest state).

  // The x86 condition after the flag operation `flags` for ARM condition
  // `cond`; or a constant (0 / 1) in `constant`; false if there is none.
  // FCMP sets N for less, Z and C for equal, C for greater, C and V for
  // unordered; after ucomisd a, b x86 has ZF, PF and CF for unordered, CF for
  // less, ZF for equal. Some conditions take the compare with the operands
  // swapped (ucomisd b, a); EQ and NE (two x86 flags) are not fused.
  static bool fcmp_swapped(unsigned cond) { return cond == 2 || cond == 3 || cond == 4 || cond == 5 || cond == 8 || cond == 9; }

  static bool fused_condition(const Inst& flags_inst, unsigned cond, Cond& x86, int& constant) {
    const Opcode flags = flags_inst.op;
    constant = -1;
    if (cond >= 14) {  // AL, NV
      constant = 1;
      return true;
    }
    if (flags == Opcode::FCmp) {
      if (flags_inst.size != 4 && flags_inst.size != 8) return false;
      switch (cond) {
        case 12: x86 = Cond::A; return true;   // GT: greater
        case 10: x86 = Cond::AE; return true;  // GE: greater or equal
        case 11: x86 = Cond::B; return true;   // LT: less or unordered
        case 13: x86 = Cond::BE; return true;  // LE: less, equal or unordered
        case 6: x86 = Cond::P; return true;    // VS: unordered
        case 7: x86 = Cond::NP; return true;   // VC
        case 3: case 4: x86 = Cond::A; return true;   // CC, MI: less (swapped: b > a)
        case 2: case 5: x86 = Cond::BE; return true;  // CS, PL: not less (swapped)
        case 8: x86 = Cond::B; return true;    // HI: greater or unordered (swapped)
        case 9: x86 = Cond::AE; return true;   // LS: less or equal (swapped)
        default: return false;                 // EQ, NE
      }
    }
    static constexpr Cond common[8] = {Cond::E, Cond::NE, Cond::B, Cond::B, Cond::S, Cond::NS, Cond::O, Cond::NO};
    switch (cond) {
      case 0: case 1: case 4: case 5: case 6: case 7:
        if (flags == Opcode::FlagsLogic && (cond == 6 || cond == 7)) {  // V clear
          constant = cond == 7;
          return true;
        }
        x86 = common[cond];
        return true;
      case 10: x86 = Cond::GE; return true;  // N == V
      case 11: x86 = Cond::L; return true;
      case 12: x86 = Cond::G; return true;   // !Z && N == V
      case 13: x86 = Cond::LE; return true;
      default: break;  // CS, CC, HI, LS: the carry
    }
    switch (flags) {
      case Opcode::FlagsSub:  // ARM's C is "no borrow": x86's CF inverted
        x86 = cond == 2 ? Cond::AE : cond == 3 ? Cond::B : cond == 8 ? Cond::A : Cond::BE;
        return true;
      case Opcode::FlagsAdd:  // C is the carry, as x86's CF; HI/LS have no x86 condition
        if (cond == 8 || cond == 9) return false;
        x86 = cond == 2 ? Cond::B : Cond::AE;
        return true;
      default:  // FlagsLogic: C clear
        constant = cond == 3 || cond == 9;
        return true;
    }
  }

  static bool fusable(Opcode op) {
    return op == Opcode::FlagsSub || op == Opcode::FlagsAdd || op == Opcode::FlagsLogic || op == Opcode::FCmp;
  }

  // A branch condition that is a fused condition used by nothing else: the
  // terminator jumps on the x86 flags (the value itself is not emitted).
  bool branch_on_flags(const Inst*& flags, Cond& x86, int& constant) const {
    const ir::Terminator& t = block_.term;
    if (t.kind != ir::Terminator::Kind::Branch || t.value == ir::kNoValue) return false;
    const Inst& cond = block_.insts[t.value];
    if (cond.op != Opcode::CondHolds || cond_uses_[t.value] != 0) return false;
    flags = &block_.insts[cond.args[0]];
    return fusable(flags->op) && fused_condition(*flags, cond.aux, x86, constant);
  }

  // Flag operations whose only users are conditions it fuses with: they emit nothing.
  void find_lazy_flags() {
    const size_t n = block_.insts.size();
    lazy_.assign(n, 0);
    for (size_t i = 0; i < n; ++i)
      if (fusable(block_.insts[i].op)) lazy_[i] = 1;
    auto other_use = [&](ValueId v) {
      if (v != ir::kNoValue && v < n) lazy_[v] = 0;
    };
    cond_uses_.assign(n, 0);  // uses of each value by instructions (not the terminator)
    for (size_t i = 0; i < n; ++i) {
      const Inst& in = block_.insts[i];
      if (in.op == Opcode::Nop) continue;
      for (unsigned k = 0; k < ir::arg_count(in.op); ++k)
        if (in.args[k] != ir::kNoValue && in.args[k] < n) ++cond_uses_[in.args[k]];
    }
    for (size_t i = 0; i < n; ++i) {
      const Inst& in = block_.insts[i];
      if (in.op == Opcode::Nop) continue;
      for (unsigned k = 0; k < ir::arg_count(in.op); ++k) {
        const ValueId a = in.args[k];
        if (a == ir::kNoValue) continue;
        Cond x86;
        int constant;
        if (in.op == Opcode::CondHolds && k == 0 && fusable(block_.insts[a].op) &&
            fused_condition(block_.insts[a], in.aux, x86, constant))
          continue;
        other_use(a);
      }
    }
    // Fused conditions only selects use: they emit nothing (see Select).
    select_cond_.assign(n, 0);
    {
      std::vector<uint32_t> select_uses(n, 0);
      for (size_t i = 0; i < n; ++i)
        if (block_.insts[i].op == Opcode::Select && block_.insts[i].args[0] < n) ++select_uses[block_.insts[i].args[0]];
      for (size_t i = 0; i < n; ++i) {
        const Inst& in = block_.insts[i];
        if (in.op != Opcode::CondHolds || !select_uses[i] || select_uses[i] != cond_uses_[i] ||
            block_.term.value == i)
          continue;
        const Inst& f = block_.insts[in.args[0]];
        Cond x86;
        int constant;
        if (fusable(f.op) && fused_condition(f, in.aux, x86, constant) && constant < 0) select_cond_[i] = 1;
      }
    }
    const Inst* flags;
    Cond x86;
    int constant;
    // (Only the linking branch terminator jumps on the flags.)
    if (chain_.link_helper && branch_on_flags(flags, x86, constant) && constant < 0) {
      branch_cond_ = true;  // the terminator repeats the flag operation itself
      lazy_cond_ = block_.term.value;
    } else {
      other_use(block_.term.value);
    }
  }

  // Repeat the x86 flag operation of `flags`.
  void redo_flags(const Inst& flags, unsigned cond) {
    if (flags.op == Opcode::FCmp) {
      const bool swap = fcmp_swapped(cond);
      fp_get(0, flags.args[swap ? 1 : 0]);
      fp_get(1, flags.args[swap ? 0 : 1]);
      a_.sse(flags.size == 8 ? 0x66 : 0, {0x2E}, 0, 1u);  // ucomisd/ucomiss
    } else if (flags.op == Opcode::FlagsLogic) {
      get(RAX, flags.args[0]);
      a_.test(RAX, RAX, flags.size == 8);
    } else {
      alu_op(flags.op == Opcode::FlagsSub ? Alu::Cmp : Alu::Add, flags);
    }
  }

  // CondHolds on the flags of a fusable operation, if it can be fused.
  bool fused_cond_holds(ValueId v, const Inst& in) {
    const Inst& flags = block_.insts[in.args[0]];
    Cond x86;
    int constant;
    if (!fusable(flags.op) || !fused_condition(flags, in.aux, x86, constant)) return false;
    if (constant >= 0) {
      a_.mov_imm(RAX, static_cast<uint64_t>(constant));
    } else {
      redo_flags(flags, in.aux);
      a_.setcc(x86, RAX);
      a_.movzx8(RAX, RAX);
    }
    put(v, RAX);
    return true;
  }

  // RAX = the next pc (stored): jump into its block if the thread's table has
  // it translated, else (or if the dispatcher has to look first) fall through.
  void chain(std::vector<Assembler::Label>& to_dispatcher) {
    auto header = [](int32_t field) { return Mem{kScratch, static_cast<int32_t>(field - 8 * kChainHeaderSlots)}; };
    a_.load(RCX, header(offsetof(ChainHeader, stop_pc)));
    a_.alu(Alu::Cmp, RAX, RCX);
    to_dispatcher.push_back(a_.jcc(Cond::E));
    a_.load(RCX, state_mem(chain_.interrupt_offset));
    a_.test(RCX, RCX);
    to_dispatcher.push_back(a_.jcc(Cond::NE));
    a_.load(RCX, header(offsetof(ChainHeader, generation)));
    a_.load(RCX, Mem{RCX, 0});
    a_.load(RDX, header(offsetof(ChainHeader, table_generation)));
    a_.alu(Alu::Cmp, RCX, RDX);
    to_dispatcher.push_back(a_.jcc(Cond::NE));  // translations were invalidated: the table is stale
    a_.mov(RDX, RAX);
    a_.shift_imm(Shift::Shr, RDX, 2);
    a_.alu_imm(Alu::And, RDX, static_cast<int32_t>(chain_.table_mask), false);
    a_.shift_imm(Shift::Shl, RDX, 3);
    a_.load(RCX, header(offsetof(ChainHeader, table)));
    a_.alu(Alu::Add, RDX, RCX);
    a_.load(RDX, Mem{RDX, 0});  // the entry
    a_.test(RDX, RDX);
    to_dispatcher.push_back(a_.jcc(Cond::E));
    a_.load(RCX, Mem{RDX, chain_.entry_guest_pc});
    a_.alu(Alu::Cmp, RCX, RAX);
    to_dispatcher.push_back(a_.jcc(Cond::NE));
    a_.load(RDX, Mem{RDX, chain_.entry_chain_target});
    a_.test(RDX, RDX);
    to_dispatcher.push_back(a_.jcc(Cond::E));
    a_.store(state_mem(chain_.block_pc_offset), RAX, 8);
    a_.jmp(RDX);
  }

  // --- direct links ------------------------------------------------------------------

  struct PendingLink {
    Assembler::Label jump;       // the site's jmp rel32 (to the stub until linked)
    Assembler::Label interrupt;  // the interrupt check's exit
    uint64_t target;
  };

  // Go to the constant guest pc `target`: through a link site, or to the
  // dispatcher if an interrupt is pending.
  void link_to(uint64_t target, std::vector<PendingLink>& pending) {
    PendingLink l;
    l.target = target;
    a_.mov_imm(RAX, target);
    a_.store(state_mem(chain_.block_pc_offset), RAX, 8);
    a_.load(RCX, state_mem(chain_.interrupt_offset));
    a_.test(RCX, RCX);
    l.interrupt = a_.jcc(Cond::NE);
    while ((a_.size() + 1) % 4) a_.nop();  // the rel32 4-byte aligned (blocks start 16-byte aligned)
    l.jump = a_.jmp();
    pending.push_back(l);
  }

  // The stubs: store the pc, ask the link helper, jump where it says or return.
  void link_stubs(const std::vector<PendingLink>& pending) {
    for (size_t k = 0; k < pending.size(); ++k) {
      const PendingLink& l = pending[k];
      a_.bind(l.interrupt);
      a_.mov_imm(RAX, l.target);
      store_pc(RAX);
      epilogue();
      const size_t stub = a_.size();
      a_.bind(l.jump);
      if (links_) links_->push_back({static_cast<uint32_t>(l.jump.patch), static_cast<uint32_t>(stub), l.target});
      a_.mov_imm(RAX, l.target);
      store_pc(RAX);
      a_.mov_imm(kCallArgs[0], chain_.link_context);
      a_.mov_imm(kCallArgs[1], k);
      a_.mov_imm(RAX, chain_.link_helper);
      a_.call(RAX);
      a_.test(RAX, RAX);
      const Assembler::Label unlinked = a_.jcc(Cond::E);
      a_.jmp(RAX);
      a_.bind(unlinked);
      epilogue();
    }
  }

  void terminator() {
    const ir::Terminator& t = block_.term;
    auto edge = [&](uint64_t target, std::vector<PendingLink>& pending) {
      if (target == block_.guest_pc && !loop_slots_.empty()) back_edge();
      else link_to(target, pending);
    };
    if (chain_.link_helper && t.kind == ir::Terminator::Kind::Jump) {
      std::vector<PendingLink> pending;
      edge(t.target, pending);
      link_stubs(pending);
      return;
    }
    if (chain_.link_helper && t.kind == ir::Terminator::Kind::Branch) {
      std::vector<PendingLink> pending;
      Assembler::Label not_taken;
      const Inst* flags;
      Cond x86;
      int constant;
      if (branch_cond_ && branch_on_flags(flags, x86, constant) && constant < 0) {
        redo_flags(*flags, block_.insts[t.value].aux);
        not_taken = a_.jcc(static_cast<Cond>(static_cast<uint8_t>(x86) ^ 1));
      } else {
        get(RDX, t.value);
        a_.test(RDX, RDX, true);
        not_taken = a_.jcc(Cond::E);
      }
      edge(t.target, pending);
      a_.bind(not_taken);
      edge(t.fallthrough, pending);
      link_stubs(pending);
      return;
    }
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
        epilogue();
        return;
    }
    if (chain_.table_mask) {
      std::vector<Assembler::Label> to_dispatcher;
      chain(to_dispatcher);
      for (const Assembler::Label& l : to_dispatcher) a_.bind(l);
    }
    epilogue();
  }

  const ir::Block& block_;
  const ir::StateLayout& layout_;
  const ChainLayout& chain_;
  std::vector<FaultSite>* faults_;
  std::vector<LinkSite>* links_;
  size_t body_ = 0;
  std::vector<uint8_t> lazy_;  // flag operations not emitted (see find_lazy_flags)
  std::vector<Reg> reg_;       // each value's register, or kNoReg (see allocate_registers)
  std::vector<int8_t> xreg_;   // or its XMM register, or -1
  std::vector<ColdHelper> cold_;  // slow paths emitted after the block (see cold_helper)
  std::vector<uint32_t> cond_uses_;  // uses of each value by instructions
  std::vector<LoopSlot> loop_slots_;  // see find_loop_slots
  std::vector<uint8_t> select_cond_;  // fused conditions only selects use (not emitted)
  std::vector<uint8_t> hoisted_;      // GetRegs emitted at the top of the block
  size_t loop_head_ = 0;
  bool branch_cond_ = false;   // the branch condition is not emitted (see branch_on_flags)
  ValueId lazy_cond_ = ir::kNoValue;
  Assembler a_;
};

}  // namespace

std::vector<uint8_t> Emitter::compile(const ir::Block& block, std::vector<FaultSite>* faults, size_t* body,
                                      std::vector<LinkSite>* links) const {
  if (block.insts.size() > kMaxBlockValues) return {};
  if (faults) faults->clear();
  if (links) links->clear();
  Compiler compiler(block, layout_, chain_, faults, links);
  std::vector<uint8_t> code = compiler.run();
  if (body) *body = compiler.body();
  return code;
}

}  // namespace juice::x64
