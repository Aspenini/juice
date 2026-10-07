#include <algorithm>
#include <atomic>
#include <cstring>
#include <vector>

#include "core/ir/ir.hpp"

namespace juice::ir {

namespace {

uint64_t load_mem(uint64_t addr, unsigned size, bool sign) {
  const void* p = reinterpret_cast<const void*>(static_cast<uintptr_t>(addr));
  switch (size) {
    case 1: { int8_t s; uint8_t u; std::memcpy(&u, p, 1); std::memcpy(&s, p, 1);
              return sign ? static_cast<uint64_t>(int64_t{s}) : u; }
    case 2: { int16_t s; uint16_t u; std::memcpy(&u, p, 2); std::memcpy(&s, p, 2);
              return sign ? static_cast<uint64_t>(int64_t{s}) : u; }
    case 4: { int32_t s; uint32_t u; std::memcpy(&u, p, 4); std::memcpy(&s, p, 4);
              return sign ? static_cast<uint64_t>(int64_t{s}) : u; }
    default: { uint64_t u; std::memcpy(&u, p, 8); return u; }
  }
}

void store_mem(uint64_t addr, uint64_t value, unsigned size) {
  std::memcpy(reinterpret_cast<void*>(static_cast<uintptr_t>(addr)), &value, size);
}

}  // namespace

void interpret(const Block& block, uint64_t* state, const StateLayout& layout, volatile size_t* current) {
  thread_local std::vector<uint64_t> values;
  values.assign(block.insts.size(), 0);
  auto arg = [&](const Inst& in, unsigned k) { return in.args[k] == kNoValue ? 0 : values[in.args[k]]; };

  for (size_t i = 0; i < block.insts.size(); ++i) {
    const Inst& in = block.insts[i];
    if (current) *current = i;
    switch (in.op) {
      case Opcode::Nop:
        break;
      case Opcode::GetReg:
        values[i] = state[in.imm];
        break;
      case Opcode::SetReg:
        state[in.imm] = arg(in, 0);
        break;
      case Opcode::Load:
        values[i] = load_mem(arg(in, 0), in.size, in.aux != 0);
        break;
      case Opcode::Store:
        store_mem(arg(in, 0), arg(in, 1), in.size);
        break;
      case Opcode::LoadToState: {
        // Whole slots are written: data zero-extended to 8 bytes, then
        // zero-filled up to `aux` bytes.
        auto* dst = reinterpret_cast<uint8_t*>(state + in.imm);
        unsigned total = (std::max<unsigned>(in.size, in.aux) + 7) & ~7u;
        std::memset(dst, 0, total);
        std::memcpy(dst, reinterpret_cast<const void*>(static_cast<uintptr_t>(arg(in, 0))), in.size);
        break;
      }
      case Opcode::StoreFromState:
        std::memcpy(reinterpret_cast<void*>(static_cast<uintptr_t>(arg(in, 0))), state + in.imm, in.size);
        break;
      case Opcode::StateAddr:
        values[i] = reinterpret_cast<uint64_t>(state + in.imm);
        break;
      case Opcode::Fence:
        std::atomic_thread_fence(std::memory_order_seq_cst);
        break;
      case Opcode::StateOp:
        execute_state_op(in, state);
        break;
      case Opcode::AtomicRmw:
      case Opcode::AtomicCas:
      case Opcode::AtomicCasPair:
      case Opcode::AtomicRmwPair:
      case Opcode::MemOp:
      case Opcode::Counter:
        values[i] = execute_atomic(in, arg(in, 0), arg(in, 1), arg(in, 2));
        break;
      default:
        values[i] = evaluate(in, arg(in, 0), arg(in, 1), arg(in, 2));
        break;
    }
  }

  const Terminator& t = block.term;
  uint64_t& pc = state[layout.pc_slot];
  switch (t.kind) {
    case Terminator::Kind::Jump:
      pc = t.target;
      break;
    case Terminator::Kind::JumpIndirect:
      pc = values[t.value];
      break;
    case Terminator::Kind::Branch:
      pc = values[t.value] ? t.target : t.fallthrough;
      break;
    case Terminator::Kind::Exit: {
      auto* bytes = reinterpret_cast<uint8_t*>(state);
      std::memcpy(bytes + layout.exit_reason_offset, &t.exit_reason, 4);
      std::memcpy(bytes + layout.exit_info_offset, &t.exit_info, 4);
      pc = t.target;
      break;
    }
  }
}

}  // namespace juice::ir
