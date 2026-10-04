#include "core/jit/x64/assembler.hpp"

#include <cstring>
#include <initializer_list>

namespace juice::x64 {

void Assembler::dword(uint32_t v) {
  for (int i = 0; i < 4; ++i) byte(static_cast<uint8_t>(v >> (8 * i)));
}

void Assembler::qword(uint64_t v) {
  for (int i = 0; i < 8; ++i) byte(static_cast<uint8_t>(v >> (8 * i)));
}

void Assembler::rex(bool w, unsigned reg, unsigned index, unsigned base, bool force) {
  uint8_t r = static_cast<uint8_t>(0x40 | (w ? 8 : 0) | ((reg & 8) ? 4 : 0) | ((index & 8) ? 2 : 0) | ((base & 8) ? 1 : 0));
  if (r != 0x40 || force) byte(r);
}

void Assembler::modrm_reg(unsigned reg, unsigned rm) {
  byte(static_cast<uint8_t>(0xC0 | ((reg & 7) << 3) | (rm & 7)));
}

void Assembler::modrm_mem(unsigned reg, Mem m) {
  unsigned base = m.base & 7;
  uint8_t r = static_cast<uint8_t>((reg & 7) << 3);
  bool need_sib = base == 4;  // RSP / R12
  if (m.disp == 0 && base != 5) {  // RBP / R13 always need a displacement
    byte(static_cast<uint8_t>(0x00 | r | (need_sib ? 4 : base)));
    if (need_sib) byte(0x24);
  } else if (m.disp >= -128 && m.disp <= 127) {
    byte(static_cast<uint8_t>(0x40 | r | (need_sib ? 4 : base)));
    if (need_sib) byte(0x24);
    byte(static_cast<uint8_t>(m.disp));
  } else {
    byte(static_cast<uint8_t>(0x80 | r | (need_sib ? 4 : base)));
    if (need_sib) byte(0x24);
    dword(static_cast<uint32_t>(m.disp));
  }
}

void Assembler::op_rr(std::initializer_list<uint8_t> opcode, unsigned reg, unsigned rm, bool w, bool byte_regs) {
  bool force = byte_regs && ((reg >= 4 && reg < 8) || (rm >= 4 && rm < 8));
  rex(w, reg, 0, rm, force);
  for (uint8_t b : opcode) byte(b);
  modrm_reg(reg, rm);
}

void Assembler::op_rm(std::initializer_list<uint8_t> opcode, unsigned reg, Mem m, bool w, bool byte_reg) {
  bool force = byte_reg && reg >= 4 && reg < 8;
  rex(w, reg, 0, m.base, force);
  for (uint8_t b : opcode) byte(b);
  modrm_mem(reg, m);
}

// --- data movement --------------------------------------------------------------

void Assembler::mov(Reg dst, Reg src, bool w) { op_rr({0x89}, src, dst, w); }

void Assembler::mov_imm(Reg dst, uint64_t imm) {
  if (imm == 0) {
    alu(Alu::Xor, dst, dst, false);
  } else if (imm <= 0xFFFF'FFFFu) {
    rex(false, 0, 0, dst);
    byte(static_cast<uint8_t>(0xB8 + (dst & 7)));
    dword(static_cast<uint32_t>(imm));
  } else if (static_cast<int64_t>(imm) >= INT32_MIN && static_cast<int64_t>(imm) < 0) {
    rex(true, 0, 0, dst);
    byte(0xC7);
    modrm_reg(0, dst);
    dword(static_cast<uint32_t>(imm));
  } else {
    rex(true, 0, 0, dst);
    byte(static_cast<uint8_t>(0xB8 + (dst & 7)));
    qword(imm);
  }
}

void Assembler::load(Reg dst, Mem src, bool w) { op_rm({0x8B}, dst, src, w); }

void Assembler::store(Mem dst, Reg src, unsigned bytes) {
  switch (bytes) {
    case 1: op_rm({0x88}, src, dst, false, true); break;
    case 2: byte(0x66); op_rm({0x89}, src, dst, false); break;
    case 4: op_rm({0x89}, src, dst, false); break;
    default: op_rm({0x89}, src, dst, true); break;
  }
}

void Assembler::store_imm32(Mem dst, int32_t imm, bool w) {
  op_rm({0xC7}, 0, dst, w);
  dword(static_cast<uint32_t>(imm));
}

void Assembler::movzx8(Reg dst, Reg src) { op_rr({0x0F, 0xB6}, dst, src, false, true); }
void Assembler::movzx16(Reg dst, Reg src) { op_rr({0x0F, 0xB7}, dst, src, false); }
void Assembler::movsx8(Reg dst, Reg src) { op_rr({0x0F, 0xBE}, dst, src, true, true); }
void Assembler::movsx16(Reg dst, Reg src) { op_rr({0x0F, 0xBF}, dst, src, true); }
void Assembler::movsxd(Reg dst, Reg src) { op_rr({0x63}, dst, src, true); }
void Assembler::movzx8(Reg dst, Mem src) { op_rm({0x0F, 0xB6}, dst, src, false); }
void Assembler::movzx16(Reg dst, Mem src) { op_rm({0x0F, 0xB7}, dst, src, false); }
void Assembler::movsx8(Reg dst, Mem src) { op_rm({0x0F, 0xBE}, dst, src, true); }
void Assembler::movsx16(Reg dst, Mem src) { op_rm({0x0F, 0xBF}, dst, src, true); }
void Assembler::movsxd(Reg dst, Mem src) { op_rm({0x63}, dst, src, true); }

// --- arithmetic ------------------------------------------------------------------

void Assembler::alu(Alu op, Reg dst, Reg src, bool w) {
  op_rr({static_cast<uint8_t>(0x01 + 8 * static_cast<unsigned>(op))}, src, dst, w);
}

void Assembler::alu_imm(Alu op, Reg dst, int32_t imm, bool w) {
  if (imm >= -128 && imm <= 127) {
    op_rr({0x83}, static_cast<unsigned>(op), dst, w);
    byte(static_cast<uint8_t>(imm));
  } else {
    op_rr({0x81}, static_cast<unsigned>(op), dst, w);
    dword(static_cast<uint32_t>(imm));
  }
}

void Assembler::test(Reg a, Reg b, bool w) { op_rr({0x85}, b, a, w); }

void Assembler::shift_cl(Shift op, Reg r, bool w) { op_rr({0xD3}, static_cast<unsigned>(op), r, w); }

void Assembler::shift_imm(Shift op, Reg r, uint8_t amount, bool w) {
  if (amount == 1) {
    op_rr({0xD1}, static_cast<unsigned>(op), r, w);
  } else {
    op_rr({0xC1}, static_cast<unsigned>(op), r, w);
    byte(amount);
  }
}

void Assembler::imul(Reg dst, Reg src, bool w) { op_rr({0x0F, 0xAF}, dst, src, w); }
void Assembler::mul(Reg src, bool w) { op_rr({0xF7}, 4, src, w); }
void Assembler::imul1(Reg src, bool w) { op_rr({0xF7}, 5, src, w); }
void Assembler::div(Reg src, bool w) { op_rr({0xF7}, 6, src, w); }
void Assembler::idiv(Reg src, bool w) { op_rr({0xF7}, 7, src, w); }
void Assembler::not_(Reg r, bool w) { op_rr({0xF7}, 2, r, w); }
void Assembler::neg(Reg r, bool w) { op_rr({0xF7}, 3, r, w); }
void Assembler::cqo() { byte(0x48); byte(0x99); }
void Assembler::cdq() { byte(0x99); }

void Assembler::bswap(Reg r, bool w) {
  rex(w, 0, 0, r);
  byte(0x0F);
  byte(static_cast<uint8_t>(0xC8 + (r & 7)));
}

void Assembler::bsr(Reg dst, Reg src, bool w) { op_rr({0x0F, 0xBD}, dst, src, w); }

void Assembler::bt_imm(Reg r, uint8_t bit, bool w) {
  op_rr({0x0F, 0xBA}, 4, r, w);
  byte(bit);
}

void Assembler::bt(Reg base, Reg bit, bool w) { op_rr({0x0F, 0xA3}, bit, base, w); }
void Assembler::cmc() { byte(0xF5); }

void Assembler::setcc(Cond cc, Reg r8) {
  rex(false, 0, 0, r8, r8 >= 4 && r8 < 8);
  byte(0x0F);
  byte(static_cast<uint8_t>(0x90 + static_cast<unsigned>(cc)));
  modrm_reg(0, r8);
}

void Assembler::cmov(Cond cc, Reg dst, Reg src, bool w) {
  op_rr({0x0F, static_cast<uint8_t>(0x40 + static_cast<unsigned>(cc))}, dst, src, w);
}

void Assembler::lea(Reg dst, Mem src) { op_rm({0x8D}, dst, src, true); }

void Assembler::mfence() {
  byte(0x0F);
  byte(0xAE);
  byte(0xF0);
}

void Assembler::movsd_load(unsigned xmm, Mem src) {
  byte(0xF2);
  op_rm({0x0F, 0x10}, xmm, src, false);
}

void Assembler::movsd_store(Mem dst, unsigned xmm) {
  byte(0xF2);
  op_rm({0x0F, 0x11}, xmm, dst, false);
}

// --- control flow -------------------------------------------------------------------

void Assembler::push(Reg r) {
  rex(false, 0, 0, r);
  byte(static_cast<uint8_t>(0x50 + (r & 7)));
}

void Assembler::pop(Reg r) {
  rex(false, 0, 0, r);
  byte(static_cast<uint8_t>(0x58 + (r & 7)));
}

void Assembler::ret() { byte(0xC3); }

void Assembler::call(Reg target) { op_rr({0xFF}, 2, target, false); }

Assembler::Label Assembler::jmp() {
  byte(0xE9);
  Label l{code_.size()};
  dword(0);
  return l;
}

Assembler::Label Assembler::jcc(Cond cc) {
  byte(0x0F);
  byte(static_cast<uint8_t>(0x80 + static_cast<unsigned>(cc)));
  Label l{code_.size()};
  dword(0);
  return l;
}

void Assembler::bind(Label label) {
  int32_t rel = static_cast<int32_t>(code_.size() - (label.patch + 4));
  std::memcpy(&code_[label.patch], &rel, 4);
}

}  // namespace juice::x64
