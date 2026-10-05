#pragma once

// Minimal x86-64 machine code assembler used by the JIT backend.

#include <cstdint>
#include <vector>

namespace juice::x64 {

enum Reg : uint8_t {
  RAX = 0, RCX, RDX, RBX, RSP, RBP, RSI, RDI,
  R8, R9, R10, R11, R12, R13, R14, R15,
};

enum class Cond : uint8_t {
  O = 0, NO = 1, B = 2, AE = 3, E = 4, NE = 5, BE = 6, A = 7,
  S = 8, NS = 9, P = 10, NP = 11, L = 12, GE = 13, LE = 14, G = 15,
};

// Two-operand integer ALU operations, in x86 /digit order.
enum class Alu : uint8_t { Add = 0, Or = 1, Adc = 2, Sbb = 3, And = 4, Sub = 5, Xor = 6, Cmp = 7 };

// Shift/rotate operations, in x86 /digit order.
enum class Shift : uint8_t { Rol = 0, Ror = 1, Shl = 4, Shr = 5, Sar = 7 };

// Memory operand [base + disp].
struct Mem {
  Reg base;
  int32_t disp = 0;
};

class Assembler {
 public:
  struct Label {
    size_t patch = 0;  // offset of the rel32 field
  };

  const std::vector<uint8_t>& code() const { return code_; }
  size_t size() const { return code_.size(); }

  // Data movement. `w` selects 64-bit (true) or 32-bit (false) operation size.
  void mov(Reg dst, Reg src, bool w = true);
  void mov_imm(Reg dst, uint64_t imm);           // shortest encoding
  void load(Reg dst, Mem src, bool w = true);    // mov r, [m]
  void store(Mem dst, Reg src, unsigned bytes);  // mov [m], r (1/2/4/8 bytes)
  void store_imm32(Mem dst, int32_t imm, bool w);  // mov dword/qword [m], imm32
  void movzx8(Reg dst, Reg src);                 // movzx r32, r8
  void movzx16(Reg dst, Reg src);
  void movsx8(Reg dst, Reg src);                 // movsx r64, r8
  void movsx16(Reg dst, Reg src);
  void movsxd(Reg dst, Reg src);
  void movzx8(Reg dst, Mem src);                 // movzx r32, byte [m]
  void movzx16(Reg dst, Mem src);
  void movsx8(Reg dst, Mem src);                 // movsx r64, byte [m]
  void movsx16(Reg dst, Mem src);
  void movsxd(Reg dst, Mem src);

  // Arithmetic
  void alu(Alu op, Reg dst, Reg src, bool w = true);
  void alu_imm(Alu op, Reg dst, int32_t imm, bool w = true);
  void test(Reg a, Reg b, bool w = true);
  void shift_cl(Shift op, Reg r, bool w = true);
  void shift_imm(Shift op, Reg r, uint8_t amount, bool w = true);
  void imul(Reg dst, Reg src, bool w = true);  // dst *= src
  void mul(Reg src, bool w = true);            // rdx:rax = rax * src (unsigned)
  void imul1(Reg src, bool w = true);          // rdx:rax = rax * src (signed)
  void div(Reg src, bool w = true);
  void idiv(Reg src, bool w = true);
  void not_(Reg r, bool w = true);
  void neg(Reg r, bool w = true);
  void cqo();
  void cdq();
  void bswap(Reg r, bool w = true);
  void bsr(Reg dst, Reg src, bool w = true);
  void bt_imm(Reg r, uint8_t bit, bool w = true);
  void bt(Reg base, Reg bit, bool w = true);
  void cmc();
  void setcc(Cond cc, Reg r8);
  void cmov(Cond cc, Reg dst, Reg src, bool w = true);

  void lea(Reg dst, Mem src);
  void mfence();

  // SSE2 scalar double moves; `xmm` is the XMM register number (0-15).
  void movsd_load(unsigned xmm, Mem src);   // movsd xmm, [m]
  void movsd_store(Mem dst, unsigned xmm);  // movsd [m], xmm

  // Control flow
  void push(Reg r);
  void pop(Reg r);
  void ret();
  void call(Reg target);   // call r64
  Label jmp();             // forward jump, patched by bind()
  Label jcc(Cond cc);      // forward conditional jump
  void bind(Label label);  // resolve to the current position

 private:
  void byte(uint8_t b) { code_.push_back(b); }
  void dword(uint32_t v);
  void qword(uint64_t v);
  // REX prefix; `force` emits it even if empty (for SPL/BPL/SIL/DIL byte access).
  void rex(bool w, unsigned reg, unsigned index, unsigned base, bool force = false);
  void modrm_reg(unsigned reg, unsigned rm);
  void modrm_mem(unsigned reg, Mem m);
  // op r, r/m with register operand
  void op_rr(std::initializer_list<uint8_t> opcode, unsigned reg, unsigned rm, bool w, bool byte_regs = false);
  void op_rm(std::initializer_list<uint8_t> opcode, unsigned reg, Mem m, bool w, bool byte_reg = false);

  std::vector<uint8_t> code_;
};

}  // namespace juice::x64
