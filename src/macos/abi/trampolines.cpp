#include "macos/abi/trampolines.hpp"

#include <cstddef>
#include <cstring>
#include <mutex>
#include <new>
#include <vector>

#include "core/jit/x64/assembler.hpp"
#include "runtime/memory/exec_memory.hpp"

#if defined(_WIN32)
#include <windows.h>
#else
extern "C" void __register_frame(const void* fde);
#endif

namespace juice::mac {

namespace {

using namespace juice::x64;

#if defined(_WIN32)
constexpr bool kWin64 = true;  // the host's own convention (tests on Windows)
constexpr Reg kArg0 = RCX;
#else
constexpr bool kWin64 = false;
constexpr Reg kArg0 = RDI;
#endif

// What the call trampoline reads and writes (offsets used by the code).
struct RawCall {
  uint64_t fn;
  uint64_t gpr[6];
  uint64_t rax, r12, r13, r14;
  uint64_t stack;  // const uint64_t*
  uint64_t words;  // even
  uint64_t x87;
  uint64_t exception;  // set by the landing pad: the exception that unwound the call
  uint64_t pad;        // (xmm 16-byte aligned)
  Vec128 xmm[8];
  uint64_t out_rax, out_rdx, out_rcx, out_r8, out_r12, out_pad;
  Vec128 out_xmm[4];
  uint8_t st0[16];
};

// What the entry trampoline captures and returns.
struct RawEntry {
  uint64_t gpr[6];
  uint64_t rax, r12, r13, r14, r11;
  uint64_t stack;    // RSP + 8 at entry
  uint64_t handler;  // EntryHandler
  uint64_t x87;
  Vec128 xmm[8];
  uint64_t out_rax, out_rdx, out_rcx, out_r8, out_r12, out_pad;
  Vec128 out_xmm[4];
  uint8_t st0[16];
};

constexpr int32_t off(size_t o) { return static_cast<int32_t>(o); }

void movdqu_load(Assembler& a, unsigned xmm, Mem m) { a.sse(0xF3, {0x6F}, xmm, m); }
void movdqu_store(Assembler& a, Mem m, unsigned xmm) { a.sse(0xF3, {0x7F}, xmm, m); }

// fld / fstp tbyte [base + disp32] (base RBX or R11).
void x87_mem(Assembler& a, unsigned reg_field, Reg base, int32_t disp) {
  if (base >= 8) a.imm8(0x41);
  a.imm8(0xDB);
  a.imm8(static_cast<uint8_t>(0x80 | reg_field << 3 | (base & 7)));
  for (int k = 0; k < 4; ++k) a.imm8(static_cast<uint8_t>(static_cast<uint32_t>(disp) >> (8 * k)));
}

runtime::CodeArena& arena() {
  static runtime::CodeArena a(size_t{1} << 20);
  return a;
}
std::mutex g_arena_mutex;
void* g_call_personality = nullptr;
void* g_call_landing_pad = nullptr;

// --- Unwind information ------------------------------------------------------------------------
//
// Exceptions pass through the trampolines: native code's (and, on Windows,
// the tests' C++ exceptions) through the call trampoline to its landing pad,
// and those JUICE raises again through the entry trampoline into native code.

// A record of the prologue for the unwind information: after `offset` bytes,
// what has happened.
struct PrologueStep {
  enum Kind { PushReg, SetFrame, Alloc, SaveXmm } kind;
  uint8_t offset;  // code offset after the instruction
  uint8_t reg;     // x86 register number (PushReg, SetFrame: RBP), XMM number (SaveXmm)
  uint32_t value;  // Alloc: bytes; SaveXmm: offset from RSP
};

#if defined(_WIN32)

// UNWIND_INFO (version 1) for the steps, appended to the code.
std::vector<uint8_t> win64_unwind_info(const std::vector<PrologueStep>& steps, uint8_t prologue_size) {
  std::vector<uint16_t> codes;  // latest first
  uint8_t frame_register = 0;
  for (auto it = steps.rbegin(); it != steps.rend(); ++it) {
    auto code = [&](uint8_t op, uint8_t info) {
      codes.push_back(static_cast<uint16_t>(it->offset | (op | info << 4) << 8));
    };
    switch (it->kind) {
      case PrologueStep::PushReg: code(0, it->reg); break;  // UWOP_PUSH_NONVOL
      case PrologueStep::SetFrame:
        code(3, 0);  // UWOP_SET_FPREG (offset 0)
        frame_register = it->reg;
        break;
      case PrologueStep::Alloc:
        if (it->value <= 128) {
          code(2, static_cast<uint8_t>(it->value / 8 - 1));  // UWOP_ALLOC_SMALL
        } else {
          code(1, 0);  // UWOP_ALLOC_LARGE, size / 8 in the next slot
          codes.push_back(static_cast<uint16_t>(it->value / 8));
        }
        break;
      case PrologueStep::SaveXmm:
        code(8, it->reg);  // UWOP_SAVE_XMM128, offset / 16 in the next slot
        codes.push_back(static_cast<uint16_t>(it->value / 16));
        break;
    }
  }
  const auto count = static_cast<uint8_t>(codes.size());
  if (codes.size() % 2) codes.push_back(0);  // (the array has an even number of slots)
  std::vector<uint8_t> info = {1, prologue_size, count, static_cast<uint8_t>(frame_register)};
  for (uint16_t c : codes) {
    info.push_back(static_cast<uint8_t>(c));
    info.push_back(static_cast<uint8_t>(c >> 8));
  }
  return info;
}

void* install(const Assembler& a, const std::vector<PrologueStep>& steps, uint8_t prologue_size) {
  std::vector<uint8_t> blob = a.code();
  const size_t unwind_at = (blob.size() + 3) & ~size_t{3};
  blob.resize(unwind_at, 0xCC);
  const std::vector<uint8_t> info = win64_unwind_info(steps, prologue_size);
  blob.insert(blob.end(), info.begin(), info.end());
  void* code;
  {
    std::lock_guard lock(g_arena_mutex);
    code = arena().add(blob);
  }
  if (!code) throw std::bad_alloc();
  auto* function = new RUNTIME_FUNCTION{};
  function->BeginAddress = 0;
  function->EndAddress = static_cast<DWORD>(a.size());
  function->UnwindData = static_cast<DWORD>(unwind_at);
  RtlAddFunctionTable(function, 1, reinterpret_cast<DWORD64>(code));
  return code;
}

#else

void uleb(std::vector<uint8_t>& out, uint64_t v) {
  do {
    uint8_t b = v & 0x7F;
    v >>= 7;
    out.push_back(static_cast<uint8_t>(b | (v ? 0x80 : 0)));
  } while (v);
}

void u32(std::vector<uint8_t>& out, uint32_t v) {
  for (int k = 0; k < 4; ++k) out.push_back(static_cast<uint8_t>(v >> (8 * k)));
}
void u64(std::vector<uint8_t>& out, uint64_t v) {
  for (int k = 0; k < 8; ++k) out.push_back(static_cast<uint8_t>(v >> (8 * k)));
}

// x86-64 DWARF register numbers.
uint8_t dwarf_register(uint8_t reg) {
  static constexpr uint8_t kMap[16] = {0, 2, 1, 3, 7, 6, 4, 5, 8, 9, 10, 11, 12, 13, 14, 15};
  return kMap[reg & 15];
}

// A CIE and an FDE for code at [begin, begin + size) (a .eh_frame of one
// function, zero terminated) from the prologue steps; `personality` (if any)
// is called for exceptions unwinding through it.
std::vector<uint8_t> dwarf_unwind_info(uint64_t begin, uint64_t size, const std::vector<PrologueStep>& steps,
                                       void* personality, size_t& fde_offset) {
  std::vector<uint8_t> out;
  auto record = [&](std::vector<uint8_t> body) {
    while ((body.size() + 4) % 8) body.push_back(0);  // DW_CFA_nop padding
    u32(out, static_cast<uint32_t>(body.size()));
    out.insert(out.end(), body.begin(), body.end());
  };
  // CIE: code alignment 1, data alignment -8, return address in r16 (RIP).
  std::vector<uint8_t> cie;
  u32(cie, 0);
  cie.push_back(1);
  const char* augmentation = personality ? "zPR" : "zR";
  for (const char* c = augmentation; *c; ++c) cie.push_back(static_cast<uint8_t>(*c));
  cie.push_back(0);
  uleb(cie, 1);
  cie.push_back(0x78);  // -8
  cie.push_back(16);
  std::vector<uint8_t> augmentation_data;
  if (personality) {
    augmentation_data.push_back(0x00);  // absolute pointer
    u64(augmentation_data, reinterpret_cast<uint64_t>(personality));
  }
  augmentation_data.push_back(0x00);  // FDE pointers: absolute
  uleb(cie, augmentation_data.size());
  cie.insert(cie.end(), augmentation_data.begin(), augmentation_data.end());
  cie.insert(cie.end(), {0x0C, 7, 8, 0x80 | 16, 1});  // CFA = RSP + 8; RIP at CFA - 8
  record(cie);

  fde_offset = out.size();
  std::vector<uint8_t> fde;
  u32(fde, static_cast<uint32_t>(fde_offset + 4));  // back to the CIE
  u64(fde, begin);
  u64(fde, size);
  uleb(fde, 0);  // no augmentation data
  uint64_t cfa_offset = 8, location = 0;
  for (const PrologueStep& s : steps) {
    const uint64_t delta = s.offset - location;
    location = s.offset;
    if (delta < 64) fde.push_back(static_cast<uint8_t>(0x40 | delta));
    else fde.insert(fde.end(), {0x02, static_cast<uint8_t>(delta)});
    switch (s.kind) {
      case PrologueStep::PushReg:
        cfa_offset += 8;
        fde.push_back(0x0E);  // def_cfa_offset
        uleb(fde, cfa_offset);
        fde.push_back(static_cast<uint8_t>(0x80 | dwarf_register(s.reg)));  // offset
        uleb(fde, cfa_offset / 8);
        break;
      case PrologueStep::SetFrame:
        fde.push_back(0x0D);  // def_cfa_register: the CFA stays where it is
        uleb(fde, dwarf_register(s.reg));
        break;
      case PrologueStep::Alloc:
      case PrologueStep::SaveXmm:
        break;  // (only after the frame register is set: the CFA doesn't move)
    }
  }
  record(fde);
  u32(out, 0);
  return out;
}

void* install(const Assembler& a, const std::vector<PrologueStep>& steps, void* personality) {
  void* code;
  {
    std::lock_guard lock(g_arena_mutex);
    code = arena().add(a.code());
  }
  if (!code) throw std::bad_alloc();
  size_t fde_offset = 0;
  auto* table = new std::vector<uint8_t>(
      dwarf_unwind_info(reinterpret_cast<uint64_t>(code), a.size(), steps, personality, fde_offset));
#if defined(__APPLE__)
  __register_frame(table->data() + fde_offset);  // (Apple's libunwind registers one FDE)
#else
  __register_frame(table->data());  // (libgcc registers a whole .eh_frame)
#endif
  return code;
}

#endif

using CallFn = void (*)(RawCall*);

CallFn build_call() {
  Assembler a;
  std::vector<PrologueStep> steps;
  auto pushed = [&](Reg r) {
    a.push(r);
    steps.push_back({PrologueStep::PushReg, static_cast<uint8_t>(a.size()), r, 0});
  };
  for (Reg r : {RBP, RBX, R12, R13, R14, R15}) pushed(r);
  if (kWin64) {
    // RDI, RSI and XMM6-15 are preserved on Windows but not by System V callees.
    pushed(RDI);
    pushed(RSI);
    a.alu_imm(Alu::Sub, RSP, 168);
    steps.push_back({PrologueStep::Alloc, static_cast<uint8_t>(a.size()), 0, 168});
    for (unsigned k = 0; k < 10; ++k) {
      movdqu_store(a, Mem{RSP, static_cast<int32_t>(16 * k)}, 6 + k);
      steps.push_back({PrologueStep::SaveXmm, static_cast<uint8_t>(a.size()), static_cast<uint8_t>(6 + k), 16 * k});
    }
  }
  a.mov(RBP, RSP);  // the frame: RSP changes below, by the stack arguments
  steps.push_back({PrologueStep::SetFrame, static_cast<uint8_t>(a.size()), RBP, 0});
  const auto prologue_size = static_cast<uint8_t>(a.size());
  a.mov(RBX, kArg0);

  // Copy the stack arguments to [RSP], 16-byte aligned.
  a.load(RCX, Mem{RBX, off(offsetof(RawCall, words))});
  a.mov(RAX, RCX);
  a.shift_imm(Shift::Shl, RAX, 3);
  a.alu(Alu::Sub, RSP, RAX);
  a.alu_imm(Alu::And, RSP, -16);
  a.load(RSI, Mem{RBX, off(offsetof(RawCall, stack))});
  a.mov(RDI, RSP);
  const size_t loop = a.size();
  a.test(RCX, RCX);
  auto done = a.jcc(Cond::E);
  a.load(RAX, Mem{RSI, 0});
  a.store(Mem{RDI, 0}, RAX, 8);
  a.alu_imm(Alu::Add, RSI, 8);
  a.alu_imm(Alu::Add, RDI, 8);
  a.alu_imm(Alu::Sub, RCX, 1);
  a.jmp_to(loop);
  a.bind(done);

  for (unsigned k = 0; k < 8; ++k) movdqu_load(a, k, Mem{RBX, off(offsetof(RawCall, xmm) + 16 * k)});
  const Reg gprs[6] = {RDI, RSI, RDX, RCX, R8, R9};
  for (int k = 0; k < 6; ++k) a.load(gprs[k], Mem{RBX, off(offsetof(RawCall, gpr) + 8 * k)});
  a.load(R12, Mem{RBX, off(offsetof(RawCall, r12))});
  a.load(R13, Mem{RBX, off(offsetof(RawCall, r13))});
  a.load(R14, Mem{RBX, off(offsetof(RawCall, r14))});
  a.load(R11, Mem{RBX, off(offsetof(RawCall, fn))});
  a.load(RAX, Mem{RBX, off(offsetof(RawCall, rax))});
  a.call(R11);

  a.store(Mem{RBX, off(offsetof(RawCall, out_rax))}, RAX, 8);
  a.store(Mem{RBX, off(offsetof(RawCall, out_rdx))}, RDX, 8);
  a.store(Mem{RBX, off(offsetof(RawCall, out_rcx))}, RCX, 8);
  a.store(Mem{RBX, off(offsetof(RawCall, out_r8))}, R8, 8);
  a.store(Mem{RBX, off(offsetof(RawCall, out_r12))}, R12, 8);
  for (unsigned k = 0; k < 4; ++k) movdqu_store(a, Mem{RBX, off(offsetof(RawCall, out_xmm) + 16 * k)}, k);
  a.load(RCX, Mem{RBX, off(offsetof(RawCall, x87))});
  a.test(RCX, RCX);
  auto no_x87 = a.jcc(Cond::E);
  x87_mem(a, 7, RBX, off(offsetof(RawCall, st0)));  // fstp tbyte
  a.bind(no_x87);

  const size_t epilogue = a.size();
  a.mov(RSP, RBP);
  if (kWin64) {
    for (unsigned k = 0; k < 10; ++k) movdqu_load(a, 6 + k, Mem{RSP, static_cast<int32_t>(16 * k)});
    a.alu_imm(Alu::Add, RSP, 168);
    a.pop(RSI);
    a.pop(RDI);
  }
  for (Reg r : {R15, R14, R13, R12, RBX, RBP}) a.pop(r);
  a.ret();

  // The landing pad for exceptions unwinding the call (macOS: the
  // personality sends them here with RAX = the exception; RBX and RBP are
  // the frame's again).
  const size_t landing = a.size();
  a.store(Mem{RBX, off(offsetof(RawCall, exception))}, RAX, 8);
  a.jmp_to(epilogue);

#if defined(_WIN32)
  void* code = install(a, steps, prologue_size);
#else
  (void)prologue_size;
  void* code = install(a, steps, g_call_personality);
#endif
  g_call_landing_pad = static_cast<uint8_t*>(code) + landing;
  return reinterpret_cast<CallFn>(code);
}

CallFn call_trampoline() {
  static const CallFn fn = build_call();
  return fn;
}

// Called by every entry trampoline with its frame.
void dispatch_entry(RawEntry* raw) {
  EntryFrame frame;
  for (int k = 0; k < 6; ++k) frame.args.gpr[k] = raw->gpr[k];
  for (int k = 0; k < 8; ++k) frame.args.xmm[k] = raw->xmm[k];
  frame.args.stack = reinterpret_cast<const uint64_t*>(raw->stack);
  frame.args.al = raw->rax & 0xFF;
  frame.args.rax = raw->rax;
  frame.args.r12 = raw->r12;
  frame.args.r13 = raw->r13;
  frame.args.r14 = raw->r14;
  frame.target = raw->r11;
  frame.result.r12 = raw->r12;  // preserved unless the handler returns a Swift error
  reinterpret_cast<EntryHandler>(raw->handler)(frame);
  raw->out_rax = frame.result.rax;
  raw->out_rdx = frame.result.rdx;
  raw->out_rcx = frame.result.rcx;
  raw->out_r8 = frame.result.r8;
  raw->out_r12 = frame.result.r12;
  for (int k = 0; k < 4; ++k) raw->out_xmm[k] = frame.result.xmm[k];
  std::memcpy(raw->st0, frame.result.st0, sizeof(raw->st0));
  raw->x87 = frame.x87_result;
}

}  // namespace

void set_call_personality(void* personality) { g_call_personality = personality; }

void* call_landing_pad() {
  call_trampoline();
  return g_call_landing_pad;
}

void call_native(void* fn, HostCall& call, HostResult& result, bool x87_result) {
  RawCall raw{};
  raw.fn = reinterpret_cast<uint64_t>(fn);
  for (int k = 0; k < 6; ++k) raw.gpr[k] = call.gpr[k];
  for (int k = 0; k < 8; ++k) raw.xmm[k] = call.xmm[k];
  raw.rax = call.rax;
  raw.r12 = call.r12;
  raw.r13 = call.r13;
  raw.r14 = call.r14;
  if (call.stack.size() % 2) call.stack.push_back(0);
  raw.stack = reinterpret_cast<uint64_t>(call.stack.data());
  raw.words = call.stack.size();
  raw.x87 = x87_result;
  result.exception = 0;
  try {
    call_trampoline()(&raw);
  } catch (const NativeException& e) {  // (the Windows tests' native exceptions)
    result.exception = e.object;
    return;
  }
  if (raw.exception) {
    result.exception = raw.exception;
    return;
  }
  result.rax = raw.out_rax;
  result.rdx = raw.out_rdx;
  result.rcx = raw.out_rcx;
  result.r8 = raw.out_r8;
  result.r12 = raw.out_r12;
  for (int k = 0; k < 4; ++k) result.xmm[k] = raw.out_xmm[k];
  if (x87_result) std::memcpy(result.st0, raw.st0, 10);
}

void* native_entry(EntryHandler handler) {
  constexpr int32_t kShadow = kWin64 ? 32 : 0;
  constexpr int32_t kFrame = static_cast<int32_t>((sizeof(RawEntry) + 15) & ~size_t{15}) + kShadow;
  static_assert(((sizeof(RawEntry) + 15) & ~size_t{15}) % 16 == 0);
  auto at = [](size_t field) { return Mem{RSP, kShadow + off(field)}; };

  Assembler a;
  std::vector<PrologueStep> steps;
  a.push(RBP);  // RSP is now 16-byte aligned
  steps.push_back({PrologueStep::PushReg, static_cast<uint8_t>(a.size()), RBP, 0});
  a.mov(RBP, RSP);
  if (!kWin64) steps.push_back({PrologueStep::SetFrame, static_cast<uint8_t>(a.size()), RBP, 0});
  a.alu_imm(Alu::Sub, RSP, kFrame);
  if (kWin64) steps.push_back({PrologueStep::Alloc, static_cast<uint8_t>(a.size()), 0, kFrame});
  const auto prologue_size = static_cast<uint8_t>(a.size());
  a.store(at(offsetof(RawEntry, rax)), RAX, 8);
  const Reg gprs[6] = {RDI, RSI, RDX, RCX, R8, R9};
  for (int k = 0; k < 6; ++k) a.store(at(offsetof(RawEntry, gpr) + 8 * k), gprs[k], 8);
  a.store(at(offsetof(RawEntry, r12)), R12, 8);
  a.store(at(offsetof(RawEntry, r13)), R13, 8);
  a.store(at(offsetof(RawEntry, r14)), R14, 8);
  a.store(at(offsetof(RawEntry, r11)), R11, 8);
  for (unsigned k = 0; k < 8; ++k) movdqu_store(a, at(offsetof(RawEntry, xmm) + 16 * k), k);
  a.lea(RAX, Mem{RBP, 16});
  a.store(at(offsetof(RawEntry, stack)), RAX, 8);
  a.mov_imm(RAX, reinterpret_cast<uint64_t>(handler));
  a.store(at(offsetof(RawEntry, handler)), RAX, 8);
  a.lea(kArg0, at(0));
  a.mov_imm(RAX, reinterpret_cast<uint64_t>(&dispatch_entry));
  a.call(RAX);

  a.lea(R11, at(0));
  a.load(RAX, Mem{R11, off(offsetof(RawEntry, out_rax))});
  a.load(RDX, Mem{R11, off(offsetof(RawEntry, out_rdx))});
  a.load(RCX, Mem{R11, off(offsetof(RawEntry, out_rcx))});
  a.load(R8, Mem{R11, off(offsetof(RawEntry, out_r8))});
  a.load(R12, Mem{R11, off(offsetof(RawEntry, out_r12))});
  for (unsigned k = 0; k < 4; ++k) movdqu_load(a, k, Mem{R11, off(offsetof(RawEntry, out_xmm) + 16 * k)});
  a.load(R10, Mem{R11, off(offsetof(RawEntry, x87))});
  a.test(R10, R10);
  auto no_x87 = a.jcc(Cond::E);
  x87_mem(a, 5, R11, off(offsetof(RawEntry, st0)));  // fld tbyte
  a.bind(no_x87);
  a.mov(RSP, RBP);
  a.pop(RBP);
  a.ret();
#if defined(_WIN32)
  return install(a, steps, prologue_size);
#else
  (void)prologue_size;
  return install(a, steps, nullptr);
#endif
}

}  // namespace juice::mac
