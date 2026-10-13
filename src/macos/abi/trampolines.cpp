#include "macos/abi/trampolines.hpp"

#include <cstddef>
#include <cstring>
#include <mutex>
#include <new>

#include "core/jit/x64/assembler.hpp"
#include "runtime/memory/exec_memory.hpp"

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
  uint64_t pad[2];  // (xmm 16-byte aligned)
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

void* install(const Assembler& a) {
  std::lock_guard lock(g_arena_mutex);
  void* code = arena().add(a.code());
  if (!code) throw std::bad_alloc();
  return code;
}

using CallFn = void (*)(RawCall*);

CallFn build_call() {
  Assembler a;
  a.push(RBP);
  a.mov(RBP, RSP);
  for (Reg r : {RBX, R12, R13, R14, R15}) a.push(r);
  int32_t saved = 40;
  if (kWin64) {
    // RDI, RSI and XMM6-15 are preserved on Windows but not by System V callees.
    a.push(RDI);
    a.push(RSI);
    a.alu_imm(Alu::Sub, RSP, 168);
    for (unsigned k = 0; k < 10; ++k) movdqu_store(a, Mem{RSP, static_cast<int32_t>(16 * k)}, 6 + k);
    saved = 56 + 168;
  }
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

  a.lea(RSP, Mem{RBP, -saved});
  if (kWin64) {
    for (unsigned k = 0; k < 10; ++k) movdqu_load(a, 6 + k, Mem{RSP, static_cast<int32_t>(16 * k)});
    a.alu_imm(Alu::Add, RSP, 168);
    a.pop(RSI);
    a.pop(RDI);
  }
  for (Reg r : {R15, R14, R13, R12, RBX}) a.pop(r);
  a.pop(RBP);
  a.ret();
  return reinterpret_cast<CallFn>(install(a));
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
  call_trampoline()(&raw);
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
  a.push(RBP);  // RSP is now 16-byte aligned
  a.mov(RBP, RSP);
  a.alu_imm(Alu::Sub, RSP, kFrame);
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
  return install(a);
}

}  // namespace juice::mac
