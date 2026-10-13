#include "macos/abi/call_convert.hpp"

#include <algorithm>
#include <cmath>
#include <cstring>
#include <format>

namespace juice::mac {

namespace {

using Kind = CType::Kind;

uint64_t align_up(uint64_t v, uint64_t a) { return (v + a - 1) / a * a; }

// Where part of a value lives on one side of a call.
enum class Where : uint8_t {
  Gpr,            // general register `index`, from byte `reg_offset`
  Fpr,            // vector register `index`, from byte `reg_offset`
  Stack,          // the stack argument area, at byte `index`
  IndirectGpr,    // in memory at the pointer in general register `index` (guest: composites > 16 bytes)
  IndirectStack,  // in memory at the pointer at stack byte `index`
  X87Stack,       // host: a long double, as an x87 value at stack byte `index`
  X87,            // host: a long double result in ST0
  Memory,         // a result in memory (at X8 / the hidden pointer)
};

struct Piece {
  Where where;
  uint32_t index = 0;
  uint32_t reg_offset = 0;
  uint32_t value_offset = 0;  // within the value
  uint32_t size = 0;
};

using Pieces = std::vector<Piece>;

bool scalar_int(const CType& t) { return t.is_integer() && t.size <= 8; }

// Sign or zero extends an integer of t.size bytes at `v` to 8 bytes.
void extend(const CType& t, uint8_t* v) {
  if (!scalar_int(t) || t.size >= 8) return;
  uint64_t x = 0;
  std::memcpy(&x, v, t.size);
  const unsigned bits = t.size * 8;
  if (t.kind == Kind::Int && (x >> (bits - 1)) & 1) x |= ~uint64_t{0} << bits;
  std::memcpy(v, &x, 8);
}

// --- Apple ARM64 placement ---------------------------------------------------------------

struct GuestAlloc {
  unsigned ngrn = 0, nsrn = 0;
  uint64_t nsaa = 0;

  Piece stack(uint32_t size, uint64_t align, uint32_t value_offset = 0) {
    nsaa = align_up(nsaa, align);
    Piece p{Where::Stack, static_cast<uint32_t>(nsaa), 0, value_offset, size};
    nsaa += size;
    return p;
  }

  Pieces place(const CType& t, bool variadic) {
    const bool aggregate = t.is_aggregate();
    if (variadic) {
      // One (or two, for 16-byte scalars) 8-byte slots; composites > 16 bytes by reference.
      if (aggregate && t.size > 16) {
        nsaa = align_up(nsaa, 8);
        Piece p{Where::IndirectStack, static_cast<uint32_t>(nsaa), 0, 0, t.size};
        nsaa += 8;
        return {p};
      }
      const uint64_t align = t.align >= 16 ? 16 : 8;
      Piece p = stack(t.size, align);
      nsaa = align_up(nsaa, 8);
      if (scalar_int(t)) p.size = t.size;
      return {p};
    }
    switch (t.kind) {
      case Kind::Int:
      case Kind::UInt:
      case Kind::Pointer:
        if (t.size == 16) {
          ngrn = static_cast<unsigned>(align_up(ngrn, 2));
          if (ngrn < 7) {
            ngrn += 2;
            return {{Where::Gpr, ngrn - 2, 0, 0, 8}, {Where::Gpr, ngrn - 1, 0, 8, 8}};
          }
          ngrn = 8;
          return {stack(16, 16)};
        }
        if (ngrn < 8) return {{Where::Gpr, ngrn++, 0, 0, 8}};
        return {stack(t.size, t.size)};
      case Kind::Float:
      case Kind::Double:
      case Kind::LongDouble:
      case Kind::Vector:
        if (nsrn < 8) return {{Where::Fpr, nsrn++, 0, 0, t.size}};
        return {stack(t.size, t.size)};
      default:
        break;
    }
    if (t.size == 0) return {};
    Kind base;
    unsigned members;
    uint32_t member_size;
    if (is_hfa(t, base, members, member_size)) {
      if (nsrn + members <= 8) {
        Pieces p;
        for (unsigned k = 0; k < members; ++k) p.push_back({Where::Fpr, nsrn++, 0, k * member_size, member_size});
        return p;
      }
      nsrn = 8;
      return {stack(t.size, t.align)};
    }
    if (t.size > 16) {
      if (ngrn < 8) return {{Where::IndirectGpr, ngrn++, 0, 0, t.size}};
      nsaa = align_up(nsaa, 8);
      Piece p{Where::IndirectStack, static_cast<uint32_t>(nsaa), 0, 0, t.size};
      nsaa += 8;
      return {p};
    }
    const unsigned regs = (t.size + 7) / 8;
    if (t.align >= 16) ngrn = static_cast<unsigned>(align_up(ngrn, 2));
    if (ngrn + regs <= 8) {
      Pieces p;
      for (unsigned k = 0; k < regs; ++k) p.push_back({Where::Gpr, ngrn++, 0, k * 8, std::min<uint32_t>(8, t.size - k * 8)});
      return p;
    }
    ngrn = 8;
    Piece p = stack(t.size, std::max<uint64_t>(8, t.align));
    nsaa = align_up(nsaa, 8);
    return {p};
  }
};

Pieces guest_result_pieces(const CType& t) {
  switch (t.kind) {
    case Kind::Void: return {};
    case Kind::Int:
    case Kind::UInt:
    case Kind::Pointer:
      if (t.size == 16) return {{Where::Gpr, 0, 0, 0, 8}, {Where::Gpr, 1, 0, 8, 8}};
      return {{Where::Gpr, 0, 0, 0, 8}};
    case Kind::Float:
    case Kind::Double:
    case Kind::LongDouble:
    case Kind::Vector:
      return {{Where::Fpr, 0, 0, 0, t.size}};
    default:
      break;
  }
  Kind base;
  unsigned members;
  uint32_t member_size;
  if (is_hfa(t, base, members, member_size)) {
    Pieces p;
    for (unsigned k = 0; k < members; ++k) p.push_back({Where::Fpr, k, 0, k * member_size, member_size});
    return p;
  }
  if (t.size > 16) return {{Where::Memory, 8, 0, 0, t.size}};
  Pieces p;
  for (unsigned k = 0; k * 8 < t.size; ++k) p.push_back({Where::Gpr, k, 0, k * 8, std::min<uint32_t>(8, t.size - k * 8)});
  return p;
}

// --- x86-64 System V placement -----------------------------------------------------------

enum class Cls : uint8_t { None, Integer, Sse, SseUp, Memory };

Cls merge(Cls a, Cls b) {
  if (a == b) return a;
  if (a == Cls::None) return b;
  if (b == Cls::None) return a;
  if (a == Cls::Memory || b == Cls::Memory) return Cls::Memory;
  if (a == Cls::Integer || b == Cls::Integer) return Cls::Integer;
  return Cls::Sse;
}

bool classify(const CType& t, uint32_t offset, Cls cls[2]) {
  auto leaf = [&](Cls c) {
    if (t.align && offset % t.align) return false;  // unaligned: memory
    const uint32_t first = offset / 8, last = (offset + t.size - 1) / 8;
    if (last > 1) return false;
    for (uint32_t k = first; k <= last; ++k) cls[k] = merge(cls[k], c);
    return true;
  };
  switch (t.kind) {
    case Kind::Int:
    case Kind::UInt:
    case Kind::Pointer:
      return leaf(Cls::Integer);
    case Kind::Float:
    case Kind::Double:
      return leaf(Cls::Sse);
    case Kind::Vector:
      if (t.size == 16) {
        if (offset != 0) return false;
        cls[0] = merge(cls[0], Cls::Sse);
        cls[1] = Cls::SseUp;
        return true;
      }
      return leaf(Cls::Sse);
    case Kind::LongDouble:
      return false;
    case Kind::Struct:
      for (size_t k = 0; k < t.fields.size(); ++k)
        if (!classify(t.fields[k], offset + t.offsets[k], cls)) return false;
      return true;
    case Kind::Union:
      for (const CType& f : t.fields)
        if (!classify(f, offset, cls)) return false;
      return true;
    case Kind::Array:
      for (uint32_t k = 0; k < t.count; ++k)
        if (!classify(t.fields[0], offset + k * t.fields[0].size, cls)) return false;
      return true;
    default:
      return false;
  }
}

// The eightbyte classes of an aggregate, false if it goes in memory.
bool host_classes(const CType& t, Cls cls[2]) {
  cls[0] = cls[1] = Cls::None;
  if (t.size > 16 || t.size == 0) return false;
  if (!classify(t, 0, cls)) return false;
  if (cls[0] == Cls::Memory || cls[1] == Cls::Memory) return false;
  if (cls[1] == Cls::SseUp && cls[0] != Cls::Sse) cls[1] = Cls::Sse;
  return true;
}

struct HostAlloc {
  unsigned gprs = 0, sses = 0;
  uint64_t stack_bytes = 0;

  Piece stack(uint32_t size, uint64_t align) {
    stack_bytes = align_up(stack_bytes, align);
    Piece p{Where::Stack, static_cast<uint32_t>(stack_bytes), 0, 0, size};
    stack_bytes = align_up(stack_bytes + size, 8);
    return p;
  }

  Pieces place(const CType& t) {
    switch (t.kind) {
      case Kind::Int:
      case Kind::UInt:
      case Kind::Pointer:
        if (t.size == 16) {
          if (gprs + 2 <= 6) {
            gprs += 2;
            return {{Where::Gpr, gprs - 2, 0, 0, 8}, {Where::Gpr, gprs - 1, 0, 8, 8}};
          }
          return {stack(16, 16)};
        }
        if (gprs < 6) return {{Where::Gpr, gprs++, 0, 0, 8}};
        return {stack(8, 8)};
      case Kind::Float:
      case Kind::Double:
      case Kind::Vector:
        if (sses < 8) return {{Where::Fpr, sses++, 0, 0, t.size}};
        return {stack(t.size, t.size >= 16 ? 16 : 8)};
      case Kind::LongDouble: {
        Piece p = stack(16, 16);
        p.where = Where::X87Stack;
        return {p};
      }
      default:
        break;
    }
    if (t.size == 0) return {};
    Cls cls[2];
    if (host_classes(t, cls)) {
      unsigned need_gpr = 0, need_sse = 0;
      for (unsigned k = 0; k * 8 < t.size; ++k) {
        if (cls[k] == Cls::Integer) ++need_gpr;
        else if (cls[k] == Cls::Sse) ++need_sse;
      }
      if (gprs + need_gpr <= 6 && sses + need_sse <= 8) {
        Pieces p;
        for (unsigned k = 0; k * 8 < t.size; ++k) {
          const uint32_t size = std::min<uint32_t>(8, t.size - k * 8);
          if (cls[k] == Cls::Integer) p.push_back({Where::Gpr, gprs++, 0, k * 8, size});
          else if (cls[k] == Cls::Sse) p.push_back({Where::Fpr, sses++, 0, k * 8, size});
          else if (cls[k] == Cls::SseUp) p.push_back({Where::Fpr, sses - 1, 8, k * 8, size});
        }
        return p;
      }
    }
    return {stack(t.size, t.align >= 16 ? 16 : 8)};
  }
};

// Host result placement; `memory` reports a result returned through the hidden pointer.
Pieces host_result_pieces(const CType& t, bool& memory) {
  memory = false;
  switch (t.kind) {
    case Kind::Void: return {};
    case Kind::Int:
    case Kind::UInt:
    case Kind::Pointer:
      if (t.size == 16) return {{Where::Gpr, 0, 0, 0, 8}, {Where::Gpr, 1, 0, 8, 8}};
      return {{Where::Gpr, 0, 0, 0, 8}};
    case Kind::Float:
    case Kind::Double:
    case Kind::Vector:
      return {{Where::Fpr, 0, 0, 0, t.size}};
    case Kind::LongDouble:
      return {{Where::X87, 0, 0, 0, 8}};
    default:
      break;
  }
  Cls cls[2];
  if (!host_classes(t, cls)) {
    memory = true;
    return {{Where::Memory, 0, 0, 0, t.size}};
  }
  Pieces p;
  unsigned gpr = 0, sse = 0;
  for (unsigned k = 0; k * 8 < t.size; ++k) {
    const uint32_t size = std::min<uint32_t>(8, t.size - k * 8);
    if (cls[k] == Cls::Integer) p.push_back({Where::Gpr, gpr++, 0, k * 8, size});
    else if (cls[k] == Cls::Sse) p.push_back({Where::Fpr, sse++, 0, k * 8, size});
    else if (cls[k] == Cls::SseUp) p.push_back({Where::Fpr, sse - 1, 8, k * 8, size});
  }
  return p;
}

// --- Moving bytes ------------------------------------------------------------------------

// A value being converted: the guest's representation (long double as a double).
struct Value {
  std::vector<uint8_t> bytes;
  explicit Value(const CType& t) : bytes(std::max<size_t>(16, align_up(t.size, 8)), 0) {}
  uint8_t* at(uint32_t offset) { return bytes.data() + offset; }
};

void* host_pointer(uint64_t addr) { return reinterpret_cast<void*>(static_cast<uintptr_t>(addr)); }

const uint64_t* host_reg(const HostResult& r, unsigned index) {
  switch (index) {
    case 0: return &r.rax;
    case 1: return &r.rdx;
    case 2: return &r.rcx;
    default: return &r.r8;
  }
}

}  // namespace

// --- Guest calls native -------------------------------------------------------------------

std::expected<void, std::string> guest_args_to_host(const FunctionType& f, const arm64::CpuState& s, HostCall& out,
                                                    unsigned variadic_words) {
  GuestAlloc guest;
  HostAlloc host;
  bool memory_result = false;
  host_result_pieces(f.ret, memory_result);
  if (memory_result) {
    // The hidden pointer: the guest's X8 if it returns in memory too, else a buffer here.
    const bool guest_memory = !guest_result_pieces(f.ret).empty() && guest_result_pieces(f.ret)[0].where == Where::Memory;
    if (!guest_memory && f.ret.size > sizeof(out.result_buffer)) return std::unexpected("result too large");
    out.gpr[host.gprs++] = guest_memory ? s.x[8] : reinterpret_cast<uint64_t>(out.result_buffer);
  }
  auto stack_word = [&](uint64_t offset, size_t size) -> uint8_t* {
    const size_t words = (offset + size + 7) / 8;
    if (out.stack.size() < words) out.stack.resize(words, 0);
    return reinterpret_cast<uint8_t*>(out.stack.data()) + offset;
  };
  const auto* guest_stack = static_cast<const uint8_t*>(host_pointer(s.sp));

  auto convert = [&](const CType& t, bool variadic) -> std::expected<void, std::string> {
    Value v(t);
    // Read the guest's value.
    for (const Piece& p : guest.place(t, variadic)) {
      switch (p.where) {
        case Where::Gpr: std::memcpy(v.at(p.value_offset), &s.x[p.index], p.size); break;
        case Where::Fpr: std::memcpy(v.at(p.value_offset), &s.v[p.index], p.size); break;
        case Where::Stack: std::memcpy(v.at(p.value_offset), guest_stack + p.index, p.size); break;
        case Where::IndirectGpr:
        case Where::IndirectStack: {
          uint64_t ptr;
          if (p.where == Where::IndirectGpr) ptr = s.x[p.index];
          else std::memcpy(&ptr, guest_stack + p.index, 8);
          if (!ptr) return std::unexpected("null pointer for an argument passed by reference");
          v.bytes.resize(std::max<size_t>(v.bytes.size(), align_up(p.size, 8)));
          std::memcpy(v.at(0), host_pointer(ptr), p.size);
          break;
        }
        default: break;
      }
    }
    extend(t, v.at(0));
    // Write the host's.
    for (const Piece& p : host.place(t)) {
      switch (p.where) {
        case Where::Gpr: {
          uint64_t r = 0;
          std::memcpy(&r, v.at(p.value_offset), p.size);
          out.gpr[p.index] = r;
          break;
        }
        case Where::Fpr:
          if (p.reg_offset == 0) out.xmm[p.index] = {};
          std::memcpy(reinterpret_cast<uint8_t*>(&out.xmm[p.index]) + p.reg_offset, v.at(p.value_offset), p.size);
          break;
        case Where::Stack: std::memcpy(stack_word(p.index, p.size), v.at(p.value_offset), p.size); break;
        case Where::X87Stack: {
          double d;
          std::memcpy(&d, v.at(0), 8);
          double_to_x87(d, stack_word(p.index, 16));
          break;
        }
        default: break;
      }
    }
    return {};
  };

  const size_t fixed = f.variadic_from >= 0 ? static_cast<size_t>(f.variadic_from) : f.args.size();
  for (size_t k = 0; k < f.args.size(); ++k)
    if (auto r = convert(f.args[k], k >= fixed); !r) return std::unexpected(std::format("argument {}: {}", k + 1, r.error()));
  if (f.variadic_from >= 0) {
    const CType word = int_type(8, false);
    for (unsigned k = 0; k < variadic_words; ++k)
      if (auto r = convert(word, true); !r) return r;
  }
  out.al = host.sses;
  out.rax = out.al;
  if (out.stack.size() % 2) out.stack.push_back(0);  // the call keeps RSP 16-byte aligned
  out.r12 = s.x[21];
  out.r13 = s.x[20];
  out.r14 = s.x[22];
  return {};
}

void host_result_to_guest(const FunctionType& f, const HostCall& call, const HostResult& r, arm64::CpuState& s) {
  Value v(f.ret);
  bool memory = false;
  for (const Piece& p : host_result_pieces(f.ret, memory)) {
    switch (p.where) {
      case Where::Gpr: std::memcpy(v.at(p.value_offset), host_reg(r, p.index), p.size); break;
      case Where::Fpr:
        std::memcpy(v.at(p.value_offset), reinterpret_cast<const uint8_t*>(&r.xmm[p.index]) + p.reg_offset, p.size);
        break;
      case Where::X87: {
        const double d = x87_to_double(r.st0);
        std::memcpy(v.at(0), &d, 8);
        break;
      }
      case Where::Memory: {
        const uint64_t hidden = call.gpr[0];
        if (hidden == reinterpret_cast<uint64_t>(call.result_buffer)) {
          v.bytes.resize(std::max<size_t>(v.bytes.size(), align_up(p.size, 8)));
          std::memcpy(v.at(0), call.result_buffer, p.size);
        }
        break;
      }
      default: break;
    }
  }
  extend(f.ret, v.at(0));
  for (const Piece& p : guest_result_pieces(f.ret)) {
    switch (p.where) {
      case Where::Gpr: {
        uint64_t x = 0;
        std::memcpy(&x, v.at(p.value_offset), p.size);
        s.x[p.index] = x;
        break;
      }
      case Where::Fpr:
        s.v[p.index] = {};
        std::memcpy(&s.v[p.index], v.at(p.value_offset), p.size);
        break;
      case Where::Memory:
        // The native function wrote to X8 itself unless the result went to the buffer.
        if (memory && call.gpr[0] == reinterpret_cast<uint64_t>(call.result_buffer))
          std::memcpy(host_pointer(s.x[8]), v.at(0), p.size);
        break;
      default: break;
    }
  }
  s.x[21] = r.r12;
}

void generic_args_to_host(const arm64::CpuState& s, HostCall& out) {
  for (int k = 0; k < 6; ++k) out.gpr[k] = s.x[k];
  out.stack = {s.x[6], s.x[7]};
  for (int k = 0; k < 8; ++k) out.xmm[k] = {s.v[k].lo, s.v[k].hi};
  out.al = 8;
  out.rax = s.x[8];
  out.r12 = s.x[21];
  out.r13 = s.x[20];
  out.r14 = s.x[22];
}

void generic_result_to_guest(const HostResult& r, arm64::CpuState& s) {
  s.x[0] = r.rax;
  s.x[1] = r.rdx;
  s.x[2] = r.rcx;
  s.x[3] = r.r8;
  for (int k = 0; k < 4; ++k) s.v[k] = {r.xmm[k].lo, r.xmm[k].hi};
  s.x[21] = r.r12;
}

// --- Native calls guest -------------------------------------------------------------------

std::expected<void, std::string> host_args_to_guest(const FunctionType& f, const HostFrame& in, arm64::CpuState& s,
                                                    GuestStackArea& area) {
  GuestAlloc guest;
  HostAlloc host;
  bool memory_result = false;
  host_result_pieces(f.ret, memory_result);
  if (memory_result) {
    ++host.gprs;           // the hidden pointer
    s.x[8] = in.gpr[0];    // the guest writes there if it returns in memory too
  }
  const auto* host_stack = reinterpret_cast<const uint8_t*>(in.stack);

  // The argument area first, then copies of the arguments passed by
  // reference after it (their pointers need its final size).
  area.bytes.clear();
  auto stack_bytes = [&](uint64_t offset, size_t size) -> uint8_t* {
    if (area.bytes.size() < offset + size) area.bytes.resize(offset + size, 0);
    return area.bytes.data() + offset;
  };
  std::vector<Value> by_reference;
  std::vector<Piece> reference_slots;

  for (size_t k = 0; k < f.args.size(); ++k) {
    const CType& t = f.args[k];
    const bool variadic = f.variadic_from >= 0 && static_cast<int>(k) >= f.variadic_from;
    Value v(t);
    for (const Piece& p : host.place(t)) {
      switch (p.where) {
        case Where::Gpr: std::memcpy(v.at(p.value_offset), &in.gpr[p.index], p.size); break;
        case Where::Fpr:
          std::memcpy(v.at(p.value_offset), reinterpret_cast<const uint8_t*>(&in.xmm[p.index]) + p.reg_offset, p.size);
          break;
        case Where::Stack:
          if (!host_stack) return std::unexpected("stack arguments without a stack");
          v.bytes.resize(std::max<size_t>(v.bytes.size(), align_up(p.size, 8)));
          std::memcpy(v.at(p.value_offset), host_stack + p.index, p.size);
          break;
        case Where::X87Stack: {
          if (!host_stack) return std::unexpected("stack arguments without a stack");
          const double d = x87_to_double(host_stack + p.index);
          std::memcpy(v.at(0), &d, 8);
          break;
        }
        default: break;
      }
    }
    extend(t, v.at(0));
    for (const Piece& p : guest.place(t, variadic)) {
      switch (p.where) {
        case Where::Gpr: {
          uint64_t x = 0;
          std::memcpy(&x, v.at(p.value_offset), p.size);
          s.x[p.index] = x;
          break;
        }
        case Where::Fpr:
          s.v[p.index] = {};
          std::memcpy(&s.v[p.index], v.at(p.value_offset), p.size);
          break;
        case Where::Stack: std::memcpy(stack_bytes(p.index, p.size), v.at(p.value_offset), p.size); break;
        case Where::IndirectGpr:
        case Where::IndirectStack:
          if (p.where == Where::IndirectStack) stack_bytes(p.index, 8);
          reference_slots.push_back(p);
          by_reference.push_back(std::move(v));
          v = Value(t);
          break;
        default: break;
      }
    }
  }
  // Copies of the arguments passed by reference, after the argument area.
  size_t at = align_up(area.bytes.size(), 16);
  for (size_t k = 0; k < by_reference.size(); ++k) {
    const Piece& p = reference_slots[k];
    std::memcpy(stack_bytes(at, p.size), by_reference[k].at(0), p.size);
    const uint64_t pointer = area.base + at;
    if (p.where == Where::IndirectGpr) s.x[p.index] = pointer;
    else std::memcpy(area.bytes.data() + p.index, &pointer, 8);
    at = align_up(at + p.size, 16);
  }
  area.bytes.resize(align_up(area.bytes.size(), 16), 0);
  s.x[20] = in.r13;
  s.x[21] = in.r12;
  s.x[22] = in.r14;
  return {};
}

void guest_result_to_host(const FunctionType& f, const HostFrame& in, const arm64::CpuState& s, HostResult& r) {
  Value v(f.ret);
  for (const Piece& p : guest_result_pieces(f.ret)) {
    switch (p.where) {
      case Where::Gpr: std::memcpy(v.at(p.value_offset), &s.x[p.index], p.size); break;
      case Where::Fpr: std::memcpy(v.at(p.value_offset), &s.v[p.index], p.size); break;
      default: break;  // Memory: written to X8, the host's hidden pointer
    }
  }
  extend(f.ret, v.at(0));
  bool memory = false;
  const Pieces host = host_result_pieces(f.ret, memory);
  const bool guest_memory = !guest_result_pieces(f.ret).empty() && guest_result_pieces(f.ret)[0].where == Where::Memory;
  for (const Piece& p : host) {
    switch (p.where) {
      case Where::Gpr: {
        uint64_t x = 0;
        std::memcpy(&x, v.at(p.value_offset), p.size);
        *const_cast<uint64_t*>(host_reg(r, p.index)) = x;
        break;
      }
      case Where::Fpr:
        if (p.reg_offset == 0) r.xmm[p.index] = {};
        std::memcpy(reinterpret_cast<uint8_t*>(&r.xmm[p.index]) + p.reg_offset, v.at(p.value_offset), p.size);
        break;
      case Where::X87: {
        double d;
        std::memcpy(&d, v.at(0), 8);
        double_to_x87(d, r.st0);
        break;
      }
      case Where::Memory:
        if (!guest_memory) std::memcpy(host_pointer(in.gpr[0]), v.at(0), p.size);  // (an HFA in V registers)
        r.rax = in.gpr[0];
        break;
      default: break;
    }
  }
  r.r12 = s.x[21];
}

void generic_args_to_guest(const HostFrame& in, arm64::CpuState& s) {
  for (int k = 0; k < 6; ++k) s.x[k] = in.gpr[k];
  s.x[6] = in.stack ? in.stack[0] : 0;
  s.x[7] = in.stack ? in.stack[1] : 0;
  for (int k = 0; k < 8; ++k) s.v[k] = {in.xmm[k].lo, in.xmm[k].hi};
  s.x[8] = in.rax;
  s.x[20] = in.r13;
  s.x[21] = in.r12;
  s.x[22] = in.r14;
}

void generic_result_to_host(const arm64::CpuState& s, HostResult& r) {
  r.rax = s.x[0];
  r.rdx = s.x[1];
  r.rcx = s.x[2];
  r.r8 = s.x[3];
  for (int k = 0; k < 4; ++k) r.xmm[k] = {s.v[k].lo, s.v[k].hi};
  r.r12 = s.x[21];
}

bool host_returns_in_memory(const CType& t) {
  bool memory = false;
  host_result_pieces(t, memory);
  return memory;
}

// --- x87 extended precision ---------------------------------------------------------------

void double_to_x87(double v, uint8_t out[10]) {
  uint64_t bits;
  std::memcpy(&bits, &v, 8);
  const uint16_t sign = static_cast<uint16_t>((bits >> 63) << 15);
  const int exp = static_cast<int>((bits >> 52) & 0x7FF);
  uint64_t mant = bits & ((uint64_t{1} << 52) - 1);
  uint16_t e;
  uint64_t m;
  if (exp == 0x7FF) {  // infinity, NaN
    e = 0x7FFF;
    m = uint64_t{1} << 63 | mant << 11;
  } else if (exp == 0) {
    if (mant == 0) {
      e = 0;
      m = 0;
    } else {  // subnormal: normalize
      int unbiased = 1 - 1023;
      while (!(mant & (uint64_t{1} << 52))) {
        mant <<= 1;
        --unbiased;
      }
      e = static_cast<uint16_t>(unbiased + 16383);
      m = mant << 11;
    }
  } else {
    e = static_cast<uint16_t>(exp - 1023 + 16383);
    m = uint64_t{1} << 63 | mant << 11;
  }
  std::memcpy(out, &m, 8);
  const uint16_t top = sign | e;
  std::memcpy(out + 8, &top, 2);
}

double x87_to_double(const uint8_t in[10]) {
  uint64_t m;
  uint16_t top;
  std::memcpy(&m, in, 8);
  std::memcpy(&top, in + 8, 2);
  const bool negative = top >> 15;
  const int e = top & 0x7FFF;
  double d;
  if (e == 0x7FFF) {
    if ((m << 1) == 0) {
      d = HUGE_VAL;
    } else {
      uint64_t bits = uint64_t{0x7FF} << 52 | ((m >> 11) & ((uint64_t{1} << 52) - 1)) | uint64_t{1} << 51;
      std::memcpy(&d, &bits, 8);
    }
  } else if (m == 0) {
    d = 0.0;
  } else {
    const int unbiased = (e == 0 ? 1 : e) - 16383;
    d = std::ldexp(static_cast<double>(m), unbiased - 63);
  }
  return negative ? -d : d;
}

}  // namespace juice::mac
