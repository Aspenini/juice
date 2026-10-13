#include "macos/eh/guest_unwind.hpp"

#include <array>
#include <cstring>
#include <string>
#include <vector>

namespace juice::mac {

namespace {

constexpr uint32_t kModeMask = 0x0F000000;
constexpr uint32_t kModeFrameless = 0x02000000;
constexpr uint32_t kModeDwarf = 0x03000000;
constexpr uint32_t kModeFrame = 0x04000000;
constexpr uint32_t kHasLsda = 0x40000000;
constexpr uint32_t kPersonalityMask = 0x30000000;
constexpr uint32_t kFramelessStackMask = 0x00FFF000;
constexpr uint32_t kDwarfOffsetMask = 0x00FFFFFF;

// Saved register pairs (frame and frameless modes).
constexpr uint32_t kX19X20 = 0x001, kX21X22 = 0x002, kX23X24 = 0x004, kX25X26 = 0x008, kX27X28 = 0x010;
constexpr uint32_t kD8D9 = 0x100, kD10D11 = 0x200, kD12D13 = 0x400, kD14D15 = 0x800;

template <typename T>
bool get(const MemoryReader& read, uint64_t addr, T& out) {
  return read(addr, &out, sizeof(T));
}

bool uleb(const MemoryReader& read, uint64_t& addr, uint64_t& out) {
  out = 0;
  for (unsigned shift = 0; shift < 64; shift += 7) {
    uint8_t b;
    if (!get(read, addr++, b)) return false;
    out |= uint64_t{b & 0x7Fu} << shift;
    if (!(b & 0x80)) return true;
  }
  return false;
}

bool sleb(const MemoryReader& read, uint64_t& addr, int64_t& out) {
  out = 0;
  unsigned shift = 0;
  uint8_t b;
  do {
    if (shift >= 64 || !get(read, addr++, b)) return false;
    out |= int64_t{b & 0x7F} << shift;
    shift += 7;
  } while (b & 0x80);
  if (shift < 64 && (b & 0x40)) out |= -(int64_t{1} << shift);
  return true;
}

// --- Compact unwind --------------------------------------------------------------------------

bool compact_lookup(const UnwindSections& s, uint64_t pc, FrameUnwindInfo& out, const MemoryReader& read) {
  if (!s.unwind_info) return false;
  const uint64_t base = s.unwind_info;
  uint32_t header[7];
  if (!read(base, header, sizeof(header)) || header[0] != 1) return false;
  const uint32_t common_offset = header[1], common_count = header[2];
  const uint32_t personality_offset = header[3], personality_count = header[4];
  const uint32_t index_offset = header[5], index_count = header[6];
  if (index_count < 2) return false;
  const uint64_t target = pc - s.header;
  if (pc < s.header || target > 0xFFFFFFFFull) return false;

  struct IndexEntry {
    uint32_t function, second_level, lsda_index;
  };
  auto index = [&](uint32_t k, IndexEntry& e) { return read(base + index_offset + k * 12ull, &e, 12); };
  // The last first-level entry starting at or before the target (the final entry is a sentinel).
  uint32_t lo = 0, hi = index_count - 1;
  while (hi - lo > 1) {
    const uint32_t mid = (lo + hi) / 2;
    IndexEntry e;
    if (!index(mid, e)) return false;
    if (e.function <= target) lo = mid;
    else hi = mid;
  }
  IndexEntry first, next;
  if (!index(lo, first) || !index(lo + 1, next)) return false;
  if (target < first.function || target >= next.function || !first.second_level) return false;

  const uint64_t page = base + first.second_level;
  uint32_t kind;
  if (!get(read, page, kind)) return false;
  uint32_t start = 0, end = next.function, encoding = 0;
  if (kind == 2) {  // regular: {function, encoding} pairs
    uint16_t entry_offset, entry_count;
    if (!get(read, page + 4, entry_offset) || !get(read, page + 6, entry_count) || !entry_count) return false;
    uint32_t l = 0, h = entry_count;
    while (h - l > 1) {
      const uint32_t mid = (l + h) / 2;
      uint32_t f;
      if (!get(read, page + entry_offset + mid * 8ull, f)) return false;
      if (f <= target) l = mid;
      else h = mid;
    }
    if (!get(read, page + entry_offset + l * 8ull, start) || !get(read, page + entry_offset + l * 8ull + 4, encoding))
      return false;
    if (l + 1 < entry_count && !get(read, page + entry_offset + (l + 1) * 8ull, end)) return false;
  } else if (kind == 3) {  // compressed: 24-bit function offsets, 8-bit encoding indexes
    uint16_t entry_offset, entry_count, encodings_offset, encodings_count;
    if (!get(read, page + 4, entry_offset) || !get(read, page + 6, entry_count) ||
        !get(read, page + 8, encodings_offset) || !get(read, page + 10, encodings_count) || !entry_count)
      return false;
    auto entry = [&](uint32_t k, uint32_t& e) { return get(read, page + entry_offset + k * 4ull, e); };
    uint32_t l = 0, h = entry_count;
    while (h - l > 1) {
      const uint32_t mid = (l + h) / 2;
      uint32_t e;
      if (!entry(mid, e)) return false;
      if (first.function + (e & 0xFFFFFF) <= target) l = mid;
      else h = mid;
    }
    uint32_t e;
    if (!entry(l, e)) return false;
    start = first.function + (e & 0xFFFFFF);
    if (l + 1 < entry_count) {
      uint32_t n;
      if (!entry(l + 1, n)) return false;
      end = first.function + (n & 0xFFFFFF);
    }
    const uint32_t which = e >> 24;
    if (which < common_count) {
      if (!get(read, base + common_offset + which * 4ull, encoding)) return false;
    } else {
      if (which - common_count >= encodings_count) return false;
      if (!get(read, page + encodings_offset + (which - common_count) * 4ull, encoding)) return false;
    }
  } else {
    return false;
  }
  if (target < start || encoding == 0) return false;

  out = {};
  out.start = s.header + start;
  out.end = s.header + end;
  out.encoding = encoding;
  if (const uint32_t p = (encoding & kPersonalityMask) >> 28) {
    uint32_t slot;
    if (p > personality_count || !get(read, base + personality_offset + (p - 1) * 4ull, slot)) return false;
    if (!get(read, s.header + slot, out.personality)) return false;  // (a pointer the image binds)
  }
  if (encoding & kHasLsda) {
    // The LSDA index entries of this first-level range, sorted by function.
    const uint32_t from = first.lsda_index, to = next.lsda_index;
    uint32_t l = 0, h = (to - from) / 8;
    while (l < h) {
      const uint32_t mid = (l + h) / 2;
      uint32_t f;
      if (!get(read, base + from + mid * 8ull, f)) return false;
      if (f < start) l = mid + 1;
      else h = mid;
    }
    uint32_t f, lsda;
    if (l < (to - from) / 8 && get(read, base + from + l * 8ull, f) && f == start &&
        get(read, base + from + l * 8ull + 4, lsda))
      out.lsda = s.header + lsda;
  }
  if ((encoding & kModeMask) == kModeDwarf) {
    out.dwarf = true;
    out.fde = s.eh_frame + (encoding & kDwarfOffsetMask);
  }
  return true;
}

// --- DWARF call frame information ------------------------------------------------------------

struct Cie {
  uint64_t code_align = 1;
  int64_t data_align = -8;
  uint64_t ra_register = 30;
  uint8_t fde_encoding = 0;  // DW_EH_PE_absptr
  uint8_t lsda_encoding = 0xFF;
  uint64_t personality = 0;
  bool augmented = false;  // 'z'
  uint64_t instructions = 0, end = 0;
};

struct Fde {
  Cie cie;
  uint64_t pc_begin = 0, pc_end = 0;
  uint64_t lsda = 0;
  uint64_t instructions = 0, end = 0;
};

// The extent of a CIE/FDE record at `addr`: its contents start after the length.
bool record(const MemoryReader& read, uint64_t addr, uint64_t& contents, uint64_t& end) {
  uint32_t length;
  if (!get(read, addr, length)) return false;
  if (length == 0xFFFFFFFF) {
    uint64_t length64;
    if (!get(read, addr + 4, length64)) return false;
    contents = addr + 12;
    end = contents + length64;
  } else {
    contents = addr + 4;
    end = contents + length;
  }
  return length != 0;
}

bool parse_cie(const MemoryReader& read, uint64_t addr, Cie& cie) {
  uint64_t p, end;
  if (!record(read, addr, p, end)) return false;
  uint32_t id;
  uint8_t version;
  if (!get(read, p, id) || id != 0 || !get(read, p + 4, version)) return false;
  p += 5;
  std::string augmentation;
  for (char c; get(read, p++, c) && c;) augmentation += c;
  if (version >= 4) p += 2;  // address size, segment size
  if (!uleb(read, p, cie.code_align) || !sleb(read, p, cie.data_align)) return false;
  if (version == 1) {
    uint8_t ra;
    if (!get(read, p++, ra)) return false;
    cie.ra_register = ra;
  } else if (!uleb(read, p, cie.ra_register)) {
    return false;
  }
  uint64_t after = 0;
  if (!augmentation.empty() && augmentation[0] == 'z') {
    cie.augmented = true;
    uint64_t length;
    if (!uleb(read, p, length)) return false;
    after = p + length;
    for (size_t k = 1; k < augmentation.size(); ++k) {
      switch (augmentation[k]) {
        case 'P': {
          uint8_t encoding;
          if (!get(read, p++, encoding) || !read_encoded_pointer(p, encoding, cie.personality, read)) return false;
          break;
        }
        case 'L':
          if (!get(read, p++, cie.lsda_encoding)) return false;
          break;
        case 'R':
          if (!get(read, p++, cie.fde_encoding)) return false;
          break;
        default:
          break;  // 'S' (signal frame), 'B' (arm64e keys): no data
      }
    }
    p = after;
  }
  cie.instructions = p;
  cie.end = end;
  return true;
}

bool parse_fde(const MemoryReader& read, uint64_t addr, Fde& fde) {
  uint64_t p, end;
  if (!record(read, addr, p, end)) return false;
  uint32_t cie_pointer;
  if (!get(read, p, cie_pointer) || cie_pointer == 0) return false;  // (0 would be a CIE)
  if (!parse_cie(read, p - cie_pointer, fde.cie)) return false;
  p += 4;
  uint64_t range;
  if (!read_encoded_pointer(p, fde.cie.fde_encoding, fde.pc_begin, read)) return false;
  if (!read_encoded_pointer(p, fde.cie.fde_encoding & 0x0F, range, read)) return false;
  fde.pc_end = fde.pc_begin + range;
  if (fde.cie.augmented) {
    uint64_t length;
    if (!uleb(read, p, length)) return false;
    const uint64_t after = p + length;
    if (fde.cie.lsda_encoding != 0xFF) {
      uint64_t q = p;
      if (!read_encoded_pointer(q, fde.cie.lsda_encoding, fde.lsda, read)) return false;
    }
    p = after;
  }
  fde.instructions = p;
  fde.end = end;
  return true;
}

// Finds the FDE covering `pc` by scanning __eh_frame (images without compact unwind information).
bool scan_eh_frame(const UnwindSections& s, uint64_t pc, uint64_t& fde_addr, const MemoryReader& read) {
  for (uint64_t at = s.eh_frame; at < s.eh_frame + s.eh_frame_size;) {
    uint64_t contents, end;
    if (!record(read, at, contents, end)) return false;
    uint32_t id;
    if (!get(read, contents, id)) return false;
    if (id != 0) {
      Fde fde;
      if (parse_fde(read, at, fde) && pc >= fde.pc_begin && pc < fde.pc_end) {
        fde_addr = at;
        return true;
      }
    }
    at = end;
  }
  return false;
}

// Register rules of the CFA program.
enum class Rule : uint8_t { Same, Undefined, Offset, ValOffset, Register };
struct RegRule {
  Rule rule = Rule::Same;
  int64_t value = 0;
};
constexpr unsigned kRegs = 96;  // 0-30 X, 31 SP, 64-95 V
struct CfaState {
  uint64_t cfa_register = 31;
  int64_t cfa_offset = 0;
  std::array<RegRule, kRegs> regs{};
};

// Runs CFA instructions [p, end) until the location passes `target`.
bool run_cfa(const MemoryReader& read, uint64_t p, uint64_t end, const Cie& cie, uint64_t location, uint64_t target,
             CfaState& state, const CfaState& initial) {
  std::vector<CfaState> stack;
  auto set = [&](uint64_t reg, Rule rule, int64_t value) {
    if (reg < kRegs) state.regs[reg] = {rule, value};
  };
  while (p < end) {
    uint8_t op;
    if (!get(read, p++, op)) return false;
    const uint8_t high = op & 0xC0, low = op & 0x3F;
    uint64_t a = 0, b = 0;
    int64_t sa = 0;
    if (high == 0x40) {  // advance_loc
      location += low * cie.code_align;
      if (location > target) return true;
      continue;
    }
    if (high == 0x80) {  // offset
      if (!uleb(read, p, a)) return false;
      set(low, Rule::Offset, static_cast<int64_t>(a) * cie.data_align);
      continue;
    }
    if (high == 0xC0) {  // restore
      if (low < kRegs) state.regs[low] = initial.regs[low];
      continue;
    }
    switch (op) {
      case 0x00:  // nop
        break;
      case 0x01: {  // set_loc
        uint64_t loc;
        if (!read_encoded_pointer(p, cie.fde_encoding, loc, read)) return false;
        location = loc;
        if (location > target) return true;
        break;
      }
      case 0x02:
      case 0x03:
      case 0x04: {  // advance_loc1/2/4
        uint32_t delta = 0;
        const unsigned size = op == 0x02 ? 1 : op == 0x03 ? 2 : 4;
        if (!read(p, &delta, size)) return false;
        p += size;
        location += delta * cie.code_align;
        if (location > target) return true;
        break;
      }
      case 0x05:  // offset_extended
        if (!uleb(read, p, a) || !uleb(read, p, b)) return false;
        set(a, Rule::Offset, static_cast<int64_t>(b) * cie.data_align);
        break;
      case 0x06:  // restore_extended
        if (!uleb(read, p, a)) return false;
        if (a < kRegs) state.regs[a] = initial.regs[a];
        break;
      case 0x07:  // undefined
        if (!uleb(read, p, a)) return false;
        set(a, Rule::Undefined, 0);
        break;
      case 0x08:  // same_value
        if (!uleb(read, p, a)) return false;
        set(a, Rule::Same, 0);
        break;
      case 0x09:  // register
        if (!uleb(read, p, a) || !uleb(read, p, b)) return false;
        set(a, Rule::Register, static_cast<int64_t>(b));
        break;
      case 0x0A:  // remember_state
        stack.push_back(state);
        break;
      case 0x0B:  // restore_state
        if (stack.empty()) return false;
        state = stack.back();
        stack.pop_back();
        break;
      case 0x0C:  // def_cfa
        if (!uleb(read, p, a) || !uleb(read, p, b)) return false;
        state.cfa_register = a;
        state.cfa_offset = static_cast<int64_t>(b);
        break;
      case 0x0D:  // def_cfa_register
        if (!uleb(read, p, a)) return false;
        state.cfa_register = a;
        break;
      case 0x0E:  // def_cfa_offset
        if (!uleb(read, p, a)) return false;
        state.cfa_offset = static_cast<int64_t>(a);
        break;
      case 0x11:  // offset_extended_sf
        if (!uleb(read, p, a) || !sleb(read, p, sa)) return false;
        set(a, Rule::Offset, sa * cie.data_align);
        break;
      case 0x12:  // def_cfa_sf
        if (!uleb(read, p, a) || !sleb(read, p, sa)) return false;
        state.cfa_register = a;
        state.cfa_offset = sa * cie.data_align;
        break;
      case 0x13:  // def_cfa_offset_sf
        if (!sleb(read, p, sa)) return false;
        state.cfa_offset = sa * cie.data_align;
        break;
      case 0x14:  // val_offset
        if (!uleb(read, p, a) || !uleb(read, p, b)) return false;
        set(a, Rule::ValOffset, static_cast<int64_t>(b) * cie.data_align);
        break;
      case 0x15:  // val_offset_sf
        if (!uleb(read, p, a) || !sleb(read, p, sa)) return false;
        set(a, Rule::ValOffset, sa * cie.data_align);
        break;
      case 0x2D:  // AArch64 negate_ra_state (pointer authentication: nothing to do)
        break;
      case 0x2E:  // GNU_args_size
        if (!uleb(read, p, a)) return false;
        break;
      case 0x2F:  // GNU_negative_offset_extended
        if (!uleb(read, p, a) || !uleb(read, p, b)) return false;
        set(a, Rule::Offset, -static_cast<int64_t>(b) * cie.data_align);
        break;
      default:
        return false;  // expressions (0x0F, 0x10, 0x16) and unknown operations
    }
  }
  return true;
}

uint64_t reg_value(const GuestFrame& f, uint64_t reg) {
  if (reg < 31) return f.x[reg];
  if (reg == 31) return f.sp;
  if (reg >= 72 && reg < 80) return f.d[reg - 72];
  return 0;
}

bool step_dwarf(GuestFrame& f, const FrameUnwindInfo& info, const MemoryReader& read) {
  Fde fde;
  if (!parse_fde(read, info.fde, fde)) return false;
  const uint64_t target = f.pc - 1;  // within the call
  CfaState initial;
  if (!run_cfa(read, fde.cie.instructions, fde.cie.end, fde.cie, fde.pc_begin, ~0ull, initial, initial)) return false;
  CfaState state = initial;
  if (!run_cfa(read, fde.instructions, fde.end, fde.cie, fde.pc_begin, target, state, initial)) return false;
  const uint64_t cfa = reg_value(f, state.cfa_register) + static_cast<uint64_t>(state.cfa_offset);
  GuestFrame next = f;
  for (unsigned r = 0; r < kRegs; ++r) {
    const RegRule& rule = state.regs[r];
    uint64_t v;
    switch (rule.rule) {
      case Rule::Same: continue;
      case Rule::Undefined: v = 0; break;
      case Rule::Offset:
        if (!get(read, cfa + static_cast<uint64_t>(rule.value), v)) return false;
        break;
      case Rule::ValOffset: v = cfa + static_cast<uint64_t>(rule.value); break;
      case Rule::Register: v = reg_value(f, static_cast<uint64_t>(rule.value)); break;
      default: continue;
    }
    if (r < 31) next.x[r] = v;
    else if (r >= 72 && r < 80) next.d[r - 72] = v;
  }
  const RegRule& ra = state.regs[fde.cie.ra_register < kRegs ? fde.cie.ra_register : 30];
  if (ra.rule == Rule::Undefined) return false;  // the outermost frame
  next.pc = reg_value(next, fde.cie.ra_register);
  next.sp = cfa;
  f = next;
  return true;
}

}  // namespace

bool read_encoded_pointer(uint64_t& addr, uint8_t encoding, uint64_t& out, const MemoryReader& read,
                          uint64_t func_base) {
  if (encoding == 0xFF) {  // omit
    out = 0;
    return true;
  }
  const uint64_t field = addr;
  if ((encoding & 0x70) == 0x50) {  // aligned
    addr = (addr + 7) & ~uint64_t{7};
    encoding = 0;
  }
  uint64_t v = 0;
  switch (encoding & 0x0F) {
    case 0x00: {  // absptr
      if (!get(read, addr, v)) return false;
      addr += 8;
      break;
    }
    case 0x01:
      if (!uleb(read, addr, v)) return false;
      break;
    case 0x02: {
      uint16_t x;
      if (!get(read, addr, x)) return false;
      v = x;
      addr += 2;
      break;
    }
    case 0x03: {
      uint32_t x;
      if (!get(read, addr, x)) return false;
      v = x;
      addr += 4;
      break;
    }
    case 0x04:
      if (!get(read, addr, v)) return false;
      addr += 8;
      break;
    case 0x09: {
      int64_t x;
      if (!sleb(read, addr, x)) return false;
      v = static_cast<uint64_t>(x);
      break;
    }
    case 0x0A: {
      int16_t x;
      if (!get(read, addr, x)) return false;
      v = static_cast<uint64_t>(static_cast<int64_t>(x));
      addr += 2;
      break;
    }
    case 0x0B: {
      int32_t x;
      if (!get(read, addr, x)) return false;
      v = static_cast<uint64_t>(static_cast<int64_t>(x));
      addr += 4;
      break;
    }
    case 0x0C:
      if (!get(read, addr, v)) return false;
      addr += 8;
      break;
    default:
      return false;
  }
  if (v == 0 && (encoding & 0x70) != 0) {
    out = 0;  // (a null relative pointer stays null)
  } else {
    switch (encoding & 0x70) {
      case 0x00: break;
      case 0x10: v += field; break;      // pcrel
      case 0x40: v += func_base; break;  // funcrel
      default: return false;             // textrel, datarel: not used on Darwin
    }
    if (encoding & 0x80 && !get(read, v, v)) return false;  // indirect
    out = v;
  }
  return true;
}

bool find_unwind_info(const UnwindSections& s, uint64_t pc, FrameUnwindInfo& out, const MemoryReader& read) {
  if (compact_lookup(s, pc, out, read)) {
    if (out.dwarf) {
      Fde fde;
      if (!parse_fde(read, out.fde, fde)) return false;
      out.personality = fde.cie.personality;
      out.lsda = fde.lsda;
      out.start = fde.pc_begin;
      out.end = fde.pc_end;
    }
    return true;
  }
  uint64_t fde_addr;
  if (!s.eh_frame || !scan_eh_frame(s, pc, fde_addr, read)) return false;
  Fde fde;
  if (!parse_fde(read, fde_addr, fde)) return false;
  out = {};
  out.dwarf = true;
  out.fde = fde_addr;
  out.start = fde.pc_begin;
  out.end = fde.pc_end;
  out.personality = fde.cie.personality;
  out.lsda = fde.lsda;
  return true;
}

bool step_frame(GuestFrame& f, const FrameUnwindInfo& info, const MemoryReader& read) {
  if (info.dwarf) return step_dwarf(f, info, read);
  const uint32_t e = info.encoding;
  auto restore_pairs = [&](uint64_t& loc) {
    // Pairs from the top of the save area down: X19, X20, X21, ... then D8, D9, ...
    static constexpr struct {
      uint32_t flag;
      bool fp;
      int first;
    } kPairs[] = {{kX19X20, false, 19}, {kX21X22, false, 21}, {kX23X24, false, 23}, {kX25X26, false, 25},
                  {kX27X28, false, 27}, {kD8D9, true, 0},     {kD10D11, true, 2},   {kD12D13, true, 4},
                  {kD14D15, true, 6}};
    for (const auto& pair : kPairs) {
      if (!(e & pair.flag)) continue;
      for (int k = 0; k < 2; ++k) {
        uint64_t v;
        if (!get(read, loc, v)) return false;
        loc -= 8;
        if (pair.fp) f.d[pair.first + k] = v;
        else f.x[pair.first + k] = v;
      }
    }
    return true;
  };
  switch (e & kModeMask) {
    case kModeFrame: {
      // FP points at the saved {FP, LR}; the pairs are saved below it.
      const uint64_t fp = f.x[29];
      uint64_t loc = fp - 8;
      if (!restore_pairs(loc)) return false;
      uint64_t saved_fp, lr;
      if (!get(read, fp, saved_fp) || !get(read, fp + 8, lr)) return false;
      f.x[29] = saved_fp;
      f.x[30] = lr;
      f.sp = fp + 16;
      f.pc = lr;
      return true;
    }
    case kModeFrameless: {
      const uint64_t stack = 16 * uint64_t{(e & kFramelessStackMask) >> 12};
      uint64_t loc = f.sp + stack - 8;
      if (!restore_pairs(loc)) return false;
      f.sp += stack;
      f.pc = f.x[30];
      return true;
    }
    default:
      return false;
  }
}

}  // namespace juice::mac
