#include "windows/exceptions/arm64_unwind.hpp"

#include <cstring>

// See "ARM64 exception handling" in the Microsoft ABI documentation for the
// formats decoded here.

namespace juice::win::arm64eh {

namespace {

uint64_t load64(uint64_t addr) {
  uint64_t v;
  std::memcpy(&v, reinterpret_cast<const void*>(addr), 8);
  return v;
}

// Restore `count` registers starting at x`reg` from the stack. `pos` is the
// offset of the first one in 8-byte units; a negative `pos` describes a
// pre-indexed store (the registers are at sp, and sp moves up by -pos * 8).
void restore_regs(Context& c, unsigned reg, int count, int pos) {
  const int offset = pos < 0 ? 0 : pos;
  for (int i = 0; i < count; ++i) c.x[reg + i] = load64(c.sp + 8 * (offset + i));
  if (pos < 0) c.sp += 8 * static_cast<uint64_t>(-pos);
}

void restore_fpregs(Context& c, unsigned reg, int count, int pos) {
  const int offset = pos < 0 ? 0 : pos;
  for (int i = 0; i < count; ++i) c.v[reg + i].lo = load64(c.sp + 8 * (offset + i));
  if (pos < 0) c.sp += 8 * static_cast<uint64_t>(-pos);
}

// Bytes taken by the unwind code at `p`.
unsigned code_size(uint8_t b) {
  if (b < 0xc0) return 1;
  if (b < 0xe0) return 2;
  if (b == 0xe0) return 4;
  if (b == 0xe2) return 2;
  if (b == 0xe7) return 3;
  return 1;
}

bool is_end(uint8_t b) { return b == 0xe4 || b == 0xe5; }

// Number of instructions the codes starting at `p` describe.
unsigned sequence_length(const uint8_t* p, const uint8_t* end) {
  unsigned n = 0;
  while (p < end && !is_end(*p)) {
    ++n;
    p += code_size(*p);
  }
  return n;
}

// Skip the codes of the first `instructions` instructions.
const uint8_t* skip_codes(const uint8_t* p, const uint8_t* end, unsigned instructions) {
  while (instructions && p < end && !is_end(*p)) {
    p += code_size(*p);
    --instructions;
  }
  return p;
}

void execute_codes(const uint8_t* p, const uint8_t* end, Context& c) {
  int save_next = 0;  // pending save_next codes: they extend the next paired save
  while (p < end) {
    const uint8_t b = *p;
    if (b < 0x20) {  // alloc_s
      c.sp += 16ull * (b & 0x1f);
    } else if (b < 0x40) {  // save_r19r20_x
      restore_regs(c, 19, 2 + 2 * save_next, -(b & 0x1f));
      save_next = 0;
    } else if (b < 0x80) {  // save_fplr
      restore_regs(c, 29, 2, b & 0x3f);
    } else if (b < 0xc0) {  // save_fplr_x
      restore_regs(c, 29, 2, -((b & 0x3f) + 1));
    } else if (b < 0xc8) {  // alloc_m
      c.sp += 16ull * (((b & 7u) << 8) | p[1]);
    } else if (b < 0xd0) {  // save_regp, save_regp_x
      const unsigned x = ((b & 3u) << 2) | (p[1] >> 6), z = p[1] & 0x3f;
      restore_regs(c, 19 + x, 2 + 2 * save_next, b < 0xcc ? static_cast<int>(z) : -static_cast<int>(z + 1));
      save_next = 0;
    } else if (b < 0xd4) {  // save_reg
      restore_regs(c, 19 + (((b & 3u) << 2) | (p[1] >> 6)), 1, p[1] & 0x3f);
    } else if (b < 0xd6) {  // save_reg_x
      restore_regs(c, 19 + (((b & 1u) << 3) | (p[1] >> 5)), 1, -((p[1] & 0x1f) + 1));
    } else if (b < 0xd8) {  // save_lrpair
      const unsigned x = ((b & 1u) << 2) | (p[1] >> 6), z = p[1] & 0x3f;
      restore_regs(c, 19 + 2 * x, 1, static_cast<int>(z));
      restore_regs(c, 30, 1, static_cast<int>(z) + 1);
    } else if (b < 0xdc) {  // save_fregp, save_fregp_x
      const unsigned x = ((b & 1u) << 2) | (p[1] >> 6), z = p[1] & 0x3f;
      restore_fpregs(c, 8 + x, 2 + 2 * save_next, b < 0xda ? static_cast<int>(z) : -static_cast<int>(z + 1));
      save_next = 0;
    } else if (b < 0xde) {  // save_freg
      restore_fpregs(c, 8 + (((b & 1u) << 2) | (p[1] >> 6)), 1, p[1] & 0x3f);
    } else if (b == 0xde) {  // save_freg_x
      restore_fpregs(c, 8 + (p[1] >> 5), 1, -((p[1] & 0x1f) + 1));
    } else if (b == 0xdf) {  // alloc_z (SVE): no SVE state to restore
    } else if (b == 0xe0) {  // alloc_l
      c.sp += 16ull * ((static_cast<uint32_t>(p[1]) << 16) | (p[2] << 8) | p[3]);
    } else if (b == 0xe1) {  // set_fp
      c.sp = c.x[29];
    } else if (b == 0xe2) {  // add_fp
      c.sp = c.x[29] - 8ull * p[1];
    } else if (b == 0xe3) {  // nop
    } else if (is_end(b)) {
      break;
    } else if (b == 0xe6) {  // save_next
      ++save_next;
    } else if (b == 0xe7) {  // save_any_reg: 1110 0111 '0pxrrrrr' 'ffoooooo'
      const bool pair = p[1] & 0x40, writeback = p[1] & 0x20;
      const unsigned reg = p[1] & 0x1f, type = p[2] >> 6, o = p[2] & 0x3f;
      const int count = pair ? 2 : 1;
      const int pos = writeback ? -static_cast<int>((o + 1) * 2) : static_cast<int>(type == 2 ? o * 2 : o);
      if (type == 0) {
        restore_regs(c, reg, count, pos);
      } else {
        restore_fpregs(c, reg, count, pos);  // D or the low half of Q
      }
    } else if (b == 0xe9) {  // MSFT_OP_MACHINE_FRAME: pc and sp saved by a trap
      c.pc = load64(c.sp + 8);
      c.sp = load64(c.sp);
    } else if (b == 0xea) {  // MSFT_OP_CONTEXT: a complete CONTEXT at sp
      const uint32_t flags = c.flags;
      std::memcpy(&c, reinterpret_cast<const void*>(c.sp), sizeof(Context));
      c.flags = flags;
    } else if (b == 0xec) {  // MSFT_OP_CLEAR_UNWOUND_TO_CALL
      c.flags &= ~kContextUnwoundToCall;
    }
    // 0xfc (pac_sign_lr) and other codes need no action.
    p += code_size(b);
  }
}

UnwindResult unwind_full(uint64_t base, uint64_t pc, const RuntimeFunction& f, Context& c, bool at_call) {
  UnwindResult r;
  const auto* p = reinterpret_cast<const uint32_t*>(base + f.unwind_data);
  const uint32_t header = *p++;
  const uint32_t length = header & 0x3ffff;  // instructions
  const bool has_handler = (header >> 20) & 1;
  const bool single_epilog = (header >> 21) & 1;
  uint32_t epilogs = (header >> 22) & 0x1f;
  uint32_t code_words = (header >> 27) & 0x1f;
  if (!epilogs && !code_words) {
    const uint32_t ext = *p++;
    epilogs = ext & 0xffff;
    code_words = (ext >> 16) & 0xff;
  }
  const uint32_t* scopes = p;
  if (!single_epilog) p += epilogs;
  const auto* codes = reinterpret_cast<const uint8_t*>(p);
  const uint8_t* end = codes + 4 * code_words;

  const uint32_t offset = static_cast<uint32_t>((pc - (base + f.begin)) / 4);
  const uint8_t* start = codes;
  bool in_prolog_or_epilog = false;

  const unsigned prolog = sequence_length(codes, end);
  if (at_call) {
    // pc is a return address: the call was in the body, even if the return
    // address is the first epilog instruction or the end of the function
    // (a call that doesn't return).
  } else if (offset < prolog) {
    // Only the first `offset` prolog instructions ran: skip the codes of the
    // others (codes are in reverse prolog order).
    start = skip_codes(codes, end, prolog - offset);
    in_prolog_or_epilog = true;
  } else {
    auto check_epilog = [&](uint32_t epilog_start, uint32_t index) {
      const uint8_t* epilog_codes = codes + index;
      const unsigned len = sequence_length(epilog_codes, end);
      if (offset >= epilog_start && offset <= epilog_start + len) {
        // Epilog codes are in epilog order: skip those already executed.
        start = skip_codes(epilog_codes, end, offset - epilog_start);
        in_prolog_or_epilog = true;
      }
    };
    if (single_epilog) {
      const unsigned len = sequence_length(codes + epilogs, end);
      if (length >= len + 1) check_epilog(length - len - 1, epilogs);
    } else {
      for (uint32_t i = 0; i < epilogs && !in_prolog_or_epilog; ++i)
        check_epilog(scopes[i] & 0x3ffff, scopes[i] >> 22);
    }
  }

  execute_codes(start, end, c);
  if (has_handler && !in_prolog_or_epilog) {
    const auto* h = reinterpret_cast<const uint32_t*>(end);
    r.handler = base + h[0];
    r.handler_data = reinterpret_cast<uint64_t>(h + 1);
  }
  return r;
}

void unwind_packed(uint64_t base, uint64_t pc, const RuntimeFunction& f, Context& c, bool at_call) {
  const uint32_t d = f.unwind_data;
  const unsigned flag = d & 3, function_length = (d >> 2) & 0x7ff, reg_f = (d >> 13) & 7, reg_i = (d >> 16) & 0xf,
                 h = (d >> 20) & 1, cr = (d >> 21) & 3, frame_size = (d >> 23) & 0x1ff;

  unsigned int_size = reg_i * 8, fp_size = reg_f * 8;
  if (cr == 1) int_size += 8;
  if (reg_f) fp_size += 8;
  const unsigned regsave = (int_size + fp_size + 8 * 8 * h + 0xf) & ~0xfu;
  const unsigned local_size = frame_size * 16 - regsave;
  const int int_regs = static_cast<int>(int_size / 8), fp_regs = static_cast<int>(fp_size / 8);
  const int saved_regs = static_cast<int>(regsave / 8), local_size_regs = static_cast<int>(local_size / 8);

  unsigned skip = 0;
  if (flag == 1 && !at_call) {
    const unsigned offset = static_cast<unsigned>((pc - (base + f.begin)) / 4);
    if (offset < 17 || offset + 15 >= function_length) {
      unsigned len = (int_size + 8) / 16 + (fp_size + 8) / 16;
      switch (cr) {
        case 2:
          ++len;  // pacibsp
          [[fallthrough]];
        case 3:
          len += 2;  // stp x29,lr,[sp,...] and mov x29,sp
          if (local_size <= 512) break;
          [[fallthrough]];
        default:
          if (local_size) ++len;
          if (local_size > 4088) ++len;
          break;
      }
      if (offset < len + 4 * h) {
        skip = len + 4 * h - offset;  // prolog
      } else if (offset + len + 1 >= function_length) {
        skip = offset - (function_length - (len + 1));  // epilog
      }
    }
  }

  if (!skip) {
    if (cr == 2 || cr == 3) {
      c.sp = c.x[29];
      restore_regs(c, 29, 2, 0);
    }
    c.sp += local_size;
    if (fp_size) restore_fpregs(c, 8, fp_regs, int_regs);
    if (cr == 1) restore_regs(c, 30, 1, int_regs - 1);
    restore_regs(c, 19, static_cast<int>(reg_i), -saved_regs);
    return;
  }

  unsigned pos = 0;
  switch (cr) {
    case 2:
    case 3:
      if (local_size <= 512) {
        if (pos++ >= skip) restore_regs(c, 29, 2, -local_size_regs);  // stp x29,lr,[sp,-#local_size]!
        break;
      }
      if (pos++ >= skip) restore_regs(c, 29, 2, 0);  // stp x29,lr,[sp,0]
      [[fallthrough]];
    default:
      if (!local_size) break;
      if (pos++ >= skip) c.sp += (local_size - 1) % 4088 + 1;  // sub sp,sp,#local_size
      if (local_size > 4088 && pos++ >= skip) c.sp += 4088;
      break;
  }
  if (h) pos += 4;
  if (fp_size) {
    if (reg_f % 2 == 0 && pos++ >= skip) restore_fpregs(c, 8 + reg_f, 1, int_regs + fp_regs - 1);
    for (int i = static_cast<int>((reg_f + 1) / 2) - 1; i >= 0; --i) {
      if (pos++ < skip) continue;
      if (!i && !int_size) {
        restore_fpregs(c, 8, 2, -saved_regs);
      } else {
        restore_fpregs(c, 8 + 2 * i, 2, int_regs + 2 * i);
      }
    }
  }
  if (reg_i % 2) {
    if (pos++ >= skip) {
      if (cr == 1) {
        restore_regs(c, 18 + reg_i, 2, int_regs - 2);  // stp xn,lr
      } else {
        restore_regs(c, 18 + reg_i, 1, reg_i > 1 ? static_cast<int>(reg_i) - 1 : -saved_regs);
      }
    }
  } else if (cr == 1) {
    if (pos++ >= skip) restore_regs(c, 30, 1, reg_i ? int_regs - 1 : -saved_regs);  // str lr
  }
  for (int i = static_cast<int>(reg_i / 2) - 1; i >= 0; --i) {
    if (pos++ < skip) continue;
    if (i) {
      restore_regs(c, 19 + 2 * i, 2, 2 * i);
    } else {
      restore_regs(c, 19, 2, -saved_regs);
    }
  }
}

}  // namespace

uint32_t function_length(uint64_t image_base, const RuntimeFunction& f) {
  if (f.unwind_data & 3) return ((f.unwind_data >> 2) & 0x7ff) * 4;
  const auto* header = reinterpret_cast<const uint32_t*>(image_base + f.unwind_data);
  return (*header & 0x3ffff) * 4;
}

UnwindResult virtual_unwind(uint64_t image_base, uint64_t pc, const RuntimeFunction* f, Context& context) {
  UnwindResult r;
  const bool at_call = context.flags & kContextUnwoundToCall;
  context.pc = 0;
  if (!f) {
    // Leaf function: nothing saved, the return address is still in lr.
  } else if (f->unwind_data & 3) {
    unwind_packed(image_base, pc, *f, context, at_call);
  } else {
    r = unwind_full(image_base, pc, *f, context, at_call);
  }
  if (!context.pc) context.pc = context.x[30];  // unless a machine frame or context code supplied it
  context.flags |= kContextUnwoundToCall;
  r.establisher_frame = context.sp;
  return r;
}

}  // namespace juice::win::arm64eh
