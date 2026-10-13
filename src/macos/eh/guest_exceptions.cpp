#include "macos/eh/guest_exceptions.hpp"

#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <format>
#include <tuple>

#include "macos/abi/trampolines.hpp"
#include "macos/process/mac_process.hpp"

namespace juice::mac {

namespace {

// The C++ exception header (libc++abi's __cxa_exception on 64-bit) as
// offsets from its _Unwind_Exception, which is its last member.
constexpr int64_t kPrimaryException = -88;  // __cxa_dependent_exception::primaryException
constexpr int64_t kExceptionType = -80;
constexpr int64_t kHandlerSwitchValue = -36;  // int
constexpr int64_t kActionRecord = -32;
constexpr int64_t kLanguageSpecificData = -24;
constexpr int64_t kCatchTemp = -16;
constexpr int64_t kAdjustedPtr = -8;
constexpr uint64_t kUnwindExceptionSize = 32;  // the thrown object follows

// "CLNGC++\0" (and "\1" for a dependent exception: std::rethrow_exception), "GNUCC++\0".
bool is_cxx(uint64_t exception_class) {
  const uint64_t vendor = exception_class & ~uint64_t{0xFF};
  return vendor == 0x434C4E47432B2B00ull || vendor == 0x474E5543432B2B00ull;
}

template <typename T>
T at(uint64_t addr) {
  T v;
  std::memcpy(&v, reinterpret_cast<const void*>(addr), sizeof(T));
  return v;
}
template <typename T>
void put(uint64_t addr, T v) {
  std::memcpy(reinterpret_cast<void*>(addr), &v, sizeof(T));
}

// The handler found by the search, per exception in flight on this thread:
// identified by its frame's CFA.
thread_local std::unordered_map<uint64_t, uint64_t> t_handler_cfa;

GuestFrame frame_from(const arm64::CpuState& s) {
  GuestFrame f;
  std::memcpy(f.x, s.x, sizeof(f.x));
  f.sp = s.sp;
  f.pc = s.x[30];  // the return address of the call that raised
  for (int k = 0; k < 8; ++k) f.d[k] = s.v[8 + k].lo;
  return f;
}

}  // namespace

GuestExceptions::GuestExceptions(MacProcess& process) : p_(process) {
  read_ = [](uint64_t addr, void* out, size_t size) {
    if (addr < 0x1000) return false;
    std::memcpy(out, reinterpret_cast<const void*>(addr), size);
    return true;
  };
  NativeSystem& native = p_.native();
  gxx_personality_ = reinterpret_cast<uint64_t>(native.find_symbol(nullptr, "__gxx_personality_v0"));
  objc_personality_ = reinterpret_cast<uint64_t>(native.find_symbol(nullptr, "__objc_personality_v0"));
  gcc_personality_ = reinterpret_cast<uint64_t>(native.find_symbol(nullptr, "__gcc_personality_v0"));
}

bool GuestExceptions::frame_info(uint64_t pc, FrameUnwindInfo& info) {
  const GuestImage* image = p_.image_at(pc);
  if (!image || !image->is_code(pc)) return false;
  UnwindSections s;
  s.header = image->header();
  std::tie(s.unwind_info, s.unwind_info_size) = image->section_range("__TEXT", "__unwind_info");
  s.unwind_info_size -= s.unwind_info;
  std::tie(s.eh_frame, s.eh_frame_size) = image->section_range("__TEXT", "__eh_frame");
  s.eh_frame_size -= s.eh_frame;
  return find_unwind_info(s, pc, info, read_);
}

bool GuestExceptions::known_personality(uint64_t personality) {
  if (!personality) return false;
  if (personality == gxx_personality_ || personality == objc_personality_ || personality == gcc_personality_)
    return true;
  static bool warned = false;
  if (!warned) {
    warned = true;
    std::fprintf(stderr, "juice: exceptions: frames with personality 0x%" PRIx64 " (%s) are passed over\n",
                 personality, p_.native().describe(personality).c_str());
  }
  return false;
}

bool GuestExceptions::can_catch(uint64_t catch_type, uint64_t exception, uint64_t& adjusted) {
  if (!catch_type) return true;  // catch (...)
  const uint64_t exception_class = at<uint64_t>(exception);
  if (!is_cxx(exception_class)) return false;  // foreign exceptions: only catch (...)
  const uint64_t thrown_type = at<uint64_t>(exception + kExceptionType);
  uint64_t candidate = (exception_class & 0xFF) == 1 ? at<uint64_t>(exception + kPrimaryException)
                                                    : exception + kUnwindExceptionSize;
  // The catch type's own can_catch(thrown_type, void*& adjusted): slot 4 of
  // the type_info vtable, in libc++abi and in libobjc (Objective-C catches).
  const uint64_t vtable = at<uint64_t>(catch_type);
  const uint64_t fn = at<uint64_t>(vtable + 4 * 8);
  HostCall call;
  call.gpr[0] = catch_type;
  call.gpr[1] = thrown_type;
  call.gpr[2] = reinterpret_cast<uint64_t>(&candidate);
  HostResult result;
  call_native(reinterpret_cast<void*>(fn), call, result);
  if (result.exception || !(result.rax & 0xFF)) return false;
  adjusted = candidate;
  return true;
}

// The call-site table of the frame's LSDA, as libc++abi's personality reads it.
GuestExceptions::Scan GuestExceptions::scan(const FrameUnwindInfo& info, uint64_t return_address, uint64_t exception,
                                            bool search) {
  Scan none;
  uint64_t p = info.lsda;
  const uint64_t ip = return_address - 1 - info.start;
  uint8_t lp_start_encoding, ttype_encoding, call_site_encoding;
  if (!read_(p++, &lp_start_encoding, 1)) return none;
  uint64_t lp_start = info.start;
  if (lp_start_encoding != 0xFF && !read_encoded_pointer(p, lp_start_encoding, lp_start, read_)) return none;
  if (!read_(p++, &ttype_encoding, 1)) return none;
  uint64_t class_info = 0;
  if (ttype_encoding != 0xFF) {
    uint64_t offset = 0;
    for (unsigned shift = 0;; shift += 7) {
      uint8_t b;
      if (!read_(p++, &b, 1) || shift > 63) return none;
      offset |= uint64_t{b & 0x7Fu} << shift;
      if (!(b & 0x80)) break;
    }
    class_info = p + offset;
  }
  if (!read_(p++, &call_site_encoding, 1)) return none;
  uint64_t table_length = 0;
  if (!read_encoded_pointer(p, 0x01, table_length, read_)) return none;  // uleb128
  const uint64_t table_end = p + table_length;
  const uint64_t action_table = table_end;
  auto sleb = [&](uint64_t& q, int64_t& out) {
    out = 0;
    unsigned shift = 0;
    uint8_t b;
    do {
      if (!read_(q++, &b, 1) || shift > 63) return false;
      out |= int64_t{b & 0x7F} << shift;
      shift += 7;
    } while (b & 0x80);
    if (shift < 64 && (b & 0x40)) out |= -(int64_t{1} << shift);
    return true;
  };
  // Call-site fields are offsets in the encoding's format (no pc-relative adjustment).
  const uint8_t field_encoding = call_site_encoding & 0x0F;

  while (p < table_end) {
    uint64_t start, length, landing_pad, action;
    if (!read_encoded_pointer(p, field_encoding, start, read_) ||
        !read_encoded_pointer(p, field_encoding, length, read_) ||
        !read_encoded_pointer(p, field_encoding, landing_pad, read_) || !read_encoded_pointer(p, 0x01, action, read_))
      return none;
    if (ip < start) return none;  // (the table is sorted: not covered)
    if (ip >= start + length) continue;
    if (!landing_pad) return none;  // no landing pad: nothing to do in this frame
    Scan r;
    r.landing_pad = lp_start + landing_pad;
    if (action == 0) {
      r.kind = Scan::Cleanup;
      return r;
    }
    // The action chain: type indexes (positive: catch, 0: cleanup, negative: exception specification).
    bool cleanup = false;
    uint64_t record = action_table + action - 1;
    for (;;) {
      const uint64_t this_record = record;
      int64_t type_index, next;
      if (!sleb(record, type_index)) return none;
      const uint64_t next_field = record;
      if (!sleb(record, next)) return none;
      if (type_index > 0) {
        // The type table grows down from class_info, one encoded pointer per index.
        const unsigned size = (ttype_encoding & 0x0F) == 0x02 ? 2 : (ttype_encoding & 0x0F) == 0x03 ||
                                                                     (ttype_encoding & 0x0F) == 0x0B ? 4 : 8;
        uint64_t entry = class_info - static_cast<uint64_t>(type_index) * size;
        uint64_t catch_type = 0;
        if (!read_encoded_pointer(entry, ttype_encoding, catch_type, read_)) return none;
        uint64_t adjusted = 0;
        if (can_catch(catch_type, exception, adjusted)) {
          r.kind = Scan::Handler;
          r.selector = type_index;
          r.action_record = this_record;
          r.adjusted = adjusted;
          return r;
        }
      } else if (type_index == 0) {
        cleanup = true;
      }
      // (Negative indexes, dynamic exception specifications, aren't matched.)
      if (next == 0) break;
      record = next_field + static_cast<uint64_t>(next);
    }
    if (cleanup && !search) {
      r.kind = Scan::Cleanup;
      return r;
    }
    return none;
  }
  return none;
}

uint64_t GuestExceptions::frame_cfa(const GuestFrame& frame, const FrameUnwindInfo& info) {
  GuestFrame caller = frame;
  return step_frame(caller, info, read_) ? caller.sp : 0;
}

void GuestExceptions::land(const GuestFrame& f, uint64_t landing_pad, uint64_t exception, int64_t selector) {
  MacThread& t = p_.thread();
  arm64::CpuState& s = *t.active;
  for (int k = 19; k < 31; ++k) s.x[k] = f.x[k];
  s.sp = f.sp;
  for (int k = 0; k < 8; ++k) s.v[8 + k] = {f.d[k], 0};
  s.x[0] = exception;
  s.x[1] = static_cast<uint64_t>(selector);
  s.pc = landing_pad;
  throw GuestLanding{};
}

void GuestExceptions::raise_natively(uint64_t exception) {
  t_handler_cfa.erase(exception);
  p_.native().raise_exception(exception);
  // Nothing handles it: terminate as the C++ runtime does, with the exception
  // caught so that its terminate handler (and Objective-C's) can report it.
  NativeSystem& native = p_.native();
  if (void* begin_catch = native.find_symbol(nullptr, "__cxa_begin_catch"); begin_catch && is_cxx(at<uint64_t>(exception))) {
    HostCall call;
    call.gpr[0] = exception;
    HostResult result;
    call_native(begin_catch, call, result);
  }
  if (void* terminate = native.find_symbol(nullptr, "_ZSt9terminatev")) {
    HostCall call;
    HostResult result;
    call_native(terminate, call, result);
  }
  std::fputs("juice: uncaught exception\n", stderr);
  std::abort();
}

void GuestExceptions::unwind(GuestFrame f, uint64_t exception) {
  const auto it = t_handler_cfa.find(exception);
  const uint64_t handler_cfa = it == t_handler_cfa.end() ? 0 : it->second;
  for (unsigned depth = 0; depth < 100000; ++depth) {
    FrameUnwindInfo info;
    if (!frame_info(f.pc - 1, info)) break;  // the end of this call level's guest frames
    if (info.lsda && known_personality(info.personality)) {
      const bool handler_frame = handler_cfa && frame_cfa(f, info) == handler_cfa;
      const Scan r = scan(info, f.pc, exception, false);
      if (r.kind == Scan::Handler && handler_frame) {
        t_handler_cfa.erase(exception);
        land(f, r.landing_pad, exception, r.selector);
      }
      if (r.kind == Scan::Cleanup || (r.kind == Scan::Handler && !handler_frame)) land(f, r.landing_pad, exception, 0);
    }
    if (!step_frame(f, info, read_)) break;
  }
  raise_natively(exception);
}

void GuestExceptions::native_exception(uint64_t exception) {
  MacThread& t = p_.thread();
  if (!t.active) raise_natively(exception);
  const GuestFrame start = frame_from(*t.active);
  // Search for a handler in this call level's frames.
  GuestFrame f = start;
  for (unsigned depth = 0; depth < 100000; ++depth) {
    FrameUnwindInfo info;
    if (!frame_info(f.pc - 1, info)) break;
    if (info.lsda && known_personality(info.personality)) {
      const Scan r = scan(info, f.pc, exception, true);
      if (r.kind == Scan::Handler) {
        if (is_cxx(at<uint64_t>(exception))) {
          // What __cxa_begin_catch and the C++ runtime read.
          put<int32_t>(exception + kHandlerSwitchValue, static_cast<int32_t>(r.selector));
          put<uint64_t>(exception + kActionRecord, r.action_record);
          put<uint64_t>(exception + kLanguageSpecificData, info.lsda);
          put<uint64_t>(exception + kCatchTemp, r.landing_pad);
          put<uint64_t>(exception + kAdjustedPtr, r.adjusted);
        }
        t_handler_cfa[exception] = frame_cfa(f, info);
        break;
      }
    }
    if (!step_frame(f, info, read_)) break;
  }
  unwind(start, exception);
}

void GuestExceptions::resume(arm64::CpuState& s) { unwind(frame_from(s), s.x[0]); }

}  // namespace juice::mac
