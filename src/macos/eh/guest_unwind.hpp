#pragma once

// Unwinding guest (ARM64 Mach-O) frames: compact unwind information
// (__TEXT,__unwind_info) and DWARF call frame information (__TEXT,__eh_frame,
// for functions compact unwind can't describe), as Apple's libunwind reads them.

#include <cstdint>
#include <functional>
#include <span>

namespace juice::mac {

// The registers unwinding restores: X0-X30, SP, PC and D8-D15.
struct GuestFrame {
  uint64_t x[31] = {};
  uint64_t sp = 0;
  uint64_t pc = 0;  // a return address (or, for the first frame, where execution is)
  uint64_t d[8] = {};  // D8-D15
};

// How to unwind one function.
struct FrameUnwindInfo {
  uint64_t start = 0, end = 0;  // the function
  uint64_t lsda = 0;            // language-specific data (0: none)
  uint64_t personality = 0;     // the personality routine's address (0: none)
  uint32_t encoding = 0;        // compact unwind encoding (when !dwarf)
  bool dwarf = false;
  uint64_t fde = 0;             // the DWARF FDE (when dwarf)
};

// Where an image's unwind sections are (runtime addresses).
struct UnwindSections {
  uint64_t header = 0;  // the image's mach header (compact unwind offsets are from it)
  uint64_t unwind_info = 0, unwind_info_size = 0;
  uint64_t eh_frame = 0, eh_frame_size = 0;
};

// Reads `size` bytes at `addr` (guest memory); false if it isn't readable.
using MemoryReader = std::function<bool(uint64_t addr, void* out, size_t size)>;

// The unwind information of the function containing `pc`.
bool find_unwind_info(const UnwindSections& sections, uint64_t pc, FrameUnwindInfo& out, const MemoryReader& read);

// Unwinds `frame` (in the function described by `info`) to its caller:
// restores the callee-saved registers, SP, and sets PC to the return
// address. False if the information can't be applied.
bool step_frame(GuestFrame& frame, const FrameUnwindInfo& info, const MemoryReader& read);

// Reads a DWARF exception-handling pointer of `encoding` at `*addr` (and
// advances it); `datarel`/`funcrel` bases may be 0.
bool read_encoded_pointer(uint64_t& addr, uint8_t encoding, uint64_t& out, const MemoryReader& read,
                          uint64_t func_base = 0);

}  // namespace juice::mac
