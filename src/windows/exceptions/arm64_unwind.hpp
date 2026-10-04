#pragma once

// Windows ARM64 exception handling data: the ARM64 CONTEXT and
// DISPATCHER_CONTEXT layouts as guest code sees them, and the virtual
// unwinder for the .pdata/.xdata unwind information of ARM64 images.
//
// These are the guest's structures, so they are defined here rather than
// taken from the (x64) Windows headers.

#include <cstddef>
#include <cstdint>

namespace juice::win::arm64eh {

struct Neon128 {
  uint64_t lo;
  uint64_t hi;
};

// CONTEXT on ARM64.
struct alignas(16) Context {
  uint32_t flags;
  uint32_t cpsr;
  uint64_t x[31];  // X0..X28, Fp (X29), Lr (X30)
  uint64_t sp;
  uint64_t pc;
  Neon128 v[32];
  uint32_t fpcr;
  uint32_t fpsr;
  uint32_t bcr[8];
  uint64_t bvr[8];
  uint32_t wcr[2];
  uint64_t wvr[2];
};
static_assert(offsetof(Context, sp) == 0x100 && offsetof(Context, v) == 0x110 && offsetof(Context, fpcr) == 0x310);
static_assert(sizeof(Context) == 0x390);

inline constexpr uint32_t kContextFull = 0x00400007;           // CONTEXT_ARM64 | CONTROL | INTEGER | FLOATING_POINT
inline constexpr uint32_t kContextUnwoundToCall = 0x20000000;  // pc is a return address

// RUNTIME_FUNCTION (.pdata entry).
struct RuntimeFunction {
  uint32_t begin;        // RVA
  uint32_t unwind_data;  // RVA of .xdata, or packed unwind data if the low two bits are nonzero
};

// DISPATCHER_CONTEXT on ARM64.
struct DispatcherContext {
  uint64_t control_pc;
  uint64_t image_base;
  uint64_t function_entry;  // RuntimeFunction*
  uint64_t establisher_frame;
  uint64_t target_pc;
  uint64_t context_record;  // Context*
  uint64_t language_handler;
  uint64_t handler_data;
  uint64_t history_table;
  uint32_t scope_index;
  uint8_t control_pc_is_unwound;
  uint8_t reserved[3];
  uint64_t non_volatile_registers;
};
static_assert(offsetof(DispatcherContext, scope_index) == 0x48 && sizeof(DispatcherContext) == 0x58);

// Length in bytes of the function (or function fragment) `f` describes.
uint32_t function_length(uint64_t image_base, const RuntimeFunction& f);

struct UnwindResult {
  uint64_t handler = 0;       // language handler, if the pc is in the body of a function that has one
  uint64_t handler_data = 0;  // its data (follows the handler RVA in .xdata)
  uint64_t establisher_frame = 0;  // SP on entry to the function
};

// Unwind one frame: `context` describes the state at `pc` inside the function
// `f` (nullptr for a leaf function without unwind information) and becomes the
// caller's state, with pc = the return address and kContextUnwoundToCall set.
// If `context` already has kContextUnwoundToCall, `pc` is a return address
// and the call it returns from counts as part of the function body.
// Guest memory is read directly (guest and host share the address space).
UnwindResult virtual_unwind(uint64_t image_base, uint64_t pc, const RuntimeFunction* f, Context& context);

}  // namespace juice::win::arm64eh
