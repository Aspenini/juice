#pragma once

// Machine code for crossing between JUICE and native x86-64 System V code:
//
//   call_native()   calls a native function with the registers and stack of
//                   a HostCall (call_convert.hpp) and captures its result
//                   registers;
//   native_entry()  is code native code can call as a System V function: it
//                   captures the arguments in a HostFrame and calls a
//                   handler, which runs guest code and fills the result.
//
// Both are callable from (and call) the host's own C++ convention, so they
// work on any x86-64 host: on Windows, the tests use them with clang's
// sysv_abi functions.

#include <cstdint>

#include "macos/abi/call_convert.hpp"

namespace juice::mac {

// Calls `fn` (a System V function). `x87_result`: the function returns a
// long double (in ST0).
void call_native(void* fn, HostCall& call, HostResult& result, bool x87_result = false);

// What native_entry() gives its handler.
struct EntryFrame {
  HostFrame args;
  uint64_t target = 0;  // R11 at entry: which guest function (set by whoever redirected the call)
  HostResult result;    // filled by the handler
  bool x87_result = false;  // the handler sets it to return result.st0 in ST0
};

using EntryHandler = void (*)(EntryFrame& frame);

// A System V function that captures its arguments (with R11 as `target`)
// and calls `handler`. One per handler; the code stays valid for the
// process's lifetime.
void* native_entry(EntryHandler handler);

}  // namespace juice::mac
