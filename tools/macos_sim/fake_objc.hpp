#pragma once

// A small Objective-C runtime for juice-macos-sim: enough of the native
// runtime's functions for the bridge (classes in the objc2 layout, method
// lookup through method lists and superclasses, categories), plus a native
// NSObject whose methods are System V functions.

#include <vector>

#include "macos/objc/objc_bridge.hpp"

namespace juice::sim {

struct FakeSymbol {
  const char* name;  // as dlsym names it
  void* address;
  bool code;
};

// The native symbols: objc_msgSend, objc_alloc_init, the NSObject class and
// metaclass, _objc_empty_cache, retain/release, NSObject's method implementations.
std::vector<FakeSymbol> fake_objc_symbols();

// The runtime functions the bridge calls.
juice::mac::ObjcRuntime fake_objc_runtime();

// The C++ ABI (fake_cxxabi.cpp): exceptions, type_info vtables, operator new.
std::vector<FakeSymbol> fake_cxxabi_symbols();

}  // namespace juice::sim
