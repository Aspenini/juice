#pragma once

// Objective-C for guest programs, on the host's Objective-C runtime.
//
// The guest's classes, categories, protocols and selectors are registered
// with the native runtime (in place: guest classes are the native runtime's
// classes, so native code subclasses, messages and introspects them like
// any other), and every guest method's type is recorded so that native code
// calling it (objc_msgSend from AppKit, ...) gets its arguments converted.
// The metadata layouts are the same on ARM64 and x86-64.
//
// Guest calls of objc_msgSend are JUICE's: a guest method is entered
// directly (no conversion), a native one is called with arguments converted
// per its type encoding.
//
// The native runtime is reached through ObjcRuntime (dlsym on macOS), so the
// bridge builds - and its tests run - anywhere.

#include <cstdint>
#include <initializer_list>
#include <string>
#include <unordered_map>

#include "macos/process/mac_process.hpp"

namespace juice::mac {

// The native runtime's functions JUICE uses (host calling convention).
struct ObjcRuntime {
  void* (*objc_readClassPair)(void* cls, const void* image_info) = nullptr;
  void* (*objc_getClass)(const char* name) = nullptr;
  void* (*objc_getProtocol)(const char* name) = nullptr;
  void* (*objc_allocateProtocol)(const char* name) = nullptr;
  void (*objc_registerProtocol)(void* protocol) = nullptr;
  void (*protocol_addMethodDescription)(void* protocol, void* sel, const char* types, bool required,
                                        bool instance) = nullptr;
  void (*protocol_addProtocol)(void* protocol, void* addition) = nullptr;
  void* (*sel_registerName)(const char* name) = nullptr;
  const char* (*sel_getName)(void* sel) = nullptr;
  void* (*object_getClass)(void* object) = nullptr;
  void* (*class_getSuperclass)(void* cls) = nullptr;
  const char* (*class_getName)(void* cls) = nullptr;
  bool (*class_isMetaClass)(void* cls) = nullptr;
  void* (*class_getInstanceMethod)(void* cls, void* sel) = nullptr;
  void* (*class_getMethodImplementation)(void* cls, void* sel) = nullptr;
  void* (*class_getMethodImplementation_stret)(void* cls, void* sel) = nullptr;
  void* (*class_replaceMethod)(void* cls, void* sel, void* imp, const char* types) = nullptr;
  bool (*class_addProtocol)(void* cls, void* protocol) = nullptr;
  const char* (*method_getTypeEncoding)(void* method) = nullptr;
  void* objc_msgSend = nullptr;  // (called through the conversion, not directly)

  // Fills the table from the host's libraries; false if the runtime is missing.
  bool load(NativeSystem& native);
};

class ObjcBridge {
 public:
  ObjcBridge(MacProcess& process, const ObjcRuntime& runtime);

  // Installs the bridge: the objc_msgSend builtins and the image hooks.
  void install();

  // Registers an image's Objective-C metadata (after binding).
  void register_image(GuestImage& image);
  // Calls the +load methods of an image's classes and categories (before its initializers).
  void call_load_methods(GuestImage& image);

  // objc_msgSend's work for a guest call: receiver in X0, selector in X1
  // (`super_class`: start the lookup there instead, objc_msgSendSuper).
  void message(arm64::CpuState& s, void* super_class);

  // A block's signature, if `block` is a block whose invoke function is `fn`.
  const char* block_signature(uint64_t block, uint64_t fn) const;

  const ObjcRuntime& runtime() const { return rt_; }
  static ObjcBridge* instance();

 private:
  void* register_class(GuestImage& image, uint64_t cls, int depth = 0);
  void* native_protocol(uint64_t guest_protocol);
  void record_method_types(uint64_t method_list);
  void add_category(GuestImage& image, uint64_t category);
  void call_native_method(arm64::CpuState& s, void* cls, void* sel, uint64_t imp);
  // Sends a message natively (integer and pointer arguments).
  uint64_t send(uint64_t receiver, const char* selector, std::initializer_list<uint64_t> args = {});

  MacProcess& p_;
  ObjcRuntime rt_;
  std::unordered_map<uint64_t, void*> protocols_;  // guest protocol_t -> native Protocol
  std::unordered_map<uint64_t, bool> registered_;  // guest classes done
  std::unordered_map<uint64_t, uint64_t> load_imps_;  // guest class -> its +load
  std::unordered_map<uint64_t, bool> loaded_;         // +load called
  uint64_t image_info_ = 0;
  void* load_sel_ = nullptr;
};

}  // namespace juice::mac
