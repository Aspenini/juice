#pragma once

// Swift for guest programs, on the host's Swift runtime.
//
// The Swift runtime finds types, protocols and conformances in the images
// dyld tells it about, which guest images aren't. Their records are handed
// to it through the registration functions it exports for that purpose
// (swift_registerTypeMetadataRecords, ...). The metadata layouts are the same
// on ARM64 and x86-64 (relative pointers); functions in them are guest code,
// which native code calls through the fault path like any other.
//
// Swift classes that are also Objective-C classes are then found by the
// Swift runtime's objc_getClass hook; they aren't registered with
// objc_readClassPair (see ObjcBridge).

#include "macos/process/mac_process.hpp"

namespace juice::mac {

class SwiftBridge {
 public:
  explicit SwiftBridge(MacProcess& process) : p_(process) {}

  // Registers the image hook.
  void install();

  // Hands an image's Swift records to the runtime (nothing if it has none).
  void register_image(GuestImage& image);

 private:
  using RegisterFn = void (*)(const void* begin, const void* end);
  RegisterFn function(const char* name);

  MacProcess& p_;
};

}  // namespace juice::mac
