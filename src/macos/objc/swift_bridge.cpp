#include "macos/objc/swift_bridge.hpp"

#include <cstdio>

namespace juice::mac {

SwiftBridge::RegisterFn SwiftBridge::function(const char* name) {
  return reinterpret_cast<RegisterFn>(p_.native().find_symbol(nullptr, name));
}

void SwiftBridge::register_image(GuestImage& image) {
  struct Records {
    const char* section;
    const char* function;
  };
  // Protocols before conformances (which refer to them), types with them.
  static constexpr Records kRecords[] = {
      {"__swift5_protos", "swift_registerProtocols"},
      {"__swift5_types", "swift_registerTypeMetadataRecords"},
      {"__swift5_proto", "swift_registerProtocolConformances"},
  };
  for (const Records& r : kRecords) {
    const auto [begin, end] = image.section_range("__TEXT", r.section);
    if (begin == end) continue;
    RegisterFn fn = function(r.function);
    if (!fn) {
      std::fprintf(stderr, "juice: %s uses Swift, but the Swift runtime has no %s\n", image.path.c_str(), r.function);
      continue;
    }
    if (p_.options().trace_binds)
      std::fprintf(stderr, "[juice] swift: %s: %s (%llu bytes)\n", image.path.c_str(), r.section,
                   static_cast<unsigned long long>(end - begin));
    fn(reinterpret_cast<const void*>(begin), reinterpret_cast<const void*>(end));
  }
}

void SwiftBridge::install() {
  p_.add_image_hooks([this](GuestImage& i) { register_image(i); }, nullptr);
}

}  // namespace juice::mac
