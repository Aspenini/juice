#include "macos/objc/objc_bridge.hpp"

#include <cinttypes>
#include <cstdio>
#include <cstring>
#include <format>
#include <functional>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <string_view>
#include <type_traits>
#include <utility>

namespace juice::mac {

namespace {

ObjcBridge* g_bridge = nullptr;

uint64_t load64(uint64_t addr) {
  uint64_t v;
  std::memcpy(&v, reinterpret_cast<const void*>(addr), 8);
  return v;
}
uint32_t load32(uint64_t addr) {
  uint32_t v;
  std::memcpy(&v, reinterpret_cast<const void*>(addr), 4);
  return v;
}
int32_t load_rel(uint64_t addr) {
  int32_t v;
  std::memcpy(&v, reinterpret_cast<const void*>(addr), 4);
  return v;
}
void store64(uint64_t addr, uint64_t v) { std::memcpy(reinterpret_cast<void*>(addr), &v, 8); }

template <typename T>
T* ptr(uint64_t v) {
  return reinterpret_cast<T*>(static_cast<uintptr_t>(v));
}

// Objective-C metadata sections live in __DATA or __DATA_CONST (or __DATA_DIRTY).
std::span<uint64_t> objc_section(const GuestImage& image, std::string_view name) {
  for (std::string_view segment : {"__DATA_CONST", "__DATA", "__DATA_DIRTY"}) {
    auto s = image.section_data<uint64_t>(segment, name);
    if (!s.empty()) return s;
  }
  return {};
}

uint64_t objc_section_address(const GuestImage& image, std::string_view name) {
  for (std::string_view segment : {"__DATA_CONST", "__DATA", "__DATA_DIRTY"}) {
    const auto [begin, end] = image.section_range(segment, name);
    if (begin != end) return begin;
  }
  return 0;
}

// class_t: isa, superclass, cache, vtable, bits (class_ro_t* plus Swift flags).
constexpr uint64_t kClassDataMask = 0x00007ffffffffff8ull;
uint64_t class_ro(uint64_t cls) { return load64(cls + 32) & kClassDataMask; }
bool class_is_swift(uint64_t cls) { return load64(cls + 32) & 3; }
// class_ro_t: flags, instanceStart, instanceSize, reserved, ivarLayout, name, baseMethods, baseProtocols, ...
constexpr uint64_t kRoName = 24, kRoMethods = 32, kRoProtocols = 40;
// category_t: name, cls, instanceMethods, classMethods, protocols, ...
constexpr uint64_t kCatClass = 8, kCatInstanceMethods = 16, kCatClassMethods = 24, kCatProtocols = 32;
// protocol_t: isa, name, protocols, instanceMethods, classMethods, optionalInstanceMethods, optionalClassMethods
constexpr uint64_t kProtoName = 8, kProtoProtocols = 16, kProtoMethods = 24;

// One method of a method list (big: pointers; small: 32-bit relative offsets,
// the name through a selector reference).
struct Method {
  uint64_t name;      // big: the selector's name (char*) or SEL; small: the selector reference's address
  bool small;
  const char* types;
  uint64_t imp;
};

template <typename F>
void for_each_method(uint64_t list, F&& f) {
  if (!list) return;
  const uint32_t entsize_flags = load32(list), count = load32(list + 4);
  const bool small = entsize_flags & 0x80000000u;
  const uint32_t entsize = entsize_flags & 0xFFFCu;
  if (!entsize) return;
  for (uint32_t k = 0; k < count; ++k) {
    const uint64_t e = list + 8 + uint64_t{k} * entsize;
    Method m;
    m.small = small;
    if (small) {
      m.name = e + load_rel(e);
      m.types = ptr<const char>(e + 4 + load_rel(e + 4));
      const int32_t imp = load_rel(e + 8);
      m.imp = imp ? e + 8 + imp : 0;
    } else {
      m.name = load64(e);
      m.types = ptr<const char>(load64(e + 8));
      m.imp = load64(e + 16);
    }
    f(m);
  }
}

}  // namespace

bool ObjcRuntime::load(NativeSystem& native) {
  auto get = [&](auto& field, const char* name) {
    field = reinterpret_cast<std::remove_reference_t<decltype(field)>>(native.find_symbol(nullptr, name));
    return field != nullptr;
  };
  bool ok = true;
  ok &= get(objc_readClassPair, "objc_readClassPair");
  ok &= get(objc_getClass, "objc_getClass");
  ok &= get(objc_getProtocol, "objc_getProtocol");
  ok &= get(objc_allocateProtocol, "objc_allocateProtocol");
  ok &= get(objc_registerProtocol, "objc_registerProtocol");
  ok &= get(protocol_addMethodDescription, "protocol_addMethodDescription");
  ok &= get(protocol_addProtocol, "protocol_addProtocol");
  ok &= get(sel_registerName, "sel_registerName");
  ok &= get(sel_getName, "sel_getName");
  ok &= get(object_getClass, "object_getClass");
  ok &= get(class_getSuperclass, "class_getSuperclass");
  ok &= get(class_getName, "class_getName");
  ok &= get(class_isMetaClass, "class_isMetaClass");
  ok &= get(class_getInstanceMethod, "class_getInstanceMethod");
  ok &= get(class_getMethodImplementation, "class_getMethodImplementation");
  get(class_getMethodImplementation_stret, "class_getMethodImplementation_stret");
  ok &= get(class_replaceMethod, "class_replaceMethod");
  ok &= get(class_addProtocol, "class_addProtocol");
  ok &= get(method_getTypeEncoding, "method_getTypeEncoding");
  objc_msgSend = native.find_symbol(nullptr, "objc_msgSend");
  return ok && objc_msgSend;
}

ObjcBridge::ObjcBridge(MacProcess& process, const ObjcRuntime& runtime) : p_(process), rt_(runtime) {
  g_bridge = this;
}

ObjcBridge* ObjcBridge::instance() { return g_bridge; }

// --- Registration ----------------------------------------------------------------------------

void ObjcBridge::record_method_types(uint64_t list) {
  for_each_method(list, [&](const Method& m) {
    if (m.imp && m.types && p_.is_guest_code(m.imp)) p_.set_guest_signature(m.imp, m.types);
  });
}

void* ObjcBridge::native_protocol(uint64_t guest) {
  if (!guest) return nullptr;
  if (auto it = protocols_.find(guest); it != protocols_.end()) return it->second;
  if (!p_.image_at(guest)) return ptr<void>(guest);  // already a native protocol
  const char* name = ptr<const char>(load64(guest + kProtoName));
  void* native = rt_.objc_getProtocol(name);
  if (!native) {
    native = rt_.objc_allocateProtocol(name);
    if (!native) return nullptr;
    if (const uint64_t list = load64(guest + kProtoProtocols)) {
      const uint64_t count = load64(list);
      for (uint64_t k = 0; k < count; ++k)
        if (void* sub = native_protocol(load64(list + 8 + 8 * k))) rt_.protocol_addProtocol(native, sub);
    }
    // instance, class, optional instance, optional class methods
    for (int k = 0; k < 4; ++k) {
      const bool required = k < 2, instance = k % 2 == 0;
      for_each_method(load64(guest + kProtoMethods + 8 * k), [&](const Method& m) {
        void* sel = m.small ? ptr<void>(load64(m.name)) : rt_.sel_registerName(ptr<const char>(m.name));
        rt_.protocol_addMethodDescription(native, sel, m.types, required, instance);
      });
    }
    rt_.objc_registerProtocol(native);
  }
  protocols_[guest] = native;
  return native;
}

void* ObjcBridge::register_class(GuestImage& image, uint64_t cls, int depth) {
  if (!cls) return nullptr;
  if (registered_.contains(cls)) return ptr<void>(cls);
  GuestImage* owner = p_.image_at(cls);
  if (!owner) return ptr<void>(cls);  // a native class
  if (depth > 64) return nullptr;
  registered_[cls] = true;
  const uint64_t ro = class_ro(cls);
  const char* name = ptr<const char>(load64(ro + kRoName));
  if (class_is_swift(cls)) {
    if (p_.options().trace_calls) std::fprintf(stderr, "[juice] objc: Swift class %s left to the Swift runtime\n", name);
    return ptr<void>(cls);
  }

  // The superclass first: a guest one registered, a native one realized.
  if (const uint64_t super = load64(cls + 8)) {
    if (p_.image_at(super)) register_class(*p_.image_at(super), super, depth + 1);
    else rt_.class_getInstanceMethod(ptr<void>(super), rt_.sel_registerName("self"));
  }
  // The method types (and +load), before the runtime replaces the read-only data.
  const uint64_t meta = load64(cls);
  record_method_types(load64(ro + kRoMethods));
  if (meta && p_.image_at(meta)) {
    const uint64_t class_methods = load64(class_ro(meta) + kRoMethods);
    record_method_types(class_methods);
    for_each_method(class_methods, [&](const Method& m) {
      const bool is_load = m.small ? ptr<void>(load64(m.name)) == load_sel_
                                   : std::strcmp(ptr<const char>(m.name), "load") == 0;
      if (is_load && m.imp) load_imps_[cls] = m.imp;
    });
  }
  // Protocols the class adopts, as the native runtime knows them.
  if (const uint64_t list = load64(ro + kRoProtocols)) {
    const uint64_t count = load64(list);
    for (uint64_t k = 0; k < count; ++k)
      if (void* native = native_protocol(load64(list + 8 + 8 * k))) store64(list + 8 + 8 * k, reinterpret_cast<uint64_t>(native));
  }
  void* result = rt_.objc_readClassPair(ptr<void>(cls), ptr<const void>(image_info_));
  if (!result) std::fprintf(stderr, "juice: objc: class %s could not be registered (duplicate name?)\n", name);
  (void)image;
  return result;
}

void ObjcBridge::add_category(GuestImage& image, uint64_t category) {
  uint64_t cls = load64(category + kCatClass);
  if (!cls) return;  // a weakly linked class that doesn't exist
  if (p_.image_at(cls)) register_class(*p_.image_at(cls), cls);
  void* target = ptr<void>(cls);
  void* meta = rt_.object_getClass(target);
  auto add = [&](uint64_t list, void* to) {
    for_each_method(list, [&](const Method& m) {
      void* sel = m.small ? ptr<void>(load64(m.name)) : rt_.sel_registerName(ptr<const char>(m.name));
      if (m.imp && p_.is_guest_code(m.imp) && m.types) p_.set_guest_signature(m.imp, m.types);
      rt_.class_replaceMethod(to, sel, ptr<void>(m.imp), m.types);
    });
  };
  add(load64(category + kCatInstanceMethods), target);
  add(load64(category + kCatClassMethods), meta);
  if (const uint64_t list = load64(category + kCatProtocols)) {
    const uint64_t count = load64(list);
    for (uint64_t k = 0; k < count; ++k)
      if (void* native = native_protocol(load64(list + 8 + 8 * k))) rt_.class_addProtocol(target, native);
  }
  (void)image;
}

void ObjcBridge::register_image(GuestImage& image) {
  image_info_ = objc_section_address(image, "__objc_imageinfo");
  if (!load_sel_) load_sel_ = rt_.sel_registerName("load");
  // Selectors: the guest's references become the runtime's unique selectors.
  for (uint64_t& ref : objc_section(image, "__objc_selrefs"))
    if (ref) ref = reinterpret_cast<uint64_t>(rt_.sel_registerName(ptr<const char>(ref)));
  for (uint64_t guest : objc_section(image, "__objc_protolist")) native_protocol(guest);
  for (uint64_t& ref : objc_section(image, "__objc_protorefs"))
    if (void* native = native_protocol(ref)) ref = reinterpret_cast<uint64_t>(native);
  for (uint64_t cls : objc_section(image, "__objc_classlist")) register_class(image, cls);
  for (std::string_view list : {"__objc_catlist", "__objc_catlist2"})
    for (uint64_t category : objc_section(image, list)) add_category(image, category);
}

void ObjcBridge::call_load_methods(GuestImage& image) {
  auto find_load = [&](uint64_t list) -> uint64_t {
    uint64_t found = 0;
    for_each_method(list, [&](const Method& m) {
      const char* name = m.small ? rt_.sel_getName(ptr<void>(load64(m.name))) : ptr<const char>(m.name);
      if (name && std::strcmp(name, "load") == 0) found = m.imp;
    });
    return found;
  };
  // Classes' +load, superclasses first (as recorded at registration: calling
  // into the runtime for them would run +initialize too early).
  std::function<void(uint64_t)> load_class = [&](uint64_t cls) {
    if (!cls || loaded_.contains(cls) || !p_.image_at(cls)) return;
    loaded_[cls] = true;
    load_class(reinterpret_cast<uint64_t>(rt_.class_getSuperclass(ptr<void>(cls))));
    if (auto it = load_imps_.find(cls); it != load_imps_.end())
      p_.call_guest(it->second, {cls, reinterpret_cast<uint64_t>(load_sel_)});
  };
  for (uint64_t cls : objc_section(image, "__objc_nlclslist")) load_class(cls);
  for (uint64_t category : objc_section(image, "__objc_nlcatlist")) {
    const uint64_t cls = load64(category + kCatClass);
    const uint64_t imp = find_load(load64(category + kCatClassMethods));
    if (cls && imp) p_.call_guest(imp, {cls, reinterpret_cast<uint64_t>(load_sel_)});
  }
}

// --- Messaging -------------------------------------------------------------------------------

namespace {

std::shared_mutex g_types_mutex;
std::unordered_map<const char*, std::unique_ptr<FunctionType>> g_types;  // by the runtime's encoding string

const FunctionType* method_type(const char* encoding) {
  {
    std::shared_lock lock(g_types_mutex);
    if (auto it = g_types.find(encoding); it != g_types.end()) return it->second.get();
  }
  auto parsed = parse_function(encoding);
  std::unique_lock lock(g_types_mutex);
  auto& slot = g_types[encoding];
  if (!slot && parsed) slot = std::make_unique<FunctionType>(std::move(*parsed));
  return slot.get();
}

// Variadic methods (by selector name: the runtime's types don't say so).
struct VariadicMethod {
  enum Kind {
    VaForm,      // call `other`, the same method taking a va_list after the named arguments
    ObjectList,  // a nil-terminated list of objects: passed as such
    Formatted,   // a format: make the string, then call `other` with it (nullptr: return it)
  };
  const char* selector;
  Kind kind;
  const char* other = nullptr;
};
constexpr VariadicMethod kVariadicMethods[] = {
    {"initWithFormat:", VariadicMethod::VaForm, "initWithFormat:arguments:"},
    {"initWithFormat:locale:", VariadicMethod::VaForm, "initWithFormat:locale:arguments:"},
    {"predicateWithFormat:", VariadicMethod::VaForm, "predicateWithFormat:arguments:"},
    {"raise:format:", VariadicMethod::VaForm, "raise:format:arguments:"},
    {"stringWithFormat:", VariadicMethod::Formatted, nullptr},
    {"localizedStringWithFormat:", VariadicMethod::Formatted, nullptr},
    {"appendFormat:", VariadicMethod::Formatted, "appendString:"},
    {"stringByAppendingFormat:", VariadicMethod::Formatted, "stringByAppendingString:"},
    {"arrayWithObjects:", VariadicMethod::ObjectList},
    {"initWithObjects:", VariadicMethod::ObjectList},
    {"setWithObjects:", VariadicMethod::ObjectList},
    {"orderedSetWithObjects:", VariadicMethod::ObjectList},
    {"dictionaryWithObjectsAndKeys:", VariadicMethod::ObjectList},
    {"initWithObjectsAndKeys:", VariadicMethod::ObjectList},
};

// x86-64 va_list over the guest's variadic arguments (see builtins.cpp).
struct HostVaList {
  uint32_t gp_offset = 48;
  uint32_t fp_offset = 176;
  uint64_t overflow_arg_area = 0;
  uint64_t reg_save_area = 0;
};

}  // namespace

const char* ObjcBridge::block_signature(uint64_t block, uint64_t fn) const {
  // Native code called guest function `fn` with first argument `block`: if
  // that's a block whose invoke function is `fn`, its descriptor may carry
  // the type. (`block` may be anything: read it without faulting.)
  struct Literal {
    uint64_t isa;
    uint32_t flags, reserved;
    uint64_t invoke, descriptor;
  } literal;
  NativeSystem& native = p_.native();
  if (!block || !native.read_memory(block, &literal, sizeof(literal)) || literal.invoke != fn) return nullptr;
  constexpr uint32_t kHasCopyDispose = 1u << 25, kHasSignature = 1u << 30, kSmallDescriptor = 1u << 22;
  if (!(literal.flags & kHasSignature) || (literal.flags & kSmallDescriptor) || !literal.descriptor) return nullptr;
  // reserved, size, [copy, dispose], signature
  uint64_t signature = 0;
  const uint64_t at = literal.descriptor + 16 + ((literal.flags & kHasCopyDispose) ? 16 : 0);
  if (!native.read_memory(at, &signature, 8)) return nullptr;
  return ptr<const char>(signature);
}

uint64_t ObjcBridge::send(uint64_t receiver, const char* selector, std::initializer_list<uint64_t> args) {
  arm64::CpuState call{};
  alignas(16) static thread_local uint64_t no_stack_arguments[4];
  call.sp = reinterpret_cast<uint64_t>(no_stack_arguments);
  call.x[0] = receiver;
  call.x[1] = reinterpret_cast<uint64_t>(rt_.sel_registerName(selector));
  size_t k = 2;
  for (uint64_t a : args) call.x[k++] = a;
  p_.call_native_function(reinterpret_cast<uint64_t>(rt_.objc_msgSend), call);
  return call.x[0];
}

void ObjcBridge::call_native_method(arm64::CpuState& s, void* cls, void* sel, uint64_t imp) {
  void* method = rt_.class_getInstanceMethod(cls, sel);
  const char* encoding = method ? rt_.method_getTypeEncoding(method) : nullptr;
  const FunctionType* type = encoding ? method_type(encoding) : nullptr;
  if (type && type->variadic_from < 0) {
    if (host_returns_in_memory(type->ret) && rt_.class_getMethodImplementation_stret)
      imp = reinterpret_cast<uint64_t>(rt_.class_getMethodImplementation_stret(cls, sel));
    // Variadic methods (the runtime's types don't say so: by name).
    const char* name = rt_.sel_getName(sel);
    for (const VariadicMethod& v : kVariadicMethods) {
      if (std::strcmp(name, v.selector) != 0) continue;
      const unsigned fixed = static_cast<unsigned>(type->args.size());  // self, _cmd, the named arguments
      // The variadic arguments are at SP (the named ones are in registers).
      HostVaList va;
      va.overflow_arg_area = s.sp;
      if (v.kind == VariadicMethod::VaForm) {
        arm64::CpuState call = s;
        call.x[1] = reinterpret_cast<uint64_t>(rt_.sel_registerName(v.other));
        call.x[fixed] = reinterpret_cast<uint64_t>(&va);
        void* va_imp = rt_.class_getMethodImplementation(cls, ptr<void>(call.x[1]));
        p_.call_native_function(reinterpret_cast<uint64_t>(va_imp), call);
        s.x[0] = call.x[0];
        return;
      }
      if (v.kind == VariadicMethod::Formatted) {
        // The format is the last named argument.
        static const uint64_t ns_string = reinterpret_cast<uint64_t>(rt_.objc_getClass("NSString"));
        const uint64_t text = send(send(ns_string, "alloc"), "initWithFormat:arguments:",
                                   {s.x[fixed - 1], reinterpret_cast<uint64_t>(&va)});
        send(text, "autorelease");
        s.x[0] = v.other ? send(s.x[0], v.other, {text}) : text;
        return;
      }
      // A nil-terminated list: the variadic slots up to the nil, as integers.
      unsigned words = 1;
      const auto* slots = ptr<const uint64_t>(s.sp);
      if (s.x[fixed - 1]) {  // (the list's first object is the last named argument)
        while (words < 1024 && slots[words - 1]) ++words;
      } else {
        words = 0;
      }
      FunctionType variadic = *type;
      variadic.variadic_from = static_cast<int>(fixed);
      p_.call_native_function(imp, s, &variadic, words);
      return;
    }
  }
  p_.call_native_function(imp, s, type);
}

void ObjcBridge::message(arm64::CpuState& s, void* super_class) {
  void* self = ptr<void>(s.x[0]);
  void* sel = ptr<void>(s.x[1]);
  if (!self) {  // a message to nil returns zeros
    s.x[0] = s.x[1] = 0;
    for (int k = 0; k < 4; ++k) s.v[k] = {};
    return;
  }
  void* cls = super_class ? super_class : rt_.object_getClass(self);
  const uint64_t imp = reinterpret_cast<uint64_t>(rt_.class_getMethodImplementation(cls, sel));
  if (p_.is_guest_code(imp)) {
    s.pc = imp;  // a guest method: enter it with the registers as they are (X30 returns to the caller)
    return;
  }
  call_native_method(s, cls, sel, imp);
}

namespace {

// objc_msgSend(self, _cmd, ...)
void msg_send(MacProcess&, arm64::CpuState& s) { g_bridge->message(s, nullptr); }

// objc_msgSendSuper(struct objc_super {receiver, super_class}*, _cmd, ...)
void msg_send_super(MacProcess&, arm64::CpuState& s) {
  const auto* super = ptr<const uint64_t>(s.x[0]);
  s.x[0] = super[0];
  g_bridge->message(s, ptr<void>(super[1]));
}

// objc_msgSendSuper2(struct objc_super {receiver, current_class}*, _cmd, ...)
void msg_send_super2(MacProcess&, arm64::CpuState& s) {
  const auto* super = ptr<const uint64_t>(s.x[0]);
  s.x[0] = super[0];
  g_bridge->message(s, g_bridge->runtime().class_getSuperclass(ptr<void>(super[1])));
}

// objc_retain_xN / objc_release_xN (ARM64 only): the object in XN, then objc_retain / objc_release.
template <int N, bool Retain>
void retain_release_x(MacProcess& p, arm64::CpuState& s) {
  static const uint64_t native =
      reinterpret_cast<uint64_t>(p.native().find_symbol(nullptr, Retain ? "objc_retain" : "objc_release"));
  s.x[0] = s.x[N];
  p.call_native_function(native, s);
}

template <int... N>
void add_retain_release(MacProcess& p, std::integer_sequence<int, N...>) {
  (p.add_builtin(std::format("_objc_retain_x{}", N), &retain_release_x<N, true>), ...);
  (p.add_builtin(std::format("_objc_release_x{}", N), &retain_release_x<N, false>), ...);
}

}  // namespace

void ObjcBridge::install() {
  p_.add_builtin("_objc_msgSend", msg_send);
  p_.add_builtin("_objc_msgSendSuper", msg_send_super);
  p_.add_builtin("_objc_msgSendSuper2", msg_send_super2);
  add_retain_release(p_, std::make_integer_sequence<int, 29>{});
  p_.add_image_hooks([this](GuestImage& i) { register_image(i); }, [this](GuestImage& i) { call_load_methods(i); });
  p_.set_signature_lookup([this](uint64_t fn, uint64_t first) { return block_signature(first, fn); });
}

}  // namespace juice::mac
