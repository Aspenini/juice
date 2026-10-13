#if defined(_WIN32) && defined(__clang__)

#include "fake_objc.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <utility>

#define SYSV __attribute__((sysv_abi))

namespace juice::sim {

namespace {

struct ClassT {
  ClassT* isa;
  ClassT* super;
  void* cache;
  void* vtable;
  uintptr_t bits;  // class_ro_t*
};
struct ClassRo {
  uint32_t flags, instance_start, instance_size, reserved;
  const uint8_t* ivar_layout;
  const char* name;
  const void* methods;
  const void* protocols;
  const void* ivars;
  const uint8_t* weak_ivar_layout;
  const void* properties;
};
struct MethodT {  // a big method list entry
  const char* name;
  const char* types;
  void* imp;
};
template <size_t N>
struct MethodList {
  uint32_t entsize_flags = sizeof(MethodT);
  uint32_t count = N;
  MethodT methods[N];
};
struct Point {
  double x, y, w, h;
};

const ClassRo* ro_of(const ClassT* cls) { return reinterpret_cast<const ClassRo*>(cls->bits & 0x00007ffffffffff8ull); }

std::mutex g_mutex;

const char* intern(const char* name) {
  static std::set<std::string> names;
  std::lock_guard lock(g_mutex);
  return names.insert(name).first->c_str();
}

// Methods found or added, by (class, selector name): stable pointers for Method.
std::map<std::pair<const ClassT*, std::string>, std::unique_ptr<MethodT>> g_found, g_added;
std::map<std::string, ClassT*> g_classes;

const MethodT* find_in_list(const void* list, const char* name, const ClassT* cls) {
  if (!list) return nullptr;
  const auto* bytes = static_cast<const uint8_t*>(list);
  uint32_t entsize_flags, count;
  std::memcpy(&entsize_flags, bytes, 4);
  std::memcpy(&count, bytes + 4, 4);
  const bool small = entsize_flags & 0x80000000u;
  const uint32_t entsize = entsize_flags & 0xFFFCu;
  for (uint32_t k = 0; k < count; ++k) {
    const uint8_t* e = bytes + 8 + k * entsize;
    MethodT m;
    if (small) {
      int32_t name_off, types_off, imp_off;
      std::memcpy(&name_off, e, 4);
      std::memcpy(&types_off, e + 4, 4);
      std::memcpy(&imp_off, e + 8, 4);
      const char* sel;
      std::memcpy(&sel, e + name_off, 8);  // through the selector reference
      m = {sel, reinterpret_cast<const char*>(e + 4 + types_off), const_cast<uint8_t*>(e + 8 + imp_off)};
    } else {
      std::memcpy(&m, e, sizeof(m));
    }
    if (m.name && std::strcmp(m.name, name) == 0) {
      std::lock_guard lock(g_mutex);
      auto& slot = g_found[{cls, name}];
      if (!slot) slot = std::make_unique<MethodT>(m);
      return slot.get();
    }
  }
  return nullptr;
}

const MethodT* lookup(const ClassT* cls, const char* name) {
  for (const ClassT* c = cls; c; c = c->super) {
    {
      std::lock_guard lock(g_mutex);
      if (auto it = g_added.find({c, name}); it != g_added.end()) return it->second.get();
    }
    if (const MethodT* m = find_in_list(ro_of(c)->methods, name, c)) return m;
  }
  return nullptr;
}

// --- Native (System V) side --------------------------------------------------------------------

SYSV void unrecognized(void* self, const char* sel) {
  std::fprintf(stderr, "fake objc: unrecognized selector %s sent to %p\n", sel, self);
  std::abort();
}

SYSV uint64_t objc_msgSend_(void* self, const char* sel, uint64_t a, uint64_t b, uint64_t c, uint64_t d) {
  if (!self) return 0;
  const MethodT* m = lookup(*static_cast<ClassT**>(self), sel);
  if (!m) unrecognized(self, sel);
  // (an integer call: a guest method faults into the guest, as on macOS)
  using Imp = SYSV uint64_t (*)(void*, const char*, uint64_t, uint64_t, uint64_t, uint64_t);
  return reinterpret_cast<Imp>(m->imp)(self, sel, a, b, c, d);
}

SYSV void* alloc_(ClassT* cls, const char*) {
  void* object = std::calloc(1, ro_of(cls)->instance_size + 16);
  *static_cast<ClassT**>(object) = cls;
  return object;
}
SYSV void* init_(void* self, const char*) { return self; }
SYSV void* objc_alloc_init_(ClassT* cls) {
  void* object = reinterpret_cast<void*>(objc_msgSend_(cls, intern("alloc"), 0, 0, 0, 0));
  return reinterpret_cast<void*>(objc_msgSend_(object, intern("init"), 0, 0, 0, 0));
}
SYSV void* perform_(void* self, const char*, const char* selector, void* object) {
  return reinterpret_cast<void*>(objc_msgSend_(self, selector, reinterpret_cast<uint64_t>(object), 0, 0, 0));
}
SYSV Point juice_rect_(void*, const char*) { return {1, 2, 3, 4}; }
SYSV double juice_scale_(void*, const char*, double value, float factor) { return value * factor + 0.25; }
SYSV void* identity_(void* object) { return object; }
SYSV void nothing_(void*) {}

uint64_t g_empty_cache[2];

MethodList<5> g_instance_methods = {sizeof(MethodT), 5, {
    {"init", "@16@0:8", reinterpret_cast<void*>(&init_)},
    {"performSelector:withObject:", "@32@0:8:16@24", reinterpret_cast<void*>(&perform_)},
    {"juiceRect", "{R=dddd}16@0:8", reinterpret_cast<void*>(&juice_rect_)},
    {"juiceScale:by:", "d28@0:8d16f24", reinterpret_cast<void*>(&juice_scale_)},
    {"self", "@16@0:8", reinterpret_cast<void*>(&init_)},
}};
MethodList<1> g_class_methods = {sizeof(MethodT), 1, {
    {"alloc", "@16@0:8", reinterpret_cast<void*>(&alloc_)},
}};
ClassRo g_ns_object_ro = {2 /*RO_ROOT*/, 8, 8, 0, nullptr, "NSObject", &g_instance_methods, nullptr, nullptr, nullptr, nullptr};
ClassRo g_ns_object_meta_ro = {3 /*RO_META | RO_ROOT*/, 40, 40, 0, nullptr, "NSObject", &g_class_methods, nullptr,
                               nullptr, nullptr, nullptr};
extern ClassT g_ns_object_meta;
ClassT g_ns_object = {&g_ns_object_meta, nullptr, g_empty_cache, nullptr, reinterpret_cast<uintptr_t>(&g_ns_object_ro)};
ClassT g_ns_object_meta = {&g_ns_object_meta, &g_ns_object, g_empty_cache, nullptr,
                           reinterpret_cast<uintptr_t>(&g_ns_object_meta_ro)};

// --- The runtime functions (host convention) -----------------------------------------------------

void* read_class_pair(void* cls, const void*) {
  std::lock_guard lock(g_mutex);
  g_classes[ro_of(static_cast<ClassT*>(cls))->name] = static_cast<ClassT*>(cls);
  return cls;
}
void* get_class(const char* name) {
  if (std::strcmp(name, "NSObject") == 0) return &g_ns_object;
  std::lock_guard lock(g_mutex);
  auto it = g_classes.find(name);
  return it == g_classes.end() ? nullptr : it->second;
}
std::map<std::string, void*> g_protocols;
void* get_protocol(const char* name) {
  std::lock_guard lock(g_mutex);
  auto it = g_protocols.find(name);
  return it == g_protocols.end() ? nullptr : it->second;
}
void* allocate_protocol(const char* name) { return const_cast<char*>(intern(name)); }
void register_protocol(void* p) {
  std::lock_guard lock(g_mutex);
  g_protocols[static_cast<const char*>(p)] = p;
}
void protocol_add_method(void*, void*, const char*, bool, bool) {}
void protocol_add_protocol(void*, void*) {}
void* sel_register(const char* name) { return const_cast<char*>(intern(name)); }
const char* sel_name(void* sel) { return static_cast<const char*>(sel); }
void* object_get_class(void* object) { return *static_cast<ClassT**>(object); }
void* class_get_superclass(void* cls) { return static_cast<ClassT*>(cls)->super; }
const char* class_get_name(void* cls) { return ro_of(static_cast<ClassT*>(cls))->name; }
bool class_is_meta(void* cls) { return ro_of(static_cast<ClassT*>(cls))->flags & 1; }
void* class_get_instance_method(void* cls, void* sel) {
  return const_cast<MethodT*>(lookup(static_cast<ClassT*>(cls), static_cast<const char*>(sel)));
}
void* class_get_imp(void* cls, void* sel) {
  const MethodT* m = lookup(static_cast<ClassT*>(cls), static_cast<const char*>(sel));
  return m ? m->imp : reinterpret_cast<void*>(&unrecognized);
}
void* class_replace_method(void* cls, void* sel, void* imp, const char* types) {
  std::lock_guard lock(g_mutex);
  auto& slot = g_added[{static_cast<ClassT*>(cls), static_cast<const char*>(sel)}];
  slot = std::make_unique<MethodT>(MethodT{static_cast<const char*>(sel), types, imp});
  return nullptr;
}
bool class_add_protocol(void*, void*) { return true; }
const char* method_types(void* m) { return static_cast<MethodT*>(m)->types; }

}  // namespace

std::vector<FakeSymbol> fake_objc_symbols() {
  return {
      {"objc_msgSend", reinterpret_cast<void*>(&objc_msgSend_), true},
      {"objc_alloc_init", reinterpret_cast<void*>(&objc_alloc_init_), true},
      {"objc_retain", reinterpret_cast<void*>(&identity_), true},
      {"objc_autorelease", reinterpret_cast<void*>(&identity_), true},
      {"objc_release", reinterpret_cast<void*>(&nothing_), true},
      {"OBJC_CLASS_$_NSObject", &g_ns_object, false},
      {"OBJC_METACLASS_$_NSObject", &g_ns_object_meta, false},
      {"_objc_empty_cache", g_empty_cache, false},
      {"-[NSObject init]", reinterpret_cast<void*>(&init_), true},
      {"-[NSObject performSelector:withObject:]", reinterpret_cast<void*>(&perform_), true},
      {"-[NSObject juiceRect]", reinterpret_cast<void*>(&juice_rect_), true},
      {"-[NSObject juiceScale:by:]", reinterpret_cast<void*>(&juice_scale_), true},
      {"+[NSObject alloc]", reinterpret_cast<void*>(&alloc_), true},
  };
}

juice::mac::ObjcRuntime fake_objc_runtime() {
  juice::mac::ObjcRuntime rt;
  rt.objc_readClassPair = read_class_pair;
  rt.objc_getClass = get_class;
  rt.objc_getProtocol = get_protocol;
  rt.objc_allocateProtocol = allocate_protocol;
  rt.objc_registerProtocol = register_protocol;
  rt.protocol_addMethodDescription = protocol_add_method;
  rt.protocol_addProtocol = protocol_add_protocol;
  rt.sel_registerName = sel_register;
  rt.sel_getName = sel_name;
  rt.object_getClass = object_get_class;
  rt.class_getSuperclass = class_get_superclass;
  rt.class_getName = class_get_name;
  rt.class_isMetaClass = class_is_meta;
  rt.class_getInstanceMethod = class_get_instance_method;
  rt.class_getMethodImplementation = class_get_imp;
  rt.class_getMethodImplementation_stret = class_get_imp;
  rt.class_replaceMethod = class_replace_method;
  rt.class_addProtocol = class_add_protocol;
  rt.method_getTypeEncoding = method_types;
  rt.objc_msgSend = reinterpret_cast<void*>(&objc_msgSend_);
  return rt;
}

}  // namespace juice::sim

#endif
