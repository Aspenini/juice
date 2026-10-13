// A small C++ ABI library for juice-macos-sim: exceptions with libc++abi's
// header layout (128 bytes before the thrown object, the _Unwind_Exception
// last), thrown as C++ exceptions of JUICE's NativeException (in place of
// the host's unwinder), type_info vtables whose slot 4 is can_catch, and
// two "native" functions that call guest functions (one catching).

#if defined(_WIN32) && defined(__clang__)

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

#include "fake_objc.hpp"
#include "macos/abi/trampolines.hpp"

#define SYSV __attribute__((sysv_abi))

namespace juice::sim {

namespace {

using juice::mac::NativeException;

constexpr size_t kHeader = 128;       // sizeof(__cxa_exception)
constexpr size_t kUnwindOffset = 96;  // its _Unwind_Exception
constexpr uint64_t kClangCxx = 0x434C4E47432B2B00ull;

struct Header {
  void* reserve;
  uint64_t reference_count;
  void* exception_type;
  SYSV void (*destructor)(void*);
  void* unexpected_handler;
  void* terminate_handler;
  void* next;
  int handler_count;
  int handler_switch_value;
  const uint8_t* action_record;
  const uint8_t* lsda;
  void* catch_temp;
  void* adjusted_ptr;
  uint64_t exception_class;  // _Unwind_Exception
  void* cleanup;
  uint64_t private_1, private_2;
};
static_assert(sizeof(Header) == kHeader);

Header* header_of_unwind(uint64_t ue) { return reinterpret_cast<Header*>(ue - kUnwindOffset); }
uint64_t unwind_of(Header* h) { return reinterpret_cast<uint64_t>(h) + kUnwindOffset; }

thread_local std::vector<Header*> t_caught;

SYSV void* allocate_exception(size_t size) {
  auto* h = static_cast<Header*>(std::calloc(1, kHeader + size));
  return reinterpret_cast<uint8_t*>(h) + kHeader;
}
SYSV void free_exception(void* object) { std::free(static_cast<uint8_t*>(object) - kHeader); }

SYSV void throw_(void* object, void* type, SYSV void (*destructor)(void*)) {
  auto* h = reinterpret_cast<Header*>(static_cast<uint8_t*>(object) - kHeader);
  h->exception_type = type;
  h->destructor = destructor;
  h->reference_count = 1;
  h->exception_class = kClangCxx;
  throw NativeException{unwind_of(h)};
}

SYSV void* begin_catch(uint64_t ue) {
  Header* h = header_of_unwind(ue);
  h->handler_count = h->handler_count < 0 ? -h->handler_count + 1 : h->handler_count + 1;
  if (t_caught.empty() || t_caught.back() != h) t_caught.push_back(h);
  return h->adjusted_ptr;
}

SYSV void end_catch() {
  if (t_caught.empty()) return;
  Header* h = t_caught.back();
  if (h->handler_count < 0) {  // rethrown: it lives on
    if (++h->handler_count == 0) t_caught.pop_back();
    return;
  }
  if (--h->handler_count == 0) {
    t_caught.pop_back();
    void* object = reinterpret_cast<uint8_t*>(h) + kHeader;
    if (h->destructor) h->destructor(object);  // (a guest destructor: faults into the guest)
    std::free(h);
  }
}

SYSV void rethrow() {
  if (t_caught.empty()) std::abort();
  Header* h = t_caught.back();
  h->handler_count = -h->handler_count;
  throw NativeException{unwind_of(h)};
}

SYSV void terminate_() {
  std::fputs("terminate called\n", stderr);
  std::fflush(stdout);
  std::abort();
}
SYSV int personality_(int, int, uint64_t, void*, void*) { return 8; }  // (identifies frames; never called)
SYSV void* operator_new(size_t n) { return std::malloc(n); }
SYSV void operator_delete(void* p) { std::free(p); }
SYSV void pure_virtual() { std::abort(); }

// type_info: {vtable + 16, name}; __si_class_type_info adds the base type.
struct TypeInfo {
  void* vptr;
  const char* name;
  const TypeInfo* base;  // (single inheritance classes)
};

extern void* g_class_vtable[7];
extern void* g_si_class_vtable[7];
extern void* g_fundamental_vtable[7];

// (ARM64 code tags non-unique type names with the pointer's top bit.)
const char* name_of(const TypeInfo* t) {
  return reinterpret_cast<const char*>(reinterpret_cast<uintptr_t>(t->name) & ~(uintptr_t{1} << 63));
}
bool same_type(const TypeInfo* a, const TypeInfo* b) { return a == b || std::strcmp(name_of(a), name_of(b)) == 0; }

SYSV bool can_catch(const TypeInfo* self, const TypeInfo* thrown, void** adjusted) {
  (void)adjusted;  // (single inheritance: no adjustment)
  for (const TypeInfo* t = thrown; t;) {
    if (same_type(self, t)) return true;
    t = t->vptr == &g_si_class_vtable[2] ? t->base : nullptr;
  }
  return false;
}
SYSV void nothing(void*) {}

void* g_class_vtable[7] = {nullptr, nullptr, reinterpret_cast<void*>(&nothing), reinterpret_cast<void*>(&nothing),
                           reinterpret_cast<void*>(&nothing), reinterpret_cast<void*>(&nothing),
                           reinterpret_cast<void*>(&can_catch)};
void* g_si_class_vtable[7] = {nullptr, nullptr, reinterpret_cast<void*>(&nothing), reinterpret_cast<void*>(&nothing),
                              reinterpret_cast<void*>(&nothing), reinterpret_cast<void*>(&nothing),
                              reinterpret_cast<void*>(&can_catch)};
void* g_fundamental_vtable[7] = {nullptr, nullptr, reinterpret_cast<void*>(&nothing),
                                 reinterpret_cast<void*>(&nothing), reinterpret_cast<void*>(&nothing),
                                 reinterpret_cast<void*>(&nothing), reinterpret_cast<void*>(&can_catch)};
TypeInfo g_int_type = {&g_fundamental_vtable[2], "i", nullptr};
TypeInfo g_double_type = {&g_fundamental_vtable[2], "d", nullptr};

// "Native" functions that call guest functions: one lets exceptions through,
// one catches them as native C++ code would.
SYSV void call_back(SYSV void (*fn)(int), int value) { fn(value); }
SYSV int call_catching(SYSV void (*fn)(int), int value) {
  try {
    fn(value);
    return 0;
  } catch (const NativeException& e) {
    begin_catch(e.object);
    end_catch();
    return -1;
  }
}

}  // namespace

std::vector<FakeSymbol> fake_cxxabi_symbols() {
  return {
      {"__cxa_allocate_exception", reinterpret_cast<void*>(&allocate_exception), true},
      {"__cxa_free_exception", reinterpret_cast<void*>(&free_exception), true},
      {"__cxa_throw", reinterpret_cast<void*>(&throw_), true},
      {"__cxa_begin_catch", reinterpret_cast<void*>(&begin_catch), true},
      {"__cxa_end_catch", reinterpret_cast<void*>(&end_catch), true},
      {"__cxa_rethrow", reinterpret_cast<void*>(&rethrow), true},
      {"__cxa_pure_virtual", reinterpret_cast<void*>(&pure_virtual), true},
      {"__gxx_personality_v0", reinterpret_cast<void*>(&personality_), true},
      {"_ZSt9terminatev", reinterpret_cast<void*>(&terminate_), true},
      {"_Znwm", reinterpret_cast<void*>(&operator_new), true},
      {"_ZdlPv", reinterpret_cast<void*>(&operator_delete), true},
      {"_ZTVN10__cxxabiv117__class_type_infoE", g_class_vtable, false},
      {"_ZTVN10__cxxabiv120__si_class_type_infoE", g_si_class_vtable, false},
      {"_ZTVN10__cxxabiv123__fundamental_type_infoE", g_fundamental_vtable, false},
      {"_ZTIi", &g_int_type, false},
      {"_ZTId", &g_double_type, false},
      {"call_back", reinterpret_cast<void*>(&call_back), true},
      {"call_catching", reinterpret_cast<void*>(&call_catching), true},
  };
}

}  // namespace juice::sim

#endif
