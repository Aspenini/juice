// Calls between Apple ARM64 guest code and x86-64 System V native code:
// the argument and result conversion (call_convert) and the trampolines,
// run against real System V functions (clang's sysv_abi on Windows).

#include <cstring>
#include <limits>
#include <string>
#include <vector>

#include "macos/abi/call_convert.hpp"
#include "macos/abi/ctype.hpp"
#include "macos/abi/trampolines.hpp"
#include "runtime/memory/exec_memory.hpp"
#include "test.hpp"

#if defined(__clang__) || defined(__GNUC__)
#define JUICE_SYSV_TESTS 1
#define SYSV __attribute__((sysv_abi))
#endif

using namespace juice;
using mac::CType;

namespace {

mac::FunctionType fn(const char* encoding) {
  auto f = mac::parse_function(encoding);
  if (!f) juice::test::fail(__FILE__, __LINE__, "encoding " + std::string(encoding) + ": " + f.error());
  return *f;
}

uint64_t bits(double d) {
  uint64_t v;
  std::memcpy(&v, &d, 8);
  return v;
}
uint64_t bits(float f) {
  uint32_t v;
  std::memcpy(&v, &f, 4);
  return v;
}
double as_double(uint64_t v) {
  double d;
  std::memcpy(&d, &v, 8);
  return d;
}
float as_float(uint64_t v) {
  float f;
  const auto w = static_cast<uint32_t>(v);
  std::memcpy(&f, &w, 4);
  return f;
}

struct Rect {
  double x, y, w, h;
};
struct Range {
  uint64_t location, length;
};
struct Mixed {
  double d;
  int64_t i;
};
struct Big {
  int64_t a, b, c;
};
struct Floats3 {
  float a, b, c;
};

}  // namespace

TEST(macos_type_encodings) {
  std::string_view e = "{CGRect={CGPoint=dd}{CGSize=dd}}16@0:8";
  auto rect = mac::parse_type(e);
  CHECK(rect.has_value());
  CHECK_EQ(rect->size, 32);
  CHECK_EQ(rect->align, 8);
  CHECK(e == "@0:8");
  CType::Kind base;
  unsigned members;
  uint32_t member_size;
  CHECK(mac::is_hfa(*rect, base, members, member_size));
  CHECK_EQ(members, 4);
  CHECK(base == CType::Kind::Double);

  auto f = mac::parse_function("v24@0:8^{__CFString=}16r*24@?<v@?@>32@\"NSString\"40");
  CHECK(f.has_value());
  CHECK_EQ(f->args.size(), 6);
  for (const CType& a : f->args) CHECK(a.kind == CType::Kind::Pointer);

  auto packed = mac::parse_function("{?=cid}{_NSRange=QQ}[4i]");
  CHECK(packed.has_value());
  CHECK_EQ(packed->ret.size, 16);  // char, int at 4, double at 8
  CHECK_EQ(packed->ret.offsets[1], 4);
  CHECK_EQ(packed->ret.offsets[2], 8);
  CHECK(packed->args[1].kind == CType::Kind::Pointer);  // arrays decay

  auto variadic = mac::parse_function("i*.");
  CHECK(variadic.has_value());
  CHECK_EQ(variadic->variadic_from, 1);

  CHECK(!mac::parse_function("{Opaque}").has_value());
  CHECK(!mac::parse_function("{S=Dd}").has_value());  // long double in a structure
  CHECK(!mac::parse_function("{S=i").has_value());
}

TEST(macos_x87_conversion) {
  for (double d : {0.0, -0.0, 1.0, -2.5, 3.141592653589793, 1e300, -1e-300, 4.9e-324,
                   std::numeric_limits<double>::infinity()}) {
    uint8_t x[10];
    mac::double_to_x87(d, x);
    CHECK_EQ(bits(mac::x87_to_double(x)), bits(d));
  }
  uint8_t one[10];
  mac::double_to_x87(1.0, one);
  const uint8_t expected[10] = {0, 0, 0, 0, 0, 0, 0, 0x80, 0xFF, 0x3F};
  CHECK(std::memcmp(one, expected, 10) == 0);
}

#if defined(JUICE_SYSV_TESTS)

namespace {

SYSV double mixed_args(int a, double b, char c, float d, long e, long f, long g, long h, long i, long j,
                       double k, short l) {
  return a + b + c + d + e + f + g + h + i + j + k + l;
}
SYSV double rect_area(int scale, Rect r, double extra) { return scale * (r.w * r.h) + r.x + r.y + extra; }
SYSV Rect make_rect(double x, double y) { return {x, y, x * 2, y * 2}; }
SYSV Range make_range(uint64_t a, uint64_t b) { return {a, b}; }
SYSV Mixed make_mixed(double d, int64_t i) { return {d, i}; }
SYSV Big make_big(int64_t a) { return {a, a + 1, a + 2}; }
SYSV Floats3 make_floats(float a) { return {a, a * 2, a * 3}; }
SYSV float half(float v) { return v / 2; }
SYSV signed char negative_char() { return -5; }
#if defined(_WIN32)
// long double is double in Windows code: the x87 functions are machine code.
void* machine_code(std::initializer_list<uint8_t> bytes) {
  static runtime::CodeArena arena(1 << 16);
  return arena.add(std::vector<uint8_t>(bytes));
}
// long double ld_square(long double v): fld tbyte [rsp+8]; fmul st0, st0; ret
void* ld_square_code() {
  static void* code = machine_code({0xDB, 0x6C, 0x24, 0x08, 0xD8, 0xC8, 0xC3});
  return code;
}
// double call_ld(void* fn, double v): calls the System V function `fn` with
// `v` as a long double, returns its long double result as a double.
double call_ld(void* fn, double v) {
  static void* code = machine_code({
      0x48, 0x83, 0xEC, 0x28,              // sub rsp, 40
      0xF2, 0x0F, 0x11, 0x4C, 0x24, 0x10,  // movsd [rsp+16], xmm1
      0xDD, 0x44, 0x24, 0x10,              // fld qword [rsp+16]
      0xDB, 0x3C, 0x24,                    // fstp tbyte [rsp]
      0xFF, 0xD1,                          // call rcx
      0xDD, 0x5C, 0x24, 0x10,              // fstp qword [rsp+16]
      0xF2, 0x0F, 0x10, 0x44, 0x24, 0x10,  // movsd xmm0, [rsp+16]
      0x48, 0x83, 0xC4, 0x28,              // add rsp, 40
      0xC3,
  });
  return reinterpret_cast<double (*)(void*, double)>(code)(fn, v);
}
#else
SYSV long double ld_square(long double v) { return v * v; }
void* ld_square_code() { return reinterpret_cast<void*>(&ld_square); }
double call_ld(void* fn, double v) {
  return static_cast<double>(reinterpret_cast<long double (*)(long double)>(fn)(v));
}
#endif
// int sum_ints(int count, ...) reading `count` ints: written with the
// registers its variadic arguments arrive in (va_start isn't available in
// sysv_abi functions on Windows).
SYSV int sum_ints(int count, int a, int b, int c, int d, int e, int f) {
  const int v[] = {a, b, c, d, e, f};
  int total = 0;
  for (int k = 0; k < count && k < 6; ++k) total += v[k];
  return total;
}
SYSV int64_t big_sum(Big b, int64_t x) { return b.a + b.b + b.c + x; }

// Guest state: registers, and a stack the guest's stack arguments are on.
struct Guest {
  arm64::CpuState s{};
  alignas(16) uint8_t stack[256] = {};
  Guest() { s.sp = reinterpret_cast<uint64_t>(stack); }
  template <typename T>
  void put(size_t offset, T v) {
    std::memcpy(stack + offset, &v, sizeof(T));
  }
};

// Calls `target` the way an ARM64 guest call of type `encoding` would arrive.
void call(void* target, const char* encoding, Guest& g, unsigned variadic_words = 0, bool x87 = false) {
  const mac::FunctionType f = fn(encoding);
  mac::HostCall c;
  auto r = mac::guest_args_to_host(f, g.s, c, variadic_words);
  if (!r) juice::test::fail(__FILE__, __LINE__, r.error());
  mac::HostResult result;
  mac::call_native(target, c, result, x87);
  mac::host_result_to_guest(f, c, result, g.s);
}

}  // namespace

TEST(macos_call_native_arguments) {
  // int, double, char, float, 6 longs (the last two on the guest stack:
  // ARM64 has 8 integer registers), double, short (packed on the guest stack).
  Guest g;
  g.s.x[0] = 1;
  g.s.v[0].lo = bits(0.5);
  g.s.x[1] = 3;
  g.s.v[1].lo = bits(0.25f);
  for (int k = 0; k < 6; ++k) g.s.x[2 + k] = 10 + k;  // e..j: x2..x7
  g.s.v[2].lo = bits(100.0);
  g.put<int16_t>(0, -7);  // l: the first stack argument, 2 bytes
  call(reinterpret_cast<void*>(&mixed_args), "dicdfqqqqqqds", g);
  CHECK_EQ(bits(as_double(g.s.v[0].lo)), bits(1 + 0.5 + 3 + 0.25 + (10 + 11 + 12 + 13 + 14 + 15) + 100.0 - 7));

  // More integer arguments than ARM64 registers: Apple packs stack arguments by their size.
  Guest h;
  for (int k = 0; k < 6; ++k) h.s.x[k] = 1;
  h.s.x[6] = 2;
  h.s.x[7] = 3;
  h.s.v[0].lo = bits(0.5);
  h.s.v[1].lo = bits(1.5f);
  h.s.x[1] = 1;
  // Re-describe: a (x0), b (v0), c (x1), d (v1), e..j (x2..x7), k (v2), l (stack 0).
  h.s.v[2].lo = bits(2.0);
  h.put<int16_t>(0, 9);
  call(reinterpret_cast<void*>(&mixed_args), "dicdfqqqqqqds", h);
  CHECK_EQ(bits(as_double(h.s.v[0].lo)), bits(1 + 0.5 + 1 + 1.5 + (1 + 1 + 1 + 1 + 2 + 3) + 2.0 + 9));
}

TEST(macos_call_native_structures) {
  // A CGRect: an HFA in V0-V3 on ARM64, copied onto the stack on x86-64.
  Guest g;
  g.s.x[0] = 2;
  g.s.v[0].lo = bits(1.0);
  g.s.v[1].lo = bits(2.0);
  g.s.v[2].lo = bits(3.0);
  g.s.v[3].lo = bits(4.0);
  g.s.v[4].lo = bits(0.5);
  call(reinterpret_cast<void*>(&rect_area), "di{CGRect={CGPoint=dd}{CGSize=dd}}d", g);
  CHECK_EQ(bits(as_double(g.s.v[0].lo)), bits(2 * 12.0 + 1 + 2 + 0.5));

  // Returned CGRect: memory on x86-64, V0-V3 on ARM64.
  g.s.v[0].lo = bits(1.5);
  g.s.v[1].lo = bits(2.5);
  call(reinterpret_cast<void*>(&make_rect), "{CGRect={CGPoint=dd}{CGSize=dd}}dd", g);
  CHECK_EQ(bits(as_double(g.s.v[0].lo)), bits(1.5));
  CHECK_EQ(bits(as_double(g.s.v[1].lo)), bits(2.5));
  CHECK_EQ(bits(as_double(g.s.v[2].lo)), bits(3.0));
  CHECK_EQ(bits(as_double(g.s.v[3].lo)), bits(5.0));

  // NSRange: RAX:RDX -> X0:X1.
  g.s.x[0] = 7;
  g.s.x[1] = 9;
  call(reinterpret_cast<void*>(&make_range), "{_NSRange=QQ}QQ", g);
  CHECK_EQ(g.s.x[0], 7);
  CHECK_EQ(g.s.x[1], 9);

  // {double, long}: XMM0 + RAX on x86-64, X0:X1 on ARM64.
  g.s.v[0].lo = bits(6.25);
  g.s.x[0] = 42;
  call(reinterpret_cast<void*>(&make_mixed), "{M=dq}dq", g);
  CHECK_EQ(g.s.x[0], bits(6.25));
  CHECK_EQ(g.s.x[1], 42);

  // 24 bytes: through X8 on ARM64, the hidden pointer on x86-64.
  Big big{};
  g.s.x[0] = 100;
  g.s.x[8] = reinterpret_cast<uint64_t>(&big);
  call(reinterpret_cast<void*>(&make_big), "{B=qqq}q", g);
  CHECK_EQ(big.a, 100);
  CHECK_EQ(big.c, 102);

  // Three floats: an HFA in S0-S2 on ARM64; XMM0 (two floats) and XMM1 on x86-64.
  g.s.v[0].lo = bits(1.5f);
  call(reinterpret_cast<void*>(&make_floats), "{F=fff}f", g);
  CHECK_EQ(bits(as_float(g.s.v[0].lo)), bits(1.5f));
  CHECK_EQ(bits(as_float(g.s.v[1].lo)), bits(3.0f));
  CHECK_EQ(bits(as_float(g.s.v[2].lo)), bits(4.5f));
  CHECK_EQ(g.s.v[0].lo >> 32, 0);  // the rest of the register cleared

  // A 24-byte argument: by reference on ARM64, copied onto the stack on x86-64.
  Big in{1, 2, 3};
  g.s.x[0] = reinterpret_cast<uint64_t>(&in);
  g.s.x[1] = 10;
  call(reinterpret_cast<void*>(&big_sum), "q{B=qqq}q", g);
  CHECK_EQ(g.s.x[0], 16);
}

TEST(macos_call_native_scalars) {
  Guest g;
  g.s.v[0] = {bits(5.0f) | 0xDEAD00000000ull, 0x1234};
  call(reinterpret_cast<void*>(&half), "ff", g);
  CHECK_EQ(g.s.v[0].lo, bits(2.5f));
  CHECK_EQ(g.s.v[0].hi, 0);

  call(reinterpret_cast<void*>(&negative_char), "c", g);
  CHECK_EQ(g.s.x[0], static_cast<uint64_t>(-5));  // sign extended

  // long double: a double on ARM64, x87 on x86-64 (argument on the stack, result in ST0).
  g.s.v[0].lo = bits(1.5);
  call(ld_square_code(), "DD", g, 0, true);
  CHECK_EQ(g.s.v[0].lo, bits(2.25));
}

TEST(macos_call_native_variadic) {
  // Apple ARM64 passes variadic arguments on the stack, one 8-byte slot each.
  Guest g;
  g.s.x[0] = 4;
  g.put<uint64_t>(0, 10);
  g.put<uint64_t>(8, 20);
  g.put<uint64_t>(16, static_cast<uint64_t>(-5));
  g.put<uint64_t>(24, 1);
  call(reinterpret_cast<void*>(&sum_ints), "ii.", g, 4);
  CHECK_EQ(static_cast<int32_t>(g.s.x[0]), 26);
}

namespace {

// A "guest function" for the entry tests: converts the native call to guest
// registers, then computes what the ARM64 function would, from those.
struct EntryCheck {
  const char* encoding;
  void (*guest)(arm64::CpuState& s, const mac::GuestStackArea& area);
};
EntryCheck g_entry;

void entry_handler(mac::EntryFrame& frame) {
  const mac::FunctionType f = fn(g_entry.encoding);
  arm64::CpuState s{};
  mac::GuestStackArea area;
  alignas(16) static uint8_t guest_stack[512];
  area.base = reinterpret_cast<uint64_t>(guest_stack);
  if (auto r = mac::host_args_to_guest(f, frame.args, s, area); !r) juice::test::fail(__FILE__, __LINE__, r.error());
  std::memcpy(guest_stack, area.bytes.data(), area.bytes.size());
  s.sp = area.base;
  g_entry.guest(s, area);
  mac::guest_result_to_host(f, frame.args, s, frame.result);
  frame.x87_result = f.ret.kind == CType::Kind::LongDouble;
}

const uint8_t* guest_stack_at(const arm64::CpuState& s, size_t offset) {
  return reinterpret_cast<const uint8_t*>(s.sp) + offset;
}

}  // namespace

TEST(macos_native_entry) {
  void* entry = mac::native_entry(&entry_handler);

  // Mixed arguments, the last ones on the guest stack (packed: short at 0, char at 2, int at 4).
  g_entry = {"qiqqqqqqqdsci", [](arm64::CpuState& s, const mac::GuestStackArea&) {
               int16_t sh;
               int8_t ch;
               int32_t in;
               std::memcpy(&sh, guest_stack_at(s, 0), 2);
               std::memcpy(&ch, guest_stack_at(s, 2), 1);
               std::memcpy(&in, guest_stack_at(s, 4), 4);
               int64_t total = 0;
               for (int k = 0; k < 8; ++k) total += static_cast<int64_t>(s.x[k]);
               s.x[0] = static_cast<uint64_t>(total + static_cast<int64_t>(as_double(s.v[0].lo)) + sh + ch + in);
             }};
  using Mixed9 = SYSV int64_t (*)(int, int64_t, int64_t, int64_t, int64_t, int64_t, int64_t, int64_t, double, short,
                                  signed char, int);
  CHECK_EQ(reinterpret_cast<Mixed9>(entry)(-1, 2, 3, 4, 5, 6, 7, 8, 100.0, -300, -2, 1000), 34 + 100 - 300 - 2 + 1000);

  // CGRect in (stack on x86-64, V0-V3 on ARM64) and out (V0-V3 -> memory).
  g_entry = {"{CGRect={CGPoint=dd}{CGSize=dd}}{CGRect={CGPoint=dd}{CGSize=dd}}d",
             [](arm64::CpuState& s, const mac::GuestStackArea&) {
               const double scale = as_double(s.v[4].lo);
               for (int k = 0; k < 4; ++k) s.v[k].lo = bits(as_double(s.v[k].lo) * scale);
             }};
  using RectFn = SYSV Rect (*)(Rect, double);
  const Rect r = reinterpret_cast<RectFn>(entry)({1, 2, 3, 4}, 10);
  CHECK_EQ(bits(r.x), bits(10.0));
  CHECK_EQ(bits(r.h), bits(40.0));

  // A 24-byte argument: x86-64 stack copy -> ARM64 pointer to a copy in the guest's area.
  g_entry = {"q{B=qqq}q", [](arm64::CpuState& s, const mac::GuestStackArea& area) {
               const auto* b = reinterpret_cast<const Big*>(s.x[0]);
               const bool in_area = s.x[0] >= area.base && s.x[0] < area.base + area.bytes.size();
               s.x[0] = in_area ? static_cast<uint64_t>(b->a + b->b + b->c + static_cast<int64_t>(s.x[1])) : 0;
             }};
  using BigFn = SYSV int64_t (*)(Big, int64_t);
  CHECK_EQ(reinterpret_cast<BigFn>(entry)({5, 6, 7}, 100), 118);

  // Results: {double, long} (XMM0 + RAX), 24 bytes (memory), long double (ST0).
  g_entry = {"{M=dq}", [](arm64::CpuState& s, const mac::GuestStackArea&) {
               s.x[0] = bits(0.75);
               s.x[1] = 99;
             }};
  using MixedFn = SYSV Mixed (*)();
  const Mixed m = reinterpret_cast<MixedFn>(entry)();
  CHECK_EQ(bits(m.d), bits(0.75));
  CHECK_EQ(m.i, 99);

  g_entry = {"{B=qqq}q", [](arm64::CpuState& s, const mac::GuestStackArea&) {
               auto* out = reinterpret_cast<Big*>(s.x[8]);
               *out = {static_cast<int64_t>(s.x[0]), 0, -1};
             }};
  using MakeBig = SYSV Big (*)(int64_t);
  const Big b = reinterpret_cast<MakeBig>(entry)(77);
  CHECK_EQ(b.a, 77);
  CHECK_EQ(b.c, -1);

  g_entry = {"DD", [](arm64::CpuState& s, const mac::GuestStackArea&) {
               s.v[0].lo = bits(as_double(s.v[0].lo) + 1.0);
             }};
  CHECK_EQ(bits(call_ld(entry, 2.5)), bits(3.5));
}

#endif  // JUICE_SYSV_TESTS
