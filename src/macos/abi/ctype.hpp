#pragma once

// C types as calls between ARM64 and x86-64 code need them: parsed from
// Objective-C type encodings ("v24@0:8{CGRect={CGPoint=dd}{CGSize=dd}}16"),
// which the Objective-C runtime provides for every method and which JUICE
// also uses to describe C functions.
//
// Both macOS ABIs are LP64 with the same structure layout, except for long
// double (a double on ARM64, the x87 80-bit type on x86-64); structures
// containing one are rejected.

#include <cstdint>
#include <expected>
#include <string>
#include <string_view>
#include <vector>

namespace juice::mac {

struct CType {
  enum class Kind : uint8_t {
    Void,
    Int,        // signed integer of `size` bytes (1, 2, 4, 8, 16)
    UInt,       // unsigned integer (bool too)
    Float,      // 4 bytes
    Double,     // 8 bytes
    LongDouble, // a double in ARM64 code, an x87 value in x86-64 code
    Pointer,    // pointers, id, Class, SEL, blocks, C strings, function pointers
    Struct,
    Union,
    Array,      // only inside structures
    Vector,     // a SIMD vector of `size` bytes (8 or 16) of float elements ("simd_float4")
  };
  Kind kind = Kind::Void;
  uint32_t size = 0;
  uint32_t align = 1;
  uint32_t count = 0;        // Array: element count; Vector: element count
  std::vector<CType> fields; // Struct/Union: members; Array/Vector: the element
  std::vector<uint32_t> offsets;  // Struct: member offsets
  std::string name;               // Struct/Union: the tag, for diagnostics

  bool is_aggregate() const { return kind == Kind::Struct || kind == Kind::Union || kind == Kind::Array; }
  bool is_integer() const { return kind == Kind::Int || kind == Kind::UInt || kind == Kind::Pointer; }
  bool is_float() const { return kind == Kind::Float || kind == Kind::Double; }
};

// A function type: return type and arguments; arguments from `variadic_from`
// on are the variadic ones (-1: not variadic). In encodings, '.' marks where
// the variadic arguments start (a JUICE extension).
struct FunctionType {
  CType ret;
  std::vector<CType> args;
  int variadic_from = -1;
};

// Parses one type at the start of `encoding`, advancing it past the type and
// any following offset digits.
std::expected<CType, std::string> parse_type(std::string_view& encoding);

// Parses a whole method or function encoding: the return type, then the arguments.
std::expected<FunctionType, std::string> parse_function(std::string_view encoding);

// Homogeneous floating point aggregate (ARM64): a structure/array of 1-4
// members, all floats or all doubles (or all identical vectors) after
// flattening. Sets `base` to the element kind and `members` to the count.
bool is_hfa(const CType& t, CType::Kind& base, unsigned& members, uint32_t& member_size);

// Common types
CType int_type(uint32_t size, bool is_signed);
CType pointer_type();
CType double_type();
CType float_type();

}  // namespace juice::mac
