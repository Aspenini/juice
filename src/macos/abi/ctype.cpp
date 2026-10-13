#include "macos/abi/ctype.hpp"

#include <algorithm>
#include <format>

namespace juice::mac {

namespace {

using Kind = CType::Kind;

CType scalar(Kind kind, uint32_t size) {
  CType t;
  t.kind = kind;
  t.size = size;
  t.align = size ? size : 1;
  return t;
}

void skip_digits(std::string_view& s) {
  if (!s.empty() && s[0] == '-') s.remove_prefix(1);
  while (!s.empty() && s[0] >= '0' && s[0] <= '9') s.remove_prefix(1);
}

void skip_quoted(std::string_view& s) {
  if (s.empty() || s[0] != '"') return;
  const size_t end = s.find('"', 1);
  s.remove_prefix(end == std::string_view::npos ? s.size() : end + 1);
}

bool contains_long_double(const CType& t) {
  if (t.kind == Kind::LongDouble) return true;
  return std::ranges::any_of(t.fields, contains_long_double);
}

std::expected<CType, std::string> parse(std::string_view& s, unsigned depth);

// The members of a structure or union up to `close`.
std::expected<void, std::string> parse_members(std::string_view& s, char close, CType& t, unsigned depth) {
  while (!s.empty() && s[0] != close) {
    skip_quoted(s);  // field names, in some encodings
    if (!s.empty() && s[0] == close) break;
    auto m = parse(s, depth + 1);
    if (!m) return std::unexpected(m.error());
    if (m->kind == Kind::Void) return std::unexpected("void member");
    if (contains_long_double(*m)) return std::unexpected("long double inside a structure");
    t.fields.push_back(std::move(*m));
  }
  if (s.empty()) return std::unexpected(std::format("unterminated {}", close == '}' ? "structure" : "union"));
  s.remove_prefix(1);
  return {};
}

void layout_struct(CType& t) {
  uint32_t offset = 0, align = 1;
  t.offsets.clear();
  for (const CType& f : t.fields) {
    offset = (offset + f.align - 1) / f.align * f.align;
    t.offsets.push_back(offset);
    offset += f.size;
    align = std::max(align, f.align);
  }
  t.align = align;
  t.size = (offset + align - 1) / align * align;
}

std::expected<CType, std::string> parse(std::string_view& s, unsigned depth) {
  if (depth > 32) return std::unexpected("type nested too deeply");
  // Qualifiers: const, in, inout, out, bycopy, byref, oneway, atomic.
  while (!s.empty() && std::string_view("rnNoORVA").find(s[0]) != std::string_view::npos) s.remove_prefix(1);
  if (s.empty()) return std::unexpected("missing type");
  const char c = s[0];
  s.remove_prefix(1);
  switch (c) {
    case 'c': return scalar(Kind::Int, 1);
    case 'C': return scalar(Kind::UInt, 1);
    case 'B': return scalar(Kind::UInt, 1);
    case 's': return scalar(Kind::Int, 2);
    case 'S': return scalar(Kind::UInt, 2);
    case 'i': return scalar(Kind::Int, 4);
    case 'I': return scalar(Kind::UInt, 4);
    case 'l': return scalar(Kind::Int, 4);   // ("long" in 32-bit encodings; LP64 long is 'q')
    case 'L': return scalar(Kind::UInt, 4);
    case 'q': return scalar(Kind::Int, 8);
    case 'Q': return scalar(Kind::UInt, 8);
    case 't': return scalar(Kind::Int, 16);
    case 'T': return scalar(Kind::UInt, 16);
    case 'f': return scalar(Kind::Float, 4);
    case 'd': return scalar(Kind::Double, 8);
    case 'D': return scalar(Kind::LongDouble, 8);  // (the ARM64 size; see CType)
    case 'v': return scalar(Kind::Void, 0);
    case '*':
    case '#':
    case ':':
    case '?':
      return scalar(Kind::Pointer, 8);
    case '@':
      if (!s.empty() && s[0] == '?') {  // a block, maybe with its signature: @?<v@?@>
        s.remove_prefix(1);
        if (!s.empty() && s[0] == '<') {
          int nest = 0;
          size_t k = 0;
          for (; k < s.size(); ++k) {
            if (s[k] == '<') ++nest;
            else if (s[k] == '>' && --nest == 0) break;
          }
          s.remove_prefix(std::min(k + 1, s.size()));
        }
      } else {
        skip_quoted(s);  // @"NSString"
      }
      return scalar(Kind::Pointer, 8);
    case '^': {
      // The pointee may be incomplete ({Opaque}) or unknown (?); its layout doesn't matter.
      auto pointee = parse(s, depth + 1);
      if (!pointee) return std::unexpected(pointee.error());
      return scalar(Kind::Pointer, 8);
    }
    case 'j': {  // _Complex: two of the element
      auto e = parse(s, depth + 1);
      if (!e) return std::unexpected(e.error());
      if (!e->is_float()) return std::unexpected("complex type of a non-floating point element");
      CType t;
      t.kind = Kind::Struct;
      t.name = "_Complex";
      t.fields = {*e, *e};
      layout_struct(t);
      return t;
    }
    case '[': {
      uint32_t n = 0;
      while (!s.empty() && s[0] >= '0' && s[0] <= '9') n = n * 10 + static_cast<uint32_t>(s[0] - '0'), s.remove_prefix(1);
      auto e = parse(s, depth + 1);
      if (!e) return std::unexpected(e.error());
      if (s.empty() || s[0] != ']') return std::unexpected("unterminated array");
      s.remove_prefix(1);
      if (contains_long_double(*e)) return std::unexpected("long double inside an array");
      CType t;
      t.kind = Kind::Array;
      t.count = n;
      t.size = e->size * n;
      t.align = e->align;
      t.fields.push_back(std::move(*e));
      return t;
    }
    case '{':
    case '(': {
      const char close = c == '{' ? '}' : ')';
      CType t;
      t.kind = c == '{' ? Kind::Struct : Kind::Union;
      // The tag up to '=' or the end of the type (an opaque structure has no members).
      size_t k = 0;
      while (k < s.size() && s[k] != '=' && s[k] != close) ++k;
      if (k == s.size()) return std::unexpected("unterminated structure");
      t.name = s.substr(0, k);
      s.remove_prefix(k);
      if (s[0] == close) {
        s.remove_prefix(1);
        return std::unexpected(std::format("structure {} without its members", t.name));
      }
      s.remove_prefix(1);  // '='
      if (auto m = parse_members(s, close, t, depth); !m) return std::unexpected(m.error());
      if (t.kind == Kind::Struct) {
        layout_struct(t);
      } else {
        for (const CType& f : t.fields) {
          t.size = std::max(t.size, f.size);
          t.align = std::max(t.align, f.align);
        }
        t.size = (t.size + t.align - 1) / t.align * t.align;
      }
      return t;
    }
    case 'b':
      return std::unexpected("bit field");
    default:
      return std::unexpected(std::format("unknown type code '{}'", c));
  }
}

}  // namespace

std::expected<CType, std::string> parse_type(std::string_view& encoding) {
  auto t = parse(encoding, 0);
  if (t) skip_digits(encoding);
  return t;
}

std::expected<FunctionType, std::string> parse_function(std::string_view encoding) {
  FunctionType f;
  auto ret = parse_type(encoding);
  if (!ret) return std::unexpected("return type: " + ret.error());
  if (ret->kind == Kind::Array) return std::unexpected("array return type");
  f.ret = std::move(*ret);
  while (!encoding.empty()) {
    if (encoding[0] == '.') {
      if (f.variadic_from < 0) f.variadic_from = static_cast<int>(f.args.size());
      encoding.remove_prefix(1);
      continue;
    }
    auto a = parse_type(encoding);
    if (!a) return std::unexpected(std::format("argument {}: {}", f.args.size() + 1, a.error()));
    if (a->kind == Kind::Void) return std::unexpected("void argument");
    if (a->kind == Kind::Array) a = pointer_type();  // arrays decay
    f.args.push_back(std::move(*a));
  }
  return f;
}

namespace {

bool flatten_hfa(const CType& t, Kind& base, uint32_t& member_size, unsigned& members) {
  switch (t.kind) {
    case Kind::Float:
    case Kind::Double:
    case Kind::Vector:
      if (members == 0) {
        base = t.kind;
        member_size = t.size;
      } else if (t.kind != base || t.size != member_size) {
        return false;
      }
      return ++members <= 4;
    case Kind::Struct:
      for (const CType& f : t.fields)
        if (!flatten_hfa(f, base, member_size, members)) return false;
      return true;
    case Kind::Array:
      for (uint32_t k = 0; k < t.count; ++k)
        if (!flatten_hfa(t.fields[0], base, member_size, members)) return false;
      return true;
    default:
      return false;  // integers, pointers, unions
  }
}

}  // namespace

bool is_hfa(const CType& t, CType::Kind& base, unsigned& members, uint32_t& member_size) {
  if (t.kind != Kind::Struct && t.kind != Kind::Array) return false;
  members = 0;
  if (!flatten_hfa(t, base, member_size, members) || members == 0) return false;
  return t.size == members * member_size;  // no padding
}

CType int_type(uint32_t size, bool is_signed) { return scalar(is_signed ? Kind::Int : Kind::UInt, size); }
CType pointer_type() { return scalar(Kind::Pointer, 8); }
CType double_type() { return scalar(Kind::Double, 8); }
CType float_type() { return scalar(Kind::Float, 4); }

}  // namespace juice::mac
