// Semantics of the vector-lane and floating point IR operations.
//
// Floating point follows the Arm architecture where it differs from x86:
// NaN propagation order, the default NaN, FMAX/FMIN signed zeros and
// saturating float -> integer conversion. Rounding is round-to-nearest-even
// (the FPCR default) and denormals are not flushed.

#include <algorithm>
#include <bit>
#include <cmath>
#include <initializer_list>
#include <cstdint>
#include <limits>

#include "core/ir/eval_simd.hpp"

namespace juice::ir {
namespace {

// --- lanes ------------------------------------------------------------------------

constexpr uint64_t lane_mask(unsigned bits) { return bits >= 64 ? ~0ull : (1ull << bits) - 1; }

struct Lanes {
  unsigned esize;  // bytes
  unsigned bits;
  unsigned count;  // lanes per 64-bit half
  explicit Lanes(unsigned e) : esize(e ? e : 8), bits(esize * 8), count(8 / esize) {}
  uint64_t get(uint64_t v, unsigned i) const { return bits == 64 ? v : (v >> (i * bits)) & lane_mask(bits); }
  int64_t sget(uint64_t v, unsigned i) const {
    uint64_t x = get(v, i);
    return bits == 64 ? static_cast<int64_t>(x) : static_cast<int64_t>(x << (64 - bits)) >> (64 - bits);
  }
  uint64_t put(uint64_t v, unsigned i, uint64_t x) const {
    if (bits == 64) return x;
    const uint64_t m = lane_mask(bits) << (i * bits);
    return (v & ~m) | ((x << (i * bits)) & m);
  }
};

template <typename F>
uint64_t map2(uint64_t a, uint64_t b, const Lanes& l, F f) {
  uint64_t r = 0;
  for (unsigned i = 0; i < l.count; ++i) r = l.put(r, i, f(i));
  (void)a;
  (void)b;
  return r;
}

uint64_t vcmp(uint64_t a, uint64_t b, const Lanes& l, VecPred pred) {
  return map2(a, b, l, [&](unsigned i) -> uint64_t {
    bool r = false;
    switch (pred) {
      case VecPred::Eq: r = l.get(a, i) == l.get(b, i); break;
      case VecPred::Gt: r = l.sget(a, i) > l.sget(b, i); break;
      case VecPred::Ge: r = l.sget(a, i) >= l.sget(b, i); break;
      case VecPred::Hi: r = l.get(a, i) > l.get(b, i); break;
      case VecPred::Hs: r = l.get(a, i) >= l.get(b, i); break;
      case VecPred::Tst: r = (l.get(a, i) & l.get(b, i)) != 0; break;
    }
    return r ? ~0ull : 0;
  });
}

uint64_t vreduce(uint64_t a, const Lanes& l, VecReduce kind) {
  uint64_t acc = l.get(a, 0);
  int64_t sacc = l.sget(a, 0);
  for (unsigned i = 1; i < l.count; ++i) {
    switch (kind) {
      case VecReduce::Add: acc += l.get(a, i); break;
      case VecReduce::UMax: acc = std::max(acc, l.get(a, i)); break;
      case VecReduce::UMin: acc = std::min(acc, l.get(a, i)); break;
      case VecReduce::SMax: sacc = std::max(sacc, l.sget(a, i)); break;
      case VecReduce::SMin: sacc = std::min(sacc, l.sget(a, i)); break;
      case VecReduce::UAddLong: acc += l.get(a, i); break;
      case VecReduce::SAddLong: sacc += l.sget(a, i); break;
    }
  }
  switch (kind) {
    case VecReduce::SMax:
    case VecReduce::SMin: return static_cast<uint64_t>(sacc) & lane_mask(l.bits);
    case VecReduce::SAddLong: return static_cast<uint64_t>(sacc);
    case VecReduce::UAddLong: return acc;
    default: return acc & lane_mask(l.bits);
  }
}

uint64_t eval_vector(const Inst& in, uint64_t a, uint64_t b) {
  const Lanes l(in.aux & 0xF);
  const unsigned hi = in.aux >> 4;
  switch (in.op) {
    case Opcode::VAdd: return map2(a, b, l, [&](unsigned i) { return l.get(a, i) + l.get(b, i); });
    case Opcode::VSub: return map2(a, b, l, [&](unsigned i) { return l.get(a, i) - l.get(b, i); });
    case Opcode::VMul: return map2(a, b, l, [&](unsigned i) { return l.get(a, i) * l.get(b, i); });
    case Opcode::VCmp: return vcmp(a, b, l, static_cast<VecPred>(hi));
    case Opcode::VMax:
    case Opcode::VMin: {
      const bool max = in.op == Opcode::VMax;
      const bool sign = hi & 1;
      return map2(a, b, l, [&](unsigned i) -> uint64_t {
        if (sign) {
          int64_t x = l.sget(a, i), y = l.sget(b, i);
          return static_cast<uint64_t>(max ? std::max(x, y) : std::min(x, y));
        }
        uint64_t x = l.get(a, i), y = l.get(b, i);
        return max ? std::max(x, y) : std::min(x, y);
      });
    }
    case Opcode::VAbs:
      return map2(a, b, l, [&](unsigned i) {
        int64_t x = l.sget(a, i);
        return x < 0 ? 0 - static_cast<uint64_t>(x) : static_cast<uint64_t>(x);
      });
    case Opcode::VShl:
      return map2(a, b, l, [&](unsigned i) { return b >= l.bits ? 0 : l.get(a, i) << b; });
    case Opcode::VLShr:
      return map2(a, b, l, [&](unsigned i) { return b >= l.bits ? 0 : l.get(a, i) >> b; });
    case Opcode::VAShr:
      return map2(a, b, l, [&](unsigned i) {
        return static_cast<uint64_t>(l.sget(a, i) >> std::min<uint64_t>(b, l.bits - 1));
      });
    case Opcode::VUnzip:
      return map2(a, b, l, [&](unsigned i) {
        unsigned src = 2 * i + (hi & 1);
        return src < l.count ? l.get(a, src) : l.get(b, src - l.count);
      });
    case Opcode::VZip: {
      const unsigned start = (hi & 1) ? l.count / 2 : 0;
      return map2(a, b, l, [&](unsigned i) { return (i & 1) ? l.get(b, start + i / 2) : l.get(a, start + i / 2); });
    }
    case Opcode::VTrn: {
      const unsigned s = hi & 1;
      return map2(a, b, l, [&](unsigned i) { return (i & 1) ? l.get(b, (i & ~1u) + s) : l.get(a, (i & ~1u) + s); });
    }
    case Opcode::VWiden: {
      const bool sign = hi & 1;
      const uint64_t src = (hi & 2) ? a >> 32 : a & 0xFFFF'FFFFu;
      const Lanes wide(l.esize * 2);
      uint64_t r = 0;
      for (unsigned i = 0; i < wide.count; ++i)
        r = wide.put(r, i, sign ? static_cast<uint64_t>(l.sget(src, i)) : l.get(src, i));
      return r;
    }
    case Opcode::VReduce: return vreduce(a, l, static_cast<VecReduce>(hi));
    case Opcode::VCnt: {
      const Lanes bytes(1);
      return map2(a, b, bytes, [&](unsigned i) { return static_cast<uint64_t>(std::popcount(bytes.get(a, i))); });
    }
    case Opcode::VRev: {
      const unsigned per = hi / l.esize;  // lanes per container
      return map2(a, b, l, [&](unsigned i) {
        unsigned base = i - i % per;
        return l.get(a, base + (per - 1 - i % per));
      });
    }
    default:
      return 0;
  }
}

// --- floating point ------------------------------------------------------------------

template <typename T>
struct FpTraits;
template <>
struct FpTraits<float> {
  using Bits = uint32_t;
  static constexpr Bits kQuiet = 0x0040'0000u;
  static constexpr Bits kDefaultNaN = 0x7FC0'0000u;
};
template <>
struct FpTraits<double> {
  using Bits = uint64_t;
  static constexpr Bits kQuiet = 0x0008'0000'0000'0000ull;
  static constexpr Bits kDefaultNaN = 0x7FF8'0000'0000'0000ull;
};

template <typename T>
T from_bits(uint64_t v) {
  return std::bit_cast<T>(static_cast<typename FpTraits<T>::Bits>(v));
}
template <typename T>
uint64_t to_bits(T v) {
  return std::bit_cast<typename FpTraits<T>::Bits>(v);
}
template <typename T>
bool is_snan(T v) {
  return std::isnan(v) && !(to_bits(v) & FpTraits<T>::kQuiet);
}
template <typename T>
uint64_t quiet(T v) {
  return to_bits(v) | FpTraits<T>::kQuiet;
}

// FPProcessNaNs: the first signaling NaN, else the first quiet NaN, quieted.
template <typename T>
bool process_nans(std::initializer_list<T> ops, uint64_t& out) {
  for (T v : ops)
    if (is_snan(v)) {
      out = quiet(v);
      return true;
    }
  for (T v : ops)
    if (std::isnan(v)) {
      out = quiet(v);
      return true;
    }
  return false;
}

// Arm generates the positive default NaN where x86 produces a negative one.
template <typename T>
uint64_t result_bits(T r) {
  return std::isnan(r) ? FpTraits<T>::kDefaultNaN : to_bits(r);
}

template <typename T>
uint64_t fp_minmax(T x, T y, bool max, bool number) {
  uint64_t nan;
  if (number) {
    // FMAXNM/FMINNM: a single quiet NaN loses against a number.
    bool xq = std::isnan(x) && !is_snan(x), yq = std::isnan(y) && !is_snan(y);
    if (xq && !std::isnan(y)) return to_bits(y);
    if (yq && !std::isnan(x)) return to_bits(x);
  }
  if (process_nans({x, y}, nan)) return nan;
  if (x == 0 && y == 0 && std::signbit(x) != std::signbit(y)) return to_bits(max ? T(0) : -T(0));
  return to_bits(max ? (x > y ? x : y) : (x < y ? x : y));
}

template <typename T>
T round_to_integral(T x, FpRound mode) {
  switch (mode) {
    case FpRound::NearestEven: return std::nearbyint(x);
    case FpRound::PlusInf: return std::ceil(x);
    case FpRound::MinusInf: return std::floor(x);
    case FpRound::Zero: return std::trunc(x);
    case FpRound::NearestAway: return std::round(x);
  }
  return x;
}

template <typename T>
uint64_t fp_to_int(T x, FpRound mode, bool sign, unsigned size) {
  if (std::isnan(x)) return 0;
  const double r = static_cast<double>(round_to_integral(x, mode));
  if (sign) {
    const double lo = size == 8 ? -9223372036854775808.0 : -2147483648.0;
    const double hi = size == 8 ? 9223372036854775808.0 : 2147483648.0;
    int64_t v;
    if (r < lo) v = size == 8 ? std::numeric_limits<int64_t>::min() : std::numeric_limits<int32_t>::min();
    else if (r >= hi) v = size == 8 ? std::numeric_limits<int64_t>::max() : std::numeric_limits<int32_t>::max();
    else v = static_cast<int64_t>(r);
    return size == 8 ? static_cast<uint64_t>(v) : static_cast<uint32_t>(v);
  }
  const double hi = size == 8 ? 18446744073709551616.0 : 4294967296.0;
  if (r <= 0) return 0;
  if (r >= hi) return size == 8 ? ~0ull : 0xFFFF'FFFFu;
  return static_cast<uint64_t>(r);
}

template <typename T>
uint64_t eval_fp(const Inst& in, uint64_t ra, uint64_t rb, uint64_t rc) {
  const T a = from_bits<T>(ra), b = from_bits<T>(rb), c = from_bits<T>(rc);
  uint64_t nan;
  switch (in.op) {
    case Opcode::FAdd: return process_nans({a, b}, nan) ? nan : result_bits(a + b);
    case Opcode::FSub: return process_nans({a, b}, nan) ? nan : result_bits(a - b);
    case Opcode::FMul: return process_nans({a, b}, nan) ? nan : result_bits(a * b);
    case Opcode::FDiv: return process_nans({a, b}, nan) ? nan : result_bits(a / b);
    case Opcode::FMax: return fp_minmax(a, b, true, false);
    case Opcode::FMin: return fp_minmax(a, b, false, false);
    case Opcode::FMaxNm: return fp_minmax(a, b, true, true);
    case Opcode::FMinNm: return fp_minmax(a, b, false, true);
    case Opcode::FSqrt: return process_nans({a}, nan) ? nan : result_bits(std::sqrt(a));
    case Opcode::FMadd: return process_nans({c, a, b}, nan) ? nan : result_bits(std::fma(a, b, c));
    case Opcode::FRint:
      return process_nans({a}, nan) ? nan : to_bits(round_to_integral(a, static_cast<FpRound>(in.aux)));
    case Opcode::FCmp:
      if (std::isnan(a) || std::isnan(b)) return kFlagC | kFlagV;
      if (a == b) return kFlagZ | kFlagC;
      return a < b ? kFlagN : kFlagC;
    default:
      return 0;
  }
}

}  // namespace

uint64_t evaluate_simd(const Inst& in, uint64_t a, uint64_t b, uint64_t c) {
  switch (in.op) {
    case Opcode::FAdd: case Opcode::FSub: case Opcode::FMul: case Opcode::FDiv: case Opcode::FMax:
    case Opcode::FMin: case Opcode::FMaxNm: case Opcode::FMinNm: case Opcode::FSqrt: case Opcode::FMadd:
    case Opcode::FRint: case Opcode::FCmp:
      return in.size == 4 ? eval_fp<float>(in, a, b, c) : eval_fp<double>(in, a, b, c);
    case Opcode::FCvt:
      if (in.aux == 4 && in.size == 8) {
        const float f = from_bits<float>(a);
        return std::isnan(f) ? to_bits(static_cast<double>(from_bits<float>(quiet(f)))) | FpTraits<double>::kQuiet
                             : to_bits(static_cast<double>(f));
      }
      if (in.aux == 8 && in.size == 4) {
        const double d = from_bits<double>(a);
        return std::isnan(d) ? (to_bits(static_cast<float>(d)) | FpTraits<float>::kQuiet) : to_bits(static_cast<float>(d));
      }
      return a;
    case Opcode::FToInt: {
      const auto mode = static_cast<FpRound>(in.aux & 7);
      const bool sign = (in.aux >> 3) & 1;
      return (in.aux >> 4) & 1 ? fp_to_int(from_bits<double>(a), mode, sign, in.size)
                               : fp_to_int(from_bits<float>(a), mode, sign, in.size);
    }
    case Opcode::IntToF: {
      const bool sign = in.aux & 1;
      const bool wide = (in.aux >> 1) & 1;
      const uint64_t u = wide ? a : (a & 0xFFFF'FFFFu);
      const int64_t s = wide ? static_cast<int64_t>(a) : static_cast<int64_t>(static_cast<int32_t>(a));
      if (in.size == 4) return to_bits(sign ? static_cast<float>(s) : static_cast<float>(u));
      return to_bits(sign ? static_cast<double>(s) : static_cast<double>(u));
    }
    default:
      return eval_vector(in, a, b);
  }
}

}  // namespace juice::ir
