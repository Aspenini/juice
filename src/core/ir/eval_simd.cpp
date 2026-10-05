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

// --- VLane: integer lanes -----------------------------------------------------------

int64_t lane_smin(unsigned bits) { return bits >= 64 ? std::numeric_limits<int64_t>::min() : -(int64_t{1} << (bits - 1)); }
int64_t lane_smax(unsigned bits) { return bits >= 64 ? std::numeric_limits<int64_t>::max() : (int64_t{1} << (bits - 1)) - 1; }
uint64_t lane_umax(unsigned bits) { return lane_mask(bits); }

uint64_t sat_signed(int64_t v, unsigned bits) {
  return static_cast<uint64_t>(std::clamp(v, lane_smin(bits), lane_smax(bits)));
}

uint64_t sat_add(uint64_t x, uint64_t y, const Lanes& l, unsigned i, bool sign, bool sub) {
  if (sign) {
    const int64_t a = l.sget(x, i), b = l.sget(y, i);
    if (l.bits < 64) return sat_signed(sub ? a - b : a + b, l.bits);
    const uint64_t r = sub ? static_cast<uint64_t>(a) - static_cast<uint64_t>(b)
                           : static_cast<uint64_t>(a) + static_cast<uint64_t>(b);
    const bool overflow = sub ? ((a ^ b) & (a ^ static_cast<int64_t>(r))) < 0
                              : (~(a ^ b) & (a ^ static_cast<int64_t>(r))) < 0;
    if (!overflow) return r;
    return static_cast<uint64_t>(a < 0 ? std::numeric_limits<int64_t>::min() : std::numeric_limits<int64_t>::max());
  }
  const uint64_t a = l.get(x, i), b = l.get(y, i);
  if (sub) return a < b ? 0 : a - b;
  const uint64_t r = (a + b) & lane_mask(l.bits);
  return r < a ? lane_umax(l.bits) : r;
}

// Rounding right shift by n (1..bits) without intermediate overflow.
uint64_t rshr_lane(uint64_t x, const Lanes& l, unsigned i, unsigned n, bool sign) {
  if (sign) {
    const int64_t v = l.sget(x, i);
    if (n > l.bits) return 0;
    const int64_t shifted = n >= 64 ? (v < 0 ? -1 : 0) : v >> n;
    const int64_t round = (v >> (n - 1)) & 1;
    return static_cast<uint64_t>(shifted + round);
  }
  const uint64_t v = l.get(x, i);
  if (n > l.bits) return 0;
  const uint64_t shifted = n >= 64 ? 0 : v >> n;
  return shifted + ((v >> (n - 1)) & 1);
}

// Saturating left shift of one lane by n (0..bits-1); mode as VecOp::SatShlImm.
uint64_t sat_shl_lane(uint64_t x, const Lanes& l, unsigned i, unsigned n, unsigned mode) {
  if (mode == 1) {  // unsigned -> unsigned
    const uint64_t v = l.get(x, i);
    if (v == 0) return 0;
    if (n >= l.bits || (v >> (l.bits - n)) != 0) return lane_umax(l.bits);
    return v << n;
  }
  const int64_t v = l.sget(x, i);
  if (mode == 2) {  // signed -> unsigned
    if (v < 0) return 0;
    const uint64_t u = static_cast<uint64_t>(v);
    if (u == 0) return 0;
    if (n >= l.bits || (u >> (l.bits - n)) != 0) return lane_umax(l.bits);
    return u << n;
  }
  if (v == 0) return 0;
  if (n >= l.bits) return static_cast<uint64_t>(v < 0 ? lane_smin(l.bits) : lane_smax(l.bits));
  const int64_t lo = lane_smin(l.bits) >> n, hi = lane_smax(l.bits) >> n;
  if (v < lo) return static_cast<uint64_t>(lane_smin(l.bits));
  if (v > hi) return static_cast<uint64_t>(lane_smax(l.bits));
  return static_cast<uint64_t>(v) << n;
}

// SSHL/USHL and their rounding/saturating forms: shift by the signed low byte of b's lane.
uint64_t shl_reg_lane(uint64_t x, uint64_t y, const Lanes& l, unsigned i, bool sign, bool rounding, bool saturating) {
  const int shift = static_cast<int8_t>(l.get(y, i) & 0xFF);
  if (shift >= 0) {
    if (saturating) return sat_shl_lane(x, l, i, static_cast<unsigned>(std::min(shift, 64)), sign ? 0 : 1);
    if (static_cast<unsigned>(shift) >= l.bits) return 0;
    return l.get(x, i) << shift;
  }
  const unsigned n = static_cast<unsigned>(-shift);
  if (rounding) return rshr_lane(x, l, i, n, sign);
  if (sign) return static_cast<uint64_t>(l.sget(x, i) >> std::min(n, 63u));
  return n >= l.bits ? 0 : l.get(x, i) >> n;
}

uint64_t narrow_lane(uint64_t wide_value, unsigned bits, unsigned mode, bool wide_signed_source) {
  // wide_value is a lane of 2 * bits; saturate it to `bits`.
  (void)wide_signed_source;
  const unsigned wbits = bits * 2;
  const uint64_t raw = wide_value & lane_mask(wbits);
  const int64_t s = wbits == 64 ? static_cast<int64_t>(raw) : static_cast<int64_t>(raw << (64 - wbits)) >> (64 - wbits);
  switch (mode) {
    case 0: return sat_signed(s, bits) & lane_mask(bits);
    case 1: return std::min<uint64_t>(raw, lane_umax(bits));
    default: return s < 0 ? 0 : std::min<uint64_t>(static_cast<uint64_t>(s), lane_umax(bits));
  }
}

uint64_t pmul8(uint64_t x, uint64_t y) {
  uint64_t r = 0;
  for (unsigned k = 0; k < 8; ++k)
    if ((y >> k) & 1) r ^= x << k;
  return r;
}

uint64_t sat_dmul_high(uint64_t x, uint64_t y, const Lanes& l, unsigned i, bool round) {
  const int64_t a = l.sget(x, i), b = l.sget(y, i);
  if (a == lane_smin(l.bits) && b == lane_smin(l.bits)) return static_cast<uint64_t>(lane_smax(l.bits));
  // bits <= 32: the doubled product fits in 64 bits.
  int64_t p = 2 * a * b;
  if (round) p += int64_t{1} << (l.bits - 1);
  return static_cast<uint64_t>(p >> l.bits);
}

// --- VLane: floating point lanes --------------------------------------------------------

uint16_t f32_to_f16(uint32_t f) {
  const uint32_t sign = (f >> 16) & 0x8000;
  const int exp = static_cast<int>((f >> 23) & 0xFF);
  uint32_t mant = f & 0x7F'FFFF;
  if (exp == 0xFF) {
    if (mant == 0) return static_cast<uint16_t>(sign | 0x7C00);
    return static_cast<uint16_t>(sign | 0x7E00 | (mant >> 13));  // quiet NaN, top payload bits
  }
  int e = exp - 127 + 15;
  if (e >= 31) return static_cast<uint16_t>(sign | 0x7C00);  // overflow (round to nearest)
  if (e <= 0) {
    if (e < -10) return static_cast<uint16_t>(sign);  // underflows to zero
    mant |= 0x80'0000;
    const unsigned shift = static_cast<unsigned>(14 - e);
    uint32_t h = mant >> shift;
    const uint32_t rem = mant & ((1u << shift) - 1), half = 1u << (shift - 1);
    if (rem > half || (rem == half && (h & 1))) ++h;
    return static_cast<uint16_t>(sign | h);
  }
  uint32_t h = (static_cast<uint32_t>(e) << 10) | (mant >> 13);
  const uint32_t rem = mant & 0x1FFF;
  if (rem > 0x1000 || (rem == 0x1000 && (h & 1))) ++h;  // may carry into the exponent: correct
  return static_cast<uint16_t>(sign | h);
}

uint32_t f16_to_f32(uint16_t h) {
  const uint32_t sign = static_cast<uint32_t>(h & 0x8000) << 16;
  const unsigned exp = (h >> 10) & 0x1F;
  uint32_t mant = h & 0x3FF;
  if (exp == 0x1F) return sign | 0x7F80'0000 | (mant << 13) | (mant ? 0x40'0000 : 0);  // NaNs are quieted
  if (exp == 0) {
    if (mant == 0) return sign;
    int e = -14;
    while (!(mant & 0x400)) {
      mant <<= 1;
      --e;
    }
    mant &= 0x3FF;
    return sign | (static_cast<uint32_t>(e + 127) << 23) | (mant << 13);
  }
  return sign | ((exp - 15 + 127) << 23) | (mant << 13);
}

unsigned recip_estimate(unsigned a) {  // 256 <= a <= 511
  a = a * 2 + 1;
  const unsigned b = (1u << 19) / a;
  return (b + 1) / 2;
}

unsigned rsqrt_estimate(unsigned a) {  // 128 <= a <= 511
  if (a < 256) {
    a = a * 2 + 1;
  } else {
    a = (a >> 1) << 1;
    a = (a + 1) * 2;
  }
  unsigned b = 512;
  while (uint64_t{a} * (b + 1) * (b + 1) < (uint64_t{1} << 28)) ++b;
  return (b + 1) / 2;
}

template <typename T>
uint64_t fp_recip_estimate(T x) {
  using Bits = typename FpTraits<T>::Bits;
  constexpr unsigned kMant = sizeof(T) == 4 ? 23 : 52, kExpBits = sizeof(T) == 4 ? 8 : 11;
  constexpr int kBias = sizeof(T) == 4 ? 127 : 1023;
  const Bits bits = static_cast<Bits>(to_bits(x));
  const Bits sign = bits & (Bits{1} << (kMant + kExpBits));
  uint64_t nan;
  if (process_nans({x}, nan)) return nan;
  if (std::isinf(x)) return sign;
  if (x == 0) return sign | to_bits(std::numeric_limits<T>::infinity());
  if (std::fabs(x) < std::ldexp(T(1), -(kBias + 1))) return sign | to_bits(std::numeric_limits<T>::infinity());
  Bits fraction = bits & ((Bits{1} << kMant) - 1);
  int exp = static_cast<int>((bits >> kMant) & ((1u << kExpBits) - 1));
  if (exp == 0) {
    if (!((fraction >> (kMant - 1)) & 1)) {
      exp = -1;
      fraction = (fraction << 2) & ((Bits{1} << kMant) - 1);
    } else {
      fraction = (fraction << 1) & ((Bits{1} << kMant) - 1);
    }
  }
  const unsigned scaled = static_cast<unsigned>(0x100 | (fraction >> (kMant - 8)));
  int result_exp = 2 * kBias - 1 - exp;
  const unsigned estimate = recip_estimate(scaled);
  Bits out_fraction = static_cast<Bits>(estimate & 0xFF) << (kMant - 8);
  if (result_exp == 0) {
    out_fraction = (Bits{1} << (kMant - 1)) | (out_fraction >> 1);
  } else if (result_exp == -1) {
    out_fraction = (Bits{1} << (kMant - 2)) | (out_fraction >> 2);
    result_exp = 0;
  }
  return sign | (static_cast<Bits>(result_exp) << kMant) | out_fraction;
}

template <typename T>
uint64_t fp_rsqrt_estimate(T x) {
  using Bits = typename FpTraits<T>::Bits;
  constexpr unsigned kMant = sizeof(T) == 4 ? 23 : 52, kExpBits = sizeof(T) == 4 ? 8 : 11;
  constexpr int kBias = sizeof(T) == 4 ? 127 : 1023;
  const Bits bits = static_cast<Bits>(to_bits(x));
  uint64_t nan;
  if (process_nans({x}, nan)) return nan;
  if (x == 0) return (bits & (Bits{1} << (kMant + kExpBits))) | to_bits(std::numeric_limits<T>::infinity());
  if (std::signbit(x)) return FpTraits<T>::kDefaultNaN;
  if (std::isinf(x)) return 0;
  Bits fraction = bits & ((Bits{1} << kMant) - 1);
  int exp = static_cast<int>((bits >> kMant) & ((1u << kExpBits) - 1));
  if (exp == 0) {
    while (!((fraction >> (kMant - 1)) & 1)) {
      fraction <<= 1;
      --exp;
    }
    fraction = (fraction << 1) & ((Bits{1} << kMant) - 1);
  }
  const unsigned scaled = (exp & 1) == 0 ? static_cast<unsigned>(0x100 | (fraction >> (kMant - 8)))
                                         : static_cast<unsigned>(0x80 | (fraction >> (kMant - 7)));
  const int result_exp = (3 * kBias - 1 - exp) / 2;
  const unsigned estimate = rsqrt_estimate(scaled);
  return (static_cast<Bits>(result_exp) << kMant) | (static_cast<Bits>(estimate & 0xFF) << (kMant - 8));
}

template <typename T>
uint64_t fp_lane(VecOp op, uint64_t ra, uint64_t rb, uint64_t rc, unsigned aux, uint64_t fbits) {
  const T a = from_bits<T>(ra), b = from_bits<T>(rb), c = from_bits<T>(rc);
  Inst s;
  s.size = sizeof(T);
  auto scalar = [&](Opcode o, uint64_t x, uint64_t y = 0, uint64_t z = 0, uint8_t saux = 0) {
    s.op = o;
    s.aux = saux;
    return eval_fp<T>(s, x, y, z);
  };
  const uint64_t ones = lane_mask(sizeof(T) * 8);
  uint64_t nan;
  switch (op) {
    case VecOp::FAdd: return scalar(Opcode::FAdd, ra, rb);
    case VecOp::FSub: return scalar(Opcode::FSub, ra, rb);
    case VecOp::FMul: return scalar(Opcode::FMul, ra, rb);
    case VecOp::FDiv: return scalar(Opcode::FDiv, ra, rb);
    case VecOp::FMax: return scalar(Opcode::FMax, ra, rb);
    case VecOp::FMin: return scalar(Opcode::FMin, ra, rb);
    case VecOp::FMaxNm: return scalar(Opcode::FMaxNm, ra, rb);
    case VecOp::FMinNm: return scalar(Opcode::FMinNm, ra, rb);
    case VecOp::FAbd: return scalar(Opcode::FSub, ra, rb) & (ones >> 1);
    case VecOp::FMulX:
      if ((std::isinf(a) && b == 0) || (a == 0 && std::isinf(b))) {
        if (process_nans({a, b}, nan)) return nan;
        return to_bits(std::signbit(a) != std::signbit(b) ? T(-2) : T(2));
      }
      return scalar(Opcode::FMul, ra, rb);
    case VecOp::FMla: return scalar(Opcode::FMadd, ra, rb, rc);
    case VecOp::FMls: return scalar(Opcode::FMadd, to_bits(-a), rb, rc);
    case VecOp::FCmEq: return !std::isnan(a) && !std::isnan(b) && a == b ? ones : 0;
    case VecOp::FCmGe: return !std::isnan(a) && !std::isnan(b) && a >= b ? ones : 0;
    case VecOp::FCmGt: return !std::isnan(a) && !std::isnan(b) && a > b ? ones : 0;
    case VecOp::FAcGe: return !std::isnan(a) && !std::isnan(b) && std::fabs(a) >= std::fabs(b) ? ones : 0;
    case VecOp::FAcGt: return !std::isnan(a) && !std::isnan(b) && std::fabs(a) > std::fabs(b) ? ones : 0;
    case VecOp::FRecps:
      if (process_nans({a, b}, nan)) return nan;
      if ((std::isinf(a) && b == 0) || (a == 0 && std::isinf(b))) return to_bits(T(2));
      return result_bits(std::fma(-a, b, T(2)));
    case VecOp::FRsqrts:
      if (process_nans({a, b}, nan)) return nan;
      if ((std::isinf(a) && b == 0) || (a == 0 && std::isinf(b))) return to_bits(T(1.5));
      return result_bits(std::fma(-a, b, T(3)) / T(2));
    case VecOp::FSqrt: return scalar(Opcode::FSqrt, ra);
    case VecOp::FRecpe: return fp_recip_estimate(a);
    case VecOp::FRsqrte: return fp_rsqrt_estimate(a);
    case VecOp::FRint: return scalar(Opcode::FRint, ra, 0, 0, static_cast<uint8_t>((aux >> 4) & 7));
    case VecOp::FToInt: {
      const T scaled = fbits ? std::ldexp(a, static_cast<int>(fbits)) : a;
      return fp_to_int(scaled, static_cast<FpRound>((aux >> 4) & 7), (aux >> 7) & 1, sizeof(T));
    }
    case VecOp::IntToF: {
      const unsigned bits = sizeof(T) * 8;
      const uint64_t u = ra & lane_mask(bits);
      const int64_t sv = bits == 64 ? static_cast<int64_t>(u) : static_cast<int64_t>(u << (64 - bits)) >> (64 - bits);
      T v = (aux >> 4) & 1 ? static_cast<T>(sv) : static_cast<T>(u);
      if (fbits) v = std::ldexp(v, -static_cast<int>(fbits));
      return to_bits(v);
    }
    default:
      return 0;
  }
  (void)c;
}

uint64_t eval_lane(const Inst& in, uint64_t a, uint64_t b, uint64_t c) {
  const auto op = static_cast<VecOp>(in.imm);
  const unsigned aux = in.aux;
  const Lanes l(aux & 0xF);
  const bool sign = (aux >> 4) & 1;
  const unsigned mode = (aux >> 4) & 3;
  switch (op) {
    case VecOp::SatAdd: return map2(a, b, l, [&](unsigned i) { return sat_add(a, b, l, i, sign, false); });
    case VecOp::SatSub: return map2(a, b, l, [&](unsigned i) { return sat_add(a, b, l, i, sign, true); });
    case VecOp::Abd:
      return map2(a, b, l, [&](unsigned i) -> uint64_t {
        if (sign) {
          const int64_t x = l.sget(a, i), y = l.sget(b, i);
          return x > y ? static_cast<uint64_t>(x) - static_cast<uint64_t>(y) : static_cast<uint64_t>(y) - static_cast<uint64_t>(x);
        }
        const uint64_t x = l.get(a, i), y = l.get(b, i);
        return x > y ? x - y : y - x;
      });
    case VecOp::HAdd:
    case VecOp::RHAdd:
    case VecOp::HSub:  // element size <= 4: the sums fit in 64 bits
      return map2(a, b, l, [&](unsigned i) -> uint64_t {
        const int64_t x = sign ? l.sget(a, i) : static_cast<int64_t>(l.get(a, i));
        const int64_t y = sign ? l.sget(b, i) : static_cast<int64_t>(l.get(b, i));
        const int64_t r = op == VecOp::HSub ? x - y : x + y + (op == VecOp::RHAdd ? 1 : 0);
        return static_cast<uint64_t>(r >> 1);
      });
    case VecOp::ShlReg: return map2(a, b, l, [&](unsigned i) { return shl_reg_lane(a, b, l, i, sign, false, false); });
    case VecOp::RShlReg: return map2(a, b, l, [&](unsigned i) { return shl_reg_lane(a, b, l, i, sign, true, false); });
    case VecOp::SatShlReg: return map2(a, b, l, [&](unsigned i) { return shl_reg_lane(a, b, l, i, sign, false, true); });
    case VecOp::SatRShlReg: return map2(a, b, l, [&](unsigned i) { return shl_reg_lane(a, b, l, i, sign, true, true); });
    case VecOp::RShr: return map2(a, b, l, [&](unsigned i) { return rshr_lane(a, l, i, static_cast<unsigned>(b), sign); });
    case VecOp::SatShlImm:
      return map2(a, b, l, [&](unsigned i) { return sat_shl_lane(a, l, i, static_cast<unsigned>(b), mode); });
    case VecOp::SatNarrow: {
      const Lanes wide(l.esize * 2);
      uint64_t r = 0;
      for (unsigned i = 0; i < wide.count; ++i) r = l.put(r, i, narrow_lane(wide.get(a, i), l.bits, mode, true));
      return r;
    }
    case VecOp::AddLongPairwise: {
      const Lanes wide(l.esize * 2);
      uint64_t r = 0;
      for (unsigned i = 0; i < wide.count; ++i) {
        const uint64_t s = sign ? static_cast<uint64_t>(l.sget(a, 2 * i) + l.sget(a, 2 * i + 1))
                                : l.get(a, 2 * i) + l.get(a, 2 * i + 1);
        r = wide.put(r, i, s);
      }
      return r;
    }
    case VecOp::PMul: {
      const Lanes bytes(1);
      return map2(a, b, bytes, [&](unsigned i) { return pmul8(bytes.get(a, i), bytes.get(b, i)) & 0xFF; });
    }
    case VecOp::PMulLong: {
      const unsigned first = (aux >> 5) & 1 ? 4 : 0;
      const Lanes bytes(1), halves(2);
      uint64_t r = 0;
      for (unsigned i = 0; i < 4; ++i) r = halves.put(r, i, pmul8(bytes.get(a, first + i), bytes.get(b, first + i)));
      return r;
    }
    case VecOp::SatDMulHigh:
      return map2(a, b, l, [&](unsigned i) { return sat_dmul_high(a, b, l, i, (aux >> 5) & 1); });
    case VecOp::TblPart: {
      const Lanes bytes(1);
      const unsigned base = aux * 8;
      return map2(a, b, bytes, [&](unsigned i) {
        const unsigned idx = static_cast<unsigned>(bytes.get(b, i));
        return idx >= base && idx < base + 8 ? bytes.get(c, idx - base) : bytes.get(a, i);
      });
    }
    case VecOp::Clz:
      return map2(a, b, l, [&](unsigned i) {
        const uint64_t v = l.get(a, i);
        return static_cast<uint64_t>(v ? std::countl_zero(v) - (64 - static_cast<int>(l.bits)) : static_cast<int>(l.bits));
      });
    case VecOp::Cls:
      return map2(a, b, l, [&](unsigned i) {
        const int64_t v = l.sget(a, i);
        const uint64_t x = static_cast<uint64_t>(v < 0 ? ~v : v) & lane_mask(l.bits);
        return static_cast<uint64_t>((x ? std::countl_zero(x) - (64 - static_cast<int>(l.bits)) : static_cast<int>(l.bits)) - 1);
      });
    case VecOp::Rbit: {
      const Lanes bytes(1);
      return map2(a, b, bytes, [&](unsigned i) {
        uint64_t v = bytes.get(a, i), r = 0;
        for (unsigned k = 0; k < 8; ++k) r |= ((v >> k) & 1) << (7 - k);
        return r;
      });
    }
    case VecOp::SatAbs:
      return map2(a, b, l, [&](unsigned i) -> uint64_t {
        const int64_t v = l.sget(a, i);
        if (v == lane_smin(l.bits)) return static_cast<uint64_t>(lane_smax(l.bits));
        return static_cast<uint64_t>(v < 0 ? -v : v);
      });
    case VecOp::SatNeg:
      return map2(a, b, l, [&](unsigned i) -> uint64_t {
        const int64_t v = l.sget(a, i);
        if (v == lane_smin(l.bits)) return static_cast<uint64_t>(lane_smax(l.bits));
        return static_cast<uint64_t>(-v);
      });
    case VecOp::FCvtUp: {
      const uint64_t src = (aux >> 4) & 1 ? a >> 32 : a & 0xFFFF'FFFFu;
      if (l.esize == 8) {
        Inst cvt;
        cvt.op = Opcode::FCvt;
        cvt.size = 8;
        cvt.aux = 4;
        return evaluate_simd(cvt, src, 0, 0);
      }
      return uint64_t{f16_to_f32(static_cast<uint16_t>(src))} | (uint64_t{f16_to_f32(static_cast<uint16_t>(src >> 16))} << 32);
    }
    case VecOp::FCvtDown: {
      if (l.esize == 4) {
        Inst cvt;
        cvt.op = Opcode::FCvt;
        cvt.size = 4;
        cvt.aux = 8;
        return evaluate_simd(cvt, a, 0, 0) | (evaluate_simd(cvt, b, 0, 0) << 32);
      }
      auto pack = [](uint64_t v) {
        return uint64_t{f32_to_f16(static_cast<uint32_t>(v))} | (uint64_t{f32_to_f16(static_cast<uint32_t>(v >> 32))} << 16);
      };
      return pack(a) | (pack(b) << 32);
    }
    default: {
      if (op < VecOp::FAdd || op >= VecOp::Count_) return 0;
      const uint64_t fbits = (op == VecOp::FToInt || op == VecOp::IntToF) ? b : 0;
      return map2(a, b, l, [&](unsigned i) {
        const uint64_t x = l.get(a, i), y = l.get(b, i), z = l.get(c, i);
        return l.esize == 8 ? fp_lane<double>(op, x, y, z, aux, fbits) : fp_lane<float>(op, x, y, z, aux, fbits);
      });
    }
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
    case Opcode::VLane:
      return eval_lane(in, a, b, c);
    default:
      return eval_vector(in, a, b);
  }
}

}  // namespace juice::ir
