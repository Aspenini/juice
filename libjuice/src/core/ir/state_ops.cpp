// StateOp: operations on 128-bit values held in pairs of state slots, for
// instructions whose results depend on both halves of their operands (the
// Arm cryptographic extensions). The definitions follow the Arm
// architecture's pseudocode for AESE/AESD/AESMC/AESIMC, SHA1*, SHA256*,
// SHA512* and PMULL (1Q).

#include <array>
#include <bit>
#include <cstdint>
#include <cstring>

#include "core/ir/eval_simd.hpp"
#include "core/ir/ir.hpp"

namespace juice::ir {
namespace {

struct U128 {
  uint64_t lo, hi;
};

U128 read(const uint64_t* state, unsigned slot) { return {state[slot], state[slot + 1]}; }
void write(uint64_t* state, unsigned slot, U128 v) {
  state[slot] = v.lo;
  state[slot + 1] = v.hi;
}

// --- AES ------------------------------------------------------------------------------

uint8_t gf_mul(uint8_t a, uint8_t b) {
  uint8_t r = 0;
  while (b) {
    if (b & 1) r ^= a;
    a = static_cast<uint8_t>((a << 1) ^ ((a & 0x80) ? 0x1B : 0));
    b >>= 1;
  }
  return r;
}

struct AesTables {
  std::array<uint8_t, 256> sbox{}, inv_sbox{};
  AesTables() {
    for (unsigned x = 0; x < 256; ++x) {
      uint8_t inv = 0;
      for (unsigned y = 1; x && y < 256; ++y)
        if (gf_mul(static_cast<uint8_t>(x), static_cast<uint8_t>(y)) == 1) inv = static_cast<uint8_t>(y);
      const uint8_t s = static_cast<uint8_t>(inv ^ std::rotl(inv, 1) ^ std::rotl(inv, 2) ^ std::rotl(inv, 3) ^
                                             std::rotl(inv, 4) ^ 0x63);
      sbox[x] = s;
      inv_sbox[s] = static_cast<uint8_t>(x);
    }
  }
};

const AesTables& aes() {
  static const AesTables t;
  return t;
}

// The state's bytes are those of the 128-bit value, least significant first;
// byte 4c + r is row r of column c.
using Bytes = std::array<uint8_t, 16>;
Bytes to_bytes(U128 v) {
  Bytes b;
  std::memcpy(b.data(), &v.lo, 8);
  std::memcpy(b.data() + 8, &v.hi, 8);
  return b;
}
U128 from_bytes(const Bytes& b) {
  U128 v;
  std::memcpy(&v.lo, b.data(), 8);
  std::memcpy(&v.hi, b.data() + 8, 8);
  return v;
}

U128 aes_round(U128 v, bool decrypt) {
  // (Inv)ShiftRows: row r rotates left (right) by r columns; then (Inv)SubBytes.
  static constexpr uint8_t kShift[16] = {0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11};
  static constexpr uint8_t kInvShift[16] = {0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3};
  const Bytes in = to_bytes(v);
  const auto& box = decrypt ? aes().inv_sbox : aes().sbox;
  Bytes out;
  for (unsigned i = 0; i < 16; ++i) out[i] = box[in[decrypt ? kInvShift[i] : kShift[i]]];
  return from_bytes(out);
}

U128 aes_mix(U128 v, bool inverse) {
  const Bytes in = to_bytes(v);
  Bytes out;
  static constexpr uint8_t kMix[4] = {2, 3, 1, 1};
  static constexpr uint8_t kInvMix[4] = {14, 11, 13, 9};
  const uint8_t* m = inverse ? kInvMix : kMix;
  for (unsigned c = 0; c < 4; ++c)
    for (unsigned r = 0; r < 4; ++r) {
      uint8_t acc = 0;
      for (unsigned k = 0; k < 4; ++k) acc ^= gf_mul(in[4 * c + (r + k) % 4], m[k]);
      out[4 * c + r] = acc;
    }
  return from_bytes(out);
}

// --- SHA-1 / SHA-256: four 32-bit words, word 0 least significant -----------------------

using Words = std::array<uint32_t, 4>;
Words to_words(U128 v) {
  return {static_cast<uint32_t>(v.lo), static_cast<uint32_t>(v.lo >> 32), static_cast<uint32_t>(v.hi),
          static_cast<uint32_t>(v.hi >> 32)};
}
U128 from_words(const Words& w) {
  return {w[0] | (uint64_t{w[1]} << 32), w[2] | (uint64_t{w[3]} << 32)};
}

uint32_t choose(uint32_t x, uint32_t y, uint32_t z) { return ((y ^ z) & x) ^ z; }
uint32_t parity(uint32_t x, uint32_t y, uint32_t z) { return x ^ y ^ z; }
uint32_t majority(uint32_t x, uint32_t y, uint32_t z) { return (x & y) | ((x | y) & z); }

U128 sha1_hash(U128 abcd, uint32_t e, U128 wk, StateOpKind kind) {
  Words x = to_words(abcd);
  const Words w = to_words(wk);
  uint32_t y = e;
  for (unsigned i = 0; i < 4; ++i) {
    const uint32_t t = kind == StateOpKind::Sha1C   ? choose(x[1], x[2], x[3])
                       : kind == StateOpKind::Sha1M ? majority(x[1], x[2], x[3])
                                                    : parity(x[1], x[2], x[3]);
    y = y + std::rotl(x[0], 5) + t + w[i];
    x[1] = std::rotl(x[1], 30);
    // <Y, X> = ROL(Y:X, 32)
    const uint32_t top = x[3];
    x = {y, x[0], x[1], x[2]};
    y = top;
  }
  return from_words(x);
}

U128 sha1_su0(U128 d, U128 n, U128 m) {
  const Words a = to_words(d), b = to_words(n), c = to_words(m);
  return from_words({a[2] ^ a[0] ^ c[0], a[3] ^ a[1] ^ c[1], b[0] ^ a[2] ^ c[2], b[1] ^ a[3] ^ c[3]});
}

U128 sha1_su1(U128 d, U128 n) {
  const Words a = to_words(d), b = to_words(n);
  const Words t = {a[0] ^ b[1], a[1] ^ b[2], a[2] ^ b[3], a[3]};
  return from_words({std::rotl(t[0], 1), std::rotl(t[1], 1), std::rotl(t[2], 1),
                     std::rotl(t[3], 1) ^ std::rotl(t[0], 2)});
}

uint32_t sigma_big0(uint32_t x) { return std::rotr(x, 2) ^ std::rotr(x, 13) ^ std::rotr(x, 22); }
uint32_t sigma_big1(uint32_t x) { return std::rotr(x, 6) ^ std::rotr(x, 11) ^ std::rotr(x, 25); }
uint32_t sigma_small0(uint32_t x) { return std::rotr(x, 7) ^ std::rotr(x, 18) ^ (x >> 3); }
uint32_t sigma_small1(uint32_t x) { return std::rotr(x, 17) ^ std::rotr(x, 19) ^ (x >> 10); }

// SHA256hash(X = abcd, Y = efgh, W): returns X for SHA256H, Y for SHA256H2.
U128 sha256_hash(U128 abcd, U128 efgh, U128 wk, bool part1) {
  Words x = to_words(abcd), y = to_words(efgh);
  const Words w = to_words(wk);
  for (unsigned i = 0; i < 4; ++i) {
    const uint32_t ch = choose(y[0], y[1], y[2]);
    const uint32_t maj = majority(x[0], x[1], x[2]);
    const uint32_t t = y[3] + sigma_big1(y[0]) + ch + w[i];
    x[3] = t + x[3];
    y[3] = t + sigma_big0(x[0]) + maj;
    // <Y, X> = ROL(Y:X, 32)
    const Words ox = x, oy = y;
    x = {oy[3], ox[0], ox[1], ox[2]};
    y = {ox[3], oy[0], oy[1], oy[2]};
  }
  return from_words(part1 ? x : y);
}

U128 sha256_su0(U128 d, U128 n) {
  const Words a = to_words(d), b = to_words(n);
  const Words t = {a[1], a[2], a[3], b[0]};
  Words r;
  for (unsigned i = 0; i < 4; ++i) r[i] = sigma_small0(t[i]) + a[i];
  return from_words(r);
}

U128 sha256_su1(U128 d, U128 n, U128 m) {
  const Words a = to_words(d), b = to_words(n), c = to_words(m);
  const Words t0 = {b[1], b[2], b[3], c[0]};
  Words r;
  r[0] = sigma_small1(c[2]) + a[0] + t0[0];
  r[1] = sigma_small1(c[3]) + a[1] + t0[1];
  r[2] = sigma_small1(r[0]) + a[2] + t0[2];
  r[3] = sigma_small1(r[1]) + a[3] + t0[3];
  return from_words(r);
}

// --- SHA-512: two 64-bit lanes -------------------------------------------------------------

uint64_t choose64(uint64_t x, uint64_t y, uint64_t z) { return (x & (y ^ z)) ^ z; }
uint64_t majority64(uint64_t x, uint64_t y, uint64_t z) { return (x & y) | ((x | y) & z); }
uint64_t sigma512_big0(uint64_t x) { return std::rotr(x, 28) ^ std::rotr(x, 34) ^ std::rotr(x, 39); }
uint64_t sigma512_big1(uint64_t x) { return std::rotr(x, 14) ^ std::rotr(x, 18) ^ std::rotr(x, 41); }
uint64_t sigma512_small0(uint64_t x) { return std::rotr(x, 1) ^ std::rotr(x, 8) ^ (x >> 7); }
uint64_t sigma512_small1(uint64_t x) { return std::rotr(x, 19) ^ std::rotr(x, 61) ^ (x >> 6); }

U128 sha512_h(U128 d, U128 n, U128 m) {
  const uint64_t hi = d.hi + sigma512_big1(m.hi) + choose64(m.hi, n.lo, n.hi);
  const uint64_t t = hi + m.lo;
  const uint64_t lo = d.lo + sigma512_big1(t) + choose64(t, m.hi, n.lo);
  return {lo, hi};
}

U128 sha512_h2(U128 d, U128 n, U128 m) {
  const uint64_t hi = d.hi + sigma512_big0(m.lo) + majority64(n.lo, m.hi, m.lo);
  const uint64_t lo = d.lo + sigma512_big0(hi) + majority64(hi, m.lo, m.hi);
  return {lo, hi};
}

U128 sha512_su0(U128 d, U128 n) { return {d.lo + sigma512_small0(d.hi), d.hi + sigma512_small0(n.lo)}; }

U128 sha512_su1(U128 d, U128 n, U128 m) {
  return {d.lo + sigma512_small1(n.lo) + m.lo, d.hi + sigma512_small1(n.hi) + m.hi};
}

// --- PMULL (1Q) ------------------------------------------------------------------------------

U128 clmul64(uint64_t a, uint64_t b) {
  U128 r{0, 0};
  for (unsigned k = 0; k < 64; ++k) {
    if (!((b >> k) & 1)) continue;
    r.lo ^= a << k;
    if (k) r.hi ^= a >> (64 - k);
  }
  return r;
}

// --- Matrix multiply-accumulate: d (2x2) += n (2 rows) * m (2 rows) transposed ---------------

U128 mmla(U128 d, U128 n, U128 m, unsigned signs) {
  const Bytes a = to_bytes(n), b = to_bytes(m);
  Words acc = to_words(d);
  for (unsigned i = 0; i < 2; ++i)
    for (unsigned j = 0; j < 2; ++j) {
      uint32_t sum = acc[2 * i + j];
      for (unsigned k = 0; k < 8; ++k) {
        const int32_t x = (signs & 1) ? static_cast<int8_t>(a[8 * i + k]) : a[8 * i + k];
        const int32_t y = (signs & 2) ? static_cast<int8_t>(b[8 * j + k]) : b[8 * j + k];
        sum += static_cast<uint32_t>(x * y);
      }
      acc[2 * i + j] = sum;
    }
  return from_words(acc);
}

U128 bf_mmla(U128 d, U128 n, U128 m) {
  auto bf = [](U128 v, unsigned k) { return static_cast<uint16_t>((k < 4 ? v.lo : v.hi) >> (16 * (k % 4))); };
  Words acc = to_words(d);
  for (unsigned i = 0; i < 2; ++i)
    for (unsigned j = 0; j < 2; ++j) {
      uint32_t sum = acc[2 * i + j];
      for (unsigned k = 0; k < 4; k += 2)
        sum = bf_dot_add(sum, bf(n, 4 * i + k), bf(n, 4 * i + k + 1), bf(m, 4 * j + k), bf(m, 4 * j + k + 1));
      acc[2 * i + j] = sum;
    }
  return from_words(acc);
}

// --- SM3 --------------------------------------------------------------------------------

uint32_t sm3_p1(uint32_t x) { return x ^ std::rotl(x, 15) ^ std::rotl(x, 23); }

U128 sm3_ss1(U128 n, U128 m, U128 a) {
  const uint32_t r = std::rotl(std::rotl(to_words(n)[3], 12) + to_words(m)[3] + to_words(a)[3], 7);
  return from_words({0, 0, 0, r});
}

U128 sm3_tt(U128 d, U128 n, U128 m, unsigned index, StateOpKind kind) {
  const Words x = to_words(d);
  const uint32_t w = to_words(m)[index & 3], ss = to_words(n)[3];
  if (kind == StateOpKind::Sm3Tt1a || kind == StateOpKind::Sm3Tt1b) {
    const uint32_t ff = kind == StateOpKind::Sm3Tt1a ? x[3] ^ x[2] ^ x[1] : majority(x[3], x[2], x[1]);
    const uint32_t ss2 = ss ^ std::rotl(x[3], 12);
    return from_words({x[1], std::rotl(x[2], 9), x[3], ff + x[0] + ss2 + w});
  }
  const uint32_t gg = kind == StateOpKind::Sm3Tt2a ? x[3] ^ x[2] ^ x[1] : (x[3] & x[2]) | (~x[3] & x[1]);
  const uint32_t tt2 = gg + x[0] + ss + w;
  return from_words({x[1], std::rotl(x[2], 19), x[3], tt2 ^ std::rotl(tt2, 9) ^ std::rotl(tt2, 17)});
}

U128 sm3_partw1(U128 d, U128 n, U128 m) {
  const Words a = to_words(d), b = to_words(n), c = to_words(m);
  Words r;
  for (unsigned k = 0; k < 3; ++k) r[k] = sm3_p1(a[k] ^ b[k] ^ std::rotl(c[k + 1], 15));
  r[3] = sm3_p1(a[3] ^ b[3] ^ std::rotl(r[0], 15));
  return from_words(r);
}

U128 sm3_partw2(U128 d, U128 n, U128 m) {
  const Words a = to_words(d), b = to_words(n), c = to_words(m);
  Words t, r;
  for (unsigned k = 0; k < 4; ++k) {
    t[k] = b[k] ^ std::rotl(c[k], 7);
    r[k] = a[k] ^ t[k];
  }
  r[3] ^= sm3_p1(std::rotl(t[0], 15));
  return from_words(r);
}

// --- SM4 ----------------------------------------------------------------------------------
// The S-box is the affine-inverse-affine construction over GF(2^8) with the
// polynomial x^8 + x^7 + x^6 + x^5 + x^4 + x^2 + 1 (it reproduces the
// standard's table and test vectors).

struct Sm4Tables {
  std::array<uint8_t, 256> sbox{};
  Sm4Tables() {
    auto mul = [](unsigned a, unsigned b) {
      unsigned r = 0;
      while (b) {
        if (b & 1) r ^= a;
        a <<= 1;
        if (a & 0x100) a ^= 0x1F5;
        b >>= 1;
      }
      return r;
    };
    auto affine = [](unsigned x) {  // circulant matrix of 0xA7, plus 0xD3
      unsigned out = 0;
      for (unsigned i = 0; i < 8; ++i) {
        const unsigned row = ((0xA7u << i) | (0xA7u >> (8 - i))) & 0xFF;
        if (std::popcount(row & x) & 1) out |= 1u << i;
      }
      return out ^ 0xD3;
    };
    std::array<unsigned, 256> inv{};
    for (unsigned x = 1; x < 256; ++x)
      for (unsigned y = 1; y < 256; ++y)
        if (mul(x, y) == 1) {
          inv[x] = y;
          break;
        }
    for (unsigned x = 0; x < 256; ++x) sbox[x] = static_cast<uint8_t>(affine(inv[affine(x)]));
  }
};

uint32_t sm4_tau(uint32_t a) {
  static const Sm4Tables t;
  uint32_t r = 0;
  for (unsigned k = 0; k < 4; ++k) r |= uint32_t{t.sbox[(a >> (8 * k)) & 0xFF]} << (8 * k);
  return r;
}

// Four rounds: each new word from the three before it and a key word.
U128 sm4_rounds(U128 d, U128 keys, bool key_schedule) {
  Words x = to_words(d);
  const Words k = to_words(keys);
  for (unsigned i = 0; i < 4; ++i) {
    uint32_t t = sm4_tau(x[1] ^ x[2] ^ x[3] ^ k[i]);
    t = key_schedule ? t ^ std::rotl(t, 13) ^ std::rotl(t, 23)
                     : t ^ std::rotl(t, 2) ^ std::rotl(t, 10) ^ std::rotl(t, 18) ^ std::rotl(t, 24);
    x = {x[1], x[2], x[3], x[0] ^ t};
  }
  return from_words(x);
}

}  // namespace

void execute_state_op(const Inst& in, uint64_t* state) {
  const auto kind = static_cast<StateOpKind>(in.imm & 0xFF);
  const unsigned d = (in.imm >> 8) & 0xFF, n = (in.imm >> 16) & 0xFF, m = (in.imm >> 24) & 0xFF;
  const U128 vd = read(state, d), vn = read(state, n), vm = read(state, m);
  U128 r{};
  switch (kind) {
    case StateOpKind::AesE: r = aes_round({vd.lo ^ vn.lo, vd.hi ^ vn.hi}, false); break;
    case StateOpKind::AesD: r = aes_round({vd.lo ^ vn.lo, vd.hi ^ vn.hi}, true); break;
    case StateOpKind::AesMc: r = aes_mix(vn, false); break;
    case StateOpKind::AesImc: r = aes_mix(vn, true); break;
    case StateOpKind::Sha1C:
    case StateOpKind::Sha1P:
    case StateOpKind::Sha1M: r = sha1_hash(vd, static_cast<uint32_t>(vn.lo), vm, kind); break;
    case StateOpKind::Sha1Su0: r = sha1_su0(vd, vn, vm); break;
    case StateOpKind::Sha1Su1: r = sha1_su1(vd, vn); break;
    case StateOpKind::Sha256H: r = sha256_hash(vd, vn, vm, true); break;
    case StateOpKind::Sha256H2: r = sha256_hash(vn, vd, vm, false); break;
    case StateOpKind::Sha256Su0: r = sha256_su0(vd, vn); break;
    case StateOpKind::Sha256Su1: r = sha256_su1(vd, vn, vm); break;
    case StateOpKind::Sha512H: r = sha512_h(vd, vn, vm); break;
    case StateOpKind::Sha512H2: r = sha512_h2(vd, vn, vm); break;
    case StateOpKind::Sha512Su0: r = sha512_su0(vd, vn); break;
    case StateOpKind::Sha512Su1: r = sha512_su1(vd, vn, vm); break;
    case StateOpKind::PMull64: r = in.aux ? clmul64(vn.hi, vm.hi) : clmul64(vn.lo, vm.lo); break;
    case StateOpKind::Mmla: r = mmla(vd, vn, vm, in.aux); break;
    case StateOpKind::BfMmla: r = bf_mmla(vd, vn, vm); break;
    case StateOpKind::Sm3Ss1: r = sm3_ss1(vn, vm, read(state, in.aux)); break;
    case StateOpKind::Sm3Tt1a:
    case StateOpKind::Sm3Tt1b:
    case StateOpKind::Sm3Tt2a:
    case StateOpKind::Sm3Tt2b: r = sm3_tt(vd, vn, vm, in.aux, kind); break;
    case StateOpKind::Sm3PartW1: r = sm3_partw1(vd, vn, vm); break;
    case StateOpKind::Sm3PartW2: r = sm3_partw2(vd, vn, vm); break;
    case StateOpKind::Sm4E: r = sm4_rounds(vd, vn, false); break;
    case StateOpKind::Sm4EKey: r = sm4_rounds(vn, vm, true); break;
  }
  write(state, d, r);
}

}  // namespace juice::ir
