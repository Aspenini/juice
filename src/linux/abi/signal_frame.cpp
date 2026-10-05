#include "linux/abi/signal_frame.hpp"

#include <cstring>

namespace juice::lx {

namespace {

template <typename T>
void store(uint64_t addr, T v) {
  std::memcpy(reinterpret_cast<void*>(addr), &v, sizeof(T));
}
template <typename T>
T load(uint64_t addr) {
  T v;
  std::memcpy(&v, reinterpret_cast<const void*>(addr), sizeof(T));
  return v;
}

// struct sigcontext offsets (relative to uc_mcontext)
constexpr uint64_t kScFault = 0, kScRegs = 8, kScSp = 256, kScPc = 264, kScPstate = 272, kScReserved = 288;
// fpsimd_context offsets (relative to the record)
constexpr uint64_t kFpMagic = 0, kFpSize = 4, kFpFpsr = 8, kFpFpcr = 12, kFpVregs = 16;
constexpr uint32_t kFpsimdSize = 16 + 32 * 16;

}  // namespace

uint64_t push_signal_frame(arm64::CpuState& s, uint64_t sp, const SignalDelivery& d) {
  const uint64_t frame = (sp - kSignalFrameSize) & ~uint64_t{15};
  std::memset(reinterpret_cast<void*>(frame), 0, kSignalFrameSize);

  // siginfo
  if (d.siginfo) {
    std::memcpy(reinterpret_cast<void*>(frame), d.siginfo, kSigInfoSize);
  } else {
    store<int32_t>(frame, d.sig);
  }

  // ucontext
  const uint64_t uc = frame + kUcontextOffset;
  store<uint64_t>(uc + 16, d.altstack_sp);
  store<int32_t>(uc + 24, static_cast<int32_t>(d.altstack_flags));
  store<uint64_t>(uc + 32, d.altstack_size);
  store<uint64_t>(uc + 40, d.saved_mask);

  // sigcontext
  const uint64_t mc = frame + kMcontextOffset;
  store<uint64_t>(mc + kScFault, d.fault_address);
  std::memcpy(reinterpret_cast<void*>(mc + kScRegs), s.x, sizeof(s.x));
  store<uint64_t>(mc + kScSp, s.sp);
  store<uint64_t>(mc + kScPc, s.pc);
  store<uint64_t>(mc + kScPstate, s.nzcv & 0xF000'0000u);

  // fpsimd_context, then the terminating empty record (already zero)
  const uint64_t fp = mc + kScReserved;
  store<uint32_t>(fp + kFpMagic, kFpsimdMagic);
  store<uint32_t>(fp + kFpSize, kFpsimdSize);
  store<uint32_t>(fp + kFpFpsr, static_cast<uint32_t>(s.fpsr));
  store<uint32_t>(fp + kFpFpcr, static_cast<uint32_t>(s.fpcr));
  for (int i = 0; i < 32; ++i) {
    store<uint64_t>(fp + kFpVregs + 16 * i, s.v[i].lo);
    store<uint64_t>(fp + kFpVregs + 16 * i + 8, s.v[i].hi);
  }

  // frame record for unwinders: the interrupted fp and lr
  const uint64_t record = frame + kFrameRecordOffset;
  store<uint64_t>(record, s.x[29]);
  store<uint64_t>(record + 8, s.x[30]);

  s.x[0] = static_cast<uint64_t>(d.sig);
  s.x[1] = frame;
  s.x[2] = uc;
  s.x[29] = record;
  s.x[30] = d.restorer;
  s.sp = frame;
  s.pc = d.handler;
  return frame;
}

bool pop_signal_frame(arm64::CpuState& s, uint64_t& mask) {
  const uint64_t frame = s.sp;
  const uint64_t uc = frame + kUcontextOffset;
  const uint64_t mc = frame + kMcontextOffset;
  mask = load<uint64_t>(uc + 40);
  std::memcpy(s.x, reinterpret_cast<const void*>(mc + kScRegs), sizeof(s.x));
  s.sp = load<uint64_t>(mc + kScSp);
  s.pc = load<uint64_t>(mc + kScPc);
  s.nzcv = load<uint64_t>(mc + kScPstate) & 0xF000'0000u;
  // Walk the records in __reserved for the FP/SIMD state.
  uint64_t rec = mc + kScReserved;
  const uint64_t end = rec + 4096;
  while (rec + 8 <= end) {
    const uint32_t magic = load<uint32_t>(rec), size = load<uint32_t>(rec + 4);
    if (magic == 0) break;
    if (size < 8 || rec + size > end) return false;
    if (magic == kFpsimdMagic && size >= kFpsimdSize) {
      s.fpsr = load<uint32_t>(rec + kFpFpsr);
      s.fpcr = load<uint32_t>(rec + kFpFpcr);
      for (int i = 0; i < 32; ++i) {
        s.v[i].lo = load<uint64_t>(rec + kFpVregs + 16 * i);
        s.v[i].hi = load<uint64_t>(rec + kFpVregs + 16 * i + 8);
      }
    }
    rec += size;
  }
  return true;
}

}  // namespace juice::lx
