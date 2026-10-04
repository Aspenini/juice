#include "core/arm64/state/cpu_state.hpp"

#include <array>
#include <format>
#include <string>

namespace juice::arm64 {

const char* to_string(ExitReason reason) {
  switch (reason) {
    case ExitReason::None: return "none";
    case ExitReason::Svc: return "svc";
    case ExitReason::Brk: return "brk";
    case ExitReason::Hlt: return "hlt";
    case ExitReason::Undefined: return "undefined instruction";
    case ExitReason::Unsupported: return "unsupported instruction";
    case ExitReason::FetchFault: return "instruction fetch fault";
  }
  return "?";
}

const char* slot_name(uint16_t s) {
  static const std::array<std::string, slot::Count> names = [] {
    std::array<std::string, slot::Count> n;
    for (unsigned i = 0; i < 31; ++i) n[i] = std::format("x{}", i);
    n[slot::SP] = "sp";
    n[slot::PC] = "pc";
    n[slot::NZCV] = "nzcv";
    for (unsigned i = 0; i < 32; ++i) {
      n[slot::VLo(i)] = std::format("v{}.lo", i);
      n[slot::VHi(i)] = std::format("v{}.hi", i);
    }
    n[slot::FPCR] = "fpcr";
    n[slot::FPSR] = "fpsr";
    n[slot::TPIDR_EL0] = "tpidr_el0";
    n[slot::TPIDRRO_EL0] = "tpidrro_el0";
    n[slot::Exit] = "exit";
    n[slot::BlockPc] = "block_pc";
    return n;
  }();
  return s < slot::Count ? names[s].c_str() : "?";
}

}  // namespace juice::arm64
