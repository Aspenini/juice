#pragma once

// libjuice: a portable ARM64 -> x86-64 dynamic binary translator.
//
// The library translates and runs AArch64 user-mode code inside the host
// process. It knows nothing about operating systems: a frontend (Windows PE,
// Linux ELF, ...) maps the guest program, implements runtime::Environment to
// supply code bytes and handle what the guest asks of its system (system
// calls, API thunks, interrupts), and drives runtime::Engine.
//
// Guest and host share one address space: guest addresses are host pointers.
// The only host requirement beyond standard C++23 is executable memory
// (VirtualAlloc on Windows, mmap elsewhere) and an x86-64 CPU with CMPXCHG16B.
//
//   #include <juice/juice.hpp>
//
//   struct MyEnv : juice::runtime::Environment {
//     bool read_code(uint64_t addr, uint32_t& word) override;
//     juice::runtime::Action on_exit(juice::arm64::CpuState& state) override;  // SVC, BRK, ...
//   };
//
//   MyEnv env;
//   juice::runtime::Engine engine(env);
//   juice::arm64::CpuState state{};
//   state.pc = entry;
//   state.sp = stack_top;
//   engine.run(state);

#include "core/arm64/decode/instruction.hpp"  // decode(), disassemble(): ARM64 instruction decoding
#include "core/arm64/state/cpu_state.hpp"     // CpuState: guest registers and exit reasons
#include "runtime/engine.hpp"                 // Engine, Environment, EngineOptions

namespace juice {

inline constexpr const char* kVersion = "0.2.0";

}  // namespace juice
