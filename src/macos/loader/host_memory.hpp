#pragma once

// Address space for guest images and stacks: reserve, protect, release.
// Guest code is never mapped executable for the host (JUICE runs
// translations of it), so a native call into guest code faults and can be
// redirected into the guest (see native_entry()).

#include <cstdint>

namespace juice::mac {

inline constexpr int kProtNone = 0;
inline constexpr int kProtRead = 1;
inline constexpr int kProtWrite = 2;

// Reserves and commits `size` bytes of zeroed, read-write memory, at `preferred`
// if possible (0: anywhere). Returns 0 on failure.
uint64_t reserve_memory(uint64_t size, uint64_t preferred = 0);
bool protect_memory(uint64_t addr, uint64_t size, int prot);
void release_memory(uint64_t addr, uint64_t size);

inline constexpr uint64_t kHostPageSize = 4096;

}  // namespace juice::mac
