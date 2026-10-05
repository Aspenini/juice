#pragma once

// Where the Linux AArch64 and x86-64 user ABIs differ for the same system
// call: structure layouts and flag values. Defined here explicitly (not from
// host headers) so the code is portable and testable on any host.

#include <cstdint>

namespace juice::lx {

// struct stat as AArch64 Linux defines it (asm-generic): 128 bytes.
struct Arm64Stat {
  uint64_t st_dev;
  uint64_t st_ino;
  uint32_t st_mode;
  uint32_t st_nlink;
  uint32_t st_uid;
  uint32_t st_gid;
  uint64_t st_rdev;
  uint64_t pad1;
  int64_t st_size;
  int32_t st_blksize;
  int32_t pad2;
  int64_t st_blocks;
  int64_t st_atime_sec;
  uint64_t st_atime_nsec;
  int64_t st_mtime_sec;
  uint64_t st_mtime_nsec;
  int64_t st_ctime_sec;
  uint64_t st_ctime_nsec;
  uint32_t unused4;
  uint32_t unused5;
};
static_assert(sizeof(Arm64Stat) == 128);

// struct stat as x86-64 Linux defines it: 144 bytes.
struct X64Stat {
  uint64_t st_dev;
  uint64_t st_ino;
  uint64_t st_nlink;
  uint32_t st_mode;
  uint32_t st_uid;
  uint32_t st_gid;
  int32_t pad0;
  uint64_t st_rdev;
  int64_t st_size;
  int64_t st_blksize;
  int64_t st_blocks;
  int64_t st_atime_sec;
  uint64_t st_atime_nsec;
  int64_t st_mtime_sec;
  uint64_t st_mtime_nsec;
  int64_t st_ctime_sec;
  uint64_t st_ctime_nsec;
  int64_t unused[3];
};
static_assert(sizeof(X64Stat) == 144);

Arm64Stat to_arm64(const X64Stat& s);

// struct epoll_event: 16 bytes on AArch64, packed to 12 on x86-64.
struct Arm64EpollEvent {
  uint32_t events;
  uint32_t pad;
  uint64_t data;
};
#pragma pack(push, 1)
struct X64EpollEvent {
  uint32_t events;
  uint64_t data;
};
#pragma pack(pop)
static_assert(sizeof(Arm64EpollEvent) == 16 && sizeof(X64EpollEvent) == 12);

// open()/fcntl(F_GETFL/F_SETFL) flags: O_DIRECTORY, O_NOFOLLOW, O_DIRECT and
// O_LARGEFILE have different values; the rest are the same.
uint32_t open_flags_to_host(uint32_t arm64_flags);
uint32_t open_flags_to_guest(uint32_t x64_flags);

// AT_HWCAP bits for AArch64 (what JUICE's translator implements).
inline constexpr uint64_t kHwcapFp = 1u << 0;
inline constexpr uint64_t kHwcapAsimd = 1u << 1;
inline constexpr uint64_t kHwcapAtomics = 1u << 8;  // LSE
inline constexpr uint64_t kHwcaps = kHwcapFp | kHwcapAsimd | kHwcapAtomics;

// Auxiliary vector keys (AT_*; named differently to stay clear of the host's macros).
enum : uint64_t {
  kAtNull = 0, kAtPhdr = 3, kAtPhent = 4, kAtPhnum = 5, kAtPagesz = 6, kAtBase = 7, kAtFlags = 8, kAtEntry = 9,
  kAtUid = 11, kAtEuid = 12, kAtGid = 13, kAtEgid = 14, kAtPlatform = 15, kAtHwcap = 16, kAtClktck = 17,
  kAtSecure = 23, kAtRandom = 25, kAtHwcap2 = 26, kAtExecfn = 31, kAtMinsigstksz = 51,
};

}  // namespace juice::lx
