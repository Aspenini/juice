#include "linux/abi/translate.hpp"

namespace juice::lx {

namespace {

// AArch64 (arch/arm64/include/uapi/asm/fcntl.h) vs x86-64 (asm-generic) values.
constexpr uint32_t kArmDirectory = 0040000, kArmNoFollow = 0100000, kArmDirect = 0200000, kArmLargeFile = 0400000;
constexpr uint32_t kX64Direct = 0040000, kX64LargeFile = 0100000, kX64Directory = 0200000, kX64NoFollow = 0400000;
constexpr uint32_t kArmSpecial = kArmDirectory | kArmNoFollow | kArmDirect | kArmLargeFile;
constexpr uint32_t kX64Special = kX64Direct | kX64LargeFile | kX64Directory | kX64NoFollow;

}  // namespace

Arm64Stat to_arm64(const X64Stat& s) {
  Arm64Stat a{};
  a.st_dev = s.st_dev;
  a.st_ino = s.st_ino;
  a.st_mode = s.st_mode;
  a.st_nlink = static_cast<uint32_t>(s.st_nlink);
  a.st_uid = s.st_uid;
  a.st_gid = s.st_gid;
  a.st_rdev = s.st_rdev;
  a.st_size = s.st_size;
  a.st_blksize = static_cast<int32_t>(s.st_blksize);
  a.st_blocks = s.st_blocks;
  a.st_atime_sec = s.st_atime_sec;
  a.st_atime_nsec = s.st_atime_nsec;
  a.st_mtime_sec = s.st_mtime_sec;
  a.st_mtime_nsec = s.st_mtime_nsec;
  a.st_ctime_sec = s.st_ctime_sec;
  a.st_ctime_nsec = s.st_ctime_nsec;
  return a;
}

uint32_t open_flags_to_host(uint32_t f) {
  uint32_t r = f & ~kArmSpecial;
  if (f & kArmDirectory) r |= kX64Directory;
  if (f & kArmNoFollow) r |= kX64NoFollow;
  if (f & kArmDirect) r |= kX64Direct;
  if (f & kArmLargeFile) r |= kX64LargeFile;
  return r;
}

uint32_t open_flags_to_guest(uint32_t f) {
  uint32_t r = f & ~kX64Special;
  if (f & kX64Directory) r |= kArmDirectory;
  if (f & kX64NoFollow) r |= kArmNoFollow;
  if (f & kX64Direct) r |= kArmDirect;
  if (f & kX64LargeFile) r |= kArmLargeFile;
  return r;
}

}  // namespace juice::lx
