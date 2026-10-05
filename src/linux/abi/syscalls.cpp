#include "linux/abi/syscalls.hpp"

#include <array>
#include <string_view>

namespace juice::lx::sys {

namespace {

struct Entry {
  uint32_t nr;
  const char* name;
};

#define E(x) {x, #x}
constexpr Entry kEntries[] = {
    E(io_setup), E(io_destroy), E(io_submit), E(io_cancel), E(io_getevents), E(setxattr), E(lsetxattr),
    E(fsetxattr), E(getxattr), E(lgetxattr), E(fgetxattr), E(listxattr), E(llistxattr), E(flistxattr),
    E(removexattr), E(lremovexattr), E(fremovexattr), E(getcwd), E(lookup_dcookie), E(eventfd2), E(epoll_create1),
    E(epoll_ctl), E(epoll_pwait), E(dup), E(dup3), E(fcntl), E(inotify_init1), E(inotify_add_watch),
    E(inotify_rm_watch), E(ioctl), E(ioprio_set), E(ioprio_get), E(flock), E(mknodat), E(mkdirat), E(unlinkat),
    E(symlinkat), E(linkat), E(renameat), E(umount2), E(mount), E(pivot_root), E(nfsservctl), E(statfs),
    E(fstatfs), E(truncate), E(ftruncate), E(fallocate), E(faccessat), E(chdir), E(fchdir), E(chroot), E(fchmod),
    E(fchmodat), E(fchownat), E(fchown), E(openat), E(close), E(vhangup), E(pipe2), E(quotactl), E(getdents64),
    E(lseek), E(read), E(write), E(readv), E(writev), E(pread64), E(pwrite64), E(preadv), E(pwritev), E(sendfile),
    E(pselect6), E(ppoll), E(signalfd4), E(vmsplice), E(splice), E(tee), E(readlinkat), E(newfstatat), E(fstat),
    E(sync), E(fsync), E(fdatasync), E(sync_file_range), E(timerfd_create), E(timerfd_settime),
    E(timerfd_gettime), E(utimensat), E(acct), E(capget), E(capset), E(personality), E(exit), E(exit_group),
    E(waitid), E(set_tid_address), E(unshare), E(futex), E(set_robust_list), E(get_robust_list), E(nanosleep),
    E(getitimer), E(setitimer), E(kexec_load), E(init_module), E(delete_module), E(timer_create),
    E(timer_gettime), E(timer_getoverrun), E(timer_settime), E(timer_delete), E(clock_settime),
    E(clock_gettime), E(clock_getres), E(clock_nanosleep), E(syslog), E(ptrace), E(sched_setparam),
    E(sched_setscheduler), E(sched_getscheduler), E(sched_getparam), E(sched_setaffinity), E(sched_getaffinity),
    E(sched_yield), E(sched_get_priority_max), E(sched_get_priority_min), E(sched_rr_get_interval),
    E(restart_syscall), E(kill), E(tkill), E(tgkill), E(sigaltstack), E(rt_sigsuspend), E(rt_sigaction),
    E(rt_sigprocmask), E(rt_sigpending), E(rt_sigtimedwait), E(rt_sigqueueinfo), E(rt_sigreturn),
    E(setpriority), E(getpriority), E(reboot), E(setregid), E(setgid), E(setreuid), E(setuid), E(setresuid),
    E(getresuid), E(setresgid), E(getresgid), E(setfsuid), E(setfsgid), E(times), E(setpgid), E(getpgid),
    E(getsid), E(setsid), E(getgroups), E(setgroups), E(uname), E(sethostname), E(setdomainname), E(getrlimit),
    E(setrlimit), E(getrusage), E(umask), E(prctl), E(getcpu), E(gettimeofday), E(settimeofday), E(adjtimex),
    E(getpid), E(getppid), E(getuid), E(geteuid), E(getgid), E(getegid), E(gettid), E(sysinfo), E(mq_open),
    E(mq_unlink), E(mq_timedsend), E(mq_timedreceive), E(mq_notify), E(mq_getsetattr), E(msgget), E(msgctl),
    E(msgrcv), E(msgsnd), E(semget), E(semctl), E(semtimedop), E(semop), E(shmget), E(shmctl), E(shmat), E(shmdt),
    E(socket), E(socketpair), E(bind), E(listen), E(accept), E(connect), E(getsockname), E(getpeername),
    E(sendto), E(recvfrom), E(setsockopt), E(getsockopt), E(shutdown), E(sendmsg), E(recvmsg), E(readahead),
    E(brk), E(munmap), E(mremap), E(add_key), E(request_key), E(keyctl), E(clone), E(execve), E(mmap),
    E(fadvise64), E(swapon), E(swapoff), E(mprotect), E(msync), E(mlock), E(munlock), E(mlockall),
    E(munlockall), E(mincore), E(madvise), E(remap_file_pages), E(mbind), E(get_mempolicy), E(set_mempolicy),
    E(migrate_pages), E(move_pages), E(rt_tgsigqueueinfo), E(perf_event_open), E(accept4), E(recvmmsg),
    E(wait4), E(prlimit64), E(fanotify_init), E(fanotify_mark), E(name_to_handle_at), E(open_by_handle_at),
    E(clock_adjtime), E(syncfs), E(setns), E(sendmmsg), E(process_vm_readv), E(process_vm_writev), E(kcmp),
    E(finit_module), E(sched_setattr), E(sched_getattr), E(renameat2), E(seccomp), E(getrandom),
    E(memfd_create), E(bpf), E(execveat), E(userfaultfd), E(membarrier), E(mlock2), E(copy_file_range),
    E(preadv2), E(pwritev2), E(pkey_mprotect), E(pkey_alloc), E(pkey_free), E(statx), E(io_pgetevents), E(rseq),
    E(kexec_file_load), E(pidfd_send_signal), E(io_uring_setup), E(io_uring_enter), E(io_uring_register),
    E(open_tree), E(move_mount), E(fsopen), E(fsconfig), E(fsmount), E(fspick), E(pidfd_open), E(clone3),
    E(close_range), E(openat2), E(pidfd_getfd), E(faccessat2), E(process_madvise), E(epoll_pwait2),
    E(mount_setattr), E(quotactl_fd), E(landlock_create_ruleset), E(landlock_add_rule),
    E(landlock_restrict_self), E(memfd_secret), E(process_mrelease), E(futex_waitv),
    E(set_mempolicy_home_node), E(cachestat), E(fchmodat2), E(map_shadow_stack), E(futex_wake), E(futex_wait),
    E(futex_requeue), E(statmount), E(listmount), E(lsm_get_self_attr), E(lsm_set_self_attr),
    E(lsm_list_modules), E(mseal),
};
#undef E

constexpr auto kTable = [] {
  std::array<const char*, 512> t{};
  for (const Entry& e : kEntries) t[e.nr] = e.name;
  return t;
}();

}  // namespace

const char* name(uint64_t nr) { return nr < kTable.size() && kTable[nr] ? kTable[nr] : "?"; }

}  // namespace juice::lx::sys
