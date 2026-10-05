// Signals: handlers with siginfo, masks, the alternate stack, SA_RESTART,
// timers, sigsuspend, SIGCHLD from a forked child, default actions.
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>

static volatile sig_atomic_t got_usr1, got_alrm, got_chld, info_ok, on_altstack;
static char altstack[65536];

static void on_usr1(int sig, siginfo_t* info, void* uc) {
  (void)uc;
  got_usr1 = sig;
  info_ok = info->si_signo == SIGUSR1 && info->si_pid == getpid();
  stack_t ss;
  sigaltstack(NULL, &ss);
  on_altstack = (ss.ss_flags & SS_ONSTACK) != 0;
}
static void on_alrm(int sig) { got_alrm = sig; }
static void on_chld(int sig) { got_chld = sig; }

int main(void) {
  stack_t ss = {.ss_sp = altstack, .ss_size = sizeof(altstack)};
  sigaltstack(&ss, NULL);
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_sigaction = on_usr1;
  sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
  sigaction(SIGUSR1, &sa, NULL);
  raise(SIGUSR1);
  printf("usr1=%d info=%d altstack=%d\n", got_usr1, info_ok, on_altstack);

  // Blocked: pending until unblocked.
  sigset_t set, old;
  sigemptyset(&set);
  sigaddset(&set, SIGUSR1);
  sigprocmask(SIG_BLOCK, &set, &old);
  got_usr1 = 0;
  raise(SIGUSR1);
  sigset_t pending;
  sigpending(&pending);
  printf("blocked: delivered=%d pending=%d\n", got_usr1, sigismember(&pending, SIGUSR1));
  sigprocmask(SIG_SETMASK, &old, NULL);
  printf("unblocked: delivered=%d\n", got_usr1);

  // A timer interrupting a read() of a pipe: SA_RESTART resumes it.
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = on_alrm;
  sa.sa_flags = SA_RESTART;
  sigaction(SIGALRM, &sa, NULL);
  int fds[2];
  if (pipe(fds) != 0) return 1;
  fflush(stdout);
  pid_t writer = fork();
  if (writer == 0) {
    usleep(300000);
    if (write(fds[1], "z", 1) != 1) _exit(1);
    _exit(0);
  }
  struct itimerval it = {.it_value = {.tv_usec = 50000}};
  setitimer(ITIMER_REAL, &it, NULL);
  char c = 0;
  ssize_t n = read(fds[0], &c, 1);
  printf("restarted read: n=%zd c=%c alarm=%d\n", n, c, got_alrm);
  waitpid(writer, NULL, 0);

  // Without SA_RESTART the call fails with EINTR.
  sa.sa_flags = 0;
  sigaction(SIGALRM, &sa, NULL);
  got_alrm = 0;
  setitimer(ITIMER_REAL, &it, NULL);
  n = read(fds[0], &c, 1);
  printf("interrupted read: n=%zd EINTR=%d alarm=%d\n", n, errno == EINTR, got_alrm);

  // sigsuspend: SIGCHLD blocked except while waiting.
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = on_chld;
  sigaction(SIGCHLD, &sa, NULL);
  sigemptyset(&set);
  sigaddset(&set, SIGCHLD);
  sigprocmask(SIG_BLOCK, &set, &old);
  fflush(stdout);
  pid_t child = fork();
  if (child == 0) _exit(42);
  sigset_t wait_mask;
  sigemptyset(&wait_mask);
  while (!got_chld) sigsuspend(&wait_mask);
  sigprocmask(SIG_SETMASK, &old, NULL);
  int status = 0;
  waitpid(child, &status, 0);
  printf("sigchld=%d child exit=%d\n", got_chld, WEXITSTATUS(status));

  // Ignored and default dispositions.
  signal(SIGUSR2, SIG_IGN);
  raise(SIGUSR2);
  printf("ignored ok\n");
  fflush(stdout);
  signal(SIGTERM, SIG_DFL);
  pid_t victim = fork();
  if (victim == 0) {
    raise(SIGTERM);
    _exit(0);
  }
  waitpid(victim, &status, 0);
  printf("killed by SIGTERM=%d\n", WIFSIGNALED(status) && WTERMSIG(status) == SIGTERM);
  return 0;
}
