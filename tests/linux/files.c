// File system calls whose structures or flags differ between AArch64 and x86-64.
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <unistd.h>

int main(int argc, char** argv) {
  (void)argc;
  char dir[] = "/tmp/juice-files-XXXXXX";
  if (!mkdtemp(dir)) return 1;
  char path[256];
  snprintf(path, sizeof(path), "%s/data.txt", dir);

  int fd = open(path, O_CREAT | O_RDWR | O_TRUNC | O_CLOEXEC, 0640);
  if (fd < 0) return 2;
  const char text[] = "hello, file\n";
  printf("write=%zd\n", write(fd, text, sizeof(text) - 1));
  printf("lseek=%ld\n", (long)lseek(fd, 7, SEEK_SET));
  char buf[64] = {0};
  printf("read=%zd '%s'\n", read(fd, buf, sizeof(buf) - 1), buf);

  struct stat st;
  printf("fstat=%d size=%ld mode=%o regular=%d\n", fstat(fd, &st), (long)st.st_size, st.st_mode & 0777,
         S_ISREG(st.st_mode));
  printf("stat=%d nlink=%lu\n", stat(path, &st), (unsigned long)st.st_nlink);
  printf("lstat dir=%d isdir=%d\n", lstat(dir, &st), S_ISDIR(st.st_mode));

  // Flags with different values on x86-64.
  int flags = fcntl(fd, F_GETFL);
  printf("O_RDWR=%d\n", (flags & O_ACCMODE) == O_RDWR);
  printf("O_NONBLOCK set=%d\n", fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0 && (fcntl(fd, F_GETFL) & O_NONBLOCK) != 0);
  close(fd);
  int dfd = open(dir, O_RDONLY | O_DIRECTORY);
  printf("O_DIRECTORY on dir=%d\n", dfd >= 0);
  printf("O_DIRECTORY on file=%d ENOTDIR=%d\n", open(path, O_RDONLY | O_DIRECTORY), errno == ENOTDIR);
  printf("fstatat=%d\n", fstatat(dfd, "data.txt", &st, 0) == 0 && st.st_size == 12);
  close(dfd);
  char linkpath[256];
  snprintf(linkpath, sizeof(linkpath), "%s/link", dir);
  printf("symlink=%d\n", symlink(path, linkpath));
  printf("O_NOFOLLOW=%d ELOOP=%d\n", open(linkpath, O_RDONLY | O_NOFOLLOW), errno == ELOOP);

  DIR* d = opendir(dir);
  int entries = 0;
  for (struct dirent* e; (e = readdir(d));) entries += e->d_name[0] != '.';
  closedir(d);
  printf("entries=%d\n", entries);

  // epoll_event is packed on x86-64.
  int ep = epoll_create1(EPOLL_CLOEXEC);
  int pipefd[2];
  if (pipe(pipefd) != 0) return 3;
  struct epoll_event ev = {.events = EPOLLIN, .data.u64 = 0x1122334455667788ull};
  epoll_ctl(ep, EPOLL_CTL_ADD, pipefd[0], &ev);
  if (write(pipefd[1], "x", 1) != 1) return 4;
  struct epoll_event out[4];
  int n = epoll_wait(ep, out, 4, 1000);
  printf("epoll n=%d events=%x data=%llx\n", n, out[0].events, (unsigned long long)out[0].data.u64);

  // The program's own path, and the machine it believes it runs on.
  char self[4096];
  ssize_t len = readlink("/proc/self/exe", self, sizeof(self) - 1);
  self[len > 0 ? len : 0] = 0;
  printf("self exe matches=%d\n", strcmp(basename(self), basename(argv[0])) == 0);
  struct utsname u;
  uname(&u);
  printf("machine known=%d\n", !strcmp(u.machine, "aarch64") || !strcmp(u.machine, "x86_64"));

  unlink(linkpath);
  unlink(path);
  printf("rmdir=%d\n", rmdir(dir));
  return 0;
}
