// fork + execve of an AArch64 program (this one), and of host programs
// through the shell.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char** argv) {
  if (argc > 1 && strcmp(argv[1], "child") == 0) {
    printf("child: argc=%d arg=%s env=%s\n", argc, argv[2], getenv("JUICE_EXEC_TEST"));
    return 9;
  }
  fflush(stdout);
  pid_t pid = fork();
  if (pid == 0) {
    char* args[] = {argv[0], "child", "two words", NULL};
    char* env[] = {"JUICE_EXEC_TEST=passed", NULL};
    execve("/proc/self/exe", args, env);
    perror("execve");
    _exit(127);
  }
  int status = 0;
  waitpid(pid, &status, 0);
  printf("parent: child exit=%d\n", WEXITSTATUS(status));

  FILE* p = popen("echo from the shell", "r");
  char line[128] = {0};
  if (p && fgets(line, sizeof(line), p)) printf("popen: %s", line);
  printf("pclose=%d\n", p ? WEXITSTATUS(pclose(p)) : -1);
  printf("system=%d\n", WEXITSTATUS(system("exit 5")));
  return 0;
}
