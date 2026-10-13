// C++ exceptions through guest frames: catch by value and by base class,
// destructors on the way (cleanups), rethrow, and exceptions crossing native
// code both ways - through a native function that calls back into the
// program, and caught by native code. Built without an SDK.
extern "C" int printf(const char*, ...);
extern "C" void call_back(void (*fn)(int), int value);     // native: calls fn(value)
extern "C" int call_catching(void (*fn)(int), int value);  // native: calls fn(value), -1 if it threw

struct Base {
  virtual ~Base() {}
  int code = 1;
};
struct Derived : Base {
  Derived() { code = 2; }
};
struct Guard {
  const char* name;
  ~Guard() { printf("~%s\n", name); }
};

__attribute__((noinline)) static void thrower(int v) {
  Guard g{"thrower"};
  if (v == 1) throw 42;
  if (v == 2) throw Derived();
  if (v == 3) throw 1.5;
  printf("no throw\n");
}

__attribute__((noinline)) static void middle(int v) {
  Guard g{"middle"};
  thrower(v);
}

int main() {
  try {
    thrower(1);
  } catch (int e) {
    printf("int %d\n", e);
  }
  try {
    middle(2);
  } catch (Base& b) {
    printf("base %d\n", b.code);
  }
  try {
    try {
      thrower(1);
    } catch (...) {
      printf("rethrow\n");
      throw;
    }
  } catch (int e) {
    printf("again %d\n", e);
  }
  try {
    thrower(3);
  } catch (int) {
    printf("wrong\n");
  } catch (double d) {
    printf("double %.1f\n", d);
  }
  try {
    call_back(middle, 1);
  } catch (int e) {
    printf("through native %d\n", e);
  }
  printf("caught natively %d\n", call_catching(middle, 2));
  printf("no exception %d\n", call_catching(thrower, 0));
  try {
    Guard g{"outer"};
    thrower(1);
  } catch (int) {
    printf("after outer\n");
  }
  return 0;
}
