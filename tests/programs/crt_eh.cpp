// C++ exceptions: throw and catch by value, reference and pointer, class
// hierarchies, catch(...), rethrow, nested try blocks, destructors during
// unwinding, exceptions from constructors, standard library exceptions,
// std::exception_ptr and exceptions in threads.
#include <cstdio>
#include <exception>
#include <memory>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace {

int g_live = 0;

struct Tracer {
  const char* name;
  explicit Tracer(const char* n) : name(n) {
    ++g_live;
    std::printf("  construct %s\n", name);
  }
  ~Tracer() {
    --g_live;
    std::printf("  destruct %s\n", name);
  }
};

struct Base {
  int value;
  explicit Base(int v) : value(v) {}
  virtual ~Base() = default;
  virtual const char* kind() const { return "Base"; }
};

struct Derived : Base {
  std::string text;
  Derived(int v, std::string t) : Base(v), text(std::move(t)) {}
  const char* kind() const override { return "Derived"; }
};

struct Counted {
  static int copies;
  int id;
  explicit Counted(int i) : id(i) {}
  Counted(const Counted& o) : id(o.id) { ++copies; }
};
int Counted::copies = 0;

__declspec(noinline) void thrower(int what) {
  Tracer t("thrower local");
  switch (what) {
    case 0: throw 42;
    case 1: throw Derived(7, "derived text");
    case 2: throw std::runtime_error("runtime error text");
    case 3: throw std::string("a string");
    case 4: throw 2.5;
    case 5: throw Counted(9);
  }
}

__declspec(noinline) void middle(int what) {
  Tracer t("middle local");
  std::vector<std::unique_ptr<Tracer>> owned;
  owned.push_back(std::make_unique<Tracer>("heap tracer"));
  thrower(what);
  std::printf("  not reached\n");
}

void basic_types() {
  std::printf("basic types\n");
  try {
    middle(0);
  } catch (int v) {
    std::printf("  caught int %d, live tracers %d\n", v, g_live);
  }
  try {
    middle(4);
  } catch (const char*) {
    std::printf("  wrong handler\n");
  } catch (double d) {
    std::printf("  caught double %.2f\n", d);
  }
  try {
    middle(3);
  } catch (const std::string& s) {
    std::printf("  caught string '%s'\n", s.c_str());
  }
}

void hierarchy() {
  std::printf("hierarchy\n");
  try {
    middle(1);
  } catch (const Base& b) {
    std::printf("  caught %s by base reference, value %d\n", b.kind(), b.value);
  }
  try {
    middle(2);
  } catch (const std::logic_error&) {
    std::printf("  wrong handler\n");
  } catch (const std::exception& e) {
    std::printf("  caught std::exception: %s\n", e.what());
  }
  try {
    middle(5);
  } catch (Counted c) {
    std::printf("  caught Counted %d by value, copies %d\n", c.id, Counted::copies > 0);
  }
}

void catch_all_and_rethrow() {
  std::printf("rethrow\n");
  try {
    try {
      middle(2);
    } catch (...) {
      std::printf("  catch(...) rethrows\n");
      throw;
    }
  } catch (const std::runtime_error& e) {
    std::printf("  outer caught: %s\n", e.what());
  }
  try {
    try {
      thrower(0);
    } catch (int v) {
      std::printf("  caught %d, throwing a new exception\n", v);
      throw std::logic_error("thrown from a catch block");
    }
  } catch (const std::logic_error& e) {
    std::printf("  outer caught: %s\n", e.what());
  }
}

struct Throwing {
  Tracer member{"member"};
  explicit Throwing(bool fail) {
    if (fail) throw std::invalid_argument("constructor failed");
  }
};

void constructors() {
  std::printf("constructors\n");
  try {
    Throwing ok(false);
    Throwing bad(true);
  } catch (const std::invalid_argument& e) {
    std::printf("  caught: %s, live tracers %d\n", e.what(), g_live);
  }
}

void standard_library() {
  std::printf("standard library\n");
  std::vector<int> v(3);
  try {
    v.at(10) = 1;
  } catch (const std::out_of_range&) {
    std::printf("  vector::at threw out_of_range\n");
  }
  try {
    std::string s("abc");
    s.substr(10);
  } catch (const std::out_of_range&) {
    std::printf("  string::substr threw out_of_range\n");
  }
  try {
    std::stoi("not a number");
  } catch (const std::invalid_argument&) {
    std::printf("  stoi threw invalid_argument\n");
  }
}

void exception_ptr() {
  std::printf("exception_ptr\n");
  std::exception_ptr saved;
  try {
    middle(2);
  } catch (...) {
    saved = std::current_exception();
  }
  try {
    std::rethrow_exception(saved);
  } catch (const std::exception& e) {
    std::printf("  rethrown from exception_ptr: %s\n", e.what());
  }
}

void threads() {
  std::printf("threads\n");
  std::exception_ptr from_thread;
  std::thread t([&] {
    try {
      thrower(0);
    } catch (...) {
      from_thread = std::current_exception();
    }
  });
  t.join();
  try {
    std::rethrow_exception(from_thread);
  } catch (int v) {
    std::printf("  thread exception %d\n", v);
  }
}

int deep(int n) {
  Tracer t("deep");
  if (n == 0) throw n;
  return deep(n - 1) + 1;
}

void deep_unwind() {
  std::printf("deep unwind\n");
  try {
    deep(3);
  } catch (int) {
    std::printf("  live tracers %d\n", g_live);
  }
}

}  // namespace

int main() {
  basic_types();
  hierarchy();
  catch_all_and_rethrow();
  constructors();
  standard_library();
  exception_ptr();
  threads();
  deep_unwind();
  std::printf("done, live tracers %d\n", g_live);
  return 0;
}
