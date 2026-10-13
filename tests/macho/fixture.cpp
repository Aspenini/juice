// C++: virtual functions, templates and inline functions (weak definitions),
// exceptions, guarded statics.
extern "C" int printf(const char*, ...);

struct Shape {
  virtual ~Shape() {}
  virtual int area() const = 0;
};
struct Square : Shape {
  int side;
  explicit Square(int s) : side(s) {}
  int area() const override { return side * side; }
};
template <typename T>
T twice(T v) { return v + v; }
inline int& counter() {
  static int value = twice(21);
  return value;
}

int main() {
  Shape* s = new Square(3);
  int result = s->area();
  delete s;
  try {
    if (result == 9) throw twice(counter());
  } catch (int v) {
    printf("caught %d\n", v);
  }
  return 0;
}
