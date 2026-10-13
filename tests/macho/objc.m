// Objective-C on the host's runtime: a guest class (subclass of the native
// NSObject) with ivars, super calls, a category, +load, methods native code
// calls back (performSelector:withObject:), and native methods returning a
// structure (memory on x86-64) and taking floating point arguments. Built
// without an SDK: NSObject is declared here.
int printf(const char*, ...);

struct R {
  double x, y, w, h;
};

__attribute__((objc_root_class))
@interface NSObject {
  Class isa;
}
+ (id)alloc;
- (id)init;
- (id)performSelector:(SEL)selector withObject:(id)object;
- (struct R)juiceRect;
- (double)juiceScale:(double)value by:(float)factor;
@end

@interface Counter : NSObject {
  int count;
  double total;
}
- (int)add:(int)v;
- (double)total;
- (id)describe:(id)tag;
@end

@implementation Counter
+ (void)load {
  printf("load Counter\n");
}
- (id)init {
  self = [super init];
  count = 100;
  return self;
}
- (int)add:(int)v {
  count += v;
  total += v * 0.5;
  return count;
}
- (double)total {
  return total;
}
- (id)describe:(id)tag {
  printf("describe %d %s\n", count, tag == self ? "self" : "other");
  return self;
}
@end

@interface Counter (Extra)
- (int)twice;
@end

@implementation Counter (Extra)
- (int)twice {
  return [self add:0] * 2;
}
@end

int main(void) {
  Counter* c = [[Counter alloc] init];
  printf("add %d\n", [c add:5]);
  printf("total %.2f\n", [c total]);
  printf("twice %d\n", [c twice]);
  id r = [c performSelector:@selector(describe:) withObject:c];
  printf("returned %s\n", r == c ? "self" : "other");
  struct R rect = [c juiceRect];
  printf("rect %.1f %.1f %.1f %.1f\n", rect.x, rect.y, rect.w, rect.h);
  printf("scale %.3f\n", [c juiceScale:2.0 by:1.5f]);
  return 0;
}
