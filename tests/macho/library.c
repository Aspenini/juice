// A library: exported functions and data, a hidden function, a pointer table.
int printf(const char*, ...);
__attribute__((visibility("hidden"))) int hidden(int v) { return v * 3; }
int library_value = 11;
int library_function(int v) { return hidden(v) + library_value; }
int (*library_table[])(int) = {library_function, hidden};
__attribute__((weak)) int library_weak(void) { return printf("weak\n"); }
