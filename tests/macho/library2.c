// The guest library program.c links (@rpath/liblibrary2.dylib).
int library_value = 11;
static int hidden(int v) { return v * 3; }
int library_function(int v) { return hidden(v) + library_value; }
double library_scale(double v, float f) { return v * f + 0.125; }
