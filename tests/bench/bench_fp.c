/* Scalar floating point: a Mandelbrot set, an n-body simulation and a
 * numerical integration with transcendental functions. */
#include <math.h>
#include <stdio.h>

static unsigned mandelbrot(int size, int iterations) {
  unsigned inside = 0;
  for (int y = 0; y < size; ++y) {
    for (int x = 0; x < size; ++x) {
      const double cr = 2.5 * x / size - 2.0, ci = 2.0 * y / size - 1.0;
      double zr = 0, zi = 0;
      int i = 0;
      while (i < iterations && zr * zr + zi * zi <= 4.0) {
        const double t = zr * zr - zi * zi + cr;
        zi = 2.0 * zr * zi + ci;
        zr = t;
        ++i;
      }
      if (i == iterations) ++inside;
    }
  }
  return inside;
}

typedef struct {
  double x, y, z, vx, vy, vz, mass;
} Body;

static double nbody(int steps) {
  Body b[5] = {
      {0, 0, 0, 0, 0, 0, 39.47841760435743},
      {4.84, -1.16, -0.10, 0.606, 2.81, -0.025, 0.037},
      {8.34, 4.12, -0.40, -1.01, 1.82, 0.008, 0.011},
      {12.89, -15.11, -0.22, 1.08, 0.868, -0.010, 0.0017},
      {15.37, -25.91, 0.17, 0.979, 0.594, -0.034, 0.002},
  };
  const double dt = 0.01;
  for (int s = 0; s < steps; ++s) {
    for (int i = 0; i < 5; ++i) {
      for (int j = i + 1; j < 5; ++j) {
        const double dx = b[i].x - b[j].x, dy = b[i].y - b[j].y, dz = b[i].z - b[j].z;
        const double d2 = dx * dx + dy * dy + dz * dz;
        const double mag = dt / (d2 * sqrt(d2));
        b[i].vx -= dx * b[j].mass * mag;
        b[i].vy -= dy * b[j].mass * mag;
        b[i].vz -= dz * b[j].mass * mag;
        b[j].vx += dx * b[i].mass * mag;
        b[j].vy += dy * b[i].mass * mag;
        b[j].vz += dz * b[i].mass * mag;
      }
    }
    for (int i = 0; i < 5; ++i) {
      b[i].x += dt * b[i].vx;
      b[i].y += dt * b[i].vy;
      b[i].z += dt * b[i].vz;
    }
  }
  double e = 0;
  for (int i = 0; i < 5; ++i) e += 0.5 * b[i].mass * (b[i].vx * b[i].vx + b[i].vy * b[i].vy + b[i].vz * b[i].vz);
  return e;
}

static double integrate(int n) {
  double sum = 0;
  const double h = 3.0 / n;
  for (int i = 0; i < n; ++i) {
    const double x = (i + 0.5) * h;
    sum += sin(x) * exp(-x) + log1p(x) / (1.0 + x * x);
  }
  return sum * h;
}

int main(void) {
  printf("mandelbrot %u\n", mandelbrot(600, 200));
  printf("nbody %.9f\n", nbody(800000));
  printf("integral %.9f\n", integrate(3000000));
  return 0;
}
