#include "fixed_point.h"

#include "fixed_point.h"

// Convert integer to fixed-point
int fp_from_int(int n) {
    return n * F;
}

// Convert fixed-point to integer (truncate)
int fp_to_int(int x) {
    return x / F;
}

// Convert fixed-point to integer (round to nearest)
int fp_to_int_nearest(int x) {
    if (x >= 0)
        return (x + F / 2) / F;
    else
        return (x - F / 2) / F;
}

// Add two fixed-point numbers
int fp_add(int x, int y) {
    return x + y;
}

// Add fixed-point and integer
int fp_add_int(int x, int n) {
    return x + n * F;
}

// Subtract two fixed-point numbers
int fp_sub(int x, int y) {
    return x - y;
}

// Subtract integer from fixed-point
int fp_sub_int(int x, int n) {
    return x - n * F;
}

// Multiply two fixed-point numbers
int fp_mul(int x, int y) {
    return ((int64_t)x) * y / F;
}

// Multiply fixed-point by integer
int fp_mul_int(int x, int n) {
    return x * n;
}

// Divide two fixed-point numbers
int fp_div(int x, int y) {
    return ((int64_t)x) * F / y;
}

// Divide fixed-point by integer
int fp_div_int(int x, int n) {
    return x / n;
}