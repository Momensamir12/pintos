#ifndef FIXED_POINT_H
#define FIXED_POINT_H
#include <stdint.h>

#define F (1 << 14)

int fp_from_int(int n);
int fp_to_int(int x);
int fp_to_int_nearest(int x);
int fp_add(int x, int y);
int fp_add_int(int x, int n);
int fp_sub(int x, int y);
int fp_sub_int(int x, int n);
int fp_mul(int x, int y);
int fp_mul_int(int x, int n);
int fp_div(int x, int y);
int fp_div_int(int x, int n);




#endif /* FIXED_POINT_H */



