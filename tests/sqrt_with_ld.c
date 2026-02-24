// gcc -o ./tests/sqrt_with_libm ./tests/sqrt_with_libm.c -lm -Wl,--dynamic-linker=$(pwd)/examples/ld_interp/target/release/ld
#include<math.h>
#include <stdio.h>

int main () {
  float s = sqrt(4.0);
  printf("%f\n",s);
  return 0;
}

