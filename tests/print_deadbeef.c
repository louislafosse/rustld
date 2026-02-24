// gcc -o ./tests/print_deadbeef ./tests/print_deadbeef.c -lm -Wl,--dynamic-linker=$(pwd)/examples/ld_interp/target/release/ld
#include <stdio.h>

int main(){
  int deadbeef = 0xdeadbeef;
  printf("0x%x\n", deadbeef);
  return 0;
}
