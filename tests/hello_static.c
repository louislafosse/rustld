// gcc -o ./tests/hello_static ./tests/hello_static.c -lm -Wl,--dynamic-linker=$(pwd)/examples/ld_interp/target/release/ld
#include <stdio.h>

int main(void) {
    puts("hello from binary");
    return 0;
}
