#include <stdio.h>

int plugin_compute(int x) {
    return x * 7 + 3;
}

void plugin_hello(void) {
    puts("plugin: hello from musl shared object");
}
