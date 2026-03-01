#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>

typedef int (*plugin_compute_fn)(int);
typedef void (*plugin_hello_fn)(void);

int main(int argc, char** argv) {
    const char* path = argc > 1 ? argv[1] : "./libmusl_plugin.so";
    void* h = dlopen(path, RTLD_NOW);
    if (!h) {
        fprintf(stderr, "dlopen failed: %s\n", dlerror());
        return 10;
    }

    plugin_compute_fn compute = (plugin_compute_fn)dlsym(h, "plugin_compute");
    plugin_hello_fn hello = (plugin_hello_fn)dlsym(h, "plugin_hello");
    const char* err = dlerror();
    if (err != NULL || !compute || !hello) {
        fprintf(stderr, "dlsym failed: %s\n", err ? err : "null");
        dlclose(h);
        return 11;
    }

    hello();
    printf("plugin_compute(9)=%d\n", compute(9));
    dlclose(h);
    return 0;
}
