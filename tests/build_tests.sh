
if [ -f "tests/build_tests.sh" ]; then
	PREFIX="tests/"
else
	PREFIX=""
fi

if [ "${1:-}" = "clean" ]; then
    rm -rf \
        ${PREFIX}hello_musl \
        ${PREFIX}hello_static \
        ${PREFIX}print_deadbeef \
        ${PREFIX}sqrt_with_ld \
        ${PREFIX}hello_arm64_musl \
        ${PREFIX}hello_arm64_musl_static \
        ${PREFIX}hello_arm64_glibc \
        ${PREFIX}hello_arm64_glibc_static \
        ${PREFIX}libhello.so \
        ${PREFIX}musl_regex_io \
        ${PREFIX}musl_threads_tls \
        ${PREFIX}musl_dlopen_main \
        ${PREFIX}libmusl_plugin.so \
        ${PREFIX}musl_regex_io_a64 \
        ${PREFIX}musl_threads_tls_a64 \
        ${PREFIX}musl_dlopen_main_a64 \
        ${PREFIX}libmusl_plugin_a64.so
    exit 0
fi

rm -rf ${PREFIX}hello_musl ${PREFIX}hello_static ${PREFIX}print_deadbeef ${PREFIX}sqrt_with_ld
gcc ${PREFIX}print_deadbeef.c -o ${PREFIX}print_deadbeef -lm -Wl,--dynamic-linker=$(pwd)/examples/ld_interp/target/release/ld
gcc ${PREFIX}sqrt_with_ld.c -o ${PREFIX}sqrt_with_ld -lm
gcc ${PREFIX}hello_static.c -o ${PREFIX}hello_static -static
musl-gcc ${PREFIX}hello_static.c -o ${PREFIX}hello_musl
zig cc -target aarch64-linux-musl -O2 -dynamic \
    -Wl,--dynamic-linker=/lib/ld-musl-aarch64.so.1 \
    -o ${PREFIX}hello_arm64_musl ${PREFIX}hello_static.c
zig cc -target aarch64-linux-musl -O2 -o ${PREFIX}hello_arm64_musl_static ${PREFIX}hello_static.c
zig cc -target aarch64-linux-gnu -O2 -dynamic \
    -Wl,--dynamic-linker=/lib/ld-linux-aarch64.so.1 \
    -o ${PREFIX}hello_arm64_glibc ${PREFIX}hello_static.c
zig cc -target aarch64-linux-gnu -O2 -o ${PREFIX}hello_arm64_glibc_static ${PREFIX}hello_static.c
gcc -fPIC -shared ${PREFIX}hello_dyn_lib.c -o ${PREFIX}libhello.so

# musl-focused conformance targets (x86_64)
musl-gcc ${PREFIX}musl_regex_io.c -O2 -o ${PREFIX}musl_regex_io -ldl -pthread
musl-gcc ${PREFIX}musl_threads_tls.c -O2 -o ${PREFIX}musl_threads_tls -ldl -pthread
musl-gcc ${PREFIX}musl_dlopen_main.c -O2 -o ${PREFIX}musl_dlopen_main -ldl
musl-gcc ${PREFIX}musl_plugin.c -O2 -fPIC -shared -o ${PREFIX}libmusl_plugin.so

# musl-focused conformance targets (aarch64)
zig cc -target aarch64-linux-musl -O2 -dynamic \
    -Wl,--dynamic-linker=/lib/ld-musl-aarch64.so.1 \
    -o ${PREFIX}musl_regex_io_a64 ${PREFIX}musl_regex_io.c -ldl -pthread
zig cc -target aarch64-linux-musl -O2 -dynamic \
    -Wl,--dynamic-linker=/lib/ld-musl-aarch64.so.1 \
    -o ${PREFIX}musl_threads_tls_a64 ${PREFIX}musl_threads_tls.c -ldl -pthread
zig cc -target aarch64-linux-musl -O2 -dynamic \
    -Wl,--dynamic-linker=/lib/ld-musl-aarch64.so.1 \
    -o ${PREFIX}musl_dlopen_main_a64 ${PREFIX}musl_dlopen_main.c -ldl
zig cc -target aarch64-linux-musl -O2 -dynamic \
    -Wl,--dynamic-linker=/lib/ld-musl-aarch64.so.1 \
    -fPIC -shared ${PREFIX}musl_plugin.c -o ${PREFIX}libmusl_plugin_a64.so
