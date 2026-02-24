
if [ -f "tests/build_tests.sh" ]; then
	PREFIX="tests/"
else
	PREFIX=""
fi

if [ "$1" = "clean" ]; then
    rm -rf ${PREFIX}hello_musl ${PREFIX}hello_static ${PREFIX}print_deadbeef ${PREFIX}sqrt_with_ld ${PREFIX}hello_arm64_musl ${PREFIX}hello_arm64_musl_static ${PREFIX}hello_arm64_glibc ${PREFIX}hello_arm64_glibc_static
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
