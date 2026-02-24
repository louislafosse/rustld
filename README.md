# Rustld
A modern x86_64 & AArch64 ELF loader (static & dynamic linker + compatible glibc & musl) written in Rust

## Build

```bash
# Run any binary (static, glibc, musl) on host arch
cargo build --release --example rustld
./target/release/examples/rustld /bin/ls

# If you want to embed the custom linker path into your binary
cd examples/ld_interp && cargo build --release && cd ../..
gcc -o ./tests/print_deadbeef ./tests/print_deadbeef.c -lm -Wl,--dynamic-linker=$(pwd)/examples/ld_interp/target/release/ld
file tests/print_deadbeef

# Build C wrapper example using rustld.h (links against librustld.so)
cargo build --release
gcc -O2 -I./include -o ./target/release/examples/rustld_c ./examples/rustld_c.c \
  -L./target/release -lrustld -Wl,-rpath,'$ORIGIN/..'
./target/release/examples/rustld_c /bin/ls
```

## Run from the SDK
```rs

// In Rust :
// See exact implementation in ./examples/rustld.rs
rustld::ElfLoader::execute_from_bytes(
    target_bytes,
    target_argc,
    target_argv,
    host_env_pointer,
    &auxv_items,
    false,
);

// In C :
// See exact implementation in ./examples/rustld_c.c
#include "rustld.h"

int32_t rc = rustld_elfloader_execute_from_bytes(
    target_bytes,           // mapped ELF bytes
    target_len,             // ELF size
    target_argc,            // argv count for target
    target_argv,            // argv for target (argv[0] = target path)
    NULL,                   // envp override (NULL => parent env)
    NULL,                   // auxv override (NULL => parent auxv)
    0,                      // auxv_len
    0                       // verbose
);
```

## Build & Run AArch64 From x86_64 host

```bash
rustup target add aarch64-unknown-linux-gnu
sudo dnf install -y zig qemu-user

# From repo root, create linker wrapper
mkdir -p tools
cat > tools/zigcc-aarch64-gnu.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export ZIG_GLOBAL_CACHE_DIR="${ZIG_GLOBAL_CACHE_DIR:-$ROOT_DIR/target/.zig-global-cache}"
export ZIG_LOCAL_CACHE_DIR="${ZIG_LOCAL_CACHE_DIR:-$ROOT_DIR/target/.zig-local-cache}"
exec zig cc -target aarch64-linux-gnu "$@"
EOF
chmod +x tools/zigcc-aarch64-gnu.sh
# Build AArch64 rustld
CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=./tools/zigcc-aarch64-gnu.sh \
cargo build --release --target aarch64-unknown-linux-gnu --example rustld
file ./target/aarch64-unknown-linux-gnu/release/examples/rustld
rm -rf tools

sudo dnf -y --use-host-config \
  --releasever=43 --forcearch=aarch64 \
  --installroot=/tmp/aarch64-root \
  --repo=fedora --repo=updates \
  --setopt=install_weak_deps=False \
  --setopt=module_platform_id=platform:f43 \
  install bash coreutils glibc glibc-langpack-en libgcc libstdc++ musl-filesystem musl-libc \
          zlib openssl-libs ca-certificates curl python3

bash tests/build_tests.sh

export ROOT=/tmp/aarch64-root
export RUSTLD=./target/aarch64-unknown-linux-gnu/release/examples/rustld
export LD_LIBRARY_PATH="$ROOT/lib:$ROOT/lib64:$ROOT/usr/lib:$ROOT/usr/lib64"
export QEMU_LD_PREFIX="$ROOT"

qemu-aarch64 -L "$ROOT" "$RUSTLD" ./tests/hello_arm64_glibc
# Works with hello_arm64_glibc_static, hello_arm64_musl, hello_arm64_musl_static
qemu-aarch64 -L "$ROOT" "$RUSTLD" "$ROOT/usr/bin/curl" --version
```

References:  
https://github.com/bminor/glibc/blob/master/elf/rtld.c  
https://github.com/kraj/musl/blob/kraj/master/ldso/dynlink.c  
https://github.com/5-pebbles/miros  

https://github.com/pauldcs/macho-loader-rs  
https://github.com/apple-oss-distributions/dyld/blob/main/dyld/Loader.cpp  
