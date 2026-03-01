# Rustld
A modern x86_64 & AArch64 ELF loader (static & dynamic linker + compatible glibc & musl) written in Rust

## Build

```bash
# Run any binary (static, glibc, musl) on host arch
cargo build --release --example rustld
./target/release/examples/rustld /bin/ls
./target/release/examples/rustld --entry-symbol hello ./tests/libhello.so

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
// In Rust:
// See exact implementation in ./examples/rustld.rs

// With syscall trampoline obfuscation:
rustld::ElfLoader::new_with_obf(true).execute_from_bytes(target_bytes, target_argv, None, None, false);

// Without obfuscation:
rustld::ElfLoader::new().execute_from_bytes(target_bytes, target_argv, None, None, false);

// Optional explicit entrypoint:
rustld::ElfLoader::new_with_obf(true).execute_from_bytes_with_entry(
    target_bytes, target_argv,
    Some("hello"), // or None
    None,          // or Some(0x399)
    None, None, false,
);
```

```c
// In C:
// See exact implementation in ./examples/rustld_c.c
#include "rustld.h"

// Last argument: 1 = indirect trampoline syscalls
//                0 = direct inline syscalls
int32_t rc = rustld_elfloader_execute_from_bytes(
    target_bytes,           // mapped ELF bytes
    target_len,             // ELF size
    target_argc,            // argv count for target
    target_argv,            // argv for target (argv[0] = target path)
    NULL,                   // envp override (NULL => parent env)
    NULL,                   // auxv override (NULL => parent auxv)
    0,                      // auxv_len
    0,                      // verbose
    1                       // indirect_syscalls (1 = trampoline, 0 = direct)
);

// Optional explicit entrypoint override
int32_t rc2 = rustld_elfloader_execute_from_bytes_with_entry(
    target_bytes,
    target_len,
    target_argc,
    target_argv,
    "hello",               // entry_symbol (or NULL)
    0x399,                  // entry_address
    0,                      // entry_address_is_set (set 1 to use address)
    NULL,
    NULL,
    0,
    0,
    1                       // indirect_syscalls
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

# If you want to run all the test suite in one command
RUSTLD_X86=./target/release/examples/rustld AARCH64_ROOT=/tmp/aarch64-root ./tests/test_suite.sh
```

## Known Limitations
- Loading `/usr/bin/fish` through `rustld` is currently unstable in PTY mode and can abort after startup when typing commands.

References:  
https://github.com/bminor/glibc/blob/master/elf/rtld.c  
https://github.com/kraj/musl/blob/kraj/master/ldso/dynlink.c  
https://github.com/5-pebbles/miros  

https://github.com/pauldcs/macho-loader-rs  
https://github.com/apple-oss-distributions/dyld/blob/main/dyld/Loader.cpp  
