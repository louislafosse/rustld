# ld_interp

A minimal PT_INTERP-compatible dynamic linker trampoline written in Rust (`no_std`, `no_main`).

It forwards execution to the project loader binary (`rustld`) and preserves target argv/env.

## Build

```bash
cd examples/ld_interp
cargo build --release
```

Output binary:

```bash
examples/ld_interp/target/x86_64-unknown-linux-gnu/release/ld
```

## Use as ELF interpreter

```bash
INTERP="$(pwd)/examples/ld_interp/release/ld"
gcc -o ./examples/print_deadbeef_interp ./tests/print_deadbeef.c -lm -Wl,--dynamic-linker="$INTERP"
./examples/print_deadbeef_interp
```
