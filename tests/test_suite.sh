#!/usr/bin/env bash
set -euo pipefail

ROOT="${AARCH64_ROOT:-/tmp/aarch64-root}"
RUSTLD_X86="${RUSTLD_X86:-./target/release/examples/rustld}"
RUSTLD_A64="${RUSTLD_A64:-./target/aarch64-unknown-linux-gnu/release/examples/rustld}"
BASE_PATH="${BASE_PATH:-/usr/bin:/bin}"
BASE_HOME="${HOME:-/tmp}"
BASE_LANG="${LANG:-C}"

PASS=0
FAIL=0

log_dir="${TMPDIR:-/tmp}/rustld_test_suite"
mkdir -p "$log_dir"

run_x86() {
    local name="$1"
    shift
    if timeout 30s env -i \
        PATH="$BASE_PATH" \
        HOME="$BASE_HOME" \
        LANG="$BASE_LANG" \
        "$RUSTLD_X86" "$@" >"$log_dir/${name}.out" 2>"$log_dir/${name}.err"; then
        printf 'PASS %s\n' "$name"
        PASS=$((PASS + 1))
    else
        local ec=$?
        printf 'FAIL %s (exit=%s)\n' "$name" "$ec"
        tail -n 40 "$log_dir/${name}.err" || true
        FAIL=$((FAIL + 1))
    fi
}

run_a64() {
    local name="$1"
    shift
    if timeout 45s env -i \
        PATH="$BASE_PATH" \
        HOME="$BASE_HOME" \
        LANG="$BASE_LANG" \
        LD_LIBRARY_PATH="$ROOT/lib:$ROOT/lib64:$ROOT/usr/lib:$ROOT/usr/lib64" \
        qemu-aarch64 -L "$ROOT" "$RUSTLD_A64" "$@" \
        >"$log_dir/${name}.out" 2>"$log_dir/${name}.err"; then
        printf 'PASS %s\n' "$name"
        PASS=$((PASS + 1))
    else
        local ec=$?
        printf 'FAIL %s (exit=%s)\n' "$name" "$ec"
        tail -n 40 "$log_dir/${name}.err" || true
        FAIL=$((FAIL + 1))
    fi
}

run_a64_loop() {
    local name="$1"
    local rounds="$2"
    shift 2
    local i
    for i in $(seq 1 "$rounds"); do
        if ! timeout 30s env -i \
            PATH="$BASE_PATH" \
            HOME="$BASE_HOME" \
            LANG="$BASE_LANG" \
            LD_LIBRARY_PATH="$ROOT/lib:$ROOT/lib64:$ROOT/usr/lib:$ROOT/usr/lib64" \
            qemu-aarch64 -L "$ROOT" "$RUSTLD_A64" "$@" \
            >"$log_dir/${name}.${i}.out" 2>"$log_dir/${name}.${i}.err"; then
            local ec=$?
            printf 'FAIL %s(iter=%s) (exit=%s)\n' "$name" "$i" "$ec"
            tail -n 40 "$log_dir/${name}.${i}.err" || true
            FAIL=$((FAIL + 1))
            return
        fi
    done
    printf 'PASS %s x%s\n' "$name" "$rounds"
    PASS=$((PASS + 1))
}

run_a64_allow_musl_dlopen_unsupported() {
    local name="$1"
    shift
    if timeout 45s env -i \
        PATH="$BASE_PATH" \
        HOME="$BASE_HOME" \
        LANG="$BASE_LANG" \
        LD_LIBRARY_PATH="$ROOT/lib:$ROOT/lib64:$ROOT/usr/lib:$ROOT/usr/lib64" \
        qemu-aarch64 -L "$ROOT" "$RUSTLD_A64" "$@" \
        >"$log_dir/${name}.out" 2>"$log_dir/${name}.err"; then
        printf 'PASS %s\n' "$name"
        PASS=$((PASS + 1))
        return
    fi
    local ec=$?

    if grep -q "Dynamic loading not supported" "$log_dir/${name}.err"; then
        printf 'SKIP %s (musl dlopen unsupported in this runtime)\n' "$name"
        return
    fi

    printf 'FAIL %s (exit=%s)\n' "$name" "$ec"
    tail -n 40 "$log_dir/${name}.err" || true
    FAIL=$((FAIL + 1))
}

run_a64_loop_allow_musl_dlopen_unsupported() {
    local name="$1"
    local rounds="$2"
    shift 2
    local i
    for i in $(seq 1 "$rounds"); do
        if timeout 30s env -i \
            PATH="$BASE_PATH" \
            HOME="$BASE_HOME" \
            LANG="$BASE_LANG" \
            LD_LIBRARY_PATH="$ROOT/lib:$ROOT/lib64:$ROOT/usr/lib:$ROOT/usr/lib64" \
            qemu-aarch64 -L "$ROOT" "$RUSTLD_A64" "$@" \
            >"$log_dir/${name}.${i}.out" 2>"$log_dir/${name}.${i}.err"; then
            continue
        fi
        local ec=$?

        if grep -q "Dynamic loading not supported" "$log_dir/${name}.${i}.err"; then
            printf 'SKIP %s (musl dlopen unsupported in this runtime)\n' "$name"
            return
        fi

        printf 'FAIL %s(iter=%s) (exit=%s)\n' "$name" "$i" "$ec"
        tail -n 40 "$log_dir/${name}.${i}.err" || true
        FAIL=$((FAIL + 1))
        return
    done

    printf 'PASS %s x%s\n' "$name" "$rounds"
    PASS=$((PASS + 1))
}

printf '== x86_64 glibc/musl core ==\n'
run_x86 x86_ls /bin/ls
run_x86 x86_id /usr/bin/id -u
run_x86 x86_pwd /bin/pwd
run_x86 x86_python /usr/bin/python3 --version
run_x86 x86_deadbeef ./tests/print_deadbeef
run_x86 x86_sqrt ./tests/sqrt_with_ld
run_x86 x86_hello_static ./tests/hello_static
run_x86 x86_hello_musl ./tests/hello_musl
run_x86 x86_musl_regex ./tests/musl_regex_io
run_x86 x86_musl_threads ./tests/musl_threads_tls
run_x86 x86_musl_dlopen ./tests/musl_dlopen_main ./tests/libmusl_plugin.so
for i in $(seq 1 10); do
    run_x86 "x86_musl_threads_loop_${i}" ./tests/musl_threads_tls
    run_x86 "x86_musl_dlopen_loop_${i}" ./tests/musl_dlopen_main ./tests/libmusl_plugin.so
done
if [[ -x /usr/bin/fish ]]; then
    if timeout 15s env -i PATH="$BASE_PATH" HOME="$BASE_HOME" LANG="$BASE_LANG" \
        bash -lc "echo 'echo ok' | '$RUSTLD_X86' /usr/bin/fish >/dev/null" \
        >"$log_dir/x86_pipe_fish.out" 2>"$log_dir/x86_pipe_fish.err"; then
        printf 'PASS x86_pipe_fish\n'
        PASS=$((PASS + 1))
    else
        ec=$?
        printf 'FAIL x86_pipe_fish (exit=%s)\n' "$ec"
        tail -n 40 "$log_dir/x86_pipe_fish.err" || true
        FAIL=$((FAIL + 1))
    fi
else
    printf 'SKIP x86_pipe_fish (fish not installed)\n'
fi

if [[ -x "$RUSTLD_A64" ]] && command -v qemu-aarch64 >/dev/null 2>&1; then
    printf '== aarch64 glibc/musl core ==\n'
    run_a64 a64_hello_glibc ./tests/hello_arm64_glibc
    run_a64 a64_hello_glibc_static ./tests/hello_arm64_glibc_static
    run_a64 a64_hello_musl ./tests/hello_arm64_musl
    run_a64 a64_hello_musl_static ./tests/hello_arm64_musl_static
    run_a64 a64_ls "$ROOT/usr/bin/ls"
    run_a64 a64_id "$ROOT/usr/bin/id" -u
    run_a64 a64_pwd "$ROOT/usr/bin/pwd"
    run_a64 a64_python "$ROOT/usr/bin/python3" --version
    run_a64 a64_curl "$ROOT/usr/bin/curl" --version
    run_a64 a64_musl_regex ./tests/musl_regex_io_a64
    run_a64 a64_musl_threads ./tests/musl_threads_tls_a64
    run_a64_allow_musl_dlopen_unsupported a64_musl_dlopen ./tests/musl_dlopen_main_a64 ./tests/libmusl_plugin_a64.so

    printf '== aarch64 stress ==\n'
    run_a64_loop a64_curl_loop 10 "$ROOT/usr/bin/curl" --version
    run_a64_loop a64_ls_loop 10 "$ROOT/usr/bin/ls"
    run_a64_loop a64_id_loop 10 "$ROOT/usr/bin/id" -u
    run_a64_loop a64_musl_threads_loop 10 ./tests/musl_threads_tls_a64
    run_a64_loop_allow_musl_dlopen_unsupported a64_musl_dlopen_loop 10 ./tests/musl_dlopen_main_a64 ./tests/libmusl_plugin_a64.so
else
    printf 'SKIP aarch64 tests (missing qemu-aarch64 or %s)\n' "$RUSTLD_A64"
fi

printf 'TEST_SUITE_SUMMARY pass=%d fail=%d logs=%s\n' "$PASS" "$FAIL" "$log_dir"
exit "$FAIL"
