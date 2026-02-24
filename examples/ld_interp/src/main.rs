#![no_std]
#![no_main]

use core::arch::{asm, naked_asm};

const AT_FDCWD: isize = -100;
const SYS_READLINKAT: usize = 267;
const SYS_EXECVE: usize = 59;
const SYS_WRITE: usize = 1;
const SYS_EXIT: usize = 60;

const FALLBACK_RUSTLD_MAIN: &[u8] =
    concat!(env!("CARGO_MANIFEST_DIR"), "/../../target/release/rustld\0").as_bytes();
const FALLBACK_RUSTLD_EXAMPLE: &[u8] =
    concat!(env!("CARGO_MANIFEST_DIR"), "/../../target/release/examples/rustld\0").as_bytes();

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { exit_now(127) }
}

#[no_mangle]
pub extern "C" fn rust_eh_personality() {}

#[unsafe(naked)]
#[no_mangle]
pub unsafe extern "C" fn _start() -> ! {
    naked_asm!(
        "mov rdi, rsp",
        "jmp {entry}",
        entry = sym start_from_stack,
    );
}

unsafe extern "C" fn start_from_stack(sp: *const usize) -> ! {
    let argc = *sp;
    let argv = sp.add(1) as *const *const u8;
    let envp = argv.add(argc + 1);

    if argc == 0 {
        write_stderr(b"ld(interp): missing argv\n");
        exit_now(127);
    }

    let argv0 = *argv;
    let manual_mode = argc >= 2 && cstr_basename_eq(argv0, b"ld");
    let target_start = if manual_mode { 1usize } else { 0usize };

    if argc <= target_start {
        write_stderr(b"Usage: ld <program> [args...]\n");
        exit_now(127);
    }

    let mut new_argv: [*const u8; 512] = [core::ptr::null(); 512];
    let mut out = 1usize;
    let mut i = target_start;
    while i < argc && out + 1 < new_argv.len() {
        new_argv[out] = *argv.add(i);
        out += 1;
        i += 1;
    }
    new_argv[out] = core::ptr::null();

    // Try fixed workspace fallback paths first.
    new_argv[0] = FALLBACK_RUSTLD_MAIN.as_ptr();
    if execve(FALLBACK_RUSTLD_MAIN.as_ptr(), new_argv.as_ptr(), envp) == 0 {
        exit_now(0);
    }
    new_argv[0] = FALLBACK_RUSTLD_EXAMPLE.as_ptr();
    if execve(FALLBACK_RUSTLD_EXAMPLE.as_ptr(), new_argv.as_ptr(), envp) == 0 {
        exit_now(0);
    }

    // Then try alongside this interpreter binary.
    let mut self_path = [0u8; 4096];
    let self_len = readlink_proc_self_exe(&mut self_path);
    if self_len > 0 {
        let self_len = self_len as usize;
        self_path[self_len] = 0;

        let mut dir = [0u8; 4096];
        let dir_len = dirname_from_path(self_path.as_ptr(), &mut dir);
        if dir_len > 0 {
            let mut candidate = [0u8; 4096];
            if join_path(&mut candidate, &dir[..dir_len], b"rustld") {
                new_argv[0] = candidate.as_ptr();
                if execve(candidate.as_ptr(), new_argv.as_ptr(), envp) == 0 {
                    exit_now(0);
                }
            }
        }
    }

    write_stderr(b"ld(interp): failed to exec rustld\n");
    exit_now(127);
}

unsafe fn syscall3(n: usize, a1: usize, a2: usize, a3: usize) -> isize {
    let ret: isize;
    asm!(
        "syscall",
        inlateout("rax") n as isize => ret,
        in("rdi") a1 as isize,
        in("rsi") a2 as isize,
        in("rdx") a3 as isize,
        lateout("rcx") _,
        lateout("r11") _,
        options(nostack, preserves_flags),
    );
    ret
}

unsafe fn syscall4(n: usize, a1: usize, a2: usize, a3: usize, a4: usize) -> isize {
    let ret: isize;
    asm!(
        "syscall",
        inlateout("rax") n as isize => ret,
        in("rdi") a1 as isize,
        in("rsi") a2 as isize,
        in("rdx") a3 as isize,
        in("r10") a4 as isize,
        lateout("rcx") _,
        lateout("r11") _,
        options(nostack, preserves_flags),
    );
    ret
}

unsafe fn readlink_proc_self_exe(buf: &mut [u8]) -> isize {
    let path = b"/proc/self/exe\0";
    if buf.len() < 2 {
        return -1;
    }
    syscall4(
        SYS_READLINKAT,
        AT_FDCWD as usize,
        path.as_ptr() as usize,
        buf.as_mut_ptr() as usize,
        buf.len() - 1,
    )
}

unsafe fn execve(path: *const u8, argv: *const *const u8, envp: *const *const u8) -> isize {
    syscall3(SYS_EXECVE, path as usize, argv as usize, envp as usize)
}

unsafe fn write_stderr(msg: &[u8]) {
    let _ = syscall3(SYS_WRITE, 2, msg.as_ptr() as usize, msg.len());
}

unsafe fn exit_now(code: i32) -> ! {
    let _ = syscall3(SYS_EXIT, code as usize, 0, 0);
    core::hint::unreachable_unchecked();
}

unsafe fn c_strlen(mut p: *const u8) -> usize {
    let mut n = 0usize;
    while !p.is_null() && *p != 0 {
        n += 1;
        p = p.add(1);
    }
    n
}

unsafe fn cstr_basename_eq(path: *const u8, name: &[u8]) -> bool {
    let len = c_strlen(path);
    if len == 0 {
        return false;
    }
    let mut start = 0usize;
    let mut i = 0usize;
    while i < len {
        if *path.add(i) == b'/' {
            start = i + 1;
        }
        i += 1;
    }
    let base_len = len - start;
    if base_len != name.len() {
        return false;
    }
    let mut j = 0usize;
    while j < base_len {
        if *path.add(start + j) != name[j] {
            return false;
        }
        j += 1;
    }
    true
}

unsafe fn dirname_from_path(path: *const u8, out: &mut [u8]) -> usize {
    let len = c_strlen(path);
    if len == 0 || out.len() < 2 {
        return 0;
    }

    let mut cut = 0usize;
    let mut i = 0usize;
    while i < len {
        if *path.add(i) == b'/' {
            cut = i;
        }
        i += 1;
    }

    if cut == 0 {
        out[0] = b'.';
        out[1] = 0;
        return 1;
    }

    if cut + 1 >= out.len() {
        return 0;
    }

    let mut j = 0usize;
    while j < cut {
        out[j] = *path.add(j);
        j += 1;
    }
    out[cut] = 0;
    cut
}

fn join_path(out: &mut [u8], dir: &[u8], leaf: &[u8]) -> bool {
    if dir.is_empty() {
        return false;
    }

    let needs_sep = dir[dir.len() - 1] != b'/';
    let total = dir.len() + usize::from(needs_sep) + leaf.len();
    if total + 1 > out.len() {
        return false;
    }

    let mut pos = 0usize;
    out[..dir.len()].copy_from_slice(dir);
    pos += dir.len();
    if needs_sep {
        out[pos] = b'/';
        pos += 1;
    }
    out[pos..pos + leaf.len()].copy_from_slice(leaf);
    pos += leaf.len();
    out[pos] = 0;
    true
}

#[no_mangle]
pub unsafe extern "C" fn memcpy(dst: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    let mut i = 0usize;
    while i < n {
        *dst.add(i) = *src.add(i);
        i += 1;
    }
    dst
}

#[no_mangle]
pub unsafe extern "C" fn memset(dst: *mut u8, value: i32, n: usize) -> *mut u8 {
    let mut i = 0usize;
    let v = value as u8;
    while i < n {
        *dst.add(i) = v;
        i += 1;
    }
    dst
}

#[no_mangle]
pub unsafe extern "C" fn strlen(s: *const u8) -> usize {
    c_strlen(s)
}
