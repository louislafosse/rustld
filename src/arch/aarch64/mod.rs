use core::{
    arch::{asm, global_asm},
    ffi::{c_char, c_void},
};
use crate::syscall::trampoline::indirect_syscall6;

#[inline(always)]
unsafe fn syscall0(number: usize) -> isize {
    unsafe { indirect_syscall6(number, 0, 0, 0, 0, 0, 0) }
}

#[inline(always)]
unsafe fn syscall1(number: usize, arg0: usize) -> isize {
    unsafe { indirect_syscall6(number, arg0, 0, 0, 0, 0, 0) }
}

#[inline(always)]
unsafe fn syscall3(number: usize, arg0: usize, arg1: usize, arg2: usize) -> isize {
    unsafe { indirect_syscall6(number, arg0, arg1, arg2, 0, 0, 0) }
}

#[inline(always)]
unsafe fn syscall4(number: usize, arg0: usize, arg1: usize, arg2: usize, arg3: usize) -> isize {
    unsafe { indirect_syscall6(number, arg0, arg1, arg2, arg3, 0, 0) }
}

#[inline(always)]
pub(crate) unsafe fn current_stack_pointer() -> *const u8 {
    let sp: usize;
    asm!(
        "mov {}, sp",
        out(reg) sp,
        options(nomem, nostack, preserves_flags),
    );
    sp as *const u8
}

#[inline(always)]
pub(crate) unsafe fn openat_readonly(path_ptr: *const c_char) -> i32 {
    openat(-100, path_ptr, 0, 0) as i32
}

#[inline(always)]
pub(crate) unsafe fn openat(dirfd: i32, path_ptr: *const c_char, flags: i32, mode: u32) -> isize {
    const OPENAT: usize = 56;
    syscall4(
        OPENAT,
        dirfd as isize as usize,
        path_ptr as usize,
        flags as isize as usize,
        mode as usize,
    )
}

#[inline(always)]
pub(crate) unsafe fn read(fd: i32, buf: *mut c_void, len: usize) -> isize {
    const READ: usize = 63;
    syscall3(READ, fd as isize as usize, buf as usize, len)
}

#[inline(always)]
pub(crate) unsafe fn write(fd: i32, buf: *const c_void, len: usize) -> isize {
    const WRITE: usize = 64;
    syscall3(WRITE, fd as isize as usize, buf as usize, len)
}

#[inline(always)]
pub(crate) fn close(fd: i32) -> isize {
    const CLOSE: usize = 57;
    unsafe { syscall1(CLOSE, fd as isize as usize) }
}



#[inline(always)]
pub(crate) unsafe fn execve(
    path_ptr: *const c_char,
    argv: *const *const c_char,
    envp: *const *const c_char,
) -> isize {
    const EXECVE: usize = 221;
    syscall3(EXECVE, path_ptr as usize, argv as usize, envp as usize)
}

#[inline(always)]
pub(crate) unsafe fn close_fd(fd: i32) {
    let _ = close(fd);
}

#[inline(always)]
pub(crate) unsafe fn pread(fd: i32, buf: *mut u8, len: usize, offset: usize) -> isize {
    const PREAD64: usize = 67;
    syscall4(PREAD64, fd as isize as usize, buf as usize, len, offset)
}

#[inline(always)]
pub(crate) unsafe fn getrandom(buf: *mut u8, len: usize) -> isize {
    const GETRANDOM: usize = 278;
    syscall3(GETRANDOM, buf as usize, len, 0)
}

#[inline(always)]
pub(crate) fn running_under_valgrind() -> bool {
    false
}

#[inline(always)]
pub(crate) unsafe fn jump_to_entry(entry: usize, stack: usize, _rtld_fini: usize) -> ! {
    if stack != 0 {
        asm!(
            "mov sp, x1",
            // Use a neutral loader-fini argument on aarch64 handoff.
            // glibc tolerates NULL here, and musl startup paths are stricter
            // about unexpected loader ABI register state.
            "mov x0, xzr",
            "br x3",
            in("x1") stack,
            in("x3") entry,
            options(noreturn),
        );
    }

    asm!(
        "mov x0, xzr",
        "br x3",
        in("x3") entry,
        options(noreturn),
    );
}

#[inline(always)]
pub(crate) fn gettid() -> i32 {
    const GETTID: usize = 178;
    unsafe { syscall0(GETTID) as i32 }
}

#[inline(always)]
pub(crate) fn getpid() -> i32 {
    const GETPID: usize = 172;
    unsafe { syscall0(GETPID) as i32 }
}

#[inline(always)]
pub(crate) fn tgkill(pid: i32, tid: i32, sig: i32) -> isize {
    const TGKILL: usize = 131;
    unsafe {
        syscall3(
            TGKILL,
            pid as isize as usize,
            tid as isize as usize,
            sig as isize as usize,
        )
    }
}

#[inline(always)]
pub(crate) unsafe fn trap() -> ! {
    asm!("brk #0", options(noreturn, nostack));
}

#[inline(always)]
pub(crate) unsafe fn memmove(dst: *mut u8, src: *const u8, len: usize) -> *mut u8 {
    core::ptr::copy(src, dst, len);
    dst
}

#[inline(always)]
pub(crate) unsafe fn memcpy(dst: *mut u8, src: *const u8, len: usize) -> *mut u8 {
    core::ptr::copy_nonoverlapping(src, dst, len);
    dst
}

#[inline(always)]
pub(crate) unsafe fn memset(dst: *mut u8, value: u8, len: usize) -> *mut u8 {
    core::ptr::write_bytes(dst, value, len);
    dst
}

#[inline(always)]
pub(crate) unsafe fn memcmp(left: *const u8, right: *const u8, len: usize) -> i32 {
    let mut idx = 0usize;
    while idx < len {
        let l = *left.add(idx);
        let r = *right.add(idx);
        if l != r {
            return (l as i32) - (r as i32);
        }
        idx += 1;
    }
    0
}

unsafe extern "C" {
    fn __tls_get_addr(module_and_offset: *const ()) -> *mut c_void;
}

global_asm!(
    r#"
.global __rustld_tlsdesc_return
.type __rustld_tlsdesc_return, %function
__rustld_tlsdesc_return:
    sub sp, sp, #96
    stp x1, x2, [sp, #0]
    stp x3, x4, [sp, #16]
    stp x5, x6, [sp, #32]
    stp x7, x8, [sp, #48]
    stp x9, x10, [sp, #64]
    cbz x0, 1f
    ldr x0, [x0, #8]
    b 2f
1:
    mov x0, xzr
2:
    ldp x9, x10, [sp, #64]
    ldp x7, x8, [sp, #48]
    ldp x5, x6, [sp, #32]
    ldp x3, x4, [sp, #16]
    ldp x1, x2, [sp, #0]
    add sp, sp, #96
    ret

.global __rustld_tlsdesc_resolver
.type __rustld_tlsdesc_resolver, %function
__rustld_tlsdesc_resolver:
    sub sp, sp, #112
    stp x1, x2, [sp, #0]
    stp x3, x4, [sp, #16]
    stp x5, x6, [sp, #32]
    stp x7, x8, [sp, #48]
    stp x9, x10, [sp, #64]
    str x30, [sp, #80]
    cbz x0, 3f
    ldr x0, [x0, #8]
    bl __tls_get_addr
    mrs x10, tpidr_el0
    sub x0, x0, x10
    b 4f
3:
    mov x0, xzr
4:
    ldr x30, [sp, #80]
    ldp x9, x10, [sp, #64]
    ldp x7, x8, [sp, #48]
    ldp x5, x6, [sp, #32]
    ldp x3, x4, [sp, #16]
    ldp x1, x2, [sp, #0]
    add sp, sp, #112
    ret
"#
);

unsafe extern "C" {
    fn __rustld_tlsdesc_return(desc: *const usize) -> usize;
    fn __rustld_tlsdesc_resolver(desc: *const usize) -> usize;
}

#[inline(always)]
pub(crate) fn tlsdesc_resolver_addr() -> usize {
    __rustld_tlsdesc_resolver as *const () as usize
}

#[inline(always)]
pub(crate) fn tlsdesc_return_addr() -> usize {
    __rustld_tlsdesc_return as *const () as usize
}
