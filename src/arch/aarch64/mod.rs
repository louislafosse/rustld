use core::{
    arch::asm,
    ffi::{c_char, c_void},
};

#[inline(always)]
unsafe fn syscall0(number: usize) -> isize {
    let rc: isize;
    asm!(
        "svc 0",
        in("x8") number,
        lateout("x0") rc,
        options(nostack),
    );
    rc
}

#[inline(always)]
unsafe fn syscall3(number: usize, arg0: usize, arg1: usize, arg2: usize) -> isize {
    let rc: isize;
    asm!(
        "svc 0",
        in("x8") number,
        in("x0") arg0,
        in("x1") arg1,
        in("x2") arg2,
        lateout("x0") rc,
        options(nostack),
    );
    rc
}

#[inline(always)]
unsafe fn syscall4(number: usize, arg0: usize, arg1: usize, arg2: usize, arg3: usize) -> isize {
    let rc: isize;
    asm!(
        "svc 0",
        in("x8") number,
        in("x0") arg0,
        in("x1") arg1,
        in("x2") arg2,
        in("x3") arg3,
        lateout("x0") rc,
        options(nostack),
    );
    rc
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
unsafe fn syscall1(number: usize, arg0: usize) -> isize {
    let rc: isize;
    asm!(
        "svc 0",
        in("x8") number,
        in("x0") arg0,
        lateout("x0") rc,
        options(nostack),
    );
    rc
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
pub(crate) unsafe fn jump_to_entry(entry: usize, stack: usize, rtld_fini: usize) -> ! {
    if stack != 0 {
        asm!(
            "mov sp, x1",
            // glibc aarch64 _start reads argc/argv from stack and expects
            // rtld_fini in x0 from the dynamic loader.
            "mov x0, x2",
            "br x3",
            in("x1") stack,
            in("x2") rtld_fini,
            in("x3") entry,
            options(noreturn),
        );
    }

    asm!(
        "mov x0, x2",
        "br x3",
        in("x2") rtld_fini,
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

#[no_mangle]
pub unsafe extern "C" fn __rustld_tlsdesc_return(desc: *const usize) -> usize {
    if desc.is_null() {
        return 0;
    }
    core::ptr::read(desc.add(1))
}

unsafe extern "C" {
    fn __tls_get_addr(module_and_offset: *const ()) -> *mut c_void;
}

#[inline(always)]
unsafe fn read_thread_pointer() -> usize {
    let tp: usize;
    asm!(
        "mrs {}, tpidr_el0",
        out(reg) tp,
        options(nomem, nostack, preserves_flags),
    );
    tp
}

#[no_mangle]
pub unsafe extern "C" fn __rustld_tlsdesc_resolver(desc: *const usize) -> usize {
    if desc.is_null() {
        return 0;
    }
    let module_and_offset = core::ptr::read(desc.add(1)) as *const ();
    let addr = __tls_get_addr(module_and_offset) as usize;
    let tp = read_thread_pointer();
    addr.wrapping_sub(tp)
}

#[inline(always)]
pub(crate) fn tlsdesc_resolver_addr() -> usize {
    __rustld_tlsdesc_resolver as usize
}

#[inline(always)]
pub(crate) fn tlsdesc_return_addr() -> usize {
    __rustld_tlsdesc_return as usize
}
