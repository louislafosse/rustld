use core::{
    arch::asm,
    ffi::{c_char, c_void},
};
use std::arch::naked_asm;

#[inline(always)]
pub(crate) unsafe fn current_stack_pointer() -> *const u8 {
    let rsp: usize;
    asm!(
        "mov {}, rsp",
        out(reg) rsp,
        options(nomem, nostack, preserves_flags),
    );
    rsp as *const u8
}

#[inline(always)]
pub(crate) unsafe fn openat_readonly(path_ptr: *const c_char) -> i32 {
    openat(-100, path_ptr, 0, 0) as i32
}

#[inline(always)]
pub(crate) unsafe fn openat(dirfd: i32, path_ptr: *const c_char, flags: i32, mode: u32) -> isize {
    const OPENAT: usize = 257;
    let rc: isize;
    asm!(
        "syscall",
        inlateout("rax") OPENAT => rc,
        in("rdi") dirfd as isize,
        in("rsi") path_ptr,
        in("rdx") flags as isize,
        in("r10") mode as isize,
        lateout("rcx") _,
        lateout("r11") _,
        options(nostack, preserves_flags),
    );
    rc
}

#[inline(always)]
pub(crate) unsafe fn read(fd: i32, buf: *mut c_void, len: usize) -> isize {
    const READ: usize = 0;
    let rc: isize;
    asm!(
        "syscall",
        inlateout("rax") READ => rc,
        in("rdi") fd as isize,
        in("rsi") buf,
        in("rdx") len,
        lateout("rcx") _,
        lateout("r11") _,
        options(nostack, preserves_flags),
    );
    rc
}

#[inline(always)]
pub(crate) unsafe fn write(fd: i32, buf: *const c_void, len: usize) -> isize {
    const WRITE: usize = 1;
    let rc: isize;
    asm!(
        "syscall",
        inlateout("rax") WRITE => rc,
        in("rdi") fd as isize,
        in("rsi") buf,
        in("rdx") len,
        lateout("rcx") _,
        lateout("r11") _,
        options(nostack, preserves_flags),
    );
    rc
}

#[inline(always)]
pub(crate) fn close(fd: i32) -> isize {
    const CLOSE: usize = 3;
    let rc: isize;
    unsafe {
        asm!(
            "syscall",
            inlateout("rax") CLOSE => rc,
            in("rdi") fd as isize,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack, preserves_flags),
        );
    }
    rc
}

#[inline(always)]
pub(crate) unsafe fn execve(
    path_ptr: *const c_char,
    argv: *const *const c_char,
    envp: *const *const c_char,
) -> isize {
    const EXECVE: usize = 59;
    let rc: isize;
    asm!(
        "syscall",
        inlateout("rax") EXECVE => rc,
        in("rdi") path_ptr,
        in("rsi") argv,
        in("rdx") envp,
        lateout("rcx") _,
        lateout("r11") _,
        options(nostack, preserves_flags),
    );
    rc
}

#[inline(always)]
pub(crate) unsafe fn close_fd(fd: i32) {
    let _ = close(fd);
}

#[inline(always)]
pub(crate) unsafe fn pread(fd: i32, buf: *mut u8, len: usize, offset: usize) -> isize {
    const PREAD64: usize = 17;
    let rc: isize;
    asm!(
        "syscall",
        inlateout("rax") PREAD64 => rc,
        in("rdi") fd,
        in("rsi") buf,
        in("rdx") len,
        in("r10") offset,
        lateout("rcx") _,
        lateout("r11") _,
        options(nostack, preserves_flags),
    );
    rc
}

#[inline(always)]
pub(crate) unsafe fn getrandom(buf: *mut u8, len: usize) -> isize {
    const GETRANDOM: usize = 318;
    let rc: isize;
    asm!(
        "syscall",
        inlateout("rax") GETRANDOM => rc,
        in("rdi") buf,
        in("rsi") len,
        in("rdx") 0usize,
        lateout("rcx") _,
        lateout("r11") _,
        options(nostack, preserves_flags),
    );
    rc
}

#[inline(always)]
pub(crate) fn running_under_valgrind() -> bool {
    const VG_USERREQ_RUNNING_ON_VALGRIND: usize = 0x1001;
    unsafe { valgrind_client_request(VG_USERREQ_RUNNING_ON_VALGRIND, 0, 0, 0, 0, 0) != 0 }
}

#[inline(always)]
unsafe fn valgrind_client_request(
    request: usize,
    arg1: usize,
    arg2: usize,
    arg3: usize,
    arg4: usize,
    arg5: usize,
) -> usize {
    let args = [request, arg1, arg2, arg3, arg4, arg5];
    let mut ret: usize;
    asm!(
        "xor edx, edx",
        "rol rdi, 3",
        "rol rdi, 13",
        "rol rdi, 61",
        "rol rdi, 51",
        "xchg rbx, rbx",
        in("rax") args.as_ptr(),
        lateout("rdx") ret,
        lateout("rcx") _,
        lateout("rsi") _,
        lateout("r8") _,
        lateout("r9") _,
        lateout("r10") _,
        lateout("r11") _,
        lateout("rdi") _,
        options(nostack, preserves_flags),
    );
    ret
}

#[inline(always)]
unsafe fn register_stack_for_valgrind(new_sp: usize) {
    // Keep in sync with start::build_stack() reservation size.
    const STACK_SIZE: usize = 8 * 1024 * 1024;
    const VG_USERREQ_STACK_REGISTER: usize = 0x1501;
    const VG_USERREQ_MAKE_MEM_DEFINED: usize = 0x4d43_0002;

    let stack_end = (new_sp + 4095) & !4095usize;
    let stack_start = stack_end.saturating_sub(STACK_SIZE);
    let _ = valgrind_client_request(
        VG_USERREQ_MAKE_MEM_DEFINED,
        stack_start,
        STACK_SIZE,
        0,
        0,
        0,
    );
    let _ = valgrind_client_request(VG_USERREQ_STACK_REGISTER, stack_start, stack_end, 0, 0, 0);
}

#[inline(always)]
pub(crate) unsafe fn jump_to_entry(entry: usize, stack: usize, rtld_fini: usize) -> ! {
    if stack != 0 {
        if running_under_valgrind() {
            register_stack_for_valgrind(stack);
        }
        asm!(
            "mov rsp, rsi",
            "xor eax, eax",
            "xor ebp, ebp",
            "jmp rdi",
            in("rdi") entry,
            in("rsi") stack,
            in("rdx") rtld_fini,
            options(noreturn),
        );
    }

    asm!(
        "xor eax, eax",
        "xor ebp, ebp",
        "jmp rdi",
        in("rdi") entry,
        in("rdx") rtld_fini,
        options(noreturn),
    );
}

#[inline(always)]
pub(crate) fn gettid() -> i32 {
    const GETTID: usize = 186;
    let tid: isize;
    unsafe {
        asm!(
            "syscall",
            inlateout("rax") GETTID => tid,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack, preserves_flags),
        );
    }
    tid as i32
}

#[inline(always)]
pub(crate) fn getpid() -> i32 {
    const GETPID: usize = 39;
    let pid: isize;
    unsafe {
        asm!(
            "syscall",
            inlateout("rax") GETPID => pid,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack, preserves_flags),
        );
    }
    pid as i32
}

#[inline(always)]
pub(crate) fn tgkill(pid: i32, tid: i32, sig: i32) -> isize {
    const TGKILL: usize = 234;
    let rc: isize;
    unsafe {
        asm!(
            "syscall",
            inlateout("rax") TGKILL => rc,
            in("rdi") pid as isize,
            in("rsi") tid as isize,
            in("rdx") sig as isize,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack, preserves_flags),
        );
    }
    rc
}

#[inline(always)]
pub(crate) unsafe fn trap() -> ! {
    asm!("ud2", options(noreturn, nostack));
}

#[inline(always)]
pub(crate) unsafe fn memmove(dst: *mut u8, src: *const u8, len: usize) -> *mut u8 {
    if len == 0 {
        return dst;
    }

    if (dst as usize) <= (src as usize) {
        asm!(
            "rep movsb",
            inout("rdi") dst => _,
            inout("rsi") src => _,
            inout("rcx") len => _,
            options(nostack, preserves_flags)
        );
    } else {
        asm!(
            "std",
            "rep movsb",
            "cld",
            inout("rdi") dst.add(len - 1) => _,
            inout("rsi") src.add(len - 1) => _,
            inout("rcx") len => _,
            options(nostack)
        );
    }
    dst
}

#[inline(always)]
pub(crate) unsafe fn memcpy(dst: *mut u8, src: *const u8, len: usize) -> *mut u8 {
    asm!(
        "rep movsb",
        inout("rdi") dst => _,
        inout("rsi") src => _,
        inout("rcx") len => _,
        options(nostack, preserves_flags)
    );
    dst
}

#[inline(always)]
pub(crate) unsafe fn memset(dst: *mut u8, value: u8, len: usize) -> *mut u8 {
    asm!(
        "rep stosb",
        inout("rdi") dst => _,
        in("al") value,
        inout("rcx") len => _,
        options(nostack, preserves_flags)
    );
    dst
}

#[inline(always)]
pub(crate) unsafe fn memcmp(left: *const u8, right: *const u8, len: usize) -> i32 {
    let ordering: i32;
    asm!(
        "xor {ordering:e}, {ordering:e}",
        "repe cmpsb",
        "seta {ordering:l}",
        "sbb {ordering:e}, 0",
        inout("rdi") left => _,
        inout("rsi") right => _,
        inout("rcx") len => _,
        ordering = out(reg) ordering,
        options(nostack)
    );
    ordering
}

unsafe extern "C" {
    fn __tls_get_addr(module_and_offset: *const ()) -> *mut c_void;
}

#[unsafe(naked)]
#[no_mangle]
pub unsafe extern "C" fn __rustld_tlsdesc_return() -> usize {
    naked_asm!("mov rax, [rax + 8]", "ret",);
}

#[unsafe(naked)]
#[no_mangle]
pub unsafe extern "C" fn __rustld_tlsdesc_resolver() -> usize {
    naked_asm!(
        "push rcx",
        "push rdx",
        "push rsi",
        "push rdi",
        "push r8",
        "push r9",
        "push r10",
        "push r11",
        "mov rdi, [rax + 8]",
        "sub rsp, 8",
        "call {tls_get_addr}",
        "add rsp, 8",
        "mov r11, rax",
        "mov rax, qword ptr fs:0",
        "sub r11, rax",
        "mov rax, r11",
        "pop r11",
        "pop r10",
        "pop r9",
        "pop r8",
        "pop rdi",
        "pop rsi",
        "pop rdx",
        "pop rcx",
        "ret",
        tls_get_addr = sym __tls_get_addr,
    );
}

#[inline(always)]
pub(crate) fn tlsdesc_resolver_addr() -> usize {
    __rustld_tlsdesc_resolver as usize
}

#[inline(always)]
pub(crate) fn tlsdesc_return_addr() -> usize {
    __rustld_tlsdesc_return as usize
}
