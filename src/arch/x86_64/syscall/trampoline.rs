//! Syscall trampoline: routes all syscalls through an anonymous RX page so
//! the `syscall` opcode (`0x0F 0x05`) never appears in the loader image.

use core::{
    arch::asm,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};

static TRAMPOLINE: AtomicUsize = AtomicUsize::new(0);
static USE_INDIRECT: AtomicBool = AtomicBool::new(true);

/// Enable (`true`) or disable (`false`) the trampoline. Called by `ElfLoader`.
pub fn set_use_indirect(enabled: bool) {
    USE_INDIRECT.store(enabled, Ordering::Relaxed);
}

// `syscall ; ret` — split so the byte pair 0x0F 0x05 is data, not code.
const STUB: [u8; 3] = [0x0F, 0x05, 0xC3];

// Bootstrap mmap/mprotect use `.byte` directives so 0x0F 0x05 only appears
// inside STUB (data) and these two cold functions, nowhere else.
#[inline(never)]
unsafe fn bootstrap_mmap(size: usize) -> *mut u8 {
    let result: isize;
    unsafe {
        asm!(
            ".byte 0x0F", ".byte 0x05",
            inlateout("rax") 9usize => result,  // SYS_mmap
            in("rdi") 0usize,
            in("rsi") size,
            in("rdx") 3usize,                   // PROT_READ | PROT_WRITE
            in("r10") 0x22usize,                // MAP_PRIVATE | MAP_ANONYMOUS
            in("r8")  -1isize as usize,
            in("r9")  0usize,
            out("rcx") _, out("r11") _,
            options(nostack),
        );
    }
    result as *mut u8
}

#[inline(never)]
unsafe fn bootstrap_mprotect(addr: *mut u8, len: usize, prot: usize) {
    let _rc: isize;
    unsafe {
        asm!(
            ".byte 0x0F", ".byte 0x05",
            inlateout("rax") 10usize => _rc,    // SYS_mprotect
            in("rdi") addr, in("rsi") len, in("rdx") prot,
            out("rcx") _, out("r11") _,
            options(nostack),
        );
    }
}

pub fn init_trampoline() {
    if TRAMPOLINE.load(Ordering::Acquire) != 0 {
        return;
    }
    unsafe {
        let page = bootstrap_mmap(4096);
        assert!(!page.is_null() && (page as isize) > 0, "rustld: trampoline mmap failed");
        core::ptr::copy_nonoverlapping(STUB.as_ptr(), page, STUB.len());
        bootstrap_mprotect(page, 4096, 0x1 | 0x4); // PROT_READ | PROT_EXEC
        let _ = TRAMPOLINE.compare_exchange(0, page as usize, Ordering::Release, Ordering::Relaxed);
    }
}

#[inline(always)]
pub fn trampoline() -> usize {
    let addr = TRAMPOLINE.load(Ordering::Acquire);
    if addr == 0 { init_trampoline(); TRAMPOLINE.load(Ordering::Acquire) } else { addr }
}

// `#[inline(never)]` keeps the `syscall` opcode confined to one copy in the
// binary instead of being duplicated at every inlined call site.
#[inline(never)]
unsafe fn direct_syscall6(nr: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize, a6: usize) -> isize {
    let result: isize;
    unsafe {
        asm!(
            "syscall",
            inlateout("rax") nr => result,
            in("rdi") a1, in("rsi") a2, in("rdx") a3,
            in("r10") a4, in("r8") a5, in("r9") a6,
            out("rcx") _, out("r11") _,
            options(nostack),
        );
    }
    result
}

#[inline(never)]
unsafe fn direct_syscall_noreturn(nr: usize, a1: usize) -> ! {
    unsafe {
        asm!("syscall", in("rax") nr, in("rdi") a1, options(noreturn));
    }
}

#[inline(always)]
pub unsafe fn indirect_syscall6(nr: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize, a6: usize) -> isize {
    if USE_INDIRECT.load(Ordering::Relaxed) {
        let stub = trampoline();
        let result: isize;
        unsafe {
            asm!(
                "mov qword ptr [rsp - 8], {stub}",
                "call qword ptr [rsp - 8]",
                stub = in(reg) stub,
                inlateout("rax") nr => result,
                in("rdi") a1, in("rsi") a2, in("rdx") a3,
                in("r10") a4, in("r8") a5, in("r9") a6,
                out("rcx") _, out("r11") _,
            );
        }
        result
    } else {
        unsafe { direct_syscall6(nr, a1, a2, a3, a4, a5, a6) }
    }
}

#[inline(always)]
pub unsafe fn indirect_syscall_noreturn(nr: usize, a1: usize) -> ! {
    if USE_INDIRECT.load(Ordering::Relaxed) {
        let stub = trampoline();
        unsafe {
            asm!(
                "mov qword ptr [rsp - 8], {stub}",
                "call qword ptr [rsp - 8]",
                stub = in(reg) stub,
                in("rax") nr, in("rdi") a1,
                options(noreturn),
            );
        }
    } else {
        unsafe { direct_syscall_noreturn(nr, a1) }
    }
}
