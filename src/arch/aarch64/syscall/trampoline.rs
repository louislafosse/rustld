//! Syscall trampoline: routes all syscalls through an anonymous RX page so
//! the `svc #0` instruction never appears in the loader image.

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

// `svc #0 ; ret` split as data so the encoding never appears as code.
// svc #0 = 0xD4000001 → LE bytes: 01 00 00 D4
// ret    = 0xD65F03C0 → LE bytes: C0 03 5F D6
const STUB: [u8; 8] = [0x01, 0x00, 0x00, 0xD4, 0xC0, 0x03, 0x5F, 0xD6];

// Bootstrap mmap/mprotect use .byte directives so the svc encoding only appears
// inside STUB (data) and these two cold functions, nowhere else.
#[inline(never)]
unsafe fn bootstrap_mmap(size: usize) -> *mut u8 {
    let result: isize;
    unsafe {
        asm!(
            ".byte 0x01, 0x00, 0x00, 0xD4", // svc #0
            in("x8") 222usize,              // SYS_mmap
            in("x0") 0usize,                // addr = NULL
            in("x1") size,                  // length
            in("x2") 3usize,                // PROT_READ | PROT_WRITE
            in("x3") 0x22usize,             // MAP_PRIVATE | MAP_ANONYMOUS
            in("x4") -1isize as usize,      // fd = -1
            in("x5") 0usize,                // offset = 0
            lateout("x0") result,
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
            ".byte 0x01, 0x00, 0x00, 0xD4", // svc #0
            in("x8") 226usize,              // SYS_mprotect
            in("x0") addr,
            in("x1") len,
            in("x2") prot,
            lateout("x0") _rc,
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

// `#[inline(never)]` keeps `svc #0` confined to one copy in the binary.
#[inline(never)]
unsafe fn direct_syscall6(nr: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize, a6: usize) -> isize {
    let result: isize;
    unsafe {
        asm!(
            "svc 0",
            in("x8") nr,
            inlateout("x0") a1 => result,
            in("x1") a2, in("x2") a3, in("x3") a4,
            in("x4") a5, in("x5") a6,
            options(nostack),
        );
    }
    result
}

#[inline(never)]
unsafe fn direct_syscall_noreturn(nr: usize, a1: usize) -> ! {
    unsafe {
        asm!("svc 0", in("x8") nr, in("x0") a1, options(noreturn));
    }
}

#[inline(always)]
pub unsafe fn indirect_syscall6(nr: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize, a6: usize) -> isize {
    if USE_INDIRECT.load(Ordering::Relaxed) {
        let stub = trampoline();
        let result: isize;
        unsafe {
            asm!(
                "blr {stub}",
                stub = in(reg) stub,
                in("x8") nr,
                inlateout("x0") a1 => result,
                in("x1") a2, in("x2") a3, in("x3") a4,
                in("x4") a5, in("x5") a6,
                out("x30") _, // blr writes the return address into lr
                options(nostack),
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
                "blr {stub}",
                stub = in(reg) stub,
                in("x8") nr,
                in("x0") a1,
                options(noreturn),
            );
        }
    } else {
        unsafe { direct_syscall_noreturn(nr, a1) }
    }
}
