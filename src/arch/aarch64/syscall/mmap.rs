use std::arch::asm;

use crate::io_macros::syscall_debug_assert;

// Protection flags:
pub const PROT_NONE: usize = 0x0;
pub const PROT_READ: usize = 0x1;
pub const PROT_WRITE: usize = 0x2;
pub const PROT_EXEC: usize = 0x4;
pub const PROT_GROWSDOWN: isize = 0x01000000;
pub const PROT_GROWSUP: isize = 0x02000000;

// MAP flags:
pub const MAP_FILE: usize = 0x0;
pub const MAP_SHARED: usize = 0x1;
pub const MAP_PRIVATE: usize = 0x2;
pub const MAP_FIXED: usize = 0x10;
pub const MAP_ANONYMOUS: usize = 0x20;
pub const MAP_STACK: usize = 0x20000;

pub unsafe fn mmap(
    pointer: *mut u8,
    size: usize,
    protection_flags: usize,
    map_flags: usize,
    file_descriptor: isize,
    file_offset: usize,
) -> *mut u8 {
    const MMAP: usize = 222;

    let mut result: isize;
    unsafe {
        asm!(
            "svc 0",
            in("x8") MMAP,
            in("x0") pointer,
            in("x1") size,
            in("x2") protection_flags,
            in("x3") map_flags,
            in("x4") file_descriptor,
            in("x5") file_offset,
            lateout("x0") result,
            options(nostack)
        );
    }
    syscall_debug_assert!(result >= 0);
    result as *mut u8
}

#[inline(always)]
pub unsafe fn munmap(pointer: *mut u8, size: usize) {
    const MUNMAP: usize = 215;

    let mut result: isize;
    unsafe {
        asm!(
            "svc 0",
            in("x8") MUNMAP,
            in("x0") pointer,
            in("x1") size,
            lateout("x0") result,
            options(nostack)
        );
    }
    syscall_debug_assert!(result >= 0);
    let _ = result;
}

#[inline(always)]
pub unsafe fn mprotect(addr: *mut u8, len: usize, prot: usize) -> isize {
    const MPROTECT: usize = 226;

    let mut result: isize;
    unsafe {
        asm!(
            "svc 0",
            in("x8") MPROTECT,
            in("x0") addr,
            in("x1") len,
            in("x2") prot,
            lateout("x0") result,
            options(nostack)
        );
    }
    result
}
