use crate::io_macros::syscall_debug_assert;
use super::trampoline::indirect_syscall6;

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

// #[inline(always)]
pub unsafe fn mmap(
    pointer: *mut u8,
    size: usize,
    protection_flags: usize,
    map_flags: usize,
    file_descriptor: isize,
    file_offset: usize,
) -> *mut u8 {
    const MMAP: usize = 9;

    let result = unsafe {
        indirect_syscall6(
            MMAP,
            pointer as usize,
            size,
            protection_flags,
            map_flags,
            file_descriptor as usize,
            file_offset,
        )
    };
    syscall_debug_assert!(result >= 0);
    result as *mut u8
}

#[inline(always)]
pub unsafe fn munmap(pointer: *mut u8, size: usize) {
    const MUNMAP: usize = 11;

    let _result =
        unsafe { indirect_syscall6(MUNMAP, pointer as usize, size, 0, 0, 0, 0) };
    syscall_debug_assert!(_result >= 0);
}

#[inline(always)]
pub unsafe fn mprotect(addr: *mut u8, len: usize, prot: usize) -> isize {
    const MPROTECT: usize = 10;

    unsafe { indirect_syscall6(MPROTECT, addr as usize, len, prot, 0, 0, 0) }
}
