use std::arch::asm;

use crate::io_macros::syscall_debug_assert;
use super::trampoline::indirect_syscall6;

#[inline(always)]
pub unsafe fn set_thread_pointer(new_pointer: *mut ()) {
    const ARCH_PRCTL: usize = 158;
    const ARCH_SET_FS: usize = 4098;

    unsafe {
        indirect_syscall6(ARCH_PRCTL, ARCH_SET_FS, new_pointer as usize, 0, 0, 0, 0);
    }
    syscall_debug_assert!(*new_pointer.cast::<*mut ()>() == new_pointer);
    syscall_debug_assert!(get_thread_pointer() == new_pointer);
}

#[inline(always)]
pub unsafe fn get_thread_pointer() -> *mut () {
    let pointer;
    asm!(
        "mov {}, fs:0",
        out(reg) pointer,
        options(nostack, preserves_flags, readonly)
    );
    pointer
}
