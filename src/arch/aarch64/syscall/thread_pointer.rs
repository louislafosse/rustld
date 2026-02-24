use std::arch::asm;

#[inline(always)]
pub unsafe fn set_thread_pointer(new_pointer: *mut ()) {
    asm!(
        "msr tpidr_el0, {tp}",
        tp = in(reg) new_pointer,
        options(nostack, preserves_flags)
    );
}

#[inline(always)]
pub unsafe fn get_thread_pointer() -> *mut () {
    let pointer: *mut ();
    asm!(
        "mrs {tp}, tpidr_el0",
        tp = out(reg) pointer,
        options(nostack, preserves_flags, readonly)
    );
    pointer
}
