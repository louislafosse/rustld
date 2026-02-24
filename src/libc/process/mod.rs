use std::sync::atomic::{AtomicBool, Ordering};

use crate::arch;

pub(crate) unsafe fn getpid() -> i32 {
    arch::getpid()
}

unsafe fn syscall_gettid() -> i32 {
    arch::gettid()
}

pub(crate) unsafe fn raise(signal_number: i32) -> i32 {
    let process_id = getpid();
    let thread_id = syscall_gettid();

    arch::tgkill(process_id, thread_id, signal_number) as i32
}

pub(crate) unsafe fn abort() -> ! {
    const SIGABRT: i32 = 6;

    static ABORT_IN_PROGRESS: AtomicBool = AtomicBool::new(false);

    if ABORT_IN_PROGRESS
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        arch::trap();
    }

    raise(SIGABRT);

    arch::trap();
}
