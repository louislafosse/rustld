use core::sync::atomic::{AtomicBool, Ordering};
use std::{ffi::CStr, mem::MaybeUninit};

use crate::{io_macros::syscall_debug_assert, start::environment_variables::EnvironmentIter};

#[allow(non_upper_case_globals)]
static mut environ: MaybeUninit<*mut *mut u8> = MaybeUninit::uninit();
static ENVIRON_INITIALIZED: AtomicBool = AtomicBool::new(false);

unsafe extern "C" {
    #[link_name = "__environ"]
    static mut host_environ: *mut *mut i8;
}

pub unsafe fn host_environment_pointer() -> *mut *mut u8 {
    core::ptr::read_volatile(core::ptr::addr_of!(host_environ)).cast()
}

pub unsafe fn set_environ_pointer(environ_pointer: *mut *mut u8) {
    syscall_debug_assert!((*environ_pointer.sub(1)).is_null());

    #[allow(static_mut_refs)]
    environ.write(environ_pointer);
    ENVIRON_INITIALIZED.store(true, Ordering::Release);
}

pub unsafe fn get_environ_pointer() -> *mut *mut u8 {
    if !ENVIRON_INITIALIZED.load(Ordering::Acquire) {
        return host_environment_pointer();
    }
    #[allow(static_mut_refs)]
    environ.assume_init_read()
}

pub(crate) unsafe fn getenv(variable_name_pointer: *const u8) -> *const u8 {
    let variable_name = CStr::from_ptr(variable_name_pointer.cast())
        .to_str()
        .unwrap();
    EnvironmentIter::new(get_environ_pointer())
        .find_map(|(name, value)| {
            if name == variable_name {
                Some(value.as_ptr())
            } else {
                None
            }
        })
        .unwrap_or_default()
}
