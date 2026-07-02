#[no_mangle]
pub extern "C" fn freecon(_con: *mut u8) {
    // Optional SELinux path in coreutils; treat as unavailable.
}

#[no_mangle]
pub extern "C" fn is_selinux_enabled() -> i32 {
    // Report SELinux as unavailable for portability in constrained loaders.
    0
}

/// SELinux `*getfilecon`-style stubs: report "no context available" by nulling
/// the out-pointer and returning -1. The leading args differ per function.
macro_rules! selinux_con_stub {
    ($name:ident $(, $arg:ident : $ty:ty)*) => {
        #[no_mangle]
        pub extern "C" fn $name($($arg: $ty,)* con: *mut *mut u8) -> i32 {
            if !con.is_null() {
                unsafe { *con = core::ptr::null_mut() };
            }
            -1
        }
    };
}

selinux_con_stub!(getcon);
selinux_con_stub!(getfilecon, _path: *const u8);
selinux_con_stub!(lgetfilecon, _path: *const u8);
selinux_con_stub!(getfilecon_raw, _path: *const u8);
selinux_con_stub!(fgetfilecon, _fd: i32);
