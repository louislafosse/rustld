unsafe extern "C" {
    #[link_name = "__environ"]
    static mut host_environ: *mut *mut i8;
}

pub unsafe fn host_environment_pointer() -> *mut *mut u8 {
    core::ptr::read_volatile(core::ptr::addr_of!(host_environ)).cast()
}

pub unsafe fn get_environ_pointer() -> *mut *mut u8 {
    host_environment_pointer()
}
