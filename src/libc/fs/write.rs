use crate::arch;
use std::ffi::c_void;

pub const STD_IN: i32 = 0;
pub const STD_OUT: i32 = 1;
pub const STD_ERR: i32 = 2;

pub(crate) unsafe fn write(
    file_descriptor: i32,
    buffer_pointer: *const c_void,
    buffer_length_in_bytes: usize,
) -> isize {
    arch::write(file_descriptor, buffer_pointer, buffer_length_in_bytes)
}

/// Helper function to write a string slice to a file descriptor
pub unsafe fn write_str(file_descriptor: i32, s: &str) {
    write(file_descriptor, s.as_ptr() as *const c_void, s.len());
}
