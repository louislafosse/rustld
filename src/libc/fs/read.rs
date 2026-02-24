use crate::arch;
use std::ffi::c_void;
use std::os::fd::AsRawFd;
use std::os::fd::BorrowedFd;

pub(crate) unsafe fn read(
    file_descriptor: BorrowedFd<'_>,
    buffer_pointer: *mut c_void,
    buffer_length_in_bytes: usize,
) -> isize {
    arch::read(
        file_descriptor.as_raw_fd(),
        buffer_pointer,
        buffer_length_in_bytes,
    )
}
