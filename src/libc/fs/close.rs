use crate::arch;
use std::os::fd::RawFd;

use crate::libc::errno::{set_errno, Errno};

pub(crate) unsafe fn close(file_descriptor: RawFd) -> i32 {
    if file_descriptor == -1 {
        set_errno(Errno::BADF);
        return -1;
    }

    arch::close(file_descriptor) as i32
}
