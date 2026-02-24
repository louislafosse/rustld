use crate::arch;
use crate::libc::errno::{set_errno, Errno};
use std::ffi::VaList;

const AT_FDCWD: isize = -100;
pub const S_IFMT: u32 = 1111 << 12;

pub(crate) unsafe fn open64(pathname: *const i8, flags: OFlags, mut args: VaList) -> i32 {
    let mode = if flags.create() || flags.create_unnamed_temporary_file() {
        args.arg::<u32>() & !S_IFMT
    } else {
        0
    };

    let result = arch::openat(
        AT_FDCWD as i32,
        pathname.cast(),
        flags.raw_value() as i32,
        mode,
    );
    if result < 0 {
        // The kernel returns -errno.
        set_errno(Errno(result.unsigned_abs() as u32));
        -1
    } else {
        result as i32
    }
}

pub static O_RDONLY: AccessMode = AccessMode::ReadOnly;
pub static O_WRONLY: AccessMode = AccessMode::WriteOnly;
pub static O_RDWR: AccessMode = AccessMode::ReadAndWrite;

#[repr(u8)]
#[derive(Clone, Copy)]
pub enum AccessMode {
    ReadOnly = 0b00,
    WriteOnly = 0b01,
    ReadAndWrite = 0b10,
}

// TODO: clean up these value definitions...
pub static O_CREAT: u32 = 64;
pub static O_EXCL: u32 = 128;
pub static O_NOCTTY: u32 = 256;
pub static O_TRUNC: u32 = 512;
pub static O_APPEND: u32 = 1024;
pub static O_NONBLOCK: u32 = 2048;
pub static O_DSYNC: u32 = 4096;
pub static FASYNC: u32 = 8192;
pub static O_DIRECT: u32 = 16384;
pub static O_LARGEFILE: u32 = 32768;
pub static O_DIRECTORY: u32 = 1 << 16;
pub static O_NOFOLLOW: u32 = 131072;
pub static O_NOATIME: u32 = 262144;
pub static O_CLOEXEC: u32 = 524288;
pub static __O_SYNC: u32 = 1048576;
pub static O_SYNC: u32 = 1052672;
pub static O_PATH: u32 = 2097152;
pub static O_TMPFILE: u32 = 1 << 22 | O_DIRECTORY; // O_TMPFILE should always be passed with O_DIRECTORY
pub static O_NDELAY: u32 = 2048;

#[repr(transparent)]
#[derive(Clone, Copy)]
pub struct OFlags(u32);

impl OFlags {
    pub fn create(&self) -> bool {
        self.0 & 64 != 0 // O_CREAT
    }

    pub fn create_unnamed_temporary_file(&self) -> bool {
        self.0 & (1 << 22) != 0 // O_TMPFILE
    }

    pub fn raw_value(&self) -> u32 {
        self.0
    }
}
