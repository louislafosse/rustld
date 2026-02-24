use core::ffi::{c_char, c_void};

#[cfg(target_arch = "aarch64")]
mod aarch64;
#[cfg(target_arch = "x86_64")]
mod x86_64;

#[cfg(target_arch = "aarch64")]
use aarch64 as imp;
#[cfg(target_arch = "x86_64")]
use x86_64 as imp;

#[inline(always)]
pub(crate) unsafe fn current_stack_pointer() -> *const u8 {
    imp::current_stack_pointer()
}

#[inline(always)]
pub(crate) unsafe fn openat_readonly(path_ptr: *const c_char) -> i32 {
    imp::openat_readonly(path_ptr)
}

#[inline(always)]
pub(crate) unsafe fn openat(dirfd: i32, path_ptr: *const c_char, flags: i32, mode: u32) -> isize {
    imp::openat(dirfd, path_ptr, flags, mode)
}

#[inline(always)]
pub(crate) unsafe fn read(fd: i32, buf: *mut c_void, len: usize) -> isize {
    imp::read(fd, buf, len)
}

#[inline(always)]
pub(crate) unsafe fn write(fd: i32, buf: *const c_void, len: usize) -> isize {
    imp::write(fd, buf, len)
}

#[inline(always)]
pub(crate) fn close(fd: i32) -> isize {
    imp::close(fd)
}

#[inline(always)]
pub(crate) unsafe fn execve(
    path_ptr: *const c_char,
    argv: *const *const c_char,
    envp: *const *const c_char,
) -> isize {
    imp::execve(path_ptr, argv, envp)
}

#[inline(always)]
pub(crate) unsafe fn close_fd(fd: i32) {
    imp::close_fd(fd);
}

#[inline(always)]
pub(crate) unsafe fn pread(fd: i32, buf: *mut u8, len: usize, offset: usize) -> isize {
    imp::pread(fd, buf, len, offset)
}

#[inline(always)]
pub(crate) unsafe fn getrandom(buf: *mut u8, len: usize) -> isize {
    imp::getrandom(buf, len)
}

#[inline(always)]
pub(crate) fn running_under_valgrind() -> bool {
    imp::running_under_valgrind()
}

#[inline(always)]
pub(crate) unsafe fn jump_to_entry(entry: usize, stack: usize, rtld_fini: usize) -> ! {
    imp::jump_to_entry(entry, stack, rtld_fini)
}

#[inline(always)]
pub(crate) fn gettid() -> i32 {
    imp::gettid()
}

#[inline(always)]
pub(crate) fn getpid() -> i32 {
    imp::getpid()
}

#[inline(always)]
pub(crate) fn tgkill(pid: i32, tid: i32, sig: i32) -> isize {
    imp::tgkill(pid, tid, sig)
}

#[inline(always)]
pub(crate) unsafe fn trap() -> ! {
    imp::trap()
}

#[inline(always)]
pub(crate) unsafe fn memmove(dst: *mut u8, src: *const u8, len: usize) -> *mut u8 {
    imp::memmove(dst, src, len)
}

#[inline(always)]
pub(crate) unsafe fn memcpy(dst: *mut u8, src: *const u8, len: usize) -> *mut u8 {
    imp::memcpy(dst, src, len)
}

#[inline(always)]
pub(crate) unsafe fn memset(dst: *mut u8, value: u8, len: usize) -> *mut u8 {
    imp::memset(dst, value, len)
}

#[inline(always)]
pub(crate) unsafe fn memcmp(left: *const u8, right: *const u8, len: usize) -> i32 {
    imp::memcmp(left, right, len)
}

#[inline(always)]
pub(crate) fn tlsdesc_resolver_addr() -> usize {
    imp::tlsdesc_resolver_addr()
}

#[inline(always)]
pub(crate) fn tlsdesc_return_addr() -> usize {
    imp::tlsdesc_return_addr()
}
