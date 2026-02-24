use core::ffi::c_void;

/// Minimal glibc-compatible TCB layout for x86_64.
/// Offsets match glibc's tcbhead_t so TLS access and stack canaries work.
#[repr(C, align(64))]
pub struct ThreadControlBlock {
    /// Self pointer (must be at offset 0 for arch_prctl checks)
    pub tcb: *mut ThreadControlBlock,
    /// Dynamic Thread Vector (DTV) pointer
    pub dtv: *mut usize,
    /// Self pointer (glibc expects this at offset 0x10)
    pub self_ptr: *mut ThreadControlBlock,
    /// 0 = single-threaded
    pub multiple_threads: i32,
    pub gscope_flag: i32,
    pub sysinfo: usize,
    /// Stack canary (offset 0x28)
    pub stack_guard: usize,
    /// Pointer guard (offset 0x30)
    pub pointer_guard: usize,
    pub vgetcpu_cache: [usize; 2],
    pub __glibc_reserved1: i32,
    pub __glibc_unused1: i32,
    pub __private_tm: [*mut c_void; 4],
    pub __private_ss: *mut c_void,
    pub __glibc_reserved2: isize,
    /// Extra padding to approximate glibc's full `struct pthread`.
    /// libc/pthread code reads fields at offsets well past 0x600.
    pub _padding: [usize; 2048],
}

#[repr(C)]
pub union DynamicThreadVectorItem {
    pub pointer: *mut c_void,
    pub generation_counter: usize,
}
