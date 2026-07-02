#[cfg(debug_assertions)]
use crate::libc::fs::write;
/// Stub implementations of _dl_* symbols that glibc expects from the dynamic linker
/// These are minimal no-op implementations to allow programs to run
use crate::{
    elf::symbol::Symbol,
    elf::thread_local_storage::ThreadControlBlock,
    elf::{header::ElfHeader, program_header::ProgramHeader},
    linking,
    syscall::thread_pointer::get_thread_pointer,
    tls,
};
use core::ffi::{c_char, c_void};
use core::mem::size_of;
use core::sync::atomic::{AtomicI32, AtomicU32, AtomicUsize, Ordering};

const SHN_ABS: u16 = 0xfff1;

#[cfg(target_arch = "x86_64")]
const SIGJMP_WORDS: usize = 32;
#[cfg(target_arch = "aarch64")]
const SIGJMP_WORDS: usize = 48;
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
const SIGJMP_WORDS: usize = 48;

#[repr(C)]
pub(crate) struct TlsIndex {
    pub(crate) ti_module: usize,
    pub(crate) ti_offset: usize,
}

#[repr(C, align(16))]
struct SigJmpBuf {
    // Conservative storage for glibc sigjmp_buf by architecture.
    // x86_64: ~200 bytes; aarch64: ~312 bytes.
    storage: [usize; SIGJMP_WORDS],
}

struct CatchErrorFrame {
    prev: *mut CatchErrorFrame,
    env: SigJmpBuf,
    objname: *mut *const c_char,
    errstring: *mut *const c_char,
    mallocedp: *mut u8,
    errcode: i32,
}

#[repr(C)]
struct DlException {
    objname: *const c_char,
    errstring: *const c_char,
    message_buffer: *mut c_char,
}

#[derive(Clone, Copy)]
struct CatchErrorThreadSlot {
    tid: i32,
    top: *mut CatchErrorFrame,
}

#[repr(C)]
struct LookupLinkMap {
    l_addr: usize,
    l_name: *const c_char,
    l_ld: *const u8,
}

const MAX_CATCH_ERROR_THREADS: usize = 128;
static CATCH_ERROR_STATE_LOCK: AtomicI32 = AtomicI32::new(0);
static mut CATCH_ERROR_SLOTS: [CatchErrorThreadSlot; MAX_CATCH_ERROR_THREADS] =
    [CatchErrorThreadSlot {
        tid: 0,
        top: core::ptr::null_mut(),
    }; MAX_CATCH_ERROR_THREADS];

static mut RTLD_LOOKUP_MAP: LookupLinkMap = LookupLinkMap {
    l_addr: 0,
    l_name: core::ptr::null(),
    l_ld: core::ptr::null(),
};
static mut DLERROR_BUF: [u8; 256] = [0; 256];
static mut DLERROR_PENDING: bool = false;
const DLERROR_BUF_SIZE: usize = 256;

// Runtime linker operations can be entered concurrently from multiple threads
// (dlopen/dlsym and rtld lookup callbacks). Guard access to the mutable
// DynamicLinker state with a small re-entrant spin lock keyed by TID.
static RTLD_LOCK_OWNER_TID: AtomicI32 = AtomicI32::new(0);
static RTLD_LOCK_DEPTH: AtomicU32 = AtomicU32::new(0);

#[cfg(target_arch = "x86_64")]
const TUNABLE_FORWARD_NONE: usize = 1;
#[cfg(target_arch = "x86_64")]
static TUNABLE_GET_VAL_FORWARD_ADDR: AtomicUsize = AtomicUsize::new(0);
#[cfg(target_arch = "x86_64")]
static TUNABLE_IS_INIT_FORWARD_ADDR: AtomicUsize = AtomicUsize::new(0);

#[cfg(debug_assertions)]
static STUB_TRACE_REMAINING: AtomicU32 = AtomicU32::new(200);

#[cfg(debug_assertions)]
#[inline(always)]
fn debug_stub_trace(name: &str) {
    if STUB_TRACE_REMAINING
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
            if v > 0 {
                Some(v - 1)
            } else {
                None
            }
        })
        .is_ok()
    {
        eprintln!("ld_stub: {}", name);
    }
}

#[cfg(not(debug_assertions))]
#[inline(always)]
fn debug_stub_trace(_name: &str) {}

#[inline(always)]
fn trace_thread_tls() -> bool {
    static TRACE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *TRACE.get_or_init(|| std::env::var("RUSTLD_TRACE_THREAD_TLS").is_ok())
}

#[inline(always)]
fn force_fresh_thread_tls() -> bool {
    static FORCE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *FORCE.get_or_init(|| std::env::var("RUSTLD_FORCE_FRESH_THREAD_TLS").is_ok())
}

#[inline(always)]
fn trace_rtld_lookup() -> bool {
    static TRACE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *TRACE.get_or_init(|| std::env::var("RUSTLD_TRACE_RTLD_LOOKUP").is_ok())
}

struct RtldOpGuard {
    tid: i32,
    locked: bool,
}

impl Drop for RtldOpGuard {
    fn drop(&mut self) {
        if !self.locked || self.tid <= 0 {
            return;
        }

        if RTLD_LOCK_OWNER_TID.load(Ordering::Acquire) != self.tid {
            return;
        }

        let depth = RTLD_LOCK_DEPTH.load(Ordering::Acquire);
        if depth <= 1 {
            RTLD_LOCK_DEPTH.store(0, Ordering::Release);
            RTLD_LOCK_OWNER_TID.store(0, Ordering::Release);
        } else {
            RTLD_LOCK_DEPTH.store(depth - 1, Ordering::Release);
        }
    }
}

#[inline(always)]
fn current_tid() -> i32 {
    crate::arch::gettid()
}

#[inline(always)]
fn current_pid() -> i32 {
    crate::arch::getpid()
}

#[inline(always)]
fn thread_still_alive(tid: i32) -> bool {
    if tid <= 0 {
        return false;
    }
    // tgkill(pid, tid, 0): kernel existence check for a specific thread.
    let rc = crate::arch::tgkill(current_pid(), tid, 0);
    // -ESRCH => does not exist; 0 or any other error conservatively treated as alive.
    rc != -3
}

#[inline(always)]
fn force_unlock_rtld_ops_if_owned_by_current_thread() {
    let tid = current_tid();
    if tid <= 0 {
        return;
    }
    if RTLD_LOCK_OWNER_TID.load(Ordering::Acquire) == tid {
        RTLD_LOCK_DEPTH.store(0, Ordering::Release);
        RTLD_LOCK_OWNER_TID.store(0, Ordering::Release);
    }
}

#[inline(always)]
fn lock_catch_error_state() {
    while CATCH_ERROR_STATE_LOCK
        .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        core::hint::spin_loop();
    }
}

#[inline(always)]
fn unlock_catch_error_state() {
    CATCH_ERROR_STATE_LOCK.store(0, Ordering::Release);
}

unsafe fn catch_error_get_top(tid: i32) -> *mut CatchErrorFrame {
    lock_catch_error_state();
    let mut top = core::ptr::null_mut();
    let mut idx = 0usize;
    while idx < MAX_CATCH_ERROR_THREADS {
        let slot = core::ptr::addr_of!(CATCH_ERROR_SLOTS[idx]);
        if (*slot).tid == tid {
            top = (*slot).top;
            break;
        }
        idx += 1;
    }
    unlock_catch_error_state();
    top
}

unsafe fn catch_error_set_top(tid: i32, top: *mut CatchErrorFrame) {
    lock_catch_error_state();
    let mut empty_slot: Option<usize> = None;
    let mut idx = 0usize;
    while idx < MAX_CATCH_ERROR_THREADS {
        let slot = core::ptr::addr_of_mut!(CATCH_ERROR_SLOTS[idx]);
        if (*slot).tid == tid {
            (*slot).top = top;
            if top.is_null() {
                (*slot).tid = 0;
            }
            unlock_catch_error_state();
            return;
        }
        if empty_slot.is_none() && (*slot).tid == 0 {
            empty_slot = Some(idx);
        }
        idx += 1;
    }

    // Prefer a truly free slot; otherwise reclaim a slot whose owning thread
    // has exited. Only as a last resort reuse slot 0, since clobbering a live
    // thread's frame would make its later _dl_signal_error longjmp into a
    // foreign stack.
    let reuse = empty_slot.or_else(|| {
        (0..MAX_CATCH_ERROR_THREADS).find(|&idx| {
            let slot = core::ptr::addr_of!(CATCH_ERROR_SLOTS[idx]);
            !thread_still_alive((*slot).tid)
        })
    });
    let idx = reuse.unwrap_or(0);
    let slot = core::ptr::addr_of_mut!(CATCH_ERROR_SLOTS[idx]);
    (*slot).tid = tid;
    (*slot).top = top;
    unlock_catch_error_state();
}

unsafe fn catch_error_restore_top(
    tid: i32,
    expected: *mut CatchErrorFrame,
    prev: *mut CatchErrorFrame,
) {
    lock_catch_error_state();
    let mut idx = 0usize;
    while idx < MAX_CATCH_ERROR_THREADS {
        let slot = core::ptr::addr_of_mut!(CATCH_ERROR_SLOTS[idx]);
        if (*slot).tid == tid {
            if (*slot).top == expected {
                (*slot).top = prev;
                if prev.is_null() {
                    (*slot).tid = 0;
                }
            }
            unlock_catch_error_state();
            return;
        }
        idx += 1;
    }
    unlock_catch_error_state();
}

#[inline(always)]
fn lock_rtld_ops() -> RtldOpGuard {
    let tid = current_tid();
    if tid <= 0 {
        return RtldOpGuard {
            tid: 0,
            locked: false,
        };
    }

    loop {
        let owner = RTLD_LOCK_OWNER_TID.load(Ordering::Acquire);
        let depth = RTLD_LOCK_DEPTH.load(Ordering::Acquire);

        if owner == tid {
            RTLD_LOCK_DEPTH.store(depth.saturating_add(1), Ordering::Release);
            return RtldOpGuard { tid, locked: true };
        }

        if owner == 0 {
            if RTLD_LOCK_OWNER_TID
                .compare_exchange(0, tid, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                RTLD_LOCK_DEPTH.store(1, Ordering::Release);
                return RtldOpGuard { tid, locked: true };
            }
            core::hint::spin_loop();
            continue;
        }

        // Recover from stale ownership metadata if a thread exited while
        // holding the lock or lock metadata was left inconsistent.
        if depth == 0 || !thread_still_alive(owner) {
            if RTLD_LOCK_OWNER_TID
                .compare_exchange(owner, 0, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                RTLD_LOCK_DEPTH.store(0, Ordering::Release);
                continue;
            }
        }

        // Keep the spinning lock simple/no-allocation: just issue a pause hint.
        core::hint::spin_loop();
    }
}

/// Hand a stable `*const Symbol` to glibc for a resolved rtld lookup.
///
/// glibc keeps the pointer we store into `*reference`, so it must outlive the
/// call and cannot be freed here. Intern one leaked box per distinct symbol
/// (keyed by defining object plus its symtab identity) so repeated lookups of
/// the same symbol reuse it instead of leaking a fresh box every time.
fn persist_rtld_lookup_symbol(obj_idx: usize, symbol: Symbol) -> *const Symbol {
    use std::collections::HashMap;
    use std::sync::Mutex;
    static INTERNED: Mutex<Option<HashMap<(usize, u32, usize), usize>>> = Mutex::new(None);

    let key = (obj_idx, symbol.st_name, symbol.st_value);
    let mut guard = INTERNED.lock().unwrap();
    let map = guard.get_or_insert_with(HashMap::new);
    if let Some(&ptr) = map.get(&key) {
        return ptr as *const Symbol;
    }
    let ptr = Box::into_raw(Box::new(symbol));
    map.insert(key, ptr as usize);
    ptr
}

extern "C" {
    #[link_name = "__sigsetjmp"]
    fn sigsetjmp(env: *mut SigJmpBuf, savemask: i32) -> i32;
    fn siglongjmp(env: *mut SigJmpBuf, val: i32) -> !;
    static __ehdr_start: ElfHeader;
}

#[repr(C)]
pub(crate) struct DlFindObject {
    dlfo_flags: u64,
    dlfo_map_start: *mut c_void,
    dlfo_map_end: *mut c_void,
    dlfo_link_map: *mut c_void,
    dlfo_eh_frame: *mut c_void,
    dlfo_sframe: *mut c_void,
    dlfo_reserved: [u64; 6],
}

#[repr(C)]
struct RDebug {
    r_version: i32,
    r_map: *mut c_void,
    r_brk: usize,
    r_state: i32,
    r_ldbase: usize,
}

#[unsafe(no_mangle)]
static mut _r_debug: RDebug = RDebug {
    r_version: 1,
    r_map: core::ptr::null_mut(),
    r_brk: 0,
    r_state: 0,
    r_ldbase: 0,
};

mod host_rtld;
mod misc;
mod dlfcn;
mod rtld_dispatch;
mod selinux;
mod tls_stubs;
mod errors;

pub(crate) use host_rtld::*;
pub use misc::*;
pub use dlfcn::*;
pub use rtld_dispatch::*;
pub use selinux::*;
pub use tls_stubs::*;
pub use errors::*;
