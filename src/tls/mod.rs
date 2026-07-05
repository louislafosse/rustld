use core::{
    mem::{align_of, size_of},
    ptr::null_mut,
    sync::atomic::{AtomicI32, AtomicU32, Ordering},
};
use crate::{
    elf::thread_local_storage::ThreadControlBlock,
    shared_object::SharedObject,
    syscall::{
        mmap::{mmap, MAP_ANONYMOUS, MAP_PRIVATE, PROT_READ, PROT_WRITE},
        thread_pointer::{get_thread_pointer, set_thread_pointer},
    },
    utils::round_up_to_boundary,
};

#[inline(always)]
fn trace_thread_tls() -> bool {
    static TRACE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *TRACE.get_or_init(|| std::env::var("RUSTLD_TRACE_THREAD_TLS").is_ok())
}

/// Map an anonymous read/write region, returning `None` on failure.
///
/// `arch::mmap` returns `-errno` cast to a pointer on error (never null), so
/// the correct failure predicate is a negative address, not `is_null()`.
#[inline]
unsafe fn mmap_anon(len: usize) -> Option<*mut u8> {
    let raw = mmap(
        null_mut(),
        len,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );
    if (raw as isize) < 0 || raw.is_null() {
        None
    } else {
        Some(raw)
    }
}

#[cfg(target_arch = "x86_64")]
const GLIBC_PTHREAD_TID_OFFSET: usize = 0x2d0;
#[cfg(target_arch = "x86_64")]
const GLIBC_PTHREAD_LIST_OFFSET: usize = 0x2c0;
#[cfg(target_arch = "x86_64")]
const GLIBC_TSD_KEY_BLOCK_OFFSET: isize = -0x28;
#[cfg(target_arch = "x86_64")]
const GLIBC_RSEQ_AREA_OFFSET: isize = -192;
#[cfg(target_arch = "x86_64")]
const GLIBC_RSEQ_AREA_SIZE: usize = 32;

#[cfg(target_arch = "x86_64")]
const MUSL_PTHREAD_SELF_OFFSET: usize = 0x00;
#[cfg(target_arch = "x86_64")]
const MUSL_PTHREAD_DTV_OFFSET: usize = 0x08;
#[cfg(target_arch = "x86_64")]
const MUSL_PTHREAD_PREV_OFFSET: usize = 0x10;
#[cfg(target_arch = "x86_64")]
const MUSL_PTHREAD_NEXT_OFFSET: usize = 0x18;
#[cfg(target_arch = "x86_64")]
const MUSL_PTHREAD_SYSINFO_OFFSET: usize = 0x20;
#[cfg(target_arch = "x86_64")]
const MUSL_PTHREAD_CANARY_OFFSET: usize = 0x28;
#[cfg(target_arch = "x86_64")]
const MUSL_PTHREAD_TID_OFFSET: usize = 0x30;
#[cfg(target_arch = "x86_64")]
const MUSL_PTHREAD_DETACH_STATE_OFFSET: usize = 0x38;
#[cfg(target_arch = "x86_64")]
const MUSL_PTHREAD_ROBUST_HEAD_OFFSET: usize = 0x88;
#[cfg(target_arch = "x86_64")]
const MUSL_PTHREAD_ROBUST_OFF_OFFSET: usize = 0x90;
#[cfg(target_arch = "x86_64")]
const MUSL_PTHREAD_ROBUST_PENDING_OFFSET: usize = 0x98;

#[cfg(target_arch = "x86_64")]
const MUSL_DETACH_STATE_JOINABLE: i32 = 2;

#[cfg(target_arch = "aarch64")]
const MUSL_AARCH64_PTHREAD_SIZE_BEFORE_TP: usize = 0xC8;
#[cfg(target_arch = "aarch64")]
const MUSL_AARCH64_DTV_SLOT_FROM_TP: isize = -8;
#[cfg(target_arch = "aarch64")]
const MUSL_AARCH64_SELF_OFFSET: usize = 0x00;

pub struct TlsState {
    pub tcb: *mut ThreadControlBlock,
    pub dtv: *mut usize,
    pub tls_base: *mut u8,
    pub dtv_len: usize,
    runtime_static_cursor: usize,
    modules: Vec<TlsModuleTemplate>,
}

#[repr(C)]
struct DtvEntry {
    value: usize,
    to_free: usize,
}

// Match glibc's initial DTV spare slots policy (enough headroom for
// startup dlopen activity before reallocations).
const DTV_SURPLUS_SLOTS: usize = 14;

#[derive(Clone, Copy)]
struct TlsModuleTemplate {
    module_id: usize,
    init_image: *const u8,
    filesz: usize,
    memsz: usize,
    align: usize,
    block_offset: usize,
    dynamic: bool,
    inherit_runtime_head: usize,
}

static mut TLS_STATE: Option<TlsState> = None;
static mut TLS_LAYOUT: Option<TlsLayout> = None;
static TLS_STATE_LOCK_OWNER_TID: AtomicI32 = AtomicI32::new(0);
static TLS_STATE_LOCK_DEPTH: AtomicU32 = AtomicU32::new(0);
const MAX_TRACKED_THREADS: usize = 4096;
static THREAD_TRACK_LOCK: AtomicI32 = AtomicI32::new(0);
static mut TRACKED_THREADS: [*mut ThreadControlBlock; MAX_TRACKED_THREADS] =
    [null_mut(); MAX_TRACKED_THREADS];

struct TlsStateGuard {
    tid: i32,
    locked: bool,
}

impl Drop for TlsStateGuard {
    fn drop(&mut self) {
        if !self.locked || self.tid <= 0 {
            return;
        }

        if TLS_STATE_LOCK_OWNER_TID.load(Ordering::Acquire) != self.tid {
            return;
        }

        let depth = TLS_STATE_LOCK_DEPTH.load(Ordering::Acquire);
        if depth <= 1 {
            TLS_STATE_LOCK_DEPTH.store(0, Ordering::Release);
            TLS_STATE_LOCK_OWNER_TID.store(0, Ordering::Release);
        } else {
            TLS_STATE_LOCK_DEPTH.store(depth - 1, Ordering::Release);
        }
    }
}

#[inline(always)]
fn lock_tls_state() -> TlsStateGuard {
    let tid = crate::arch::gettid();
    if tid <= 0 {
        return TlsStateGuard {
            tid: 0,
            locked: false,
        };
    }

    loop {
        let owner = TLS_STATE_LOCK_OWNER_TID.load(Ordering::Acquire);
        let depth = TLS_STATE_LOCK_DEPTH.load(Ordering::Acquire);
        if owner == tid {
            TLS_STATE_LOCK_DEPTH.store(depth.saturating_add(1), Ordering::Release);
            return TlsStateGuard { tid, locked: true };
        }

        if owner == 0
            && TLS_STATE_LOCK_OWNER_TID
                .compare_exchange(0, tid, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
        {
            TLS_STATE_LOCK_DEPTH.store(1, Ordering::Release);
            return TlsStateGuard { tid, locked: true };
        }

        core::hint::spin_loop();
    }
}

struct ThreadRegistryGuard;

impl Drop for ThreadRegistryGuard {
    #[inline(always)]
    fn drop(&mut self) {
        THREAD_TRACK_LOCK.store(0, Ordering::Release);
    }
}

#[inline(always)]
fn lock_thread_registry() -> ThreadRegistryGuard {
    while THREAD_TRACK_LOCK
        .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        core::hint::spin_loop();
    }
    ThreadRegistryGuard
}

fn register_thread_tcb(tcb: *mut ThreadControlBlock) {
    if tcb.is_null() {
        return;
    }
    let _guard = lock_thread_registry();
    unsafe {
        let mut free_slot = None;
        for idx in 0..MAX_TRACKED_THREADS {
            let entry = TRACKED_THREADS[idx];
            if entry == tcb {
                return;
            }
            if free_slot.is_none() && entry.is_null() {
                free_slot = Some(idx);
            }
        }
        if let Some(idx) = free_slot {
            TRACKED_THREADS[idx] = tcb;
        }
    }
}

pub fn unregister_thread_tcb(tcb: *mut ThreadControlBlock) {
    if tcb.is_null() {
        return;
    }
    let _guard = lock_thread_registry();
    unsafe {
        for idx in 0..MAX_TRACKED_THREADS {
            if TRACKED_THREADS[idx] == tcb {
                TRACKED_THREADS[idx] = null_mut();
                break;
            }
        }
    }
}

fn tracked_threads_snapshot() -> Vec<*mut ThreadControlBlock> {
    let mut threads = Vec::new();
    let (current_tcb, current_tid) = unsafe {
        (
            get_thread_pointer() as *mut ThreadControlBlock,
            current_tid(),
        )
    };
    let _guard = lock_thread_registry();
    unsafe {
        for idx in 0..MAX_TRACKED_THREADS {
            let tcb = TRACKED_THREADS[idx];
            if tcb.is_null() {
                continue;
            }
            if !is_thread_descriptor_live(tcb, current_tcb, current_tid) {
                TRACKED_THREADS[idx] = null_mut();
                continue;
            }
            threads.push(tcb);
        }
    }
    threads
}

#[inline(always)]
fn thread_exists(tid: i32) -> bool {
    if tid <= 0 {
        return false;
    }
    let rc = crate::arch::tgkill(crate::arch::getpid(), tid, 0);
    // -ESRCH => gone; 0 or any other error conservatively treated as alive.
    rc != -3
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn thread_tid_from_tcb(tcb: *mut ThreadControlBlock) -> i32 {
    if tcb.is_null() {
        return -1;
    }
    let base = tcb as *mut u8;
    let glibc_tid = core::ptr::read_volatile(base.add(GLIBC_PTHREAD_TID_OFFSET) as *const i32);
    if glibc_tid > 0 {
        return glibc_tid;
    }
    let musl_tid = core::ptr::read_unaligned(base.add(MUSL_PTHREAD_TID_OFFSET) as *const i32);
    if musl_tid > 0 {
        musl_tid
    } else {
        -1
    }
}

#[cfg(not(target_arch = "x86_64"))]
#[inline(always)]
unsafe fn thread_tid_from_tcb(_tcb: *mut ThreadControlBlock) -> i32 {
    -1
}

#[inline(always)]
unsafe fn is_thread_descriptor_live(
    tcb: *mut ThreadControlBlock,
    current_tcb: *mut ThreadControlBlock,
    current_tid: i32,
) -> bool {
    if tcb.is_null() {
        return false;
    }
    if tcb == current_tcb {
        return true;
    }

    #[cfg(target_arch = "x86_64")]
    {
        let tid = thread_tid_from_tcb(tcb);
        if tid <= 0 {
            return false;
        }
        if tid == current_tid {
            return true;
        }
        return thread_exists(tid);
    }

    #[cfg(not(target_arch = "x86_64"))]
    {
        true
    }
}

#[inline]
unsafe fn dtv_capacity(dtv: *mut DtvEntry) -> usize {
    if dtv.is_null() {
        0
    } else {
        (*dtv.sub(1)).value
    }
}

#[inline]
unsafe fn set_dtv_capacity(dtv: *mut DtvEntry, capacity: usize) {
    if dtv.is_null() {
        return;
    }
    (*dtv.sub(1)).value = capacity;
    (*dtv.sub(1)).to_free = 0;
}

#[inline(always)]
unsafe fn tcb_read_dtv_ptr(tcb: *mut ThreadControlBlock) -> *mut usize {
    #[cfg(target_arch = "aarch64")]
    {
        if tcb.is_null() {
            core::ptr::null_mut()
        } else {
            core::ptr::read(tcb.cast::<usize>()) as *mut usize
        }
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        if tcb.is_null() {
            core::ptr::null_mut()
        } else {
            (*tcb).dtv
        }
    }
}

#[inline(always)]
unsafe fn tcb_write_dtv_ptr(tcb: *mut ThreadControlBlock, dtv: *mut usize) {
    if tcb.is_null() {
        return;
    }
    #[cfg(target_arch = "aarch64")]
    {
        // aarch64 glibc uses DTV-at-TP: first word at TP is the DTV pointer.
        // Keep TP+8 deterministic (glibc private slot).
        let head = tcb.cast::<usize>();
        core::ptr::write(head, dtv as usize);
        core::ptr::write(head.add(1), 0);
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        (*tcb).dtv = dtv;
    }
}

#[derive(Clone, Copy)]
pub struct TlsLayout {
    pub tcb_offset: usize,
    pub tls_size: usize,
    pub module_count: usize,
    pub max_align: usize,
    pub runtime_static_start: usize,
    pub runtime_static_end: usize,
}

#[inline(always)]
unsafe fn current_tid() -> i32 {
    crate::arch::gettid()
}

/// Allocate a zeroed DTV holding `dtv_len` module slots, set its capacity and
/// generation counter, and point each module's slot at its block (a fresh
/// mapping for dynamic modules, or `tls_base + block_offset` for static ones).
/// Returns the `dtv` pointer past the `dtv[-1]` capacity header.
unsafe fn build_and_populate_dtv(
    dtv_len: usize,
    tls_base: *mut u8,
    modules: &[TlsModuleTemplate],
) -> Option<*mut DtvEntry> {
    let dtv_alloc_entries = dtv_len + 1; // +1 header slot for dtv[-1]
    let dtv_size = dtv_alloc_entries * size_of::<DtvEntry>();
    let dtv_raw = mmap_anon(dtv_size)?.cast::<DtvEntry>();
    // mmap_anon pages are already zero.

    let dtv = dtv_raw.add(1);
    set_dtv_capacity(dtv, dtv_len);
    (*dtv).value = 1; // generation counter
    (*dtv).to_free = 0;

    for module in modules {
        let base = if module.dynamic {
            match allocate_tls_module_block(module) {
                Some(base) => base,
                None => continue,
            }
        } else {
            (tls_base as usize).wrapping_add(module.block_offset)
        };
        (*dtv.add(module.module_id)).value = base;
        (*dtv.add(module.module_id)).to_free = 0;
    }
    Some(dtv)
}

unsafe fn allocate_tls_module_block(module: &TlsModuleTemplate) -> Option<usize> {
    let align = module.align.max(align_of::<usize>());
    let payload = module.memsz.max(1);
    let alloc_len = payload.checked_add(align)?;

    let raw = mmap_anon(alloc_len)?;
    // mmap_anon pages are already zero.
    let base = round_up_to_boundary(raw as usize, align);

    if module.filesz > 0 {
        let copy_len = module.filesz.min(module.memsz);
        if copy_len > 0 {
            core::ptr::copy_nonoverlapping(module.init_image, base as *mut u8, copy_len);
        }
    }
    Some(base)
}

unsafe fn initialize_glibc_thread_links(tcb: *mut ThreadControlBlock) {
    if tcb.is_null() {
        return;
    }
    #[cfg(target_arch = "x86_64")]
    {
        let list_head = (tcb as *mut u8).add(GLIBC_PTHREAD_LIST_OFFSET) as *mut usize;
        let self_ptr = list_head as usize;
        // Keep glibc-initialized non-zero links when present; otherwise seed
        // an empty self-linked list for fork bookkeeping.
        if core::ptr::read_volatile(list_head) == 0
            && core::ptr::read_volatile(list_head.add(1)) == 0
        {
            core::ptr::write_volatile(list_head, self_ptr);
            core::ptr::write_volatile(list_head.add(1), self_ptr);
        }
    }
}

mod layout;
mod install;
mod thread;
mod runtime;

pub use install::{install_tls, install_tls_musl};
pub use layout::{prepare_tls_layout, tls_layout};
pub use runtime::{finalize_runtime_tls_images, register_runtime_tls_modules, resolve_tls_address};
pub use thread::{
    allocate_tls_for_new_thread, initialize_tls_for_thread_ptr, stamp_thread_tid,
    thread_ptr_needs_tls_init,
};
