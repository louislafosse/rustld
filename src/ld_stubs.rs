#[cfg(debug_assertions)]
use crate::libc::fs::write;
/// Stub implementations of _dl_* symbols that glibc expects from the dynamic linker
/// These are minimal no-op implementations to allow programs to run
use crate::{
    arch,
    elf::symbol::Symbol,
    elf::thread_local_storage::ThreadControlBlock,
    elf::{header::ElfHeader, program_header::ProgramHeader},
    linking,
    syscall::thread_pointer::get_thread_pointer,
    tls,
};
use core::ffi::{c_char, c_void};
use core::mem::{size_of, MaybeUninit};
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, Ordering};

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
    mallocedp: *mut i32,
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
static DL_FINI_CALLED: AtomicBool = AtomicBool::new(false);
static mut RTLD_LOOKUP_SYMBOL: MaybeUninit<Symbol> = MaybeUninit::uninit();

static mut DLERROR_BUF: [u8; 256] = [0; 256];
static mut DLERROR_PENDING: bool = false;
const DLERROR_BUF_SIZE: usize = 256;

// Runtime linker operations can be entered concurrently from multiple threads
// (dlopen/dlsym and rtld lookup callbacks). Guard access to the mutable
// DynamicLinker state with a small re-entrant spin lock keyed by TID.
static RTLD_LOCK_OWNER_TID: AtomicI32 = AtomicI32::new(0);
static RTLD_LOCK_DEPTH: AtomicU32 = AtomicU32::new(0);

struct RtldOpGuard;

impl Drop for RtldOpGuard {
    fn drop(&mut self) {}
}

#[inline(always)]
fn current_tid() -> i32 {
    arch::gettid()
}

#[inline(always)]
fn current_pid() -> i32 {
    arch::getpid()
}

#[inline(always)]
fn thread_still_alive(tid: i32) -> bool {
    if tid <= 0 {
        return false;
    }
    // tgkill(pid, tid, 0): kernel existence check for a specific thread.
    let rc = arch::tgkill(current_pid(), tid, 0);
    // 0 => exists; -ESRCH => does not exist; other errors conservatively treated as alive.
    rc == 0 || rc != -3
}

#[inline(always)]
fn force_unlock_rtld_ops_if_owned_by_current_thread() {
    let _ = current_tid();
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

    if let Some(idx) = empty_slot {
        let slot = core::ptr::addr_of_mut!(CATCH_ERROR_SLOTS[idx]);
        (*slot).tid = tid;
        (*slot).top = top;
    } else {
        // Keep running even if we exceed the slot budget.
        let slot = core::ptr::addr_of_mut!(CATCH_ERROR_SLOTS[0]);
        (*slot).tid = tid;
        (*slot).top = top;
    }
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
    // Temporarily disabled: lock contention/regressions caused user-space spins
    // for some binaries (id/curl). Keep guard call sites unchanged.
    RtldOpGuard
}

#[no_mangle]
pub static mut __rustld_last_alloc_tls_enter: *mut () = core::ptr::null_mut();
#[no_mangle]
pub static mut __rustld_last_alloc_tls_ret: *mut () = core::ptr::null_mut();
#[no_mangle]
pub static mut __rustld_last_alloc_tls_init_arg: *mut () = core::ptr::null_mut();
#[no_mangle]
pub static mut __rustld_last_alloc_tls_init_ret: *mut () = core::ptr::null_mut();

extern "C" {
    #[link_name = "__sigsetjmp"]
    fn sigsetjmp(env: *mut SigJmpBuf, savemask: i32) -> i32;
    fn siglongjmp(env: *mut SigJmpBuf, val: i32) -> !;
    static __ehdr_start: ElfHeader;
}

#[repr(C)]
struct DtvEntry {
    value: usize,
    to_free: usize,
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

#[no_mangle]
pub extern "C" fn _dl_audit_preinit() {
    // Called by __libc_start_main before initialization
    // No-op for now
}

#[no_mangle]
pub extern "C" fn __libc_freeres() {
    // Valgrind's preload library calls this at exit. Skip freeing
    // libc internals to avoid touching uninitialized rtld state.
}

#[cfg(target_arch = "aarch64")]
#[no_mangle]
pub extern "C" fn _dl_fini() {
    // AArch64 teardown currently loops in libc/rtld cleanup paths.
    // Keep rtld_fini as a no-op so process exit can complete.
}

#[cfg(not(target_arch = "aarch64"))]
#[no_mangle]
pub extern "C" fn _dl_fini() {
    if DL_FINI_CALLED.swap(true, Ordering::AcqRel) {
        return;
    }
    let _guard = lock_rtld_ops();
    unsafe {
        if let Some(linker) = linking::active_linker() {
            linker.call_fini_for_loaded_objects();
        }
    }
}

type DlsymEntry = unsafe extern "C" fn(*mut c_void, *const u8) -> *mut c_void;
type DlvsymEntry = unsafe extern "C" fn(*mut c_void, *const u8, *const u8) -> *mut c_void;
type DlopenEntry = unsafe extern "C" fn(*const u8, i32) -> *mut c_void;
type DlcloseEntry = unsafe extern "C" fn(*mut c_void) -> i32;
type DlerrorEntry = unsafe extern "C" fn() -> *const c_char;

#[unsafe(no_mangle)]
pub static mut __rustld_dlsym_entry: DlsymEntry = __rustld_dlsym_entry_impl;

#[unsafe(no_mangle)]
pub static mut __rustld_dlvsym_entry: DlvsymEntry = __rustld_dlvsym_entry_impl;

#[unsafe(no_mangle)]
pub static mut __rustld_dlopen_entry: DlopenEntry = __rustld_dlopen_entry_impl;

#[unsafe(no_mangle)]
pub static mut __rustld_dlclose_entry: DlcloseEntry = __rustld_dlclose_entry_impl;

#[unsafe(no_mangle)]
pub static mut __rustld_dlerror_entry: DlerrorEntry = __rustld_dlerror_entry_impl;

#[unsafe(no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn __rustld_dlsym_entry_impl(
    handle: *mut c_void,
    name: *const u8,
) -> *mut c_void {
    let resolved = dlsym_impl(handle, name);
    #[cfg(debug_assertions)]
    {
        log_dl_symbol("dlsym", name, resolved as usize);
    }
    resolved
}

#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn dlsym(handle: *mut c_void, name: *const u8) -> *mut c_void {
    let entry = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(__rustld_dlsym_entry)) };
    unsafe { entry(handle, name) }
}

#[unsafe(no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn __rustld_dlvsym_entry_impl(
    handle: *mut c_void,
    name_ptr: *const u8,
    version_ptr: *const u8,
) -> *mut c_void {
    let resolved = if version_ptr.is_null() {
        dlsym_impl(handle, name_ptr)
    } else {
        let name = c_string(name_ptr, 512);
        let version = c_string(version_ptr, 128);
        if let (Some(name), Some(ver)) = (name, version) {
            let resolved = resolve_symbol_with_version(handle, name, ver)
                .or_else(|| resolve_symbol_for_handle(handle, name))
                .unwrap_or(core::ptr::null_mut());
            log_suspicious_runtime_symbol("dlvsym", name, resolved as usize);
            resolved
        } else {
            dlsym_impl(handle, name_ptr)
        }
    };
    #[cfg(debug_assertions)]
    {
        log_dl_symbol("dlvsym", name_ptr, resolved as usize);
    }
    resolved
}

#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn dlvsym(handle: *mut c_void, name: *const u8, version: *const u8) -> *mut c_void {
    let entry = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(__rustld_dlvsym_entry)) };
    unsafe { entry(handle, name, version) }
}

#[unsafe(no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn __rustld_dlopen_entry_impl(file: *const u8, mode: i32) -> *mut c_void {
    #[cfg(debug_assertions)]
    {
        log_dl_symbol("dlopen", file, 0);
    }
    dlopen_impl(file, mode)
}

#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn dlopen(file: *const u8, mode: i32) -> *mut c_void {
    let entry = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(__rustld_dlopen_entry)) };
    unsafe { entry(file, mode) }
}

#[unsafe(no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn __rustld_dlclose_entry_impl(_handle: *mut c_void) -> i32 {
    clear_dlerror();
    1
}

#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn dlclose(handle: *mut c_void) -> i32 {
    let entry = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(__rustld_dlclose_entry)) };
    unsafe { entry(handle) }
}

#[unsafe(no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn __rustld_dlerror_entry_impl() -> *const c_char {
    unsafe {
        if DLERROR_PENDING {
            DLERROR_PENDING = false;
            core::ptr::addr_of!(DLERROR_BUF).cast::<c_char>()
        } else {
            core::ptr::null()
        }
    }
}

#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn dlerror() -> *const c_char {
    let entry = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(__rustld_dlerror_entry)) };
    unsafe { entry() }
}

#[repr(C)]
struct DlPhdrInfo {
    dlpi_addr: usize,
    dlpi_name: *const c_char,
    dlpi_phdr: *const ProgramHeader,
    dlpi_phnum: u16,
    dlpi_adds: u64,
    dlpi_subs: u64,
    dlpi_tls_modid: usize,
    dlpi_tls_data: *mut c_void,
}

type DlIteratePhdrCallback = extern "C" fn(*mut c_void, usize, *mut c_void) -> i32;

#[unsafe(no_mangle)]
pub extern "C" fn dl_iterate_phdr(
    callback: Option<DlIteratePhdrCallback>,
    data: *mut c_void,
) -> i32 {
    const EMPTY_NAME: *const c_char = b"\0".as_ptr().cast::<c_char>();

    let Some(callback) = callback else {
        return 0;
    };

    let _guard = lock_rtld_ops();
    let linker = unsafe { linking::active_linker() };
    let Some(linker) = linker else {
        return 0;
    };

    // Use stable names so callbacks may retain dlpi_name pointers after return.
    let dlpi_adds = linker.objects.len() as u64;

    for idx in 0..linker.objects.len() {
        let object = &linker.objects[idx];
        let ehdr = object.map_start as *const ElfHeader;
        if ehdr.is_null() {
            continue;
        }

        let ident = unsafe { (*ehdr).e_ident };
        if ident[..4] != [0x7f, b'E', b'L', b'F'] {
            continue;
        }

        let phdr =
            object.map_start.wrapping_add(unsafe { (*ehdr).e_phoff }) as *const ProgramHeader;
        let phnum = unsafe { (*ehdr).e_phnum };
        if phdr.is_null() || phnum == 0 {
            continue;
        }

        let name_ptr = if idx == 0 {
            EMPTY_NAME
        } else {
            let ptr = linker.object_link_map_name_ptr(idx);
            if ptr.is_null() {
                EMPTY_NAME
            } else {
                ptr
            }
        };

        let tls_modid = object.tls.map(|tls| tls.module_id).unwrap_or(0);
        let mut info = DlPhdrInfo {
            dlpi_addr: object.base,
            dlpi_name: name_ptr,
            dlpi_phdr: phdr,
            dlpi_phnum: phnum,
            dlpi_adds,
            dlpi_subs: 0,
            dlpi_tls_modid: tls_modid,
            dlpi_tls_data: core::ptr::null_mut(),
        };

        let result = callback(
            core::ptr::addr_of_mut!(info).cast(),
            size_of::<DlPhdrInfo>(),
            data,
        );
        if result != 0 {
            return result;
        }
    }

    0
}

#[repr(C)]
pub(crate) struct DlInfo {
    dli_fname: *const c_char,
    dli_fbase: *mut c_void,
    dli_sname: *const c_char,
    dli_saddr: *mut c_void,
}

const RTLD_DL_SYMENT: i32 = 1;
const RTLD_DL_LINKMAP: i32 = 2;

unsafe fn resolve_dladdr(addr: usize, info: *mut DlInfo) -> Option<(usize, *const Symbol)> {
    if info.is_null() {
        return None;
    }

    let linker = linking::active_linker()?;
    let index = linker.object_for_address(addr)?;
    let object = linker.objects.get(index)?;

    let mut symbol_name_ptr = core::ptr::null::<c_char>();
    let mut symbol_addr = core::ptr::null_mut();
    let mut symbol_ptr = core::ptr::null();
    let mut best_match = 0usize;

    let symbol_table_ptr = object.symbol_table.as_ptr();
    if !symbol_table_ptr.is_null() && object.symbol_count != 0 {
        for sym_idx in 0..object.symbol_count {
            let sym_ptr = symbol_table_ptr.add(sym_idx);
            let sym = *sym_ptr;
            if sym.st_name == 0 || sym.st_shndx == 0 {
                continue;
            }

            let sym_base = if sym.st_shndx == SHN_ABS {
                0
            } else {
                object.base
            };
            let sym_start = sym_base.wrapping_add(sym.st_value);
            let matches = if sym.st_size == 0 {
                addr == sym_start
            } else {
                let sym_end = sym_start.wrapping_add(sym.st_size);
                addr >= sym_start && addr < sym_end
            };
            if !matches || sym_start < best_match {
                continue;
            }

            let sym_name = object.string_table.get_bytes(sym.st_name as usize);
            if sym_name.is_empty() {
                continue;
            }

            best_match = sym_start;
            symbol_name_ptr = sym_name.as_ptr().cast::<c_char>();
            symbol_addr = sym_start as *mut c_void;
            symbol_ptr = sym_ptr;
        }
    }

    let mut file_name = linker.object_link_map_name_ptr(index);
    if file_name.is_null() {
        file_name = b"\0".as_ptr().cast::<c_char>();
    }

    (*info).dli_fname = file_name;
    (*info).dli_fbase = object.base as *mut c_void;
    (*info).dli_sname = symbol_name_ptr;
    (*info).dli_saddr = symbol_addr;

    Some((index, symbol_ptr))
}

#[no_mangle]
pub extern "C" fn dladdr(addr: *const c_void, info: *mut DlInfo) -> i32 {
    if addr.is_null() || info.is_null() {
        return 0;
    }

    let _guard = lock_rtld_ops();
    unsafe {
        core::ptr::write_bytes(info.cast::<u8>(), 0, size_of::<DlInfo>());
        resolve_dladdr(addr as usize, info).is_some() as i32
    }
}

#[no_mangle]
pub extern "C" fn dladdr1(
    addr: *const c_void,
    info: *mut DlInfo,
    extra_info: *mut *mut c_void,
    flags: i32,
) -> i32 {
    if addr.is_null() || info.is_null() {
        return 0;
    }

    let _guard = lock_rtld_ops();
    unsafe {
        core::ptr::write_bytes(info.cast::<u8>(), 0, size_of::<DlInfo>());
        let Some((index, sym_ptr)) = resolve_dladdr(addr as usize, info) else {
            if !extra_info.is_null() {
                *extra_info = core::ptr::null_mut();
            }
            return 0;
        };

        if !extra_info.is_null() {
            *extra_info = match flags {
                RTLD_DL_LINKMAP => linking::active_linker()
                    .map(|linker| linker.object_link_map_ptr(index))
                    .unwrap_or(core::ptr::null_mut()),
                RTLD_DL_SYMENT => sym_ptr.cast_mut().cast::<c_void>(),
                _ => core::ptr::null_mut(),
            };
        }

        1
    }
}

fn clear_dlerror() {
    unsafe {
        DLERROR_PENDING = false;
    }
}

fn set_dlerror(msg: &str) {
    unsafe {
        let bytes = msg.as_bytes();
        let n = bytes.len().min(DLERROR_BUF_SIZE.saturating_sub(1));
        if n != 0 {
            core::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                core::ptr::addr_of_mut!(DLERROR_BUF).cast::<u8>(),
                n,
            );
        }
        core::ptr::write(core::ptr::addr_of_mut!(DLERROR_BUF).cast::<u8>().add(n), 0);
        DLERROR_PENDING = true;
    }
}

#[inline(never)]
fn c_string<'a>(ptr: *const u8, max_len: usize) -> Option<&'a str> {
    if ptr.is_null() || max_len == 0 {
        return None;
    }

    let mut idx = 0usize;
    while idx < max_len {
        let ch = unsafe { core::ptr::read_volatile(ptr.add(idx)) };
        if ch == 0 {
            break;
        }
        idx += 1;
    }

    // Reject empty strings and unterminated buffers.
    if idx == 0 || idx >= max_len {
        return None;
    }

    let bytes = unsafe { core::slice::from_raw_parts(ptr, idx) };
    core::str::from_utf8(bytes).ok()
}

#[inline(never)]
unsafe fn resolve_symbol_with_version(
    handle: *mut c_void,
    name: &str,
    version: &str,
) -> Option<*mut c_void> {
    let mut combined = [0u8; 768];
    let required = name.len().saturating_add(1).saturating_add(version.len());
    if required == 0 || required > combined.len() {
        return None;
    }

    let mut cursor = 0usize;
    combined[cursor..cursor + name.len()].copy_from_slice(name.as_bytes());
    cursor += name.len();
    combined[cursor] = b'@';
    cursor += 1;
    combined[cursor..cursor + version.len()].copy_from_slice(version.as_bytes());
    cursor += version.len();

    let Ok(combined_name) = core::str::from_utf8(&combined[..cursor]) else {
        return None;
    };
    resolve_symbol_for_handle(handle, combined_name)
}

const HANDLE_GLOBAL_SCOPE: usize = 1;
const HANDLE_OBJECT_BIAS: usize = 2;

enum DlHandle {
    GlobalScope,
    NextScope,
    Object(usize),
}

fn encode_global_handle() -> *mut c_void {
    HANDLE_GLOBAL_SCOPE as *mut c_void
}

fn encode_object_handle(idx: usize) -> *mut c_void {
    if let Some(linker) = unsafe { linking::active_linker() } {
        let map = linker.object_link_map_ptr(idx);
        if !map.is_null() {
            return map;
        }
    }
    // Backward-compatible fallback if no link_map is available.
    idx.wrapping_add(HANDLE_OBJECT_BIAS) as *mut c_void
}

fn decode_handle(handle: *mut c_void) -> Option<DlHandle> {
    let raw = handle as usize;
    if raw == 0 {
        // RTLD_DEFAULT (NULL): search global scope.
        return None;
    }
    if raw == usize::MAX {
        // RTLD_NEXT ((void*)-1): search from the next object in scope.
        return Some(DlHandle::NextScope);
    }
    if raw == HANDLE_GLOBAL_SCOPE {
        return Some(DlHandle::GlobalScope);
    }

    // Preferred encoding: real link_map pointer (glibc-compatible).
    if let Some(linker) = unsafe { linking::active_linker() } {
        if let Some(idx) = linker.object_index_for_link_map_ptr(handle.cast_const()) {
            return Some(DlHandle::Object(idx));
        }

        // Legacy synthetic integer handles from older builds.
        if let Some(idx) = raw.checked_sub(HANDLE_OBJECT_BIAS) {
            if idx < linker.objects.len() {
                return Some(DlHandle::Object(idx));
            }
        }
    }

    None
}

#[inline(never)]
unsafe fn resolve_symbol_for_handle(handle: *mut c_void, name: &str) -> Option<*mut c_void> {
    let resolve_global = |exclude: Option<usize>| {
        let linker = linking::active_linker()?;
        let resolve_name = |candidate: &str| {
            linker
                .lookup_symbol_excluding(candidate, exclude)
                .map(|(obj_idx, symbol)| {
                    let base = if symbol.st_shndx == SHN_ABS {
                        0
                    } else {
                        linker.get_base(obj_idx)
                    };
                    base.wrapping_add(symbol.st_value) as *mut c_void
                })
        };
        resolve_name(name).or_else(|| {
            name.split_once('@')
                .and_then(|(base_name, _)| resolve_name(base_name))
        })
    };

    match decode_handle(handle) {
        Some(DlHandle::GlobalScope) => {
            linking::lookup_active_symbol(name).map(|addr| addr as *mut c_void)
        }
        Some(DlHandle::NextScope) => {
            // We do not know the exact caller object here. Skipping the
            // main executable approximates RTLD_NEXT well enough for common
            // interposer paths used by large apps (e.g. Firefox launcher).
            resolve_global(Some(0))
                .or_else(|| linking::lookup_active_symbol(name).map(|addr| addr as *mut c_void))
        }
        Some(DlHandle::Object(idx)) => {
            let resolve_in_object = |candidate: &str| {
                let linker = linking::active_linker()?;
                linker
                    .lookup_symbol_in_object_scope(idx, candidate)
                    .map(|addr| addr as *mut c_void)
            };
            if let Some(addr) = resolve_in_object(name).or_else(|| {
                name.split_once('@')
                    .and_then(|(base_name, _)| resolve_in_object(base_name))
            }) {
                return Some(addr);
            }
            None
        }
        None => linking::lookup_active_symbol(name).map(|addr| addr as *mut c_void),
    }
}

#[inline(never)]
fn dlsym_impl(handle: *mut c_void, name_ptr: *const u8) -> *mut c_void {
    let _guard = lock_rtld_ops();
    clear_dlerror();
    let Some(name) = c_string(name_ptr, 512) else {
        set_dlerror("rustld: dlsym invalid symbol name");
        return core::ptr::null_mut();
    };

    unsafe {
        if let Some(addr) = resolve_symbol_for_handle(handle, &name) {
            log_suspicious_runtime_symbol("dlsym", &name, addr as usize);
            return addr;
        }
    }

    set_dlerror("rustld: dlsym symbol not found");
    core::ptr::null_mut()
}

fn log_suspicious_runtime_symbol(api: &str, name: &str, resolved: usize) {
    #[cfg(not(debug_assertions))]
    {
        let _ = (api, name, resolved);
        return;
    }

    #[cfg(debug_assertions)]
    unsafe {
        use crate::libc::fs::write;

        if let Some(linker) = linking::active_linker() {
            for (idx, object) in linker.objects.iter().enumerate() {
                let base = object.base;
                if resolved >= base && resolved.wrapping_sub(base) < 0x100 {
                    write::write_str(write::STD_ERR, "rustld: suspicious ");
                    write::write_str(write::STD_ERR, api);
                    write::write_str(write::STD_ERR, " ");
                    write::write_str(write::STD_ERR, name);
                    write::write_str(write::STD_ERR, " -> ");
                    write_hex(resolved);
                    write::write_str(write::STD_ERR, " object=");

                    let mut idx_buf = [0u8; 32];
                    let mut value = idx;
                    let mut len = 0usize;
                    if value == 0 {
                        idx_buf[0] = b'0';
                        len = 1;
                    } else {
                        while value > 0 {
                            idx_buf[len] = b'0' + (value % 10) as u8;
                            value /= 10;
                            len += 1;
                        }
                    }
                    for i in 0..len / 2 {
                        idx_buf.swap(i, len - 1 - i);
                    }
                    let idx_text = core::str::from_utf8_unchecked(&idx_buf[..len]);
                    write::write_str(write::STD_ERR, idx_text);

                    write::write_str(write::STD_ERR, " base=");
                    write_hex(base);
                    write::write_str(write::STD_ERR, "\n");
                    break;
                }
            }
        }
    }
}

#[inline(never)]
fn dlopen_impl(file_ptr: *const u8, _mode: i32) -> *mut c_void {
    let _guard = lock_rtld_ops();
    clear_dlerror();

    if file_ptr.is_null() {
        // glibc returns a handle for the main program on dlopen(NULL, ...).
        if let Some(linker) = unsafe { linking::active_linker() } {
            let main_map = linker.object_link_map_ptr(0);
            if !main_map.is_null() {
                return main_map;
            }
        }
        return encode_global_handle();
    }

    let Some(file) = c_string(file_ptr, 4096) else {
        set_dlerror("rustld: dlopen invalid file name");
        return core::ptr::null_mut();
    };

    let linker = unsafe { linking::active_linker_mut() };
    let Some(linker) = linker else {
        set_dlerror("rustld: dlopen no active linker");
        return core::ptr::null_mut();
    };

    #[cfg(debug_assertions)]
    {
        use crate::libc::fs::write;
        unsafe {
            write::write_str(write::STD_ERR, "ld_stub: dlopen request ");
            write::write_str(write::STD_ERR, &file);
            write::write_str(write::STD_ERR, "\n");
        }
        if let Some(idx) = linker.loaded_index(&file) {
            unsafe {
                write::write_str(write::STD_ERR, "ld_stub: dlopen already loaded idx=");
            }
            let mut buf = [0u8; 32];
            let mut n = idx;
            let mut len = 0usize;
            if n == 0 {
                buf[0] = b'0';
                len = 1;
            } else {
                while n > 0 {
                    buf[len] = b'0' + (n % 10) as u8;
                    n /= 10;
                    len += 1;
                }
                buf[..len].reverse();
            }
            unsafe {
                write::write_str(
                    write::STD_ERR,
                    core::str::from_utf8(&buf[..len]).unwrap_or("?"),
                );
                write::write_str(write::STD_ERR, "\n");
            }
        } else {
            unsafe {
                write::write_str(write::STD_ERR, "ld_stub: dlopen not in map yet\n");
            }
        }
    }

    let result = unsafe { linker.dlopen_runtime(&file, _mode) };
    match result {
        Ok(idx) => encode_object_handle(idx),
        Err(msg) => {
            set_dlerror(msg);
            core::ptr::null_mut()
        }
    }
}

type RtldDlopenDispatch = extern "C" fn(*const u8, i32) -> *mut c_void;
type RtldLookupDispatch = extern "C" fn(*const u8, usize, usize, *mut *const c_void) -> *mut c_void;

#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn __rustld_rtld_dlopen_dispatch_impl(file: *const u8, mode: i32) -> *mut c_void {
    let entry = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(__rustld_dlopen_entry)) };
    unsafe { entry(file, mode) }
}

#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn __rustld_rtld_lookup_dispatch_impl(
    undef_name: *const u8,
    undef_map_raw: usize,
    skip_map_raw: usize,
    reference: *mut *const c_void,
) -> *mut c_void {
    let _guard = lock_rtld_ops();
    if let Some(name) = c_string(undef_name, 512) {
        unsafe {
            if let Some(linker) = linking::active_linker() {
                let requester_idx =
                    linker.object_index_for_link_map_ptr(undef_map_raw as *const c_void);
                let skip_idx = linker.object_index_for_link_map_ptr(skip_map_raw as *const c_void);
                let resolve = |candidate: &str| {
                    if let Some(requester) = requester_idx {
                        linker.lookup_symbol_for_object_excluding(requester, candidate, skip_idx)
                    } else {
                        linker.lookup_symbol_excluding(candidate, skip_idx)
                    }
                };

                let mut matched_name = name;
                let resolved = if let Some(found) = resolve(matched_name) {
                    Some(found)
                } else if let Some((base_name, _)) = name.split_once('@') {
                    matched_name = base_name;
                    resolve(base_name)
                } else {
                    None
                };

                if let Some((obj_idx, symbol)) = resolved {
                    let base = if symbol.st_shndx == SHN_ABS {
                        0
                    } else {
                        linker.get_base(obj_idx)
                    };
                    RTLD_LOOKUP_MAP.l_addr = base;
                    RTLD_LOOKUP_MAP.l_name = linker.object_link_map_name_ptr(obj_idx);
                    RTLD_LOOKUP_MAP.l_ld = linker.objects[obj_idx].dynamic.cast::<u8>();
                    let map_ptr = linker.object_link_map_ptr(obj_idx);
                    let sym_ptr = linker
                        .lookup_symbol_entry_ptr_in_object(obj_idx, matched_name)
                        .unwrap_or_else(|| {
                            core::ptr::write(
                                core::ptr::addr_of_mut!(RTLD_LOOKUP_SYMBOL).cast::<Symbol>(),
                                symbol,
                            );
                            core::ptr::addr_of!(RTLD_LOOKUP_SYMBOL).cast::<Symbol>()
                        });

                    if !reference.is_null() {
                        *reference = sym_ptr.cast();
                    }
                    return map_ptr;
                }
            }
        }
    }

    if !reference.is_null() {
        unsafe { *reference = core::ptr::null() };
    }
    core::ptr::null_mut()
}

#[unsafe(no_mangle)]
pub static mut __rustld_rtld_dlopen_dispatch: RtldDlopenDispatch =
    __rustld_rtld_dlopen_dispatch_impl;

#[unsafe(no_mangle)]
pub static mut __rustld_rtld_lookup_dispatch: RtldLookupDispatch =
    __rustld_rtld_lookup_dispatch_impl;

#[cfg(debug_assertions)]
fn log_dl_symbol(prefix: &str, symbol: *const u8, resolved: usize) {
    use core::str;
    unsafe {
        write::write_str(write::STD_ERR, "ld_stub: ");
        write::write_str(write::STD_ERR, prefix);
        write::write_str(write::STD_ERR, " ");
    }
    if symbol.is_null() {
        unsafe { write::write_str(write::STD_ERR, "<null>\n") };
        return;
    }

    let mut len = 0usize;
    while len < 128 {
        let byte = unsafe { *symbol.add(len) };
        if byte == 0 {
            break;
        }
        len += 1;
    }
    if len == 0 {
        unsafe { write::write_str(write::STD_ERR, "<empty>\n") };
        return;
    }

    let bytes = unsafe { core::slice::from_raw_parts(symbol, len) };
    if let Ok(text) = str::from_utf8(bytes) {
        unsafe {
            write::write_str(write::STD_ERR, text);
            write::write_str(write::STD_ERR, " -> ");
            write_hex(resolved);
            write::write_str(write::STD_ERR, "\n");
        }
    } else {
        unsafe { write::write_str(write::STD_ERR, "<non-utf8>\n") };
    }
}

#[cfg(debug_assertions)]
unsafe fn write_hex(mut value: usize) {
    let mut buf = [0u8; 18];
    buf[0] = b'0';
    buf[1] = b'x';
    let hex = b"0123456789abcdef";
    for i in (0..16).rev() {
        buf[2 + i] = hex[value & 0xF];
        value >>= 4;
    }
    write::write_str(write::STD_ERR, core::str::from_utf8_unchecked(&buf));
}

#[no_mangle]
pub extern "C" fn freecon(_con: *mut u8) {
    // Optional SELinux path in coreutils; treat as unavailable.
}

#[no_mangle]
pub extern "C" fn is_selinux_enabled() -> i32 {
    // Report SELinux as unavailable for portability in constrained loaders.
    0
}

#[no_mangle]
pub extern "C" fn getcon(con: *mut *mut u8) -> i32 {
    if !con.is_null() {
        unsafe { *con = core::ptr::null_mut() };
    }
    -1
}

#[no_mangle]
pub extern "C" fn getfilecon(_path: *const u8, con: *mut *mut u8) -> i32 {
    if !con.is_null() {
        unsafe { *con = core::ptr::null_mut() };
    }
    -1
}

#[no_mangle]
pub extern "C" fn lgetfilecon(_path: *const u8, con: *mut *mut u8) -> i32 {
    if !con.is_null() {
        unsafe { *con = core::ptr::null_mut() };
    }
    -1
}

#[no_mangle]
pub extern "C" fn getfilecon_raw(_path: *const u8, con: *mut *mut u8) -> i32 {
    if !con.is_null() {
        unsafe { *con = core::ptr::null_mut() };
    }
    -1
}

#[no_mangle]
pub extern "C" fn lgetfilecon_raw(_path: *const u8, con: *mut *mut u8) -> i32 {
    if !con.is_null() {
        unsafe { *con = core::ptr::null_mut() };
    }
    -1
}

#[no_mangle]
pub extern "C" fn fgetfilecon_raw(_fd: i32, con: *mut *mut u8) -> i32 {
    if !con.is_null() {
        unsafe { *con = core::ptr::null_mut() };
    }
    -1
}

#[no_mangle]
pub extern "C" fn setfilecon_raw(_path: *const u8, _con: *const u8) -> i32 {
    -1
}

#[no_mangle]
pub extern "C" fn lsetfilecon_raw(_path: *const u8, _con: *const u8) -> i32 {
    -1
}

#[no_mangle]
pub extern "C" fn fsetfilecon_raw(_fd: i32, _con: *const u8) -> i32 {
    -1
}

#[no_mangle]
pub extern "C" fn selabel_lookup(
    _handle: *mut c_void,
    con: *mut *mut u8,
    _key: *const u8,
    _ty: i32,
) -> i32 {
    if !con.is_null() {
        unsafe { *con = core::ptr::null_mut() };
    }
    -1
}

#[no_mangle]
pub extern "C" fn selabel_lookup_raw(
    _handle: *mut c_void,
    con: *mut *mut u8,
    _key: *const u8,
    _ty: i32,
) -> i32 {
    if !con.is_null() {
        unsafe { *con = core::ptr::null_mut() };
    }
    -1
}

#[no_mangle]
pub extern "C" fn selabel_lookup_best_match(
    _handle: *mut c_void,
    con: *mut *mut u8,
    _key: *const u8,
    _aliases: *const *const u8,
    _ty: i32,
) -> i32 {
    if !con.is_null() {
        unsafe { *con = core::ptr::null_mut() };
    }
    -1
}

#[no_mangle]
pub extern "C" fn selabel_lookup_best_match_raw(
    _handle: *mut c_void,
    con: *mut *mut u8,
    _key: *const u8,
    _aliases: *const *const u8,
    _ty: i32,
) -> i32 {
    if !con.is_null() {
        unsafe { *con = core::ptr::null_mut() };
    }
    -1
}

#[no_mangle]
pub extern "C" fn _dl_find_dso_for_object(addr: *const ()) -> *const () {
    if addr.is_null() {
        return core::ptr::null();
    }

    let _guard = lock_rtld_ops();
    let linker = unsafe { linking::active_linker() };
    let Some(linker) = linker else {
        return core::ptr::null();
    };

    if let Some(index) = linker.object_for_address(addr as usize) {
        let link_map_ptr = linker.object_link_map_ptr(index);
        return link_map_ptr.cast();
    }
    core::ptr::null()
}

#[no_mangle]
pub extern "C" fn _dl_find_object(_addr: *const c_void, result: *mut DlFindObject) -> i32 {
    if _addr.is_null() || result.is_null() {
        return -1;
    }

    unsafe {
        core::ptr::write_bytes(result.cast::<u8>(), 0, size_of::<DlFindObject>());
    }

    let _guard = lock_rtld_ops();
    let linker = unsafe { linking::active_linker() };
    let Some(linker) = linker else {
        return -1;
    };

    let Some(index) = linker.object_for_address(_addr as usize) else {
        return -1;
    };

    let Some((map_start, map_end)) = linker.object_mapping_range_for_address(index, _addr as usize)
    else {
        return -1;
    };

    unsafe {
        (*result).dlfo_flags = 0;
        (*result).dlfo_map_start = map_start as *mut c_void;
        (*result).dlfo_map_end = map_end as *mut c_void;
        (*result).dlfo_link_map = linker.object_link_map_ptr(index);
        (*result).dlfo_eh_frame = linker
            .object_eh_frame_hdr(index)
            .unwrap_or(core::ptr::null()) as *mut c_void;
        (*result).dlfo_sframe = core::ptr::null_mut();
    }
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn __rustld_debug_addr_object(
    addr: usize,
    out_index: *mut usize,
    out_map_start: *mut usize,
    out_map_end: *mut usize,
) -> *const c_char {
    let _guard = lock_rtld_ops();
    let Some(linker) = (unsafe { linking::active_linker() }) else {
        return core::ptr::null();
    };
    let Some(index) = linker.object_for_address(addr) else {
        return core::ptr::null();
    };

    if !out_index.is_null() {
        unsafe { *out_index = index };
    }
    if !out_map_start.is_null() || !out_map_end.is_null() {
        if let Some((start, end)) = linker.object_mapping_range_for_address(index, addr) {
            if !out_map_start.is_null() {
                unsafe { *out_map_start = start };
            }
            if !out_map_end.is_null() {
                unsafe { *out_map_end = end };
            }
        }
    }
    linker.object_link_map_name_ptr(index)
}

#[unsafe(no_mangle)]
pub extern "C" fn __rustld_debug_addr_object_index(addr: usize) -> isize {
    let _guard = lock_rtld_ops();
    let Some(linker) = (unsafe { linking::active_linker() }) else {
        return -1;
    };
    linker
        .object_for_address(addr)
        .map(|idx| idx as isize)
        .unwrap_or(-1)
}

#[unsafe(no_mangle)]
pub extern "C" fn __rustld_debug_addr_object_map_start(addr: usize) -> usize {
    let _guard = lock_rtld_ops();
    let Some(linker) = (unsafe { linking::active_linker() }) else {
        return 0;
    };
    let Some(index) = linker.object_for_address(addr) else {
        return 0;
    };
    linker
        .object_mapping_range_for_address(index, addr)
        .map(|(start, _)| start)
        .unwrap_or(0)
}

#[unsafe(no_mangle)]
pub extern "C" fn __rustld_debug_addr_object_map_end(addr: usize) -> usize {
    let _guard = lock_rtld_ops();
    let Some(linker) = (unsafe { linking::active_linker() }) else {
        return 0;
    };
    let Some(index) = linker.object_for_address(addr) else {
        return 0;
    };
    linker
        .object_mapping_range_for_address(index, addr)
        .map(|(_, end)| end)
        .unwrap_or(0)
}

#[no_mangle]
pub extern "C" fn _dl_allocate_tls(_mem: *mut ()) -> *mut () {
    // Allocate TLS/TCB for a new thread.
    // This is required for glibc pthread startup paths that expect a non-null DTV.
    unsafe {
        __rustld_last_alloc_tls_enter = _mem;
    }
    unsafe {
        // When glibc passes a preallocated thread descriptor buffer, initialize
        // TLS in-place. pthread startup paths continue to use this pointer as TP.
        if !_mem.is_null() {
            if let Some(initialized) = tls::initialize_tls_for_thread_ptr(_mem) {
                let result = initialized.cast();
                __rustld_last_alloc_tls_ret = result;
                return result;
            }
        }

        // Fallback for callers that do not provide a thread descriptor buffer.
        if let Some(tcb) = tls::allocate_tls_for_new_thread() {
            let result = tcb.cast();
            __rustld_last_alloc_tls_ret = result;
            return result;
        }
        __rustld_last_alloc_tls_ret = core::ptr::null_mut();
    }
    core::ptr::null_mut()
}

#[no_mangle]
pub extern "C" fn _dl_allocate_tls_init(tcb: *mut (), _main_thread: usize) -> *mut () {
    // glibc may call this after mutating thread-descriptor fields. Re-apply
    // our TLS/TCB setup so fs:tcb/dtv/self pointers remain valid.
    unsafe {
        __rustld_last_alloc_tls_init_arg = tcb;
        if !tcb.is_null() {
            if let Some(initialized) = tls::initialize_tls_for_thread_ptr(tcb) {
                let current_tp = get_thread_pointer() as *mut ThreadControlBlock;
                if !current_tp.is_null() && current_tp == initialized {
                    tls::stamp_thread_tid(initialized);
                }
                let result = initialized.cast();
                __rustld_last_alloc_tls_init_ret = result;
                return result;
            }
        }
        let current_tp = get_thread_pointer();
        if !current_tp.is_null() && current_tp == tcb {
            tls::stamp_thread_tid(current_tp.cast());
        }
        __rustld_last_alloc_tls_init_ret = tcb;
    }
    tcb
}

#[no_mangle]
pub extern "C" fn _dl_deallocate_tls(_tcb: *mut (), _dealloc_tcb: usize) {
    tls::unregister_thread_tcb(_tcb as *mut ThreadControlBlock);
}

#[no_mangle]
pub extern "C" fn _dl_debug_state() {}

pub unsafe fn set_r_debug_map(map: *mut c_void) {
    _r_debug.r_map = map;
}

pub unsafe fn set_r_debug_ldbase(ldbase: usize) {
    _r_debug.r_ldbase = ldbase;
}

pub unsafe fn r_debug_ptr() -> *mut c_void {
    core::ptr::addr_of_mut!(_r_debug).cast()
}

#[no_mangle]
pub extern "C" fn _dl_signal_error(
    _errcode: i32,
    _objname: *const c_char,
    _errstring: *const c_char,
) {
    let tid = current_tid();
    let frame_ptr = unsafe { catch_error_get_top(tid) };
    if frame_ptr.is_null() {
        return;
    }
    unsafe {
        let frame = &mut *frame_ptr;
        frame.errcode = _errcode;
        if !frame.objname.is_null() {
            *frame.objname = _objname;
        }
        if !frame.errstring.is_null() {
            *frame.errstring = _errstring;
        }
        if !frame.mallocedp.is_null() {
            *frame.mallocedp = 0;
        }
        // Avoid keeping rtld lock held across non-local jump.
        force_unlock_rtld_ops_if_owned_by_current_thread();
        siglongjmp(core::ptr::addr_of_mut!(frame.env), 1);
    }
}

#[no_mangle]
pub extern "C" fn _dl_signal_exception(_errcode: i32, _exception: *const ()) {
    static MSG: &[u8] = b"rustld: rtld exception\0";
    _dl_signal_error(_errcode, core::ptr::null(), MSG.as_ptr().cast::<c_char>());
}

#[no_mangle]
pub extern "C" fn _dl_catch_exception(
    _exception: *mut (),
    operate: *const (),
    args: *const (),
) -> i32 {
    let exception = _exception as *mut DlException;
    if !exception.is_null() {
        unsafe {
            core::ptr::write_bytes(exception as *mut u8, 0, core::mem::size_of::<DlException>());
        }
    }

    let mut frame = CatchErrorFrame {
        prev: core::ptr::null_mut(),
        env: SigJmpBuf {
            storage: [0; SIGJMP_WORDS],
        },
        objname: if exception.is_null() {
            core::ptr::null_mut()
        } else {
            unsafe { core::ptr::addr_of_mut!((*exception).objname) }
        },
        errstring: if exception.is_null() {
            core::ptr::null_mut()
        } else {
            unsafe { core::ptr::addr_of_mut!((*exception).errstring) }
        },
        mallocedp: core::ptr::null_mut(),
        errcode: 0,
    };
    let tid = current_tid();
    unsafe {
        frame.prev = catch_error_get_top(tid);
    }
    let frame_ptr: *mut CatchErrorFrame = core::ptr::addr_of_mut!(frame);
    unsafe {
        catch_error_set_top(tid, frame_ptr);
    }

    let jumped = unsafe { sigsetjmp(core::ptr::addr_of_mut!((*frame_ptr).env), 0) != 0 };
    if !jumped && !operate.is_null() {
        unsafe {
            let func: extern "C" fn(*mut c_void) = core::mem::transmute(operate);
            func(args as *mut c_void);
        }
    }
    unsafe {
        catch_error_restore_top(tid, frame_ptr, (*frame_ptr).prev);
    }
    if jumped {
        unsafe { (*frame_ptr).errcode }
    } else {
        0
    }
}

#[no_mangle]
pub extern "C" fn _dl_catch_error(
    objname: *mut *const c_char,
    errstring: *mut *const c_char,
    mallocedp: *mut i32,
    operate: *const (),
    args: *const (),
) -> i32 {
    __rustld_rtld_catch_error(
        objname,
        errstring,
        mallocedp,
        operate.cast(),
        args as *mut c_void,
    )
}

/// rtld_global_ro + 0x340: internal _dl_lookup_symbol_x entry point.
#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn __rustld_rtld_lookup_symbol_x_stub(
    undef_name_raw: usize,
    undef_map_raw: usize,
    reference_raw: usize,
    _symbol_scope: usize,
    _version: usize,
    _type_class: i32,
    _flags: i32,
    skip_map_raw: usize,
) -> *mut c_void {
    clear_dlerror();
    let undef_name = undef_name_raw as *const u8;
    let reference = reference_raw as *mut *const c_void;
    let dispatch =
        unsafe { core::ptr::read_volatile(core::ptr::addr_of!(__rustld_rtld_lookup_dispatch)) };
    dispatch(undef_name, undef_map_raw, skip_map_raw, reference)
}

/// rtld_global_ro + 0x348: internal dlopen entry point used by libc wrappers.
#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn __rustld_rtld_dlopen_stub(
    file_raw: usize,
    mode: i32,
    _caller: usize,
    _nsid: isize,
    _argc: i32,
    _argv: usize,
    _envp: usize,
) -> *mut c_void {
    clear_dlerror();
    let file = file_raw as *const u8;
    let dispatch =
        unsafe { core::ptr::read_volatile(core::ptr::addr_of!(__rustld_rtld_dlopen_dispatch)) };
    dispatch(file, mode)
}

/// rtld_global_ro + 0x350: internal dlclose entry point used by libc wrappers.
pub extern "C" fn __rustld_rtld_dlclose_stub(_map: *mut c_void) -> i32 {
    let entry = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(__rustld_dlclose_entry)) };
    unsafe { entry(_map) }
}

/// rtld_global_ro + 0x358: internal catch-error helper used by dlerror_run().
pub extern "C" fn __rustld_rtld_catch_error(
    objname: *mut *const c_char,
    errstring: *mut *const c_char,
    mallocedp: *mut i32,
    operate: *const c_void,
    args: *mut c_void,
) -> i32 {
    if !objname.is_null() {
        unsafe { *objname = core::ptr::null() };
    }
    if !errstring.is_null() {
        unsafe { *errstring = core::ptr::null() };
    }
    if !mallocedp.is_null() {
        unsafe { *mallocedp = 0 };
    }

    let mut frame = CatchErrorFrame {
        prev: core::ptr::null_mut(),
        env: SigJmpBuf {
            storage: [0; SIGJMP_WORDS],
        },
        objname,
        errstring,
        mallocedp,
        errcode: 0,
    };
    let tid = current_tid();
    frame.prev = unsafe { catch_error_get_top(tid) };
    let frame_ptr: *mut CatchErrorFrame = core::ptr::addr_of_mut!(frame);
    unsafe {
        catch_error_set_top(tid, frame_ptr);
    }

    let jumped = unsafe { sigsetjmp(core::ptr::addr_of_mut!((*frame_ptr).env), 0) != 0 };

    if !jumped && !operate.is_null() {
        unsafe {
            let op: extern "C" fn(*mut c_void) = core::mem::transmute(operate);
            op(args);
        }
    }

    unsafe {
        catch_error_restore_top(tid, frame_ptr, (*frame_ptr).prev);
    }

    if jumped {
        unsafe { (*frame_ptr).errcode }
    } else {
        0
    }
}

/// rtld_global_ro + 0x360: internal error-string free helper used by dlerror_run().
pub extern "C" fn __rustld_rtld_error_free(_errstring: *mut c_void) {}

#[no_mangle]
pub extern "C" fn _dl_audit_symbind_alt(
    _sym: *const (),
    _ndx: usize,
    _refcook: *const (),
    _defcook: *const (),
    _flags: *const (),
) -> usize {
    // Audit interface for symbol binding
    // Return 0 for now
    0
}

#[no_mangle]
pub extern "C" fn _dl_rtld_di_serinfo() -> *const () {
    // Returns information about loaded objects
    // Return null for now
    core::ptr::null()
}

#[no_mangle]
pub extern "C" fn __tunable_is_initialized(_id: usize) -> i32 {
    if let Some(addr) = unsafe { linking::lookup_active_symbol("__tunable_is_initialized") } {
        let self_addr = __tunable_is_initialized as usize;
        if addr != self_addr {
            unsafe {
                let func: extern "C" fn(usize) -> i32 = core::mem::transmute(addr);
                return func(_id);
            }
        }
    }
    0
}

#[no_mangle]
pub extern "C" fn __tunable_get_val(_id: usize, valp: *mut (), callback: *const ()) {
    if let Some(addr) = unsafe { linking::lookup_active_symbol("__tunable_get_val") } {
        let self_addr = __tunable_get_val as usize;
        if addr != self_addr {
            unsafe {
                let func: extern "C" fn(usize, *mut (), *const ()) = core::mem::transmute(addr);
                func(_id, valp, callback);
                return;
            }
        }
    }
    if valp.is_null() {
        return;
    }

    unsafe {
        match _id {
            // int32-like startup tunables observed via gdb.
            2 | 11 | 13 | 14 | 15 | 16 | 17 | 18 | 19 | 20 | 21 | 22 | 24 | 32 | 35 | 38 | 40 => {
                core::ptr::write_unaligned(valp.cast::<i32>(), 0);
            }
            // uint64-like startup tunables.
            4 | 10 => {
                core::ptr::write_unaligned(valp.cast::<u64>(), 0);
            }
            // size_t-like startup tunables.
            3 | 5 | 6 | 7 | 8 | 9 | 41 | 42 => {
                core::ptr::write_unaligned(valp.cast::<usize>(), 0);
            }
            _ => {}
        }
    }

    if !callback.is_null() {
        unsafe {
            let cb: extern "C" fn(*mut ()) = core::mem::transmute(callback);
            cb(valp);
        }
    }
}

#[no_mangle]
pub extern "C" fn __tls_get_addr(_ti: *const ()) -> *mut () {
    if _ti.is_null() {
        return core::ptr::null_mut();
    }

    let ti = _ti as *const TlsIndex;
    let module = unsafe { (*ti).ti_module };
    let offset = unsafe { (*ti).ti_offset };
    unsafe { tls::resolve_tls_address(module, offset).unwrap_or(0) as *mut () }
}
