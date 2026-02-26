use core::{
    mem::{align_of, size_of},
    ptr::null_mut,
    sync::atomic::{AtomicI32, Ordering},
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
}

static mut TLS_STATE: Option<TlsState> = None;
static mut TLS_LAYOUT: Option<TlsLayout> = None;
const MAX_TRACKED_THREADS: usize = 4096;
static THREAD_TRACK_LOCK: AtomicI32 = AtomicI32::new(0);
static mut TRACKED_THREADS: [*mut ThreadControlBlock; MAX_TRACKED_THREADS] =
    [null_mut(); MAX_TRACKED_THREADS];

#[inline(always)]
fn lock_thread_registry() {
    while THREAD_TRACK_LOCK
        .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        core::hint::spin_loop();
    }
}

#[inline(always)]
fn unlock_thread_registry() {
    THREAD_TRACK_LOCK.store(0, Ordering::Release);
}

fn register_thread_tcb(tcb: *mut ThreadControlBlock) {
    if tcb.is_null() {
        return;
    }
    lock_thread_registry();
    unsafe {
        let mut free_slot = None;
        for idx in 0..MAX_TRACKED_THREADS {
            let entry = TRACKED_THREADS[idx];
            if entry == tcb {
                unlock_thread_registry();
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
    unlock_thread_registry();
}

pub fn unregister_thread_tcb(tcb: *mut ThreadControlBlock) {
    if tcb.is_null() {
        return;
    }
    lock_thread_registry();
    unsafe {
        for idx in 0..MAX_TRACKED_THREADS {
            if TRACKED_THREADS[idx] == tcb {
                TRACKED_THREADS[idx] = null_mut();
                break;
            }
        }
    }
    unlock_thread_registry();
}

fn tracked_threads_snapshot() -> Vec<*mut ThreadControlBlock> {
    let mut threads = Vec::new();
    lock_thread_registry();
    unsafe {
        for idx in 0..MAX_TRACKED_THREADS {
            let tcb = TRACKED_THREADS[idx];
            if !tcb.is_null() {
                threads.push(tcb);
            }
        }
    }
    unlock_thread_registry();
    threads
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

#[derive(Clone, Copy)]
pub struct TlsLayout {
    pub tcb_offset: usize,
    pub tls_size: usize,
    pub module_count: usize,
    pub max_align: usize,
    pub runtime_static_start: usize,
    pub runtime_static_end: usize,
}

pub unsafe fn prepare_tls_layout(objects: &mut [SharedObject]) {
    // Reserve a small fixed window below TP so glibc's rseq scratch area
    // (TP-192..TP-160 on x86_64) does not overlap any module TLS bytes.
    // Keep this modest (not the old large surplus) to avoid startup regressions.
    const RSEQ_RESERVE_BYTES: usize = 256;
    const RUNTIME_STATIC_SURPLUS_BYTES: usize = 0;
    let mut module_id = 1usize;
    let mut max_align = align_of::<ThreadControlBlock>();

    for obj in objects.iter_mut() {
        if let Some(ref mut tls) = obj.tls {
            tls.module_id = module_id;
            module_id += 1;

            let align = tls.align.max(align_of::<usize>());
            if align > max_align {
                max_align = align;
            }
        }
    }

    if module_id == 1 {
        TLS_LAYOUT = None;
        return;
    }

    // Keep the main executable's TLS segment closest to TP among module
    // TLS blocks so fixed local-exec accesses in ET_DYN executables match
    // glibc expectations.
    let mut cursor = 0usize;

    for obj in objects.iter_mut().skip(1) {
        if let Some(ref mut tls) = obj.tls {
            let align = tls.align.max(align_of::<usize>());
            cursor = round_up_to_boundary(cursor, align);
            tls.block_offset = cursor;
            cursor += tls.memsz;
            #[cfg(debug_assertions)]
            {
                eprintln!(
                    "tls-layout: module={} align={} filesz={} memsz={} block_off={}",
                    tls.module_id, align, tls.filesz, tls.memsz, tls.block_offset
                );
            }
        }
    }

    if let Some(obj) = objects.get_mut(0) {
        if let Some(ref mut tls) = obj.tls {
            let align = tls.align.max(align_of::<usize>());
            cursor = round_up_to_boundary(cursor, align);
            tls.block_offset = cursor;
            cursor += tls.memsz;
            #[cfg(debug_assertions)]
            {
                eprintln!(
                    "tls-layout: module={} align={} filesz={} memsz={} block_off={}",
                    tls.module_id, align, tls.filesz, tls.memsz, tls.block_offset
                );
            }
        }
    }

    let runtime_static_start = cursor;
    cursor = cursor.saturating_add(RUNTIME_STATIC_SURPLUS_BYTES);
    let runtime_static_end = cursor;

    // Keep an unmixed reserve immediately below TP for glibc rseq scratch.
    cursor += RSEQ_RESERVE_BYTES;
    let tcb_offset = round_up_to_boundary(cursor, align_of::<ThreadControlBlock>());
    let tls_size = tcb_offset;

    for obj in objects.iter_mut() {
        if let Some(ref mut tls) = obj.tls {
            tls.offset = (tls.block_offset as isize).wrapping_sub(tls_size as isize);
            #[cfg(debug_assertions)]
            {
                eprintln!(
                    "tls-layout: module={} tp_offset={}",
                    tls.module_id, tls.offset
                );
            }
        }
    }

    TLS_LAYOUT = Some(TlsLayout {
        tcb_offset,
        tls_size,
        module_count: module_id - 1,
        max_align,
        runtime_static_start,
        runtime_static_end,
    });
}

pub unsafe fn install_tls(objects: &[SharedObject], pseudorandom_bytes: *const [u8; 16]) {
    let layout = match TLS_LAYOUT {
        Some(layout) => layout,
        None => return,
    };

    if layout.module_count == 0 {
        return;
    }

    let total_size = layout.tcb_offset + size_of::<ThreadControlBlock>() + layout.max_align;
    let raw = mmap(
        null_mut(),
        total_size,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );
    core::ptr::write_bytes(raw, 0, total_size);

    let tls_base = round_up_to_boundary(raw as usize, layout.max_align) as *mut u8;

    let mut modules = Vec::new();
    for obj in objects.iter() {
        if let Some(tls) = obj.tls {
            modules.push(TlsModuleTemplate {
                module_id: tls.module_id,
                init_image: tls.init_image,
                filesz: tls.filesz,
                memsz: tls.memsz,
                align: tls.align,
                block_offset: tls.block_offset,
                dynamic: false,
            });
        }
    }

    // Initialize module TLS data from each module's PT_TLS template.
    for module in modules.iter() {
        if module.dynamic {
            continue;
        }
        let dst = tls_base.add(module.block_offset);
        if module.filesz > 0 {
            core::ptr::copy_nonoverlapping(module.init_image, dst, module.filesz);
        }
        if module.memsz > module.filesz {
            core::ptr::write_bytes(dst.add(module.filesz), 0, module.memsz - module.filesz);
        }
    }

    let tcb = tls_base.add(layout.tcb_offset) as *mut ThreadControlBlock;

    // Allocate and populate the DTV.
    // glibc stores DTV capacity in dtv[-1], generation in dtv[0], and
    // module pointers in dtv[module_id].
    let module_slots = layout.module_count + 1;
    let dtv_len = (module_slots + DTV_SURPLUS_SLOTS).max(module_slots);
    let dtv_alloc_entries = dtv_len + 1; // +1 header slot for dtv[-1]
    let dtv_size = dtv_alloc_entries * size_of::<DtvEntry>();
    let dtv_raw = mmap(
        null_mut(),
        dtv_size,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    ) as *mut DtvEntry;
    core::ptr::write_bytes(dtv_raw.cast::<u8>(), 0, dtv_size);

    let dtv = dtv_raw.add(1);
    set_dtv_capacity(dtv, dtv_len);
    (*dtv).value = 1; // generation counter
    (*dtv).to_free = 0;

    for module in modules.iter() {
        if module.dynamic {
            if let Some(base) = allocate_tls_module_block(module) {
                (*dtv.add(module.module_id)).value = base;
                (*dtv.add(module.module_id)).to_free = 0;
            }
        } else {
            let base = (tls_base as usize).wrapping_add(module.block_offset);
            (*dtv.add(module.module_id)).value = base;
            (*dtv.add(module.module_id)).to_free = 0;
        }
    }

    let stack_guard = if !pseudorandom_bytes.is_null() {
        let random = &*pseudorandom_bytes;
        usize::from_ne_bytes(random[..size_of::<usize>()].try_into().unwrap())
    } else {
        0
    };
    let pointer_guard = if !pseudorandom_bytes.is_null() {
        let random = &*pseudorandom_bytes;
        usize::from_ne_bytes(
            random[size_of::<usize>()..(2 * size_of::<usize>())]
                .try_into()
                .unwrap(),
        )
    } else {
        0
    };

    *tcb = ThreadControlBlock {
        tcb,
        dtv: dtv.cast::<usize>(),
        self_ptr: tcb,
        multiple_threads: 0,
        gscope_flag: 0,
        sysinfo: 0,
        stack_guard,
        pointer_guard,
        vgetcpu_cache: [0; 2],
        __glibc_reserved1: 0,
        __glibc_unused1: 0,
        __private_tm: [null_mut(); 4],
        __private_ss: null_mut(),
        __glibc_reserved2: 0,
        _padding: [0; 2048],
    };

    // glibc keeps an internal per-thread key-block pointer at tp-0x28.
    // Keep it NULL for the initial thread; child-thread setup may copy
    // this area before lazy initialization kicks in.
    #[cfg(target_arch = "x86_64")]
    {
        let tsd_key_slot = (tcb as *mut u8).offset(GLIBC_TSD_KEY_BLOCK_OFFSET) as *mut usize;
        core::ptr::write_volatile(tsd_key_slot, 0);
    }

    set_thread_pointer(tcb.cast());
    initialize_glibc_thread_links(tcb);
    stamp_thread_tid(tcb);
    register_thread_tcb(tcb);

    TLS_STATE = Some(TlsState {
        tcb,
        dtv: dtv.cast::<usize>(),
        tls_base,
        dtv_len,
        runtime_static_cursor: layout.runtime_static_start,
        modules,
    });
}

pub unsafe fn allocate_tls_for_new_thread() -> Option<*mut ThreadControlBlock> {
    let layout = TLS_LAYOUT?;
    let total_size = layout.tcb_offset + size_of::<ThreadControlBlock>() + layout.max_align;
    let raw = mmap(
        null_mut(),
        total_size,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );
    core::ptr::write_bytes(raw, 0, total_size);
    let tls_base = round_up_to_boundary(raw as usize, layout.max_align) as *mut u8;
    let tcb = tls_base.add(layout.tcb_offset) as *mut ThreadControlBlock;
    initialize_tls_block(tls_base, tcb, true)
}

pub unsafe fn initialize_tls_for_thread_ptr(
    thread_ptr: *mut (),
) -> Option<*mut ThreadControlBlock> {
    if thread_ptr.is_null() {
        return None;
    }
    let layout = TLS_LAYOUT?;
    let tcb = thread_ptr as *mut ThreadControlBlock;
    // Avoid UB from pointer-provenance-sensitive subtraction on foreign memory.
    let tls_base = (thread_ptr as usize).wrapping_sub(layout.tcb_offset) as *mut u8;
    // glibc may provide a preinitialized pthread area in `_mem` that is
    // smaller than our internal ThreadControlBlock approximation. Do not clone
    // the whole struct in that case.
    initialize_tls_block(tls_base, tcb, false)
}

unsafe fn initialize_tls_block(
    tls_base: *mut u8,
    tcb: *mut ThreadControlBlock,
    clone_full_tcb: bool,
) -> Option<*mut ThreadControlBlock> {
    let layout = TLS_LAYOUT?;
    #[allow(static_mut_refs)]
    let state = TLS_STATE.as_ref()?;

    if state.tcb.is_null() || state.dtv_len == 0 {
        return None;
    }

    // Initialize static TLS from each module's PT_TLS template.
    //
    // For glibc-provided `_mem` thread descriptors (clone_full_tcb=false),
    // do not memset the whole [tls_base, tp) range: that area can include
    // pthread metadata used by start_thread at negative TP offsets.
    // Zero/copy only concrete module blocks.
    if layout.tls_size > 0 {
        if clone_full_tcb {
            core::ptr::write_bytes(tls_base, 0, layout.tls_size);
        }
        for module in state.modules.iter() {
            if module.dynamic {
                continue;
            }
            let dst = tls_base.add(module.block_offset);
            if !clone_full_tcb && module.memsz > 0 {
                core::ptr::write_bytes(dst, 0, module.memsz);
            }
            if module.filesz > 0 {
                core::ptr::copy_nonoverlapping(module.init_image, dst, module.filesz);
            }
            if clone_full_tcb && module.memsz > module.filesz {
                core::ptr::write_bytes(dst.add(module.filesz), 0, module.memsz - module.filesz);
            }
        }
    }
    if clone_full_tcb {
        core::ptr::copy_nonoverlapping(state.tcb, tcb, 1);
    }

    let dtv_len = state.dtv_len;
    let dtv_alloc_entries = dtv_len + 1; // +1 header slot for dtv[-1]
    let dtv_size = dtv_alloc_entries * size_of::<DtvEntry>();
    let dtv_raw = mmap(
        null_mut(),
        dtv_size,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    ) as *mut DtvEntry;
    core::ptr::write_bytes(dtv_raw.cast::<u8>(), 0, dtv_size);
    let dtv = dtv_raw.add(1);
    set_dtv_capacity(dtv, dtv_len);
    (*dtv).value = 1;
    (*dtv).to_free = 0;
    for module in state.modules.iter() {
        if module.dynamic {
            if let Some(base) = allocate_tls_module_block(module) {
                (*dtv.add(module.module_id)).value = base;
                (*dtv.add(module.module_id)).to_free = 0;
            }
        } else {
            let base = (tls_base as usize).wrapping_add(module.block_offset);
            (*dtv.add(module.module_id)).value = base;
            (*dtv.add(module.module_id)).to_free = 0;
        }
    }

    (*tcb).tcb = tcb;
    (*tcb).self_ptr = tcb;
    (*tcb).dtv = dtv.cast::<usize>();
    (*tcb).multiple_threads = 1;
    (*tcb).stack_guard = (*state.tcb).stack_guard;
    (*tcb).pointer_guard = (*state.tcb).pointer_guard;

    initialize_glibc_thread_links(tcb);

    // glibc keeps an internal per-thread key-block pointer at tp-0x28.
    // For fresh, allocator-owned TCBs we must clear it.
    // For glibc-provided in-place thread descriptors, preserve the value
    // established by pthread startup internals (Qt/GLib rely on this path).
    #[cfg(target_arch = "x86_64")]
    if clone_full_tcb {
        let tsd_key_slot = (tcb as *mut u8).offset(GLIBC_TSD_KEY_BLOCK_OFFSET) as *mut usize;
        core::ptr::write_volatile(tsd_key_slot, 0);
    }

    #[cfg(target_arch = "x86_64")]
    if !clone_full_tcb {
        // glibc start_thread registers rseq for child threads using an area at
        // TP-192 (32 bytes on x86_64). Ensure this window is initialized even
        // when we preserve the rest of the caller-provided pthread block.
        let rseq_area = (tcb as *mut u8).offset(GLIBC_RSEQ_AREA_OFFSET);
        core::ptr::write_bytes(rseq_area, 0, GLIBC_RSEQ_AREA_SIZE);
    }
    register_thread_tcb(tcb);

    Some(tcb)
}

#[allow(dead_code)]
pub unsafe fn tls_state() -> Option<&'static TlsState> {
    #[allow(static_mut_refs)]
    {
        TLS_STATE.as_ref()
    }
}

pub unsafe fn tls_layout() -> Option<TlsLayout> {
    TLS_LAYOUT
}

pub unsafe fn stamp_thread_tid(tcb: *mut ThreadControlBlock) {
    if tcb.is_null() {
        return;
    }

    #[cfg(target_arch = "x86_64")]
    {
        let tid = current_tid();
        // glibc's struct pthread stores the thread id at offset 0x2d0.
        // rwlock/mutex fast paths read this field and misbehave if left zero.
        let tid_slot = (tcb as *mut u8).add(GLIBC_PTHREAD_TID_OFFSET) as *mut i32;
        core::ptr::write_volatile(tid_slot, tid);
    }
}

#[inline(always)]
unsafe fn current_tid() -> i32 {
    crate::arch::gettid()
}

unsafe fn allocate_tls_module_block(module: &TlsModuleTemplate) -> Option<usize> {
    let align = module.align.max(align_of::<usize>());
    let payload = module.memsz.max(1);
    let alloc_len = payload.checked_add(align)?;

    let raw = mmap(
        null_mut(),
        alloc_len,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    ) as *mut u8;
    if raw.is_null() {
        return None;
    }
    core::ptr::write_bytes(raw, 0, alloc_len);
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

pub unsafe fn register_runtime_tls_modules(
    objects: &mut [SharedObject],
) -> Result<(), &'static str> {
    #[allow(static_mut_refs)]
    let state = TLS_STATE.as_mut().ok_or("rustld: TLS state unavailable")?;
    let layout = TLS_LAYOUT.ok_or("rustld: TLS layout unavailable")?;
    if state.tcb.is_null() || state.dtv.is_null() || state.dtv_len == 0 {
        return Err("rustld: invalid TLS state");
    }

    let mut next_module_id = state
        .modules
        .iter()
        .map(|module| module.module_id)
        .max()
        .unwrap_or(0)
        .saturating_add(1);
    let mut new_modules = Vec::new();

    for obj in objects.iter_mut() {
        let Some(ref mut tls) = obj.tls else {
            continue;
        };
        if tls.module_id != 0 {
            continue;
        }

        tls.module_id = next_module_id;
        let align = tls.align.max(align_of::<usize>());
        let static_off = round_up_to_boundary(state.runtime_static_cursor, align);
        let static_end = static_off.saturating_add(tls.memsz);
        let static_tls_fits = static_end <= layout.runtime_static_end;

        if static_tls_fits {
            tls.block_offset = static_off;
            tls.offset = (tls.block_offset as isize).wrapping_sub(layout.tls_size as isize);
            state.runtime_static_cursor = static_end;
        } else {
            tls.offset = 0;
            tls.block_offset = 0;
        }

        new_modules.push(TlsModuleTemplate {
            module_id: next_module_id,
            init_image: tls.init_image,
            filesz: tls.filesz,
            memsz: tls.memsz,
            align: tls.align,
            block_offset: tls.block_offset,
            dynamic: !static_tls_fits,
        });
        next_module_id += 1;
    }

    if new_modules.is_empty() {
        return Ok(());
    }

    let required_slots = next_module_id.max(1);
    let new_dtv_len = (required_slots + DTV_SURPLUS_SLOTS)
        .max(required_slots)
        .max(state.dtv_len);
    let new_dtv_alloc_entries = new_dtv_len + 1; // +1 header slot for dtv[-1]
    let new_dtv_size = new_dtv_alloc_entries * size_of::<DtvEntry>();
    let new_dtv_raw = mmap(
        null_mut(),
        new_dtv_size,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    ) as *mut DtvEntry;
    if new_dtv_raw.is_null() {
        return Err("rustld: failed to allocate runtime DTV");
    }
    core::ptr::write_bytes(new_dtv_raw.cast::<u8>(), 0, new_dtv_size);

    let new_dtv = new_dtv_raw.add(1);
    set_dtv_capacity(new_dtv, new_dtv_len);

    let old_dtv = state.dtv as *mut DtvEntry;
    let old_len = dtv_capacity(old_dtv).max(state.dtv_len);
    let copied_slots = old_len.min(new_dtv_len);
    core::ptr::copy_nonoverlapping(old_dtv.sub(1), new_dtv_raw, copied_slots + 1);
    set_dtv_capacity(new_dtv, new_dtv_len);
    (*new_dtv).value = (*old_dtv).value.wrapping_add(1);
    (*new_dtv).to_free = 0;

    let current_tcb = get_thread_pointer() as *mut ThreadControlBlock;
    if current_tcb.is_null() {
        return Err("rustld: missing thread pointer");
    }
    let current_tls_base = current_thread_tls_base().ok_or("rustld: missing TLS base")?;

    for module in new_modules.iter() {
        let base = if module.dynamic {
            allocate_tls_module_block(module)
                .ok_or("rustld: failed to allocate runtime TLS block")?
        } else {
            let dst = current_tls_base.add(module.block_offset);
            if module.memsz > 0 {
                core::ptr::write_bytes(dst, 0, module.memsz);
                let copy_len = module.filesz.min(module.memsz);
                if copy_len > 0 {
                    core::ptr::copy_nonoverlapping(module.init_image, dst, copy_len);
                }
            }
            (current_tls_base as usize).wrapping_add(module.block_offset)
        };
        (*new_dtv.add(module.module_id)).value = base;
        (*new_dtv.add(module.module_id)).to_free = 0;
    }

    (*current_tcb).dtv = new_dtv.cast::<usize>();
    if state.tcb == current_tcb {
        state.tcb = current_tcb;
    }

    state.dtv = new_dtv.cast::<usize>();
    state.dtv_len = new_dtv_len;
    state.modules.extend(new_modules);

    // Propagate newly assigned static TLS blocks to other already-created
    // threads so direct TP-relative accesses (R_X86_64_TPOFF*) stay valid.
    let tracked_threads = tracked_threads_snapshot();
    for tcb in tracked_threads {
        if tcb.is_null() || tcb == current_tcb {
            continue;
        }

        let mut dtv = (*tcb).dtv as *mut DtvEntry;
        if dtv.is_null() {
            continue;
        }
        let mut capacity = dtv_capacity(dtv);
        if capacity == 0 {
            capacity = state.dtv_len;
            set_dtv_capacity(dtv, capacity);
        }

        if capacity < new_dtv_len {
            let expanded_entries = new_dtv_len + 1;
            let expanded_size = expanded_entries * size_of::<DtvEntry>();
            let expanded_raw = mmap(
                null_mut(),
                expanded_size,
                PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS,
                -1,
                0,
            ) as *mut DtvEntry;
            if expanded_raw.is_null() {
                continue;
            }
            core::ptr::write_bytes(expanded_raw.cast::<u8>(), 0, expanded_size);
            let expanded_dtv = expanded_raw.add(1);
            core::ptr::copy_nonoverlapping(dtv.sub(1), expanded_raw, capacity + 1);
            set_dtv_capacity(expanded_dtv, new_dtv_len);
            (*expanded_dtv).value = (*dtv).value.wrapping_add(1);
            (*expanded_dtv).to_free = 0;
            dtv = expanded_dtv;
            (*tcb).dtv = dtv.cast::<usize>();
            capacity = new_dtv_len;
        }

        let tls_base = (tcb as *mut u8).sub(layout.tcb_offset);
        for module in state.modules.iter() {
            if module.module_id >= capacity {
                continue;
            }
            if module.dynamic {
                continue;
            }
            let existing = (*dtv.add(module.module_id)).value;
            if existing != 0 {
                continue;
            }
            let dst = tls_base.add(module.block_offset);
            if module.memsz > 0 {
                core::ptr::write_bytes(dst, 0, module.memsz);
                let copy_len = module.filesz.min(module.memsz);
                if copy_len > 0 {
                    core::ptr::copy_nonoverlapping(module.init_image, dst, copy_len);
                }
            }
            (*dtv.add(module.module_id)).value =
                (tls_base as usize).wrapping_add(module.block_offset);
            (*dtv.add(module.module_id)).to_free = 0;
        }
    }
    Ok(())
}

pub unsafe fn finalize_runtime_tls_images(objects: &[SharedObject]) -> Result<(), &'static str> {
    #[allow(static_mut_refs)]
    let state = TLS_STATE.as_ref().ok_or("rustld: TLS state unavailable")?;
    let layout = TLS_LAYOUT.ok_or("rustld: TLS layout unavailable")?;
    if state.modules.is_empty() {
        return Ok(());
    }

    let tracked_threads = tracked_threads_snapshot();
    for tcb in tracked_threads {
        if tcb.is_null() {
            continue;
        }

        let dtv = (*tcb).dtv as *mut DtvEntry;
        if dtv.is_null() {
            continue;
        }
        let mut capacity = dtv_capacity(dtv);
        if capacity == 0 {
            capacity = state.dtv_len;
            set_dtv_capacity(dtv, capacity);
        }
        let tls_base = (tcb as *mut u8).sub(layout.tcb_offset);

        for object in objects {
            let Some(tls) = object.tls else {
                continue;
            };
            if tls.module_id == 0 || tls.module_id >= capacity {
                continue;
            }

            let Some(template) = find_module_template(&state.modules, tls.module_id) else {
                continue;
            };

            let dst = if template.dynamic {
                let base = (*dtv.add(tls.module_id)).value;
                if base == 0 {
                    continue;
                }
                base as *mut u8
            } else {
                let base = (tls_base as usize).wrapping_add(template.block_offset);
                (*dtv.add(tls.module_id)).value = base;
                (*dtv.add(tls.module_id)).to_free = 0;
                base as *mut u8
            };

            if tls.memsz > 0 {
                core::ptr::write_bytes(dst, 0, tls.memsz);
                let copy_len = tls.filesz.min(tls.memsz);
                if copy_len > 0 {
                    core::ptr::copy_nonoverlapping(tls.init_image, dst, copy_len);
                }
            }
        }
    }

    Ok(())
}

unsafe fn current_thread_tls_base() -> Option<*mut u8> {
    let layout = TLS_LAYOUT?;
    let tcb = get_thread_pointer() as *mut ThreadControlBlock;
    if tcb.is_null() {
        return None;
    }
    Some((tcb as *mut u8).sub(layout.tcb_offset))
}

fn find_module_template<'a>(
    modules: &'a [TlsModuleTemplate],
    module_id: usize,
) -> Option<&'a TlsModuleTemplate> {
    modules.iter().find(|module| module.module_id == module_id)
}

pub unsafe fn resolve_tls_address(module: usize, offset: usize) -> Option<usize> {
    if module == 0 {
        return None;
    }
    #[allow(static_mut_refs)]
    let state = TLS_STATE.as_mut()?;
    let global_len = state.dtv_len;
    if module >= global_len {
        return None;
    }

    let current_tcb = get_thread_pointer() as *mut ThreadControlBlock;
    if current_tcb.is_null() {
        return None;
    }
    let mut dtv = (*current_tcb).dtv as *mut DtvEntry;
    if dtv.is_null() {
        return None;
    }

    let mut current_len = dtv_capacity(dtv);
    if current_len == 0 {
        // Backward compatibility with previously-created tables.
        current_len = global_len;
        set_dtv_capacity(dtv, current_len);
    }

    let mut module_base = if module < current_len {
        (*dtv.add(module)).value
    } else {
        0
    };

    if module_base == 0 {
        if current_len < global_len {
            let new_len = global_len;
            let new_dtv_alloc_entries = new_len + 1; // +1 header slot for dtv[-1]
            let new_dtv_size = new_dtv_alloc_entries * size_of::<DtvEntry>();
            let new_dtv_raw = mmap(
                null_mut(),
                new_dtv_size,
                PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS,
                -1,
                0,
            ) as *mut DtvEntry;
            if new_dtv_raw.is_null() {
                return None;
            }
            core::ptr::write_bytes(new_dtv_raw.cast::<u8>(), 0, new_dtv_size);
            let new_dtv = new_dtv_raw.add(1);
            core::ptr::copy_nonoverlapping(dtv.sub(1), new_dtv_raw, current_len + 1);
            set_dtv_capacity(new_dtv, new_len);
            (*new_dtv).value = (*dtv).value.wrapping_add(1);
            (*new_dtv).to_free = 0;
            dtv = new_dtv;
            current_len = new_len;
            (*current_tcb).dtv = dtv.cast::<usize>();
            if state.tcb == current_tcb {
                state.dtv = dtv.cast::<usize>();
            }
        }

        if module < current_len {
            module_base = (*dtv.add(module)).value;
        }
        if module_base == 0 {
            let module_template = find_module_template(&state.modules, module)?;
            module_base = if module_template.dynamic {
                allocate_tls_module_block(module_template)?
            } else {
                let tls_base = current_thread_tls_base()?;
                (tls_base as usize).wrapping_add(module_template.block_offset)
            };
            (*dtv.add(module)).value = module_base;
            (*dtv.add(module)).to_free = 0;
        }
    }

    Some(module_base.wrapping_add(offset))
}
