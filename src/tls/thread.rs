use super::*;

pub unsafe fn allocate_tls_for_new_thread() -> Option<*mut ThreadControlBlock> {
    let _guard = lock_tls_state();
    let layout = TLS_LAYOUT?;
    let total_size = layout.tcb_offset + size_of::<ThreadControlBlock>() + layout.max_align;
    let raw = mmap_anon(total_size)?;
    core::ptr::write_bytes(raw, 0, total_size);
    let tls_base = round_up_to_boundary(raw as usize, layout.max_align) as *mut u8;
    let tcb = tls_base.add(layout.tcb_offset) as *mut ThreadControlBlock;
    initialize_tls_block(tls_base, tcb, true)
}

pub unsafe fn initialize_tls_for_thread_ptr(
    thread_ptr: *mut (),
) -> Option<*mut ThreadControlBlock> {
    let _guard = lock_tls_state();
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

pub unsafe fn thread_ptr_needs_tls_init(thread_ptr: *mut ()) -> bool {
    let _guard = lock_tls_state();
    if thread_ptr.is_null() {
        return false;
    }
    let Some(layout) = TLS_LAYOUT else {
        return false;
    };
    #[allow(static_mut_refs)]
    let Some(state) = TLS_STATE.as_ref() else {
        return false;
    };
    if state.dtv_len == 0 {
        return false;
    }

    let tcb = thread_ptr as *mut ThreadControlBlock;
    let dtv = tcb_read_dtv_ptr(tcb) as *mut DtvEntry;
    if dtv.is_null() {
        return true;
    }
    let capacity = dtv_capacity(dtv);
    if capacity == 0 || capacity < state.dtv_len {
        return true;
    }

    let tls_base = (tcb as *mut u8).sub(layout.tcb_offset);
    for module in state.modules.iter() {
        if module.dynamic {
            continue;
        }
        if module.module_id >= capacity {
            return true;
        }
        let expected = (tls_base as usize).wrapping_add(module.block_offset);
        let actual = (*dtv.add(module.module_id)).value;
        if actual != expected {
            return true;
        }
    }

    false
}

unsafe fn initialize_tls_block(
    tls_base: *mut u8,
    tcb: *mut ThreadControlBlock,
    clone_full_tcb: bool,
) -> Option<*mut ThreadControlBlock> {
    let _guard = lock_tls_state();
    let layout = TLS_LAYOUT?;
    #[allow(static_mut_refs)]
    let state = TLS_STATE.as_ref()?;

    if trace_thread_tls() {
        eprintln!(
            "tls:init clone_full_tcb={} tls_base={:#x} tcb={:#x} state_tcb={:#x} dtv_len={}",
            clone_full_tcb,
            tls_base as usize,
            tcb as usize,
            state.tcb as usize,
            state.dtv_len
        );
    }

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
            if !clone_full_tcb && module.inherit_runtime_head != 0 && !state.tls_base.is_null() {
                let inherit_len = module.inherit_runtime_head.min(module.memsz);
                if inherit_len != 0 {
                    let src = state.tls_base.add(module.block_offset);
                    core::ptr::copy_nonoverlapping(src, dst, inherit_len);
                }
            }
            if clone_full_tcb && module.memsz > module.filesz {
                core::ptr::write_bytes(dst.add(module.filesz), 0, module.memsz - module.filesz);
            }
        }
    }
    if clone_full_tcb {
        core::ptr::copy_nonoverlapping(state.tcb, tcb, 1);
    }

    let dtv = build_and_populate_dtv(state.dtv_len, tls_base, &state.modules)?;

    if clone_full_tcb {
        (*tcb).tcb = tcb;
        (*tcb).self_ptr = tcb;
        (*tcb).multiple_threads = 1;
        (*tcb).stack_guard = (*state.tcb).stack_guard;
        (*tcb).pointer_guard = (*state.tcb).pointer_guard;
    }

    #[cfg(target_arch = "x86_64")]
    if !clone_full_tcb {
        // Some older glibc pthread startup paths hand us an in-place thread
        // descriptor before these header words are fully seeded. Fill the
        // minimal self-referential fields when still zero, but preserve any
        // non-zero glibc state already written into the surrounding block.
        if (*tcb).tcb.is_null() {
            (*tcb).tcb = tcb;
        }
        if (*tcb).self_ptr.is_null() {
            (*tcb).self_ptr = tcb;
        }
        if (*tcb).multiple_threads == 0 {
            (*tcb).multiple_threads = 1;
        }
        (*tcb).sysinfo = (*state.tcb).sysinfo;
        (*tcb).stack_guard = (*state.tcb).stack_guard;
        (*tcb).pointer_guard = (*state.tcb).pointer_guard;
        if trace_thread_tls() {
            eprintln!(
                "tls:init in-place header tcb={:#x} self={:#x} mt={} sysinfo={:#x} stack_guard={:#x} ptr_guard={:#x}",
                (*tcb).tcb as usize,
                (*tcb).self_ptr as usize,
                (*tcb).multiple_threads,
                (*tcb).sysinfo,
                (*tcb).stack_guard,
                (*tcb).pointer_guard
            );
        }
    }

    // Keep this write for both paths so __tls_get_addr observes the DTV that
    // belongs to this thread, while preserving glibc-owned thread-descriptor
    // internals when clone_full_tcb=false.
    tcb_write_dtv_ptr(tcb, dtv.cast::<usize>());

    if clone_full_tcb {
        initialize_glibc_thread_links(tcb);
    }

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
        if trace_thread_tls() {
            eprintln!("tls:init in-place rseq_area={:#x}", rseq_area as usize);
        }
    }
    register_thread_tcb(tcb);

    if trace_thread_tls() {
        eprintln!(
            "tls:init done tcb={:#x} dtv={:#x}",
            tcb as usize,
            tcb_read_dtv_ptr(tcb) as usize
        );
    }

    Some(tcb)
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
