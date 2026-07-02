use super::*;

pub unsafe fn install_tls(objects: &[SharedObject], pseudorandom_bytes: *const [u8; 16]) {
    let _guard = lock_tls_state();
    let layout = match TLS_LAYOUT {
        Some(layout) => layout,
        None => return,
    };

    if layout.module_count == 0 {
        return;
    }

    let total_size = layout.tcb_offset + size_of::<ThreadControlBlock>() + layout.max_align;
    let raw = match mmap_anon(total_size) {
        Some(raw) => raw,
        None => return,
    };
    core::ptr::write_bytes(raw, 0, total_size);

    let tls_base = round_up_to_boundary(raw as usize, layout.max_align) as *mut u8;

    let mut modules = Vec::new();
    for obj in objects.iter() {
        let is_libc = obj.soname_str() == Some("libc.so.6");
        if let Some(tls) = obj.tls {
            modules.push(TlsModuleTemplate {
                module_id: tls.module_id,
                init_image: tls.init_image,
                filesz: tls.filesz,
                memsz: tls.memsz,
                align: tls.align,
                block_offset: tls.block_offset,
                dynamic: false,
                // glibc stores current locale/ctype pointers in the leading
                // bytes of libc's static TLS block. Copy only that narrow head
                // so child threads inherit required runtime-populated words
                // without cloning unrelated thread-private libc TLS state such
                // as malloc arena ownership.
                inherit_runtime_head: if is_libc {
                    0x40
                } else {
                    0
                },
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
    let dtv = match build_and_populate_dtv(dtv_len, tls_base, &modules) {
        Some(dtv) => dtv,
        None => return,
    };

    let stack_guard = if !pseudorandom_bytes.is_null() {
        let random = &*pseudorandom_bytes;
        let mut guard = usize::from_ne_bytes(random[..size_of::<usize>()].try_into().unwrap());
        // Match glibc's stack canary convention: keep the low byte zero so
        // simple string overflows are more likely to terminate at NUL.
        guard &= !0xffusize;
        guard
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
    tcb_write_dtv_ptr(tcb, dtv.cast::<usize>());

    // glibc keeps an internal per-thread key-block pointer at tp-0x28.
    // Keep it NULL for the initial thread; child-thread setup may copy
    // this area before lazy initialization kicks in.
    #[cfg(target_arch = "x86_64")]
    {
        let tsd_key_slot = (tcb as *mut u8).offset(GLIBC_TSD_KEY_BLOCK_OFFSET) as *mut usize;
        core::ptr::write_volatile(tsd_key_slot, 0);
    }

    set_thread_pointer(tcb.cast());
    // The initial thread descriptor must expose a valid self-linked list for
    // glibc fork/clone bookkeeping (used in child after fork paths).
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

pub unsafe fn install_tls_musl(objects: &[SharedObject], pseudorandom_bytes: *const [u8; 16]) {
    let _guard = lock_tls_state();
    install_tls(objects, pseudorandom_bytes);

    #[cfg(target_arch = "x86_64")]
    {
        #[allow(static_mut_refs)]
        let Some(state) = TLS_STATE.as_ref() else {
            return;
        };
        if state.tcb.is_null() || state.dtv.is_null() {
            return;
        }

        let pthread = state.tcb as *mut u8;
        let self_ptr = state.tcb as usize;
        let dtv_ptr = state.dtv as usize;

        // musl expects struct pthread at TP (FS:0 on x86_64).
        core::ptr::write_unaligned(
            pthread.add(MUSL_PTHREAD_SELF_OFFSET) as *mut usize,
            self_ptr,
        );
        core::ptr::write_unaligned(pthread.add(MUSL_PTHREAD_DTV_OFFSET) as *mut usize, dtv_ptr);
        core::ptr::write_unaligned(
            pthread.add(MUSL_PTHREAD_PREV_OFFSET) as *mut usize,
            self_ptr,
        );
        core::ptr::write_unaligned(
            pthread.add(MUSL_PTHREAD_NEXT_OFFSET) as *mut usize,
            self_ptr,
        );
        core::ptr::write_unaligned(
            pthread.add(MUSL_PTHREAD_SYSINFO_OFFSET) as *mut usize,
            0usize,
        );
        core::ptr::write_unaligned(
            pthread.add(MUSL_PTHREAD_CANARY_OFFSET) as *mut usize,
            (*state.tcb).stack_guard,
        );
        core::ptr::write_unaligned(
            pthread.add(MUSL_PTHREAD_TID_OFFSET) as *mut i32,
            current_tid(),
        );
        core::ptr::write_unaligned(
            pthread.add(MUSL_PTHREAD_DETACH_STATE_OFFSET) as *mut i32,
            MUSL_DETACH_STATE_JOINABLE,
        );

        let robust_head = pthread.add(MUSL_PTHREAD_ROBUST_HEAD_OFFSET) as usize;
        core::ptr::write_unaligned(
            pthread.add(MUSL_PTHREAD_ROBUST_HEAD_OFFSET) as *mut usize,
            robust_head,
        );
        core::ptr::write_unaligned(pthread.add(MUSL_PTHREAD_ROBUST_OFF_OFFSET) as *mut isize, 0);
        core::ptr::write_unaligned(
            pthread.add(MUSL_PTHREAD_ROBUST_PENDING_OFFSET) as *mut usize,
            0,
        );
    }

    #[cfg(target_arch = "aarch64")]
    {
        #[allow(static_mut_refs)]
        let Some(state) = TLS_STATE.as_ref() else {
            return;
        };
        if state.tcb.is_null() || state.dtv.is_null() {
            return;
        }

        // musl/aarch64 uses TP as an address 0xC8 bytes past struct pthread.
        // Keep TP as installed by install_tls() and seed the expected words
        // around it so pthread_self()/__tls_get_addr() see a valid layout.
        let tp = state.tcb as *mut u8;
        let pthread = tp.sub(MUSL_AARCH64_PTHREAD_SIZE_BEFORE_TP);

        core::ptr::write_bytes(pthread, 0, MUSL_AARCH64_PTHREAD_SIZE_BEFORE_TP);
        core::ptr::write_unaligned(
            pthread.add(MUSL_AARCH64_SELF_OFFSET) as *mut usize,
            pthread as usize,
        );
        core::ptr::write_unaligned(
            tp.offset(MUSL_AARCH64_DTV_SLOT_FROM_TP) as *mut usize,
            state.dtv as usize,
        );
    }
}
