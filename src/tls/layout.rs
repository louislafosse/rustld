use super::*;

pub unsafe fn prepare_tls_layout(objects: &mut [SharedObject]) {
    let _guard = lock_tls_state();
    // Reserve a fixed window below TP for runtime-private pthread/TLS state.
    // On x86_64 a small gap covers rseq scratch (TP-192..TP-160).
    // On aarch64 glibc touches deeper negative TP offsets during early startup;
    // keep a larger reserve so those accesses never underflow the mapped TLS area.
    #[cfg(target_arch = "x86_64")]
    const RSEQ_RESERVE_BYTES: usize = 256;
    #[cfg(target_arch = "aarch64")]
    const RSEQ_RESERVE_BYTES: usize = 4096;
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    const RSEQ_RESERVE_BYTES: usize = 1024;
    const RUNTIME_STATIC_SURPLUS_BYTES: usize = 64 * 1024;
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

pub unsafe fn tls_layout() -> Option<TlsLayout> {
    let _guard = lock_tls_state();
    TLS_LAYOUT
}
