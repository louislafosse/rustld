use super::*;

pub unsafe fn register_runtime_tls_modules(
    objects: &mut [SharedObject],
) -> Result<(), &'static str> {
    let _guard = lock_tls_state();
    #[allow(static_mut_refs)]
    let state = TLS_STATE.as_mut().ok_or("rustld: TLS state unavailable")?;
    let _layout = TLS_LAYOUT.ok_or("rustld: TLS layout unavailable")?;
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
        let is_libc = obj.soname_str() == Some("libc.so.6");
        let Some(ref mut tls) = obj.tls else {
            continue;
        };
        if tls.module_id != 0 {
            continue;
        }

        tls.module_id = next_module_id;
        // Keep runtime-loaded modules on dynamic TLS. The eager static-TLS
        // assignment path requires mutating other live threads' TLS blocks and
        // DTVs, which is not safe under concurrent helper threads (for example
        // curl's async resolver threads loading NSS modules via dlopen).
        let static_tls_fits = false;
        tls.offset = 0;
        tls.block_offset = 0;

        new_modules.push(TlsModuleTemplate {
            module_id: next_module_id,
            init_image: tls.init_image,
            filesz: tls.filesz,
            memsz: tls.memsz,
            align: tls.align,
            block_offset: tls.block_offset,
            dynamic: !static_tls_fits,
            inherit_runtime_head: if is_libc {
                0x40
            } else {
                0
            },
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
    let new_dtv_raw = match mmap_anon(new_dtv_size) {
        Some(raw) => raw.cast::<DtvEntry>(),
        None => return Err("rustld: failed to allocate runtime DTV"),
    };
    // mmap_anon pages are already zero.

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

    tcb_write_dtv_ptr(current_tcb, new_dtv.cast::<usize>());
    if state.tcb == current_tcb {
        state.tcb = current_tcb;
    }

    state.dtv = new_dtv.cast::<usize>();
    state.dtv_len = new_dtv_len;
    state.modules.extend(new_modules);
    Ok(())
}

pub unsafe fn finalize_runtime_tls_images(objects: &[SharedObject]) -> Result<(), &'static str> {
    let _guard = lock_tls_state();
    #[allow(static_mut_refs)]
    let state = TLS_STATE.as_ref().ok_or("rustld: TLS state unavailable")?;
    let layout = TLS_LAYOUT.ok_or("rustld: TLS layout unavailable")?;
    if state.modules.is_empty() {
        return Ok(());
    }

    let tracked_threads = tracked_threads_snapshot();
    let current_tcb = get_thread_pointer() as *mut ThreadControlBlock;
    let snapshot_tid = current_tid();
    for tcb in tracked_threads {
        if tcb.is_null() {
            continue;
        }
        if !is_thread_descriptor_live(tcb, current_tcb, snapshot_tid) {
            unregister_thread_tcb(tcb);
            continue;
        }

        let dtv = tcb_read_dtv_ptr(tcb) as *mut DtvEntry;
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
    let _guard = lock_tls_state();
    if module == 0 {
        return None;
    }
    #[allow(static_mut_refs)]
    let state = TLS_STATE.as_mut()?;
    let global_len = state.dtv_len;

    let current_tcb = get_thread_pointer() as *mut ThreadControlBlock;
    if current_tcb.is_null() {
        return None;
    }
    let mut dtv = tcb_read_dtv_ptr(current_tcb) as *mut DtvEntry;
    if dtv.is_null() {
        return None;
    }

    let mut current_len = dtv_capacity(dtv);
    if current_len == 0 {
        // Backward compatibility with previously-created tables.
        current_len = global_len;
        set_dtv_capacity(dtv, current_len);
    }

    if module >= global_len {
        // Fallback for foreign module IDs not registered in rustld TLS state:
        // if the current thread DTV already has a slot, use it directly.
        if module < current_len {
            let base = (*dtv.add(module)).value;
            if base != 0 {
                return Some(base.wrapping_add(offset));
            }
        }
        return None;
    }

    let module_template = match find_module_template(&state.modules, module) {
        Some(template) => template,
        None => {
            // Defensive fallback for layout/state skew: honor existing thread
            // DTV content instead of forcing a null TLS result.
            if module < current_len {
                let base = (*dtv.add(module)).value;
                if base != 0 {
                    return Some(base.wrapping_add(offset));
                }
            }
            return None;
        }
    };
    if !module_template.dynamic {
        // Static TLS module bases are deterministic from TP + layout.
        // Do not trust a stale/non-owned DTV slot for these modules.
        let layout = TLS_LAYOUT?;
        let tls_base = (current_tcb as *mut u8).sub(layout.tcb_offset);
        let static_base = (tls_base as usize).wrapping_add(module_template.block_offset);
        if module < current_len {
            (*dtv.add(module)).value = static_base;
            (*dtv.add(module)).to_free = 0;
        }
        return Some(static_base.wrapping_add(offset));
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
            let new_dtv_raw = mmap_anon(new_dtv_size)?.cast::<DtvEntry>();
            // mmap_anon pages are already zero.
            let new_dtv = new_dtv_raw.add(1);
            core::ptr::copy_nonoverlapping(dtv.sub(1), new_dtv_raw, current_len + 1);
            set_dtv_capacity(new_dtv, new_len);
            (*new_dtv).value = (*dtv).value.wrapping_add(1);
            (*new_dtv).to_free = 0;
            dtv = new_dtv;
            current_len = new_len;
            tcb_write_dtv_ptr(current_tcb, dtv.cast::<usize>());
            if state.tcb == current_tcb {
                state.dtv = dtv.cast::<usize>();
            }
        }

        if module < current_len {
            module_base = (*dtv.add(module)).value;
        }
        if module_base == 0 {
            module_base = allocate_tls_module_block(module_template)?;
            (*dtv.add(module)).value = module_base;
            (*dtv.add(module)).to_free = 0;
        }
    }

    Some(module_base.wrapping_add(offset))
}
