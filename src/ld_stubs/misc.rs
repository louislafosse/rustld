use super::*;

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

#[no_mangle]
pub extern "C" fn _dl_fini() {
    // Keep rtld_fini as a no-op so process exit can complete reliably.
    // Invoking custom fini walks here can recurse into partially-torn-down
    // runtime state for some binaries.
    // Keep rtld_fini as a no-op so process exit can complete.
}

#[no_mangle]
pub extern "C" fn _dl_find_dso_for_object(addr: *const ()) -> *const () {
    debug_stub_trace("_dl_find_dso_for_object");
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
