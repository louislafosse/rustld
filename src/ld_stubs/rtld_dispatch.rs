use super::*;

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
                if trace_rtld_lookup() {
                    eprintln!(
                        "rtld_lookup: name={} undef_map={:#x} requester={:?} skip_map={:#x} skip={:?}",
                        name,
                        undef_map_raw,
                        requester_idx,
                        skip_map_raw,
                        skip_idx
                    );
                }
                let resolve = |candidate: &str| {
                    if let Some(requester) = requester_idx {
                        linker.lookup_symbol_in_object_scope_excluding_rtld_slow(
                            requester,
                            candidate,
                            skip_idx,
                        )
                    } else {
                        linker.lookup_symbol_excluding(candidate, skip_idx)
                    }
                };

                let resolved = if let Some(found) = resolve(name) {
                    Some(found)
                } else if let Some((base_name, _)) = name.split_once('@') {
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
                    let sym_ptr = persist_rtld_lookup_symbol(obj_idx, symbol);

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
