use super::*;

#[no_mangle]
pub extern "C" fn _dl_signal_error(
    _errcode: i32,
    _objname: *const c_char,
    _errstring: *const c_char,
) {
    debug_stub_trace("_dl_signal_error");
    let tid = current_tid();
    let frame_ptr = unsafe { catch_error_get_top(tid) };
    if frame_ptr.is_null() {
        return;
    }
    unsafe {
        let frame = &mut *frame_ptr;
        frame.errcode = _errcode;
        if !frame.objname.is_null() {
            core::ptr::write_unaligned(frame.objname, _objname);
        }
        if !frame.errstring.is_null() {
            core::ptr::write_unaligned(frame.errstring, _errstring);
        }
        if !frame.mallocedp.is_null() {
            core::ptr::write_unaligned(frame.mallocedp, 0u8);
        }
        // Avoid keeping rtld lock held across non-local jump.
        force_unlock_rtld_ops_if_owned_by_current_thread();
        siglongjmp(core::ptr::addr_of_mut!(frame.env), 1);
    }
}

#[no_mangle]
pub extern "C" fn _dl_signal_exception(_errcode: i32, _exception: *const ()) {
    debug_stub_trace("_dl_signal_exception");
    static MSG: &[u8] = b"rustld: rtld exception\0";
    _dl_signal_error(_errcode, core::ptr::null(), MSG.as_ptr().cast::<c_char>());
}

#[inline(always)]
unsafe fn populate_dl_exception(
    exception: *mut c_void,
    objname: *const c_char,
    errstring: *const c_char,
) {
    if exception.is_null() {
        return;
    }
    let exception = exception.cast::<DlException>();
    (*exception).objname = objname;
    (*exception).errstring = errstring;
    (*exception).message_buffer = core::ptr::null_mut();
}

#[no_mangle]
pub unsafe extern "C" fn _dl_exception_create(
    exception: *mut c_void,
    objname: *const c_char,
    errstring: *const c_char,
) {
    debug_stub_trace("_dl_exception_create");
    populate_dl_exception(exception, objname, errstring);
}

#[no_mangle]
pub unsafe extern "C" fn _dl_exception_create_format(
    exception: *mut c_void,
    objname: *const c_char,
    errfmt: *const c_char,
    mut _args: ...,
) {
    debug_stub_trace("_dl_exception_create_format");
    populate_dl_exception(exception, objname, errfmt);
}

#[no_mangle]
pub unsafe extern "C" fn _dl_exception_free(exception: *mut c_void) {
    debug_stub_trace("_dl_exception_free");
    if exception.is_null() {
        return;
    }
    let exception = exception.cast::<DlException>();
    (*exception).message_buffer = core::ptr::null_mut();
}

#[no_mangle]
pub extern "C" fn _dl_catch_exception(
    _exception: *mut (),
    operate: *const (),
    args: *const (),
) -> i32 {
    debug_stub_trace("_dl_catch_exception");
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
    mallocedp: *mut u8,
    operate: *const (),
    args: *const (),
) -> i32 {
    debug_stub_trace("_dl_catch_error");
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
    debug_stub_trace("__rustld_rtld_lookup_symbol_x_stub");
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
    debug_stub_trace("__rustld_rtld_dlopen_stub");
    clear_dlerror();
    let file = file_raw as *const u8;
    let dispatch =
        unsafe { core::ptr::read_volatile(core::ptr::addr_of!(__rustld_rtld_dlopen_dispatch)) };
    dispatch(file, mode)
}

/// rtld_global_ro + 0x350: internal dlclose entry point used by libc wrappers.
pub extern "C" fn __rustld_rtld_dlclose_stub(_map: *mut c_void) -> i32 {
    debug_stub_trace("__rustld_rtld_dlclose_stub");
    let entry = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(__rustld_dlclose_entry)) };
    unsafe { entry(_map) }
}

/// rtld_global_ro + 0x358: internal catch-error helper used by dlerror_run().
pub extern "C" fn __rustld_rtld_catch_error(
    objname: *mut *const c_char,
    errstring: *mut *const c_char,
    mallocedp: *mut u8,
    operate: *const c_void,
    args: *mut c_void,
) -> i32 {
    debug_stub_trace("__rustld_rtld_catch_error");
    if !objname.is_null() {
        unsafe { core::ptr::write_unaligned(objname, core::ptr::null()) };
    }
    if !errstring.is_null() {
        unsafe { core::ptr::write_unaligned(errstring, core::ptr::null()) };
    }
    if !mallocedp.is_null() {
        unsafe { core::ptr::write_unaligned(mallocedp, 0u8) };
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

/// Legacy x86_64 glibc installs tiny lock helpers in `_rtld_global` and
/// calls them from internal libc paths like `_dl_addr@@GLIBC_PRIVATE`.
/// Ubuntu 20.04/glibc 2.31 uses `_rtld_global + 0xf08` and `+0xf10` for
/// this pair. The real loader only bumps the recursion counter at `lock+4`.
#[cfg(target_arch = "x86_64")]
#[inline(never)]
pub extern "C" fn __rustld_rtld_legacy_lock_acquire(lock: *mut u8) {
    if lock.is_null() {
        return;
    }
    let depth = unsafe { lock.add(4) as *mut i32 };
    unsafe {
        *depth = (*depth).wrapping_add(1);
    }
}

#[cfg(target_arch = "x86_64")]
#[inline(never)]
pub extern "C" fn __rustld_rtld_legacy_lock_release(lock: *mut u8) {
    if lock.is_null() {
        return;
    }
    let depth = unsafe { lock.add(4) as *mut i32 };
    unsafe {
        *depth = (*depth).wrapping_sub(1);
    }
}
