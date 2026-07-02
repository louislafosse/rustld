use super::*;

#[no_mangle]
pub extern "C" fn _dl_allocate_tls(_mem: *mut ()) -> *mut () {
    debug_stub_trace("_dl_allocate_tls");
    // Allocate TLS/TCB for a new thread.
    // This is required for glibc pthread startup paths that expect a non-null DTV.
    unsafe {
        if trace_thread_tls() {
            eprintln!("ld_stub: _dl_allocate_tls mem={:#x}", _mem as usize);
        }
        // When glibc passes a preallocated thread descriptor buffer, initialize
        // TLS in-place. pthread startup paths continue to use this pointer as TP.
        if !_mem.is_null() && !force_fresh_thread_tls() {
            if let Some(initialized) = tls::initialize_tls_for_thread_ptr(_mem) {
                let result = initialized.cast();
                if trace_thread_tls() {
                    eprintln!(
                        "ld_stub: _dl_allocate_tls in-place ret={:#x}",
                        result as usize
                    );
                }
                return result;
            }
        }

        // Fallback for callers that do not provide a thread descriptor buffer.
        if let Some(tcb) = tls::allocate_tls_for_new_thread() {
            let result = tcb.cast();
            if trace_thread_tls() {
                eprintln!("ld_stub: _dl_allocate_tls fresh ret={:#x}", result as usize);
            }
            return result;
        }
    }
    core::ptr::null_mut()
}

#[no_mangle]
pub extern "C" fn _dl_allocate_tls_init(tcb: *mut (), _main_thread: usize) -> *mut () {
    debug_stub_trace("_dl_allocate_tls_init");
    // Always (re)initialize the thread descriptor TLS view.
    unsafe {
        let current_tp = get_thread_pointer();
        if trace_thread_tls() {
            eprintln!(
                "ld_stub: _dl_allocate_tls_init arg={:#x} current_tp={:#x}",
                tcb as usize,
                current_tp as usize
            );
        }
        // glibc may call this for the current thread descriptor during startup/
        // teardown bookkeeping. For current-thread calls, only reinitialize
        // when the descriptor's DTV/static TLS view is clearly stale.
        if !tcb.is_null() {
            let needs_reinit = if tcb == current_tp {
                tls::thread_ptr_needs_tls_init(tcb)
            } else {
                true
            };
            if needs_reinit {
                if let Some(initialized) = tls::initialize_tls_for_thread_ptr(tcb) {
                    let current_tp_tcb = current_tp as *mut ThreadControlBlock;
                    if !current_tp_tcb.is_null() && current_tp_tcb == initialized {
                        tls::stamp_thread_tid(initialized);
                    }
                    let result = initialized.cast();
                    if trace_thread_tls() {
                        eprintln!(
                            "ld_stub: _dl_allocate_tls_init ret={:#x}",
                            result as usize
                        );
                    }
                    return result;
                }
            }
        }
    }
    tcb
}

#[no_mangle]
pub extern "C" fn _dl_deallocate_tls(_tcb: *mut (), _dealloc_tcb: usize) {
    debug_stub_trace("_dl_deallocate_tls");
    tls::unregister_thread_tcb(_tcb as *mut ThreadControlBlock);
}

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
    debug_stub_trace("__tunable_is_initialized");
    #[cfg(target_arch = "x86_64")]
    {
        let self_addr = __tunable_is_initialized as *const () as usize;
        if let Some(addr) = resolve_tunable_forward_addr(
            &TUNABLE_IS_INIT_FORWARD_ADDR,
            "__tunable_is_initialized",
            self_addr,
        ) {
            unsafe {
                let func: extern "C" fn(usize) -> i32 = core::mem::transmute(addr);
                return func(_id);
            }
        }
    }

    // Keep tunables handling entirely in rustld. Forwarding to glibc's
    // internal implementation depends on glibc-private rtld state and can
    // break across distro/glibc revisions.
    0
}

#[no_mangle]
pub extern "C" fn __tunable_get_val(_id: usize, valp: *mut (), callback: *const ()) {
    debug_stub_trace("__tunable_get_val");

    #[cfg(target_arch = "x86_64")]
    {
        let self_addr = __tunable_get_val as *const () as usize;
        if let Some(addr) = resolve_tunable_forward_addr(
            &TUNABLE_GET_VAL_FORWARD_ADDR,
            "__tunable_get_val",
            self_addr,
        ) {
            unsafe {
                let func: extern "C" fn(usize, *mut (), *const ()) = core::mem::transmute(addr);
                func(_id, valp, callback);
                return;
            }
        }

        if !callback.is_null() {
            #[repr(C)]
            union TunableVal {
                numval: u64,
                raw: [usize; 2],
            }

            unsafe {
                // glibc callback expects pointer to tunable value payload.
                // Zero-initialize the whole union so callbacks that read the
                // string variant (ptr + len) never observe uninitialized bytes.
                let mut payload = TunableVal { raw: [0; 2] };
                let cb: extern "C" fn(*mut ()) = core::mem::transmute(callback);
                cb((&mut payload as *mut TunableVal).cast::<()>());
            }
        } else if !valp.is_null() {
            unsafe {
                core::ptr::write_unaligned(valp.cast::<i32>(), 0);
            }
        }
        return;
    }

    #[cfg(not(target_arch = "x86_64"))]
    {
        // Keep tunables handling entirely in rustld on non-x86_64.
        // Preserve caller defaults when no callback is provided.
        let _ = valp;
        let _ = callback;
    }
}

#[no_mangle]
pub extern "C" fn __nptl_change_stack_perm(_thread: *mut ()) -> i32 {
    // Ubuntu/Debian glibc may bind this GLIBC_PRIVATE symbol from libc to ld.so.
    // rustld does not expose full NPTL internals, so keep a conservative success stub.
    0
}

#[no_mangle]
pub extern "C" fn _dl_make_stack_executable(_stack_endp: *mut *mut c_void) -> i32 {
    debug_stub_trace("_dl_make_stack_executable");
    0
}

#[no_mangle]
pub extern "C" fn _dl_get_tls_static_info(sizep: *mut usize, alignp: *mut usize) {
    debug_stub_trace("_dl_get_tls_static_info");
    let (size, align) = unsafe {
        linking::active_linker()
            .and_then(|linker| linker.tls_static_metadata())
            .unwrap_or((0x1000, 0x10))
    };
    if !sizep.is_null() {
        unsafe { core::ptr::write_unaligned(sizep, size) };
    }
    if !alignp.is_null() {
        unsafe { core::ptr::write_unaligned(alignp, align.max(1)) };
    }
}

#[no_mangle]
pub extern "C" fn __tls_get_addr(_ti: *const ()) -> *mut () {
    debug_stub_trace("__tls_get_addr");
    if _ti.is_null() {
        return core::ptr::null_mut();
    }

    let ti = _ti as *const TlsIndex;
    let module = unsafe { (*ti).ti_module };
    let offset = unsafe { (*ti).ti_offset };
    let resolved = unsafe { tls::resolve_tls_address(module, offset).unwrap_or(0) };

    resolved as *mut ()
}
