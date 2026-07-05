use super::*;

impl RtldStubs {
    pub(crate) unsafe fn new(
        exec_base: usize,
        exec_dynamic: *const u8,
        minsigstacksize: usize,
        auxv: *const AuxiliaryVectorItem,
        auxv_count: usize,
        hwcap: usize,
        hwcap2: usize,
    ) -> Self {
        const PAGE: usize = 4096;
        // Some glibc builds access fields far into struct rtld_global
        // during freeres; allocate a large zeroed block to be safe.
        const RTLD_GLOBAL_SIZE: usize = PAGE * 16;
        const RTLD_GLOBAL_RO_SIZE: usize = PAGE * 16;
        const STUB_LINK_MAP_SIZE: usize = PAGE;
        const RTLD_DATA_SIZE: usize = PAGE;
        const TOTAL_SIZE: usize =
            RTLD_GLOBAL_SIZE + RTLD_GLOBAL_RO_SIZE + STUB_LINK_MAP_SIZE + RTLD_DATA_SIZE;

        // Allocate memory for stubs. MAP_ANONYMOUS pages are kernel zero-filled
        // (and defined-zero to valgrind), so no explicit memset is needed.
        let page = mmap(
            null_mut(),
            TOTAL_SIZE,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS,
            -1,
            0,
        );

        let rtld_global = page;
        let rtld_global_ro = page.byte_add(RTLD_GLOBAL_SIZE);
        let link_map = page.byte_add(RTLD_GLOBAL_SIZE + RTLD_GLOBAL_RO_SIZE);
        let rtld_data = page.byte_add(RTLD_GLOBAL_SIZE + RTLD_GLOBAL_RO_SIZE + STUB_LINK_MAP_SIZE);
        let dlfcn_hook = link_map.byte_add(0x380) as *mut usize;

        #[cfg(target_arch = "x86_64")]
        {
            // Newer glibc IFUNC resolvers read an x86 CPU-feature block from
            // _rtld_global_ro. Seed our synthetic object from the host loader's
            // real bytes first, then override the handful of fields rustld must
            // virtualize (auxv, hooks, TLS metadata, etc.).
            if let Some(host_rtld_global_ro) = ld_stubs::host_rtld_global_ro_ptr() {
                core::ptr::copy_nonoverlapping(host_rtld_global_ro, rtld_global_ro, 928);
            }
        }

        let libc_enable_secure = rtld_data as *mut u32;
        let libc_stack_end = rtld_data.byte_add(0x08) as *mut *const u8;
        let dl_argv = rtld_data.byte_add(0x10) as *mut *const *const u8;
        let rseq_offset = rtld_data.byte_add(0x18) as *mut isize;
        let rseq_size = rtld_data.byte_add(0x20) as *mut u32;
        let rseq_flags = rtld_data.byte_add(0x24) as *mut u32;
        let pointer_chk_guard = rtld_data.byte_add(0x28) as *mut usize;
        let pointer_chk_guard_local = rtld_data.byte_add(0x30) as *mut usize;
        let stack_chk_guard = rtld_data.byte_add(0x38) as *mut usize;
        let auxv_storage = rtld_data.byte_add(0x40) as *mut AuxiliaryVectorItem;

        #[cfg(target_arch = "x86_64")]
        {
            if disable_rseq_metadata() {
                // Valgrind does not model rseq registration like native glibc
                // startup expects; advertise rseq as disabled in this mode.
                *rseq_offset = 0;
                *rseq_size = 0;
                *rseq_flags = 0;
            } else {
                // Match glibc x86_64 ABI: rseq state lives below TP.
                // offset=0 causes child threads to overwrite the TCB.
                *rseq_offset = -192;
                *rseq_size = 32;
                *rseq_flags = 0;
            }
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            // Keep conservative defaults on other architectures until their
            // exact glibc layout is wired here.
            *rseq_offset = 0;
            *rseq_size = 0;
            *rseq_flags = 0;
        }
        *pointer_chk_guard = 0x9e37_79b9_7f4a_7c15usize;
        *pointer_chk_guard_local = *pointer_chk_guard;
        *stack_chk_guard = 0xd00d_f00d_d00d_f00dusize;

        // Set up a minimal link_map for the executable:
        //   offset 0x00: l_addr (base address)
        //   offset 0x08: l_name (pointer to empty string)
        //   offset 0x10: l_ld (pointer to dynamic section)
        //   offset 0x18: l_next = NULL
        //   offset 0x20: l_prev = NULL
        //   offset 0x28: l_real = self pointer
        //   offset 0x40..0x2E0: l_info[] — pointers to DT entries (leave NULL)
        let link_map_dynamic = exec_dynamic.cast::<DynamicArrayItem>() as *mut DynamicArrayItem;
        *(link_map.byte_add(LINK_MAP_L_ADDR_OFFSET) as *mut usize) = exec_base;
        *(link_map.byte_add(LINK_MAP_L_NAME_OFFSET) as *mut *const u8) = b"\0".as_ptr();
        *(link_map.byte_add(LINK_MAP_L_LD_OFFSET) as *mut *const u8) = link_map_dynamic.cast();
        *(link_map.byte_add(LINK_MAP_L_REAL_OFFSET) as *mut *mut u8) = link_map;
        populate_link_map_dynamic_info(link_map, link_map_dynamic.cast_const());
        *dlfcn_hook.add(0) = ld_stubs::dlopen as *const () as usize;
        *dlfcn_hook.add(1) = ld_stubs::dlsym as *const () as usize;
        *dlfcn_hook.add(2) = ld_stubs::dlclose as *const () as usize;
        *dlfcn_hook.add(3) = ld_stubs::dlvsym as *const () as usize;

        // Set up _rtld_global:
        //   offset 0x00: _dl_ns[0]._ns_loaded = &link_map
        //   offset 0x08: _dl_ns[0]._ns_nloaded = 1
        //   All 16 namespaces: 112 bytes each, total 1792 (0x700)
        //   offset 0x700: _dl_nns = 1
        #[cfg(target_arch = "x86_64")]
        {
            *(rtld_global as *mut *mut u8) = link_map; // _dl_ns[0]._ns_loaded
            *(rtld_global.byte_add(0x08) as *mut u32) = 1; // _dl_ns[0]._ns_nloaded
            *(rtld_global.byte_add(0x700) as *mut usize) = 1; // _dl_nns
            // Older x86_64 glibc releases (for example Ubuntu 20.04 / glibc
            // 2.31) call a pair of tiny lock helpers via `_rtld_global +
            // 0xf08` / `+0xf10` from `_dl_addr@@GLIBC_PRIVATE`.
            // The real loader wires these to increment/decrement the counter
            // at `_rtld_global + 0x908 + 4`.
            *(rtld_global.byte_add(RTLD_GLOBAL_LEGACY_LOCK_OFFSET + 4) as *mut i32) = 0;
            *(rtld_global.byte_add(RTLD_GLOBAL_LEGACY_LOCK_ACQUIRE_OFFSET) as *mut usize) =
                ld_stubs::__rustld_rtld_legacy_lock_acquire as *const () as usize;
            *(rtld_global.byte_add(RTLD_GLOBAL_LEGACY_LOCK_RELEASE_OFFSET) as *mut usize) =
                ld_stubs::__rustld_rtld_legacy_lock_release as *const () as usize;
        }
        // libpthread/glibc fork paths consult multiple rtld-managed intrusive
        // list heads in this region. Model each head as an empty self-linked
        // list to prevent null traversal after fork in child processes.
        #[cfg(target_arch = "x86_64")]
        {
            for offset in [0x800usize, 0x810, 0x820] {
                let head = rtld_global.byte_add(offset) as *mut usize;
                let self_ptr = head as usize;
                *head = self_ptr;
                *head.add(1) = self_ptr;
            }
        }

        // Set up minimal _rtld_global_ro:
        //   offset 0x00: _dl_debug_mask = 0 (no debug)
        //   offset 0x18: _dl_pagesize = 4096
        *(rtld_global_ro.byte_add(0x18) as *mut usize) = 4096; // _dl_pagesize
        // x86_64 glibc changed _rtld_global_ro getauxval-related offsets
        // across releases. Populate both the old 2.31-era layout and the
        // newer layout so distro-specific libc builds can use either path:
        //
        //   glibc 2.31: HWCAP @ +0x58, auxv @ +0x60, HWCAP2 @ +0x1c8
        //   newer glibc: HWCAP @ +0x60, auxv @ +0x68, HWCAP2 @ +0x310
        //
        // Default to the newer layout and switch to the legacy one after
        // we identify an old target glibc family during object loading.
        *(rtld_global_ro.byte_add(0x60) as *mut usize) = hwcap;
        *(rtld_global_ro.byte_add(0x68) as *mut usize) = auxv_storage as usize;
        *(rtld_global_ro.byte_add(0x310) as *mut usize) = hwcap2;
        // glibc sysconf(_SC_MINSIGSTKSZ/_SC_SIGSTKSZ) asserts this is non-zero.
        *(rtld_global_ro.byte_add(0x20) as *mut usize) = minsigstacksize.max(2048);
        // libc dispatches dlfcn helpers through callback slots in
        // _rtld_global_ro. Offsets are architecture-specific.
        *(rtld_global_ro.byte_add(RTLD_RO_LOOKUP_SYMBOL_X_OFFSET) as *mut usize) =
            ld_stubs::__rustld_rtld_lookup_symbol_x_stub as *const () as usize;
        *(rtld_global_ro.byte_add(RTLD_RO_DLOPEN_OFFSET) as *mut usize) =
            ld_stubs::__rustld_rtld_dlopen_stub as *const () as usize;
        *(rtld_global_ro.byte_add(RTLD_RO_DLCLOSE_OFFSET) as *mut usize) =
            ld_stubs::__rustld_rtld_dlclose_stub as *const () as usize;
        *(rtld_global_ro.byte_add(RTLD_RO_CATCH_ERROR_OFFSET) as *mut usize) =
            ld_stubs::__rustld_rtld_catch_error as *const () as usize;
        *(rtld_global_ro.byte_add(RTLD_RO_ERROR_FREE_OFFSET) as *mut usize) =
            ld_stubs::__rustld_rtld_error_free as *const () as usize;
        // __libc_early_init reads static TLS size/alignment from these fields.
        // Keep non-zero defaults to avoid division-by-zero before TLS layout is known.
        *(rtld_global_ro.byte_add(0x2A0) as *mut usize) = 0x1000; // _dl_tls_static_size (default)
        *(rtld_global_ro.byte_add(0x2A8) as *mut usize) = 0x10; // _dl_tls_static_align (default)

        // Snapshot auxv into stable writable storage for libc getauxval().
        let max_auxv_items = (RTLD_DATA_SIZE - 0x40) / core::mem::size_of::<AuxiliaryVectorItem>();
        let copy_count = auxv_count.min(max_auxv_items.saturating_sub(1));
        if copy_count != 0 && !auxv.is_null() {
            core::ptr::copy_nonoverlapping(auxv, auxv_storage, copy_count);
        }
        let terminator = auxv_storage.add(copy_count);
        (*terminator).a_type = AT_NULL;
        core::ptr::write_bytes(
            core::ptr::addr_of_mut!((*terminator).a_un) as *mut u8,
            0,
            core::mem::size_of_val(&(*terminator).a_un),
        );

        let mut secure = 0u32;
        if copy_count != 0 {
            let mut cursor = auxv_storage;
            while (*cursor).a_type != AT_NULL {
                if (*cursor).a_type == AT_RANDOM {
                    let random = (*cursor).a_un.a_val as *const usize;
                    if !random.is_null() {
                        let mut stack_guard = core::ptr::read_unaligned(random);
                        stack_guard &= !0xffusize;
                        *stack_chk_guard = stack_guard;
                        let pointer_guard = core::ptr::read_unaligned(random.add(1));
                        *pointer_chk_guard = pointer_guard;
                        *pointer_chk_guard_local = pointer_guard;
                    }
                }
                if (*cursor).a_type == AT_SECURE {
                    secure = ((*cursor).a_un.a_val != 0) as u32;
                }
                cursor = cursor.add(1);
            }
        }
        *libc_enable_secure = secure;

        Self {
            rtld_global,
            rtld_global_ro,
            link_map,
            link_map_dynamic,
            dlfcn_hook,
            libc_enable_secure,
            libc_stack_end,
            dl_argv,
            rseq_offset,
            rseq_size,
            rseq_flags,
            pointer_chk_guard,
            pointer_chk_guard_local,
            stack_chk_guard,
            auxv: auxv_storage as *const AuxiliaryVectorItem,
            hwcap,
            hwcap2,
        }
    }

    pub(crate) unsafe fn set_argv_and_stack_end(&self, argv: *const *const u8, stack_end: *const u8) {
        *self.dl_argv = argv;
        *self.libc_stack_end = stack_end;
    }

    pub(crate) unsafe fn set_stack_end(&self, stack_end: *const u8) {
        *self.libc_stack_end = stack_end;
    }

    pub(crate) unsafe fn set_tls_static_metadata(&self, tls_static_size: usize, tls_static_align: usize) {
        *(self.rtld_global_ro.byte_add(0x2A0) as *mut usize) = tls_static_size;
        *(self.rtld_global_ro.byte_add(0x2A8) as *mut usize) = tls_static_align.max(1);
    }

    pub(crate) unsafe fn set_rseq_metadata(&self, offset: isize, size: u32, flags: u32) {
        *self.rseq_offset = offset;
        *self.rseq_size = size;
        *self.rseq_flags = flags;
    }

    pub(crate) unsafe fn set_glibc_getauxval_layout(&self, legacy: bool) {
        if legacy {
            *(self.rtld_global_ro.byte_add(0x58) as *mut usize) = self.hwcap;
            *(self.rtld_global_ro.byte_add(0x60) as *mut usize) = self.auxv as usize;
            *(self.rtld_global_ro.byte_add(0x1C8) as *mut usize) = self.hwcap2;
        } else {
            *(self.rtld_global_ro.byte_add(0x60) as *mut usize) = self.hwcap;
            *(self.rtld_global_ro.byte_add(0x68) as *mut usize) = self.auxv as usize;
            *(self.rtld_global_ro.byte_add(0x310) as *mut usize) = self.hwcap2;
        }
    }

    pub(crate) unsafe fn tls_static_metadata(&self) -> (usize, usize) {
        (
            *(self.rtld_global_ro.byte_add(0x2A0) as *const usize),
            *(self.rtld_global_ro.byte_add(0x2A8) as *const usize),
        )
    }

    pub(crate) unsafe fn set_ns_loaded_head(&self, map: *mut u8) {
        *(self.rtld_global.byte_add(0x00) as *mut *mut u8) = map;
    }

    #[inline(always)]
    pub(crate) fn dlfcn_hook_ptr(&self) -> usize {
        self.dlfcn_hook as usize
    }
}
