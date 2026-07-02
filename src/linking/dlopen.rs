use super::*;

impl DynamicLinker {
    #[inline(always)]
    pub(crate) fn trace_rtld_lookup() -> bool {
        static TRACE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        *TRACE.get_or_init(|| std::env::var("RUSTLD_TRACE_RTLD_LOOKUP").is_ok())
    }

    #[inline(always)]
    fn trace_runtime_nss() -> bool {
        static TRACE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        *TRACE.get_or_init(|| std::env::var("RUSTLD_TRACE_RUNTIME_NSS").is_ok())
    }

    #[inline(always)]
    fn trace_runtime_all() -> bool {
        static TRACE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        *TRACE.get_or_init(|| std::env::var("RUSTLD_TRACE_RUNTIME_ALL").is_ok())
    }

    #[inline(always)]
    fn is_runtime_nss_name(name: &str) -> bool {
        let file_name = Path::new(name)
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or(name);
        file_name.starts_with("libnss_")
    }

    #[inline(always)]
    fn allow_unsafe_systemd_nss() -> bool {
        static ALLOW: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        *ALLOW.get_or_init(|| std::env::var("RUSTLD_ALLOW_UNSAFE_SYSTEMD_NSS").is_ok())
    }

    #[inline(always)]
    fn should_skip_runtime_nss_backend(name: &str) -> bool {
        if Self::allow_unsafe_systemd_nss() {
            return false;
        }

        let file_name = Path::new(name)
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or(name);

        if !file_name.starts_with("libnss_") {
            return false;
        }

        !matches!(file_name, "libnss_files.so.2" | "libnss_dns.so.2")
    }

    fn trace_runtime_nss_object_state(&self, stage: &str, object_index: usize) {
        if !(Self::trace_runtime_nss() || Self::trace_runtime_all()) || object_index >= self.objects.len() {
            return;
        }

        let path = self.object_path(object_index).unwrap_or("<unknown>");
        let soname = unsafe { self.objects[object_index].soname_str() }.unwrap_or("<none>");
        if !Self::trace_runtime_all()
            && !Self::is_runtime_nss_name(path)
            && !Self::is_runtime_nss_name(soname)
        {
            return;
        }

        let object = &self.objects[object_index];
        let relocations = object.relocation_slices();
        let tls = object.tls.as_ref();
        unsafe {
            write::write_str(write::STD_ERR, "runtime_nss:");
            write::write_str(write::STD_ERR, stage);
            write::write_str(write::STD_ERR, ": idx=");
            write_trace_dec(object_index);
            write::write_str(write::STD_ERR, " path=");
            write::write_str(write::STD_ERR, path);
            write::write_str(write::STD_ERR, " soname=");
            write::write_str(write::STD_ERR, soname);
            write::write_str(write::STD_ERR, " base=");
            write_trace_hex(object.base);
            write::write_str(write::STD_ERR, " map=");
            write_trace_hex(object.map_start);
            write::write_str(write::STD_ERR, "-");
            write_trace_hex(object.map_end);
            write::write_str(write::STD_ERR, " tls_module=");
            write_trace_dec(tls.map(|value| value.module_id).unwrap_or(0));
            write::write_str(write::STD_ERR, " tls_memsz=");
            write_trace_hex(tls.map(|value| value.memsz).unwrap_or(0));
            write::write_str(write::STD_ERR, " rela=");
            write_trace_dec(relocations.rela_slice.len());
            write::write_str(write::STD_ERR, " relr=");
            write_trace_dec(relocations.relr_slice.len());
            write::write_str(write::STD_ERR, "\n");
        }
    }

    #[inline(always)]
    pub(crate) fn musl_libc_fallback_candidates(name: &str) -> &'static [&'static str] {
        if name != "libc.so" {
            return &[];
        }

        #[cfg(target_arch = "x86_64")]
        {
            return &[
                "/lib/ld-musl-x86_64.so.1",
                "/lib64/ld-musl-x86_64.so.1",
                "/usr/x86_64-linux-musl/lib/ld-musl-x86_64.so.1",
                "/usr/x86_64-linux-musl/lib64/ld-musl-x86_64.so.1",
                "/usr/lib/ld-musl-x86_64.so.1",
            ];
        }

        #[cfg(target_arch = "aarch64")]
        {
            return &[
                "/lib/ld-musl-aarch64.so.1",
                "/lib64/ld-musl-aarch64.so.1",
                "/usr/aarch64-linux-musl/lib/ld-musl-aarch64.so.1",
                "/usr/aarch64-linux-musl/lib64/ld-musl-aarch64.so.1",
                "/usr/lib/ld-musl-aarch64.so.1",
            ];
        }

        #[allow(unreachable_code)]
        &[]
    }

    #[inline(always)]
    pub(crate) fn is_system_bin_dir(dir: &str) -> bool {
        matches!(dir, "/bin" | "/usr/bin" | "/sbin" | "/usr/sbin")
    }

    #[inline(always)]
    pub(crate) fn is_shared_object_soname(name: &str) -> bool {
        let bytes = name.as_bytes();
        for &byte in bytes {
            if byte == b'/' {
                return false;
            }
        }
        let base = name.rsplit('/').next().unwrap_or(name);
        if base.starts_with("ld-linux") || base.starts_with("ld-musl") {
            return true;
        }
        if !base.starts_with("lib") {
            return false;
        }
        let base = base.as_bytes();
        let mut i = 0usize;
        while i + 2 < base.len() {
            if base[i] == b'.' && base[i + 1] == b's' && base[i + 2] == b'o' {
                return true;
            }
            i += 1;
        }
        false
    }

    unsafe fn runtime_init_args(
        &self,
    ) -> (
        usize,
        *const *const u8,
        *const *const u8,
        *const AuxiliaryVectorItem,
    ) {
        let argv = self
            .rtld_stubs
            .as_ref()
            .map(|stubs| *stubs.dl_argv)
            .unwrap_or(core::ptr::null());
        let mut argc = 0usize;
        if !argv.is_null() {
            while argc < 4096 {
                let current = *argv.add(argc);
                if current.is_null() {
                    break;
                }
                argc += 1;
            }
        }
        let env = crate::libc::environ::get_environ_pointer() as *const *const u8;
        let auxv = self
            .rtld_stubs
            .as_ref()
            .map(|stubs| stubs.auxv)
            .unwrap_or(core::ptr::null());
        (argc, argv, env, auxv)
    }

    pub unsafe fn rtld_dlfcn_hook(&self) -> Option<usize> {
        self.rtld_stubs
            .as_ref()
            .map(|stubs| stubs.dlfcn_hook_ptr())
    }

    pub(crate) fn resolve_object_dependency_indices(&self, idx: usize) -> SmallVec<[usize; 16]> {
        let mut deps = SmallVec::<[usize; 16]>::new();
        if idx >= self.objects.len() {
            return deps;
        }

        let object = &self.objects[idx];
        for &needed_offset in &object.needed_libraries {
            let needed_name = unsafe { object.string_table.get(needed_offset) };
            if needed_name.is_empty() {
                continue;
            }
            let Some(dep_idx) = self.loaded_index(needed_name) else {
                continue;
            };
            if dep_idx >= self.objects.len() || dep_idx == idx || deps.contains(&dep_idx) {
                continue;
            }
            deps.push(dep_idx);
        }

        deps
    }

    pub(crate) unsafe fn dependency_init_order(&self, start_idx: usize) -> SmallVec<[usize; 32]> {
        fn visit(
            idx: usize,
            start_idx: usize,
            linker: &DynamicLinker,
            state: &mut [u8],
            order: &mut SmallVec<[usize; 32]>,
        ) {
            if idx < start_idx || idx >= linker.objects.len() {
                return;
            }
            match state[idx] {
                1 | 2 => return,
                _ => {}
            }
            state[idx] = 1;

            for dep_idx in linker.resolve_object_dependency_indices(idx) {
                if dep_idx < linker.objects.len() && dep_idx != idx {
                    visit(dep_idx, start_idx, linker, state, order);
                }
            }

            state[idx] = 2;
            order.push(idx);
        }

        let mut state = vec![0u8; self.objects.len()];
        let mut order = SmallVec::<[usize; 32]>::new();
        order.reserve(self.objects.len().saturating_sub(start_idx));
        for idx in start_idx..self.objects.len() {
            visit(idx, start_idx, self, &mut state, &mut order);
        }
        order
    }

    pub unsafe fn new() -> Self {
        Self {
            objects: Vec::new(),
            library_map: Vec::new(),
            library_alias_index: FxHashMap::default(),
            object_paths: Vec::new(),
            object_link_maps: Vec::new(),
            object_link_map_dynamics: Vec::new(),
            object_link_map_names: Vec::new(),
            lookup_scopes: Vec::new(),
            rtld_stubs: None,
        }
    }

    fn visit_scope_indices(&self, idx: usize, seen: &mut [u8], order: &mut Vec<usize>) {
        if idx >= self.objects.len() || seen[idx] != 0 {
            return;
        }
        seen[idx] = 1;
        if idx != 0 {
            order.push(idx);
        }

        for dep_idx in self.resolve_object_dependency_indices(idx) {
            if dep_idx < self.objects.len() && dep_idx != idx {
                self.visit_scope_indices(dep_idx, seen, order);
            }
        }
    }

    pub fn rebuild_lookup_scopes(&mut self) {
        let object_count = self.objects.len();
        let mut new_lookup_scopes = Vec::with_capacity(object_count);
        new_lookup_scopes.resize_with(object_count, Vec::new);
        if object_count == 0 {
            let old_lookup_scopes = core::mem::replace(&mut self.lookup_scopes, new_lookup_scopes);
            core::mem::forget(old_lookup_scopes);
            return;
        }

        let mut seen = vec![0u8; object_count];
        for requester in 0..object_count {
            seen.fill(0);
            let mut order = Vec::with_capacity(object_count);

            // glibc-style global preemption: executable first.
            seen[0] = 1;
            order.push(0);

            self.visit_scope_indices(requester, &mut seen, &mut order);

            // Then remaining globals in load order.
            for idx in 1..object_count {
                if seen[idx] == 0 {
                    seen[idx] = 1;
                    order.push(idx);
                }
            }
            new_lookup_scopes[requester] = order;
        }

        let old_lookup_scopes = core::mem::replace(&mut self.lookup_scopes, new_lookup_scopes);
        core::mem::forget(old_lookup_scopes);
    }

    /// Initialize the rtld stubs using the executable's base and dynamic section.
    #[inline(always)]
    pub unsafe fn init_rtld_stubs(
        &mut self,
        exec_base: usize,
        exec_dynamic: *const u8,
        argv: *const *const u8,
        stack_end: *const u8,
        minsigstacksize: usize,
        auxv: *const AuxiliaryVectorItem,
        auxv_count: usize,
        hwcap: usize,
        hwcap2: usize,
    ) {
        let stubs = RtldStubs::new(
            exec_base,
            exec_dynamic,
            minsigstacksize,
            auxv,
            auxv_count,
            hwcap,
            hwcap2,
        );
        stubs.set_argv_and_stack_end(argv, stack_end);
        ld_stubs::set_r_debug_ldbase(exec_base);
        self.rtld_stubs = Some(stubs);
    }

    /// Initialize TLS for all loaded objects and install the thread pointer.
    pub unsafe fn prepare_tls_layout(&mut self) {
        tls::prepare_tls_layout(&mut self.objects);
        let layout = tls::tls_layout();
        if let Some(stubs) = self.rtld_stubs.as_ref() {
            #[cfg(target_arch = "x86_64")]
            if disable_rseq_metadata() || self.loaded_legacy_glibc_family() {
                stubs.set_rseq_metadata(0, 0, 0);
            } else {
                stubs.set_rseq_metadata(-192, 32, 0);
            }
            #[cfg(not(target_arch = "x86_64"))]
            stubs.set_rseq_metadata(0, 0, 0);
        }
        if let (Some(stubs), Some(layout)) = (self.rtld_stubs.as_ref(), layout) {
            let tls_static_size = layout.tls_size
                + core::mem::size_of::<crate::elf::thread_local_storage::ThreadControlBlock>();
            #[cfg(debug_assertions)]
            {
                eprintln!(
                    "loader: tls metadata size={} align={} modules={}",
                    tls_static_size, layout.max_align, layout.module_count
                );
            }
            stubs.set_tls_static_metadata(tls_static_size, layout.max_align);
        }
    }

    pub unsafe fn install_tls(&self, pseudorandom_bytes: *const [u8; 16]) {
        tls::install_tls(&self.objects, pseudorandom_bytes);
    }

    pub unsafe fn update_rtld_stack_end(&self, stack_end: *const u8) {
        if let Some(stubs) = self.rtld_stubs.as_ref() {
            stubs.set_stack_end(stack_end);
        }
    }

    pub(crate) fn map_alias(&mut self, alias: String, index: usize) {
        // Preserve first-seen alias resolution semantics.
        let base_name = Path::new(alias.as_str())
            .file_name()
            .and_then(|name| name.to_str())
            .map(|value| value.to_owned());
        if self.library_alias_index.insert(alias.clone(), index).is_none() {
            self.library_map.push((alias, index));
        }

        if let Some(base) = base_name {
            self.library_alias_index.entry(base).or_insert(index);
        }
    }

    pub(crate) fn normalize_existing_path(path: &str) -> String {
        path.to_string()
    }

    pub(crate) fn alternate_system_lib_prefix(path: &str) -> Option<String> {
        if let Some(suffix) = path.strip_prefix("/lib64/") {
            return Some(format!("/usr/lib64/{suffix}"));
        }
        if let Some(suffix) = path.strip_prefix("/usr/lib64/") {
            return Some(format!("/lib64/{suffix}"));
        }
        if let Some(suffix) = path.strip_prefix("/lib/") {
            return Some(format!("/usr/lib/{suffix}"));
        }
        if let Some(suffix) = path.strip_prefix("/usr/lib/") {
            return Some(format!("/lib/{suffix}"));
        }
        None
    }

    unsafe fn publish_dt_debug(&mut self, index: usize) {
        if index >= self.objects.len() {
            return;
        }
        let dynamic = self.objects[index].dynamic as *mut DynamicArrayItem;
        if dynamic.is_null() {
            return;
        }
        let mut cursor = dynamic;
        loop {
            let item = *cursor;
            if item.d_tag == DT_NULL {
                break;
            }
            if item.d_tag == DT_DEBUG {
                (*cursor).d_un.d_ptr = ld_stubs::r_debug_ptr();
                break;
            }
            cursor = cursor.add(1);
        }
    }

    pub(crate) fn install_link_map_for_object(&mut self, index: usize, name_hint: &str) {
        let c_name = CString::new(name_hint).unwrap_or_else(|_| CString::new("<invalid>").unwrap());
        let raw_name = c_name.into_raw();

        let mut previous = self
            .object_link_maps
            .last()
            .copied()
            .unwrap_or(core::ptr::null_mut());
        if !previous.is_null() && (previous as usize) % core::mem::align_of::<usize>() != 0 {
            previous = core::ptr::null_mut();
        }
        let map = unsafe {
            mmap(
                null_mut(),
                LINK_MAP_SIZE,
                PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if map.is_null() || (map as isize) < 0 {
            unsafe {
                write::write_str(
                    write::STD_ERR,
                    "Error: could not allocate runtime link_map\n",
                );
            }
            exit::exit(1);
        }
        unsafe {
            let dynamic_ptr = self.objects[index].dynamic as usize;
            let dynamic_for_link_map = if dynamic_ptr == 0
                || (dynamic_ptr % core::mem::align_of::<DynamicArrayItem>() != 0)
            {
                core::ptr::null()
            } else {
                self.objects[index].dynamic
            };
            let dynamic_copy =
                if legacy_glibc_link_map_needs_absolute_dynamic(name_hint) {
                    create_link_map_dynamic_copy(self.objects[index].base, dynamic_for_link_map)
                } else {
                    core::ptr::null_mut()
                };
            let link_map_dynamic = if dynamic_copy.is_null() {
                dynamic_for_link_map as *mut DynamicArrayItem
            } else {
                dynamic_copy
            };
            *(map.byte_add(LINK_MAP_L_ADDR_OFFSET) as *mut usize) = self.objects[index].base;
            *(map.byte_add(LINK_MAP_L_NAME_OFFSET) as *mut *const c_char) = raw_name;
            *(map.byte_add(LINK_MAP_L_LD_OFFSET) as *mut *const c_void) =
                link_map_dynamic as *const c_void;
            *(map.byte_add(LINK_MAP_L_NEXT_OFFSET) as *mut *mut u8) = core::ptr::null_mut();
            *(map.byte_add(LINK_MAP_L_PREV_OFFSET) as *mut *mut u8) = previous;
            *(map.byte_add(LINK_MAP_L_REAL_OFFSET) as *mut *mut u8) = map;
            populate_link_map_dynamic_info(map, link_map_dynamic.cast_const());

            if !previous.is_null() {
                *(previous.byte_add(LINK_MAP_L_NEXT_OFFSET) as *mut *mut u8) = map;
            }
            if index == 0 {
                if let Some(stubs) = self.rtld_stubs.as_ref() {
                    *(stubs.rtld_global as *mut *mut u8) = map;
                }
                ld_stubs::set_r_debug_map(map.cast());
                self.publish_dt_debug(index);
            }
        }

        self.object_link_maps.push(map);
        self.object_link_map_dynamics.push(unsafe {
            *(map.byte_add(LINK_MAP_L_LD_OFFSET) as *const *mut DynamicArrayItem)
        });
        self.object_link_map_names.push(raw_name);

        // Expose the real loaded-object list head to libc/libdl helpers.
        if index == 0 {
            if let Some(stubs) = self.rtld_stubs.as_ref() {
                unsafe {
                    stubs.set_ns_loaded_head(map);
                }
            }
        }
    }
    pub(crate) unsafe fn load_library_with_requester(
        &mut self,
        name: &str,
        requester_idx: Option<usize>,
        allow_selinux_stub: bool,
    ) -> Result<usize, &'static str> {
        if let Some(idx) = self.loaded_index(name) {
            #[cfg(debug_assertions)]
            {
                use crate::libc::fs::write;
                write::write_str(write::STD_ERR, "loader: load_library hit ");
                write::write_str(write::STD_ERR, name);
                write::write_str(write::STD_ERR, " -> existing\n");
            }
            return Ok(idx);
        }

        if allow_selinux_stub
            && Self::selinux_stub_enabled()
            && Self::should_stub_selinux_library(name)
        {
            self.map_alias(name.to_string(), usize::MAX);
            return Ok(usize::MAX);
        }

        if cfg!(target_arch = "x86_64") && name.starts_with("ld-linux") {
            self.map_alias(name.to_string(), usize::MAX);
            return Ok(usize::MAX);
        }

        let (path, fd) = match self.resolve_library_path_with_fd(name, requester_idx) {
            Some(found) => found,
            None => {
                #[cfg(debug_assertions)]
                {
                    use crate::libc::fs::write;
                    write::write_str(write::STD_ERR, "loader: resolve failed name=");
                    write::write_str(write::STD_ERR, name);
                    write::write_str(write::STD_ERR, " requester=");
                    if let Some(idx) = requester_idx {
                        if let Some(path) = self.object_path(idx) {
                            write::write_str(write::STD_ERR, path);
                        } else {
                            write::write_str(write::STD_ERR, "<none>");
                        }
                    } else {
                        write::write_str(write::STD_ERR, "<root>");
                    }
                    write::write_str(write::STD_ERR, "\n");
                }
                return Err("library not found");
            }
        };
        if let Some(idx) = self.loaded_index(&path) {
            Self::close_fd(fd);
            #[cfg(debug_assertions)]
            {
                use crate::libc::fs::write;
                write::write_str(write::STD_ERR, "loader: load_library path-hit ");
                write::write_str(write::STD_ERR, &path);
                write::write_str(write::STD_ERR, " -> existing\n");
            }
            self.map_alias(name.to_string(), idx);
            return Ok(idx);
        }

        #[cfg(debug_assertions)]
        {
            use crate::libc::fs::write;
            write::write_str(write::STD_ERR, "loader: load_library miss ");
            write::write_str(write::STD_ERR, name);
            write::write_str(write::STD_ERR, " resolved=");
            write::write_str(write::STD_ERR, &path);
            write::write_str(write::STD_ERR, "\n");
        }

        let object = SharedObject::from_fd(fd);
        Self::close_fd(fd);

        let needed_offsets: SmallVec<[usize; 16]> =
            object.needed_libraries.iter().copied().collect();
        let string_table = object.string_table;

        let idx = self.add_object_with_path(name.to_string(), Some(path), object);
        let mut resolved_dependencies = Vec::with_capacity(needed_offsets.len());
        for needed_offset in needed_offsets {
            let needed_name = string_table.get(needed_offset);
            if needed_name.is_empty() {
                continue;
            }
            let needed_name = needed_name.to_string();
            let dep_idx =
                self.load_library_with_requester(&needed_name, Some(idx), allow_selinux_stub)?;
            if dep_idx < self.objects.len() && dep_idx != idx {
                resolved_dependencies.push(dep_idx);
            }
        }
        self.objects[idx].resolved_dependencies = resolved_dependencies;

        Ok(idx)
    }

    #[inline(always)]
    fn should_stub_selinux_library(name: &str) -> bool {
        name == "libselinux.so.1" || name.ends_with("/libselinux.so.1")
    }

    #[inline(always)]
    fn selinux_stub_enabled() -> bool {
        false
    }

    pub unsafe fn load_library(
        &mut self,
        name: &str,
        _pseudorandom_bytes: *const [u8; 16],
        requester_idx: Option<usize>,
    ) {
        if self.is_loaded(name) {
            return;
        }
        if self
            .load_library_with_requester(name, requester_idx, true)
            .is_err()
        {
            write::write_str(write::STD_ERR, "Error: Could not find library: ");
            write::write_str(write::STD_ERR, name);
            write::write_str(write::STD_ERR, "\n");
            exit::exit(1);
        }
    }

    unsafe fn load_library_runtime_inner(
        &mut self,
        name: &str,
        requester_idx: Option<usize>,
    ) -> Result<usize, &'static str> {
        if Self::should_skip_runtime_nss_backend(name) {
            if Self::trace_runtime_nss() || Self::trace_runtime_all() {
                unsafe {
                    write::write_str(write::STD_ERR, "runtime_nss:skip file=");
                    write::write_str(write::STD_ERR, name);
                    write::write_str(write::STD_ERR, "\n");
                }
            }
            return Err("runtime nss backend disabled");
        }
        self.load_library_with_requester(name, requester_idx, false)
    }

    pub unsafe fn dlopen_runtime(&mut self, file: &str, _mode: i32) -> Result<usize, &'static str> {
        if file.is_empty() {
            return Ok(0);
        }

        if Self::trace_runtime_nss() && Self::is_runtime_nss_name(file) {
            unsafe {
                write::write_str(write::STD_ERR, "runtime_nss:dlopen:start file=");
                write::write_str(write::STD_ERR, file);
                write::write_str(write::STD_ERR, "\n");
            }
        }

        let start_idx = self.objects.len();
        let root_idx = self.load_library_runtime_inner(file, None)?;
        if root_idx == usize::MAX {
            return Err("unsupported runtime object");
        }
        if start_idx >= self.objects.len() {
            return Ok(root_idx);
        }

        if Self::trace_runtime_nss() {
            unsafe {
                write::write_str(write::STD_ERR, "runtime_nss:dlopen:loaded file=");
                write::write_str(write::STD_ERR, file);
                write::write_str(write::STD_ERR, " start_idx=");
                write_trace_dec(start_idx);
                write::write_str(write::STD_ERR, " root_idx=");
                write_trace_dec(root_idx);
                write::write_str(write::STD_ERR, " new_objects=");
                write_trace_dec(self.objects.len().saturating_sub(start_idx));
                write::write_str(write::STD_ERR, "\n");
            }
            for idx in start_idx..self.objects.len() {
                self.trace_runtime_nss_object_state("loaded", idx);
            }
        }

        self.rebuild_lookup_scopes();

        let new_objects_have_tls = self.objects[start_idx..]
            .iter()
            .any(|object| object.tls.is_some());
        if new_objects_have_tls {
            if Self::trace_runtime_nss() {
                unsafe {
                    write::write_str(write::STD_ERR, "runtime_nss:tls:register:start root_idx=");
                    write_trace_dec(root_idx);
                    write::write_str(write::STD_ERR, "\n");
                }
            }
            tls::register_runtime_tls_modules(&mut self.objects[start_idx..])?;
            if Self::trace_runtime_nss() {
                unsafe {
                    write::write_str(write::STD_ERR, "runtime_nss:tls:register:done root_idx=");
                    write_trace_dec(root_idx);
                    write::write_str(write::STD_ERR, "\n");
                }
                for idx in start_idx..self.objects.len() {
                    self.trace_runtime_nss_object_state("post-register-tls", idx);
                }
            }
        }

        let mut ifuncs = Vec::new();
        let mut copies = Vec::new();
        let lookup_cache_capacity = self.objects[start_idx..]
            .iter()
            .map(|object| {
                let slices = object.relocation_slices();
                slices.rela_slice.len() + (slices.relr_slice.len() / 2)
            })
            .sum::<usize>()
            .max(1024);
        let mut lookup_cache = relocation::SymbolLookupCache::with_capacity(lookup_cache_capacity);
        let relocation_indices: Vec<usize> = (start_idx..self.objects.len()).collect();
        for obj_idx in relocation_indices {
            let object_snapshot = self.objects[obj_idx].clone();
            self.trace_runtime_nss_object_state("relocate:start", obj_idx);
            relocation::relocate_with_linker(
                &object_snapshot,
                obj_idx,
                self,
                &mut ifuncs,
                &mut copies,
                &mut lookup_cache,
            );
            self.trace_runtime_nss_object_state("relocate:done", obj_idx);
            core::mem::forget(object_snapshot);
        }
        relocation::apply_copy_relocations(&copies);
        relocation::apply_irelative_relocations(&ifuncs);
        if new_objects_have_tls {
            if Self::trace_runtime_nss() {
                unsafe {
                    write::write_str(write::STD_ERR, "runtime_nss:tls:finalize:start root_idx=");
                    write_trace_dec(root_idx);
                    write::write_str(write::STD_ERR, "\n");
                }
            }
            tls::finalize_runtime_tls_images(&self.objects[start_idx..])?;
            if Self::trace_runtime_nss() {
                unsafe {
                    write::write_str(write::STD_ERR, "runtime_nss:tls:finalize:done root_idx=");
                    write_trace_dec(root_idx);
                    write::write_str(write::STD_ERR, "\n");
                }
            }
        }

        // Run init in dependency order rooted at the object requested by
        // dlopen, mirroring glibc's behavior more closely for plugin trees.
        // Falling back to start_idx keeps behavior sane if root_idx is older.
        let init_root = root_idx.max(start_idx);
        let (arg_count, arg_pointer, env_pointer, auxv_pointer) = self.runtime_init_args();
        let skip_selinux_init = skip_selinux_ctors();
        for idx in self.dependency_init_order(init_root) {
            if skip_selinux_init
                && self.objects[idx]
                    .soname_str()
                    .is_some_and(|soname| soname == "libselinux.so.1")
            {
                continue;
            }
            self.objects[idx].call_init_functions(
                arg_count,
                arg_pointer,
                env_pointer,
                auxv_pointer,
            );
        }

        Ok(root_idx)
    }
}
