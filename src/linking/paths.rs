use super::*;

impl DynamicLinker {
    #[inline(always)]
    fn host_elf_machine() -> u16 {
        #[cfg(target_arch = "x86_64")]
        {
            62 // EM_X86_64
        }
        #[cfg(target_arch = "aarch64")]
        {
            183 // EM_AARCH64
        }
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        {
            0
        }
    }

    #[inline(always)]
    unsafe fn fd_matches_host_arch(fd: i32) -> bool {
        let mut uninit = MaybeUninit::<ElfHeader>::uninit();
        let header_bytes =
            core::slice::from_raw_parts_mut(uninit.as_mut_ptr() as *mut u8, size_of::<ElfHeader>());

        let read = arch::pread(fd, header_bytes.as_mut_ptr(), header_bytes.len(), 0);
        if read != size_of::<ElfHeader>() as isize {
            return false;
        }

        let header = uninit.assume_init();
        if header.e_ident[0..4] != [0x7f, b'E', b'L', b'F'] {
            return false;
        }

        // rustld only supports little-endian 64-bit ELF objects here.
        if header.e_ident[4] != 2 || header.e_ident[5] != 1 {
            return false;
        }

        let expected_machine = Self::host_elf_machine();
        expected_machine == 0 || header.e_machine == expected_machine
    }

    fn parse_ld_so_conf_file(
        path: &Path,
        out_paths: &mut Vec<String>,
        seen_files: &mut FxHashSet<String>,
        depth: usize,
    ) {
        if depth == 0 {
            return;
        }

        let path_key = path.to_string_lossy().into_owned();
        if !seen_files.insert(path_key) {
            return;
        }

        let Ok(content) = fs::read_to_string(path) else {
            return;
        };

        for raw_line in content.lines() {
            let line = raw_line.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }

            if let Some(include_pattern) = line.strip_prefix("include ") {
                let include_pattern = include_pattern.trim();
                if include_pattern.is_empty() {
                    continue;
                }
                Self::parse_ld_so_conf_include(include_pattern, out_paths, seen_files, depth - 1);
                continue;
            }

            if line.starts_with('/') {
                let dir = line.trim_end_matches('/').to_string();
                if !out_paths.iter().any(|existing| existing == &dir) {
                    out_paths.push(dir);
                }
            }
        }
    }

    fn parse_ld_so_conf_include(
        pattern: &str,
        out_paths: &mut Vec<String>,
        seen_files: &mut FxHashSet<String>,
        depth: usize,
    ) {
        let path = Path::new(pattern);
        if !pattern.contains('*') {
            Self::parse_ld_so_conf_file(path, out_paths, seen_files, depth);
            return;
        }

        let parent = path.parent().unwrap_or_else(|| Path::new("/"));
        let file_pattern = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("");
        let (prefix, suffix) = file_pattern
            .split_once('*')
            .map(|(p, s)| (p.to_string(), s.to_string()))
            .unwrap_or_else(|| (file_pattern.to_string(), String::new()));

        let Ok(entries) = fs::read_dir(parent) else {
            return;
        };

        for entry in entries.flatten() {
            let entry_path = entry.path();
            let file_name = entry_path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("");
            if file_name.starts_with(&prefix) && file_name.ends_with(&suffix) {
                Self::parse_ld_so_conf_file(&entry_path, out_paths, seen_files, depth);
            }
        }
    }

    fn configured_library_paths() -> &'static [String] {
        CONFIGURED_LIBRARY_PATHS.get_or_init(|| {
            let mut paths = Vec::new();
            let mut seen_files = FxHashSet::default();

            Self::parse_ld_so_conf_file(
                Path::new("/etc/ld.so.conf"),
                &mut paths,
                &mut seen_files,
                8,
            );

            // Fallback for setups where /etc/ld.so.conf is missing.
            if paths.is_empty() {
                Self::parse_ld_so_conf_include(
                    "/etc/ld.so.conf.d/*.conf",
                    &mut paths,
                    &mut seen_files,
                    8,
                );
            }

            paths
        })
    }
    pub fn add_object_with_path(
        &mut self,
        name: String,
        object_path: Option<String>,
        object: SharedObject,
    ) -> usize {
        let index = self.objects.len();
        self.objects.push(object);
        self.object_paths.push(object_path.clone());
        let link_name = object_path
            .as_ref()
            .map(|path| path.as_str())
            .unwrap_or(name.as_str())
            .to_string();
        if let Some(stubs) = self.rtld_stubs.as_ref() {
            if matches!(glibc_dso_version(&link_name), Some((2, minor)) if minor <= 31) {
                unsafe {
                    stubs.set_glibc_getauxval_layout(true);
                    stubs.set_rseq_metadata(0, 0, 0);
                }
            }
        }
        if self.rtld_stubs.is_some() {
            self.install_link_map_for_object(index, &link_name);
        } else {
            // musl-target path: runtime dl* stubs can use synthetic handles.
            self.object_link_maps.push(core::ptr::null_mut());
            self.object_link_map_dynamics.push(core::ptr::null_mut());
            self.object_link_map_names.push(core::ptr::null_mut());
        }
        self.map_alias(name, index);
        if let Some(path) = object_path {
            self.map_alias(path.clone(), index);
            if let Some(alt) = Self::alternate_system_lib_prefix(&path) {
                self.map_alias(alt, index);
            }
        }
        if let Some(soname) = unsafe { self.objects[index].soname_str() } {
            self.map_alias(soname.to_string(), index);
        }
        // Topology changed; caller should rebuild scopes before heavy lookup phase.
        let old_lookup_scopes = core::mem::take(&mut self.lookup_scopes);
        core::mem::forget(old_lookup_scopes);
        index
    }

    pub fn loaded_index(&self, name: &str) -> Option<usize> {
        let base_name = strip_version_suffix(name);
        if base_name != name {
            if let Some(idx) = self.library_alias_index.get(base_name).copied() {
                return Some(idx);
            }
        }

        if let Some(idx) = self.library_alias_index.get(name).copied() {
            return Some(idx);
        }

        if let Some(alt_name) = Self::alternate_system_lib_prefix(name) {
            if let Some(idx) = self.library_alias_index.get(alt_name.as_str()).copied() {
                return Some(idx);
            }
        }
        None
    }

    pub fn object_path(&self, index: usize) -> Option<&str> {
        self.object_paths.get(index)?.as_deref()
    }

    pub(crate) fn is_loaded(&self, name: &str) -> bool {
        self.library_alias_index.contains_key(name)
    }

    fn open_path(path: &str) -> Option<i32> {
        let mut stack_buf = [0u8; 512];
        let path_bytes = path.as_bytes();
        let (ptr, _owned);
        if path_bytes.len() + 1 <= stack_buf.len() {
            stack_buf[..path_bytes.len()].copy_from_slice(path_bytes);
            stack_buf[path_bytes.len()] = 0;
            ptr = stack_buf.as_ptr() as *const c_char;
            _owned = None;
        } else {
            let owned = CString::new(path).ok()?;
            ptr = owned.as_ptr();
            _owned = Some(owned);
        }

        let fd = unsafe { Self::openat_raw(ptr) };
        if fd < 0 {
            return None;
        }
        let fd = fd as i32;
        if unsafe { !Self::fd_matches_host_arch(fd) } {
            unsafe { Self::close_fd(fd) };
            return None;
        }
        Some(fd)
    }

    pub(crate) unsafe fn close_fd(fd: i32) {
        arch::close_fd(fd);
    }

    fn object_origin_dir(&self, object_idx: usize) -> Option<&str> {
        let path = self.object_paths.get(object_idx)?.as_ref()?;
        Path::new(path).parent().and_then(|parent| parent.to_str())
    }

    fn resolve_absolute_runtime_dlopen_fallback(&self, requested: &str) -> Option<(String, i32)> {
        let requested_path = Path::new(requested);
        if !requested_path.is_absolute() {
            return None;
        }

        // Runtime launchers (for example jpackage-style binaries) often derive
        // "<self>/../lib/<launcher>.so" from /proc/self/exe. In rustld
        // in-process mode, /proc/self/exe is still rustld, so retry relative
        // to the mapped target executable directory when that shape fails.
        let requested_parent = requested_path.parent()?;
        let requested_dir = requested_parent.file_name()?.to_str()?;
        if requested_dir != "lib" && requested_dir != "lib64" {
            return None;
        }

        let soname = requested_path.file_name()?.to_str()?;
        let executable_path = self.object_path(0)?;
        let executable_dir = Path::new(executable_path).parent()?;
        let candidate_dirs = [
            executable_dir.join("lib"),
            executable_dir.join("lib64"),
            executable_dir.join("..").join("lib"),
            executable_dir.join("..").join("lib64"),
        ];

        for dir in candidate_dirs {
            let candidate = dir.join(soname);
            let Some(candidate_str) = candidate.to_str() else {
                continue;
            };
            if let Some(fd) = Self::open_path(candidate_str) {
                #[cfg(debug_assertions)]
                {
                    use crate::libc::fs::write;
                    unsafe {
                        write::write_str(write::STD_ERR, "loader: dlopen path fallback ");
                        write::write_str(write::STD_ERR, requested);
                        write::write_str(write::STD_ERR, " -> ");
                        write::write_str(write::STD_ERR, candidate_str);
                        write::write_str(write::STD_ERR, "\n");
                    }
                }
                return Some((Self::normalize_existing_path(candidate_str), fd));
            }
        }
        None
    }

    fn expand_origin_token<'a>(path: &'a str, origin: Option<&str>) -> Option<Cow<'a, str>> {
        if !path.contains("$ORIGIN") && !path.contains("${ORIGIN}") {
            return Some(Cow::Borrowed(path));
        }
        let origin = origin?;
        Some(Cow::Owned(
            path.replace("${ORIGIN}", origin).replace("$ORIGIN", origin),
        ))
    }

    fn try_open_from_search_list(
        &self,
        raw_list: &str,
        origin: Option<&str>,
        name: &str,
    ) -> Option<(String, i32)> {
        for entry in raw_list.split(':') {
            if entry.is_empty() {
                continue;
            }
            if let Some(expanded) = Self::expand_origin_token(entry, origin) {
                if let Some(found) = Self::open_joined_path(expanded.as_ref(), name) {
                    return Some(found);
                }
            }
        }
        None
    }

    fn env_var_from_environ(cache: &'static OnceLock<Option<String>>, key: &str) -> Option<&'static str> {
        cache
            .get_or_init(|| {
                let env_pointer = unsafe { crate::libc::environ::get_environ_pointer() };
                if env_pointer.is_null() {
                    return None;
                }

                let mut prefix = String::with_capacity(key.len() + 1);
                prefix.push_str(key);
                prefix.push('=');
                let prefix = prefix.into_bytes();

                let mut cursor = env_pointer;
                while unsafe { !(*cursor).is_null() } {
                    let entry_ptr = unsafe { *cursor } as *const c_char;
                    let entry = unsafe { CStr::from_ptr(entry_ptr).to_bytes() };
                    if let Some(value) = entry.strip_prefix(prefix.as_slice()) {
                        if let Ok(text) = core::str::from_utf8(value) {
                            return Some(text.to_string());
                        }
                    }
                    cursor = unsafe { cursor.add(1) };
                }
                None
            })
            .as_deref()
    }

    fn rustld_library_path_from_env() -> Option<&'static str> {
        Self::env_var_from_environ(&RUSTLD_LIBRARY_PATH, "RUSTLD_LIBRARY_PATH")
    }

    fn ld_library_path_from_env() -> Option<&'static str> {
        Self::env_var_from_environ(&LD_LIBRARY_PATH, "LD_LIBRARY_PATH")
    }

    unsafe fn openat_raw(path_ptr: *const c_char) -> isize {
        arch::openat_readonly(path_ptr) as isize
    }

    pub(crate) fn resolve_library_path_with_fd(
        &self,
        name: &str,
        requester_idx: Option<usize>,
    ) -> Option<(String, i32)> {
        if name.contains('/') {
            if let Some(fd) = Self::open_path(name) {
                return Some((Self::normalize_existing_path(name), fd));
            }
            return self.resolve_absolute_runtime_dlopen_fallback(name);
        }

        let origin = requester_idx.and_then(|idx| self.object_origin_dir(idx));
        let (runpath, rpath) = if let Some(idx) = requester_idx {
            let object = &self.objects[idx];
            unsafe { (object.runpath_str(), object.rpath_str()) }
        } else {
            (None, None)
        };

        if runpath.is_none() {
            if let Some(rpath_value) = rpath {
                if let Some(found) = self.try_open_from_search_list(rpath_value, origin, name) {
                    return Some(found);
                }
            }
        }

        if let Some(rustld_library_path) = Self::rustld_library_path_from_env() {
            if let Some(found) = self.try_open_from_search_list(rustld_library_path, origin, name) {
                return Some(found);
            }
        }

        if let Some(ld_library_path) = Self::ld_library_path_from_env() {
            if let Some(found) = self.try_open_from_search_list(ld_library_path, origin, name) {
                return Some(found);
            }
        }

        if let Some(runpath_value) = runpath {
            if let Some(found) = self.try_open_from_search_list(runpath_value, origin, name) {
                return Some(found);
            }
        }

        let skip_system_origin_probe =
            Self::is_shared_object_soname(name) && origin.is_some_and(Self::is_system_bin_dir);

        if let Some(origin_dir) = origin {
            if !skip_system_origin_probe {
                if let Some(found) = Self::open_joined_path(origin_dir, name) {
                    return Some(found);
                }
            }
        }
        if let Some(main_origin) = self.object_origin_dir(0) {
            let skip_main_origin_probe =
                Self::is_shared_object_soname(name) && Self::is_system_bin_dir(main_origin);
            if origin != Some(main_origin) && !skip_main_origin_probe {
                if let Some(found) = Self::open_joined_path(main_origin, name) {
                    return Some(found);
                }
            }
        }

        for default_dir in DEFAULT_LIBRARY_PATHS {
            if let Some(found) = Self::open_joined_path(default_dir, name) {
                return Some(found);
            }
        }

        for configured_dir in Self::configured_library_paths() {
            if let Some(found) = Self::open_joined_path(configured_dir, name) {
                return Some(found);
            }
        }

        for fallback in Self::musl_libc_fallback_candidates(name) {
            if let Some(fd) = Self::open_path(fallback) {
                return Some(((*fallback).to_string(), fd));
            }
        }

        None
    }

    fn open_joined_path(dir: &str, file: &str) -> Option<(String, i32)> {
        let needs_sep = !dir.ends_with('/');
        let total_len = dir.len() + usize::from(needs_sep) + file.len();
        if total_len + 1 <= 1024 {
            let mut stack_buf = [0u8; 1024];
            let mut pos = 0usize;
            stack_buf[..dir.len()].copy_from_slice(dir.as_bytes());
            pos += dir.len();
            if needs_sep {
                stack_buf[pos] = b'/';
                pos += 1;
            }
            stack_buf[pos..pos + file.len()].copy_from_slice(file.as_bytes());
            pos += file.len();
            stack_buf[pos] = 0;

            let fd = unsafe { Self::openat_raw(stack_buf.as_ptr() as *const c_char) };
            if fd >= 0 {
                let fd = fd as i32;
                if unsafe { !Self::fd_matches_host_arch(fd) } {
                    unsafe { Self::close_fd(fd) };
                    return None;
                }
                let path = unsafe { core::str::from_utf8_unchecked(&stack_buf[..pos]) }.to_string();
                return Some((path, fd));
            }
            return None;
        }

        let mut candidate = String::with_capacity(total_len);
        candidate.push_str(dir);
        if needs_sep {
            candidate.push('/');
        }
        candidate.push_str(file);
        Self::open_path(&candidate).map(|fd| (candidate, fd))
    }
}
