use super::*;

impl DynamicLinker {
    pub unsafe fn lookup_symbol_in_object(
        &self,
        object_index: usize,
        symbol_name: &str,
    ) -> Option<usize> {
        let object = self.objects.get(object_index)?;
        let symtab_ptr = object.symbol_table.as_ptr();
        if symtab_ptr.is_null() || object.symbol_count == 0 {
            return None;
        }

        let requested = symbol_name.as_bytes();
        for sym_idx in 0..object.symbol_count {
            let symbol = object.symbol_table.get_ref(sym_idx);
            if !object.symbol_version_is_exported(sym_idx) {
                continue;
            }
            if symbol.st_name == 0 {
                continue;
            }
            if symbol.st_shndx == SHN_UNDEF {
                continue;
            }
            let binding = symbol.st_info >> 4;
            if binding != STB_GLOBAL && binding != STB_WEAK && binding != STB_GNU_UNIQUE {
                continue;
            }
            let visibility = symbol.st_other.symbol_visibility();
            if !matches!(
                visibility,
                SymbolVisibility::Default | SymbolVisibility::Protected
            ) {
                continue;
            }

            let name = object.string_table.get_bytes(symbol.st_name as usize);
            if name.is_empty() {
                continue;
            }
            if !symbol_name_matches_bytes(name, requested) {
                continue;
            }

            let base = if symbol.st_shndx == SHN_ABS {
                0
            } else {
                object.base
            };
            return Some(base.wrapping_add(symbol.st_value));
        }
        None
    }

    const INLINE_SCOPE_SEEN_CAPACITY: usize = 512;

    #[inline(always)]
    fn is_nss_module_symbol(symbol_name: &str) -> bool {
        symbol_name.as_bytes().starts_with(b"_nss_")
    }

    #[inline]
    fn with_scope_seen<T>(&self, f: impl FnOnce(&mut [u8]) -> T) -> T {
        let object_count = self.objects.len();
        if object_count <= Self::INLINE_SCOPE_SEEN_CAPACITY {
            let mut inline_seen = [0u8; Self::INLINE_SCOPE_SEEN_CAPACITY];
            return f(&mut inline_seen[..object_count]);
        }

        let mut heap_seen = vec![0u8; object_count];
        f(&mut heap_seen)
    }

    fn visit_scope_preorder(
        &self,
        idx: usize,
        seen: &mut [u8],
        visit: &mut impl FnMut(usize) -> bool,
    ) -> bool {
        if idx >= self.objects.len() || seen[idx] != 0 {
            return false;
        }
        seen[idx] = 1;
        if visit(idx) {
            return true;
        }

        for dep_idx in self.resolve_object_dependency_indices(idx) {
            if dep_idx < self.objects.len()
                && dep_idx != idx
                && self.visit_scope_preorder(dep_idx, seen, visit)
            {
                return true;
            }
        }

        false
    }

    pub unsafe fn lookup_symbol_in_object_scope(
        &self,
        object_index: usize,
        symbol_name: &str,
    ) -> Option<usize> {
        self.with_scope_seen(|seen| {
            let mut found = None;
            let _ = self.visit_scope_preorder(object_index, seen, &mut |idx| {
                if let Some(addr) = unsafe { self.lookup_symbol_in_object(idx, symbol_name) } {
                    found = Some(addr);
                    return true;
                }
                false
            });
            found
        })
    }

    /// Look up a symbol by name across all loaded objects.
    /// Also provides stub symbols for ld-linux symbols we implement ourselves.
    #[inline(always)]
    pub unsafe fn lookup_symbol(&self, symbol_name: &str) -> Option<(usize, Symbol)> {
        self.lookup_symbol_excluding(symbol_name, None)
    }

    #[inline(always)]
    unsafe fn lookup_rtld_stub_symbol(&self, symbol_name: &str) -> Option<(usize, Symbol)> {
        let stubs = self.rtld_stubs.as_ref()?;
        let stub_addr = match symbol_name {
            "_rtld_global" => Some(stubs.rtld_global as usize),
            "_rtld_global_ro" => Some(stubs.rtld_global_ro as usize),
            "__libc_enable_secure" => Some(stubs.libc_enable_secure as usize),
            "__libc_stack_end" => Some(stubs.libc_stack_end as usize),
            "_dl_argv" => Some(stubs.dl_argv as usize),
            "__rseq_offset" => Some(stubs.rseq_offset as usize),
            "__rseq_size" => Some(stubs.rseq_size as usize),
            "__rseq_flags" => Some(stubs.rseq_flags as usize),
            "__pointer_chk_guard" => Some(stubs.pointer_chk_guard as usize),
            "__pointer_chk_guard_local" => Some(stubs.pointer_chk_guard_local as usize),
            "__stack_chk_guard" => Some(stubs.stack_chk_guard as usize),
            _ => None,
        }?;

        // SHN_ABS => callers must not add object base.
        let mut sym = core::mem::zeroed::<Symbol>();
        sym.st_value = stub_addr;
        sym.st_shndx = SHN_ABS;
        sym.st_info = (STB_GLOBAL << 4) | 1; // GLOBAL OBJECT
        Some((0, sym))
    }

    /// Look up a symbol by name, optionally skipping one object index.
    #[inline(always)]
    pub unsafe fn lookup_symbol_excluding(
        &self,
        symbol_name: &str,
        exclude_object: Option<usize>,
    ) -> Option<(usize, Symbol)> {
        if let Some(resolved) = self.lookup_rtld_stub_symbol(symbol_name) {
            return Some(resolved);
        }

        // Search loaded objects in global scope order (executable first).
        let object_count = self.objects.len();
        for obj_idx in 0..object_count {
            if exclude_object == Some(obj_idx) {
                continue;
            }
            if let Some(symbol) = self.objects[obj_idx].lookup_exported_symbol(symbol_name) {
                return Some((obj_idx, symbol));
            }
        }
        None
    }

    /// Scope-aware lookup for rtld/libdl callers.
    ///
    /// The main executable must be searched first to preserve COPY-relocation
    /// interposition semantics (e.g. optarg/std::cout copies in ET_DYN mains).
    /// After that, search the requester closure, then remaining globals.
    pub unsafe fn lookup_symbol_for_object_excluding(
        &self,
        requester_object: usize,
        symbol_name: &str,
        exclude_object: Option<usize>,
    ) -> Option<(usize, Symbol)> {
        if let Some(resolved) = self.lookup_rtld_stub_symbol(symbol_name) {
            return Some(resolved);
        }

        if requester_object >= self.objects.len() {
            return self.lookup_symbol_excluding(symbol_name, exclude_object);
        }
        let scope_snapshot = self.lookup_scopes.get(requester_object).cloned();
        if let Some(scope) = scope_snapshot {
            if !scope.is_empty() {
                for idx in scope {
                    if exclude_object == Some(idx) {
                        continue;
                    }
                    if idx >= self.objects.len() {
                        continue;
                    }
                    if let Some(symbol) = self.objects[idx].lookup_exported_symbol(symbol_name) {
                        return Some((idx, symbol));
                    }
                }
                return None;
            }
        }

        self.with_scope_seen(|seen| {
            // glibc-style global preemption: executable first.
            if !seen.is_empty() {
                seen[0] = 1;
                if exclude_object != Some(0) {
                    if let Some(symbol) = self.objects[0].lookup_exported_symbol(symbol_name) {
                        return Some((0, symbol));
                    }
                }
            }

            // Then requester/dependency closure.
            let mut found_in_scope = None;
            let _ = self.visit_scope_preorder(requester_object, seen, &mut |idx| {
                if idx == 0 {
                    return false;
                }
                if exclude_object == Some(idx) {
                    return false;
                }
                if let Some(symbol) = self.objects[idx].lookup_exported_symbol(symbol_name) {
                    found_in_scope = Some((idx, symbol));
                    return true;
                }
                false
            });
            if found_in_scope.is_some() {
                return found_in_scope;
            }

            // Finally, remaining globals in load order.
            for idx in 0..self.objects.len() {
                if seen[idx] != 0 {
                    continue;
                }
                seen[idx] = 1;
                if exclude_object == Some(idx) {
                    continue;
                }
                if let Some(symbol) = self.objects[idx].lookup_exported_symbol(symbol_name) {
                    return Some((idx, symbol));
                }
            }

            None
        })
    }

    pub unsafe fn lookup_symbol_in_object_scope_excluding_rtld_slow(
        &self,
        object_index: usize,
        symbol_name: &str,
        exclude_object: Option<usize>,
    ) -> Option<(usize, Symbol)> {
        if let Some(resolved) = self.lookup_rtld_stub_symbol(symbol_name) {
            return Some(resolved);
        }

        if object_index >= self.objects.len() {
            return self.lookup_symbol_excluding(symbol_name, exclude_object);
        }

        if Self::is_nss_module_symbol(symbol_name) && exclude_object != Some(object_index) {
            return self.objects[object_index]
                .lookup_exported_symbol_slow(symbol_name)
                .map(|symbol| (object_index, symbol));
        }

        self.with_scope_seen(|seen| {
            let mut found = None;
            let _ = self.visit_scope_preorder(object_index, seen, &mut |idx| {
                if exclude_object == Some(idx) {
                    return false;
                }
                if Self::trace_rtld_lookup() {
                    let soname = self.objects[idx].soname_str().unwrap_or("<none>");
                    eprintln!(
                        "rtld_handle_scope: root={} symbol={} try idx={} soname={}",
                        object_index,
                        symbol_name,
                        idx,
                        soname
                    );
                }
                if let Some(symbol) = self.objects[idx].lookup_exported_symbol_slow(symbol_name) {
                    found = Some((idx, symbol));
                    return true;
                }
                false
            });
            found
        })
    }

    #[inline(always)]
    pub fn get_base(&self, index: usize) -> usize {
        self.objects[index].base
    }

    pub fn object_for_address(&self, address: usize) -> Option<usize> {
        self.objects
            .iter()
            .position(|object| object.contains_address(address))
    }

    pub fn object_map_range(&self, index: usize) -> Option<(usize, usize)> {
        let object = self.objects.get(index)?;
        Some((object.map_start, object.map_end))
    }

    pub fn object_mapping_range_for_address(
        &self,
        index: usize,
        address: usize,
    ) -> Option<(usize, usize)> {
        let object = self.objects.get(index)?;
        object.containing_mapping_range(address)
    }

    pub fn object_eh_frame_hdr(&self, index: usize) -> Option<*const u8> {
        let object = self.objects.get(index)?;
        Some(object.eh_frame_hdr)
    }

    pub fn object_link_map_ptr(&self, index: usize) -> *mut c_void {
        self.object_link_maps
            .get(index)
            .copied()
            .unwrap_or(core::ptr::null_mut())
            .cast()
    }

    pub fn object_link_map_name_ptr(&self, index: usize) -> *const c_char {
        self.object_link_map_names
            .get(index)
            .copied()
            .unwrap_or(core::ptr::null_mut())
            .cast_const()
    }

    pub unsafe fn tls_static_metadata(&self) -> Option<(usize, usize)> {
        self.rtld_stubs
            .as_ref()
            .map(|stubs| stubs.tls_static_metadata())
    }

    pub(crate) fn loaded_legacy_glibc_family(&self) -> bool {
        self.object_paths
            .iter()
            .flatten()
            .any(|path| matches!(glibc_dso_version(path), Some((2, minor)) if minor <= 31))
    }

    pub fn object_index_for_link_map_ptr(&self, map_ptr: *const c_void) -> Option<usize> {
        if map_ptr.is_null() {
            return None;
        }
        self.object_link_maps
            .iter()
            .position(|&candidate| core::ptr::eq(candidate.cast::<c_void>(), map_ptr))
    }
}
