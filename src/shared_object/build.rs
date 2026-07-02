use super::*;

impl SharedObject {
    #[inline(always)]
    pub(super) unsafe fn build(
        base_addr: usize,
        dynamic_header: &ProgramHeader,
        tls: Option<TlsInfo>,
        map_start: usize,
        map_end: usize,
        load_segments: Vec<(usize, usize)>,
        eh_frame_hdr: *const u8,
    ) -> Self {
        // Dynamic Arrary:
        let dynamic_array_ptr =
            (base_addr.wrapping_add(dynamic_header.p_vaddr)) as *const DynamicArrayItem;
        let dynamic_array = DynamicArrayIter::new(dynamic_array_ptr);
        syscall_debug_assert!(dynamic_array.clone().count() != 0);

        let mut rela_pointer: *const Rela = null();
        let mut rela_count = 0;
        let mut plt_rela_pointer: *const Rela = null();
        let mut plt_rela_count = 0;
        let mut relr_pointer: *const usize = null();
        let mut relr_size = 0usize;
        let mut relr_ent = size_of::<usize>();

        let mut symbol_table_pointer: *const Symbol = null();
        let mut string_table_pointer: *const u8 = null();
        let mut needed_libraries = Vec::new();
        let mut soname = None;
        let mut rpath = None;
        let mut runpath = None;
        let mut symbol_count: usize = 0;
        let mut sysv_hash_pointer: *const u32 = null();
        let mut gnu_hash_pointer: *const u32 = null();
        let mut versym_pointer: *const u16 = null();
        let mut string_table_size: usize = 0;
        for item in dynamic_array {
            match item.d_tag {
                DT_NEEDED => needed_libraries.push(item.d_un.d_val),
                DT_SONAME => soname = Some(item.d_un.d_val),
                DT_RPATH => rpath = Some(item.d_un.d_val),
                DT_RUNPATH => runpath = Some(item.d_un.d_val),
                DT_RELA => {
                    rela_pointer = (base_addr.wrapping_add(item.d_un.d_val)) as *const Rela;
                }
                DT_RELASZ => {
                    rela_count = item.d_un.d_val / core::mem::size_of::<Rela>();
                }
                DT_RELR => {
                    relr_pointer = (base_addr.wrapping_add(item.d_un.d_val)) as *const usize;
                }
                DT_RELRSZ => {
                    relr_size = item.d_un.d_val;
                }
                DT_RELRENT => {
                    relr_ent = item.d_un.d_val;
                }
                DT_JMPREL => {
                    plt_rela_pointer = (base_addr.wrapping_add(item.d_un.d_val)) as *const Rela;
                }
                DT_PLTRELSZ => {
                    plt_rela_count = item.d_un.d_val / core::mem::size_of::<Rela>();
                }
                #[cfg(debug_assertions)]
                crate::elf::dynamic_array::DT_RELAENT => {
                    syscall_debug_assert!(item.d_un.d_val as usize == size_of::<Rela>())
                }
                // Tables:
                DT_SYMTAB => {
                    symbol_table_pointer =
                        (base_addr.wrapping_add(item.d_un.d_val)) as *const Symbol
                }
                DT_STRTAB => {
                    string_table_pointer = (base_addr.wrapping_add(item.d_un.d_val)) as *const u8
                }
                DT_STRSZ => {
                    string_table_size = item.d_un.d_val;
                }
                DT_HASH => {
                    // Hash table structure: [nbuckets, nchains, buckets..., chains...]
                    // nchains equals the number of symbol table entries
                    let hash_table = (base_addr.wrapping_add(item.d_un.d_val)) as *const u32;
                    sysv_hash_pointer = hash_table;
                    symbol_count = *hash_table.add(1) as usize;
                }
                DT_GNU_HASH => {
                    gnu_hash_pointer = (base_addr.wrapping_add(item.d_un.d_val)) as *const u32;
                }
                DT_VERSYM => {
                    versym_pointer = (base_addr.wrapping_add(item.d_un.d_val)) as *const u16;
                }
                #[cfg(debug_assertions)]
                crate::elf::dynamic_array::DT_SYMENT => {
                    syscall_debug_assert!(item.d_un.d_val as usize == size_of::<Symbol>())
                }
                _ => (),
            }
        }

        if symbol_count == 0 {
            if let Some(gnu_count) = Self::gnu_hash_symbol_count(gnu_hash_pointer) {
                symbol_count = gnu_count;
            }
        }

        // Last-resort fallback for non-standard objects without DT_HASH/DT_GNU_HASH.
        if symbol_count == 0 && !symbol_table_pointer.is_null() && !string_table_pointer.is_null() {
            let symtab_addr = symbol_table_pointer as usize;
            let strtab_addr = string_table_pointer as usize;
            if strtab_addr > symtab_addr {
                symbol_count = (strtab_addr - symtab_addr) / core::mem::size_of::<Symbol>();
            }
        }

        let export_words = symbol_count.saturating_add(Self::EXPORT_MASK_WORD_BITS - 1)
            / Self::EXPORT_MASK_WORD_BITS;
        let mut exportable_symbol_mask = vec![0usize; export_words];
        let mut exportable_any_version_mask = vec![0usize; export_words];
        if symbol_count > 0 && !symbol_table_pointer.is_null() {
            let symbol_table = SymbolTable::new(symbol_table_pointer);
            for sym_idx in 0..symbol_count {
                let symbol = symbol_table.get_ref(sym_idx);
                if !Self::symbol_is_exported(symbol) {
                    continue;
                }
                let word_idx = sym_idx / Self::EXPORT_MASK_WORD_BITS;
                let bit_idx = sym_idx % Self::EXPORT_MASK_WORD_BITS;
                exportable_any_version_mask[word_idx] |= 1usize << bit_idx;
                if Self::symbol_version_is_exported_raw(versym_pointer, sym_idx) {
                    exportable_symbol_mask[word_idx] |= 1usize << bit_idx;
                }
            }
        }

        let mut sysv_export_buckets: Vec<SmallVec<[u32; 4]>> = Vec::new();
        let mut sysv_export_any_version_buckets: Vec<SmallVec<[u32; 4]>> = Vec::new();
        if !Self::disable_indexed_export_lookup() && !sysv_hash_pointer.is_null() && symbol_count > 0 {
            let table = sysv_hash_pointer;
            let nbucket = *table as usize;
            let nchain = *table.add(1) as usize;
            if nbucket > 0 && nchain > 0 {
                sysv_export_buckets.resize_with(nbucket, SmallVec::new);
                sysv_export_any_version_buckets.resize_with(nbucket, SmallVec::new);
                let buckets_ptr = table.add(2);
                let chains_ptr = buckets_ptr.add(nbucket);
                for bucket_idx in 0..nbucket {
                    let mut sym_idx = *buckets_ptr.add(bucket_idx) as usize;
                    let mut steps = 0usize;
                    while sym_idx != 0 && sym_idx < nchain && sym_idx < symbol_count {
                        let word_idx = sym_idx / Self::EXPORT_MASK_WORD_BITS;
                        let bit_idx = sym_idx % Self::EXPORT_MASK_WORD_BITS;
                        if ((exportable_symbol_mask[word_idx] >> bit_idx) & 1) != 0 {
                            sysv_export_buckets[bucket_idx].push(sym_idx as u32);
                        }
                        if ((exportable_any_version_mask[word_idx] >> bit_idx) & 1) != 0 {
                            sysv_export_any_version_buckets[bucket_idx].push(sym_idx as u32);
                        }
                        let next_sym_idx = *chains_ptr.add(sym_idx) as usize;
                        if next_sym_idx == sym_idx {
                            break;
                        }
                        sym_idx = next_sym_idx;
                        steps = steps.saturating_add(1);
                        if steps >= nchain {
                            break;
                        }
                    }
                }
            }
        }

        let base_rela_slice = if rela_pointer.is_null() || rela_count == 0 {
            &[] as &[Rela]
        } else {
            slice::from_raw_parts(rela_pointer, rela_count)
        };

        // Merge .rela.dyn and .rela.plt into a single allocation
        let rela_slice = if !plt_rela_pointer.is_null() && plt_rela_count > 0 {
            let plt_rela_slice = slice::from_raw_parts(plt_rela_pointer, plt_rela_count);
            let mut merged = Vec::with_capacity(rela_count + plt_rela_count);
            merged.extend_from_slice(base_rela_slice);
            merged.extend_from_slice(plt_rela_slice);
            let leaked: &'static [Rela] = merged.leak();
            leaked
        } else {
            base_rela_slice
        };

        let relr_slice = if relr_pointer.is_null() || relr_size == 0 {
            &[] as &[usize]
        } else {
            #[cfg(debug_assertions)]
            syscall_debug_assert!(relr_ent as usize == size_of::<usize>());
            let count = relr_size / relr_ent as usize;
            slice::from_raw_parts(relr_pointer, count)
        };

        Self {
            base: base_addr,
            map_start,
            map_end,
            load_segments,
            eh_frame_hdr,
            global_scope: true,
            dynamic: dynamic_array_ptr,
            relocations: RelocationSlices {
                rela_slice,
                relr_slice,
            },
            needed_libraries,
            resolved_dependencies: Vec::new(),
            soname,
            rpath,
            runpath,
            symbol_table: SymbolTable::new(symbol_table_pointer),
            string_table: StringTable::new(string_table_pointer, string_table_size),
            tls,
            sysv_hash: sysv_hash_pointer,
            gnu_hash: gnu_hash_pointer,
            versym: versym_pointer,
            symbol_count,
            string_table_size,
            exportable_symbol_mask,
            sysv_export_buckets,
            sysv_export_any_version_buckets,
        }
    }

    pub(super) fn build_static(
        base_addr: usize,
        tls: Option<TlsInfo>,
        map_start: usize,
        map_end: usize,
        load_segments: Vec<(usize, usize)>,
        eh_frame_hdr: *const u8,
    ) -> Self {
        Self {
            base: base_addr,
            map_start,
            map_end,
            load_segments,
            eh_frame_hdr,
            global_scope: true,
            dynamic: null(),
            relocations: RelocationSlices {
                rela_slice: &[],
                relr_slice: &[],
            },
            needed_libraries: Vec::new(),
            resolved_dependencies: Vec::new(),
            soname: None,
            rpath: None,
            runpath: None,
            symbol_table: SymbolTable::new(null()),
            string_table: StringTable::new(null(), 0),
            tls,
            sysv_hash: null(),
            gnu_hash: null(),
            versym: null(),
            symbol_count: 0,
            string_table_size: 0,
            exportable_symbol_mask: Vec::new(),
            sysv_export_buckets: Vec::new(),
            sysv_export_any_version_buckets: Vec::new(),
        }
    }

    pub unsafe fn soname_str(&self) -> Option<&'static str> {
        self.soname.and_then(|offset| {
            let value = self.string_table.get(offset);
            (!value.is_empty()).then_some(value)
        })
    }

    pub unsafe fn rpath_str(&self) -> Option<&'static str> {
        self.rpath.and_then(|offset| {
            let value = self.string_table.get(offset);
            (!value.is_empty()).then_some(value)
        })
    }

    pub unsafe fn runpath_str(&self) -> Option<&'static str> {
        self.runpath.and_then(|offset| {
            let value = self.string_table.get(offset);
            (!value.is_empty()).then_some(value)
        })
    }

    #[inline(always)]
    pub fn contains_address(&self, address: usize) -> bool {
        for &(start, end) in &self.load_segments {
            if start <= address && address < end {
                return true;
            }
        }
        false
    }

    #[inline(always)]
    pub fn containing_mapping_range(&self, address: usize) -> Option<(usize, usize)> {
        for &(start, end) in &self.load_segments {
            if start <= address && address < end {
                return Some((start, end));
            }
        }
        None
    }

    pub unsafe fn call_init_functions(
        &self,
        arg_count: usize,
        arg_pointer: *const *const u8,
        env_pointer: *const *const u8,
        auxv_pointer: *const crate::start::auxiliary_vector::AuxiliaryVectorItem,
    ) {
        if self.dynamic.is_null() {
            return;
        }

        let mut init_fn: Option<usize> = None;
        let mut init_array_ptr: *const usize = null();
        let mut init_array_count = 0usize;

        for item in DynamicArrayIter::new(self.dynamic) {
            match item.d_tag {
                DT_INIT => {
                    init_fn = Some(item.d_un.d_ptr.addr());
                }
                DT_INIT_ARRAY => {
                    init_array_ptr =
                        (self.base.wrapping_add(item.d_un.d_ptr.addr())) as *const usize;
                }
                DT_INIT_ARRAYSZ => {
                    init_array_count = item.d_un.d_val / size_of::<usize>();
                }
                _ => (),
            }
        }

            if let Some(init_offset) = init_fn {
                let addr = self.base.wrapping_add(init_offset);
                #[cfg(debug_assertions)]
                {
                    eprintln!("init: DT_INIT addr=0x{addr:016x} base=0x{:016x}", self.base);
                }
                let func: extern "C" fn(
                    usize,
                    *const *const u8,
                    *const *const u8,
                    *const crate::start::auxiliary_vector::AuxiliaryVectorItem,
                ) = core::mem::transmute(addr);
                func(arg_count, arg_pointer, env_pointer, auxv_pointer);
            }

        if !init_array_ptr.is_null() && init_array_count > 0 {
            let init_array_addr = init_array_ptr as usize;
            if init_array_addr < self.map_start || init_array_addr >= self.map_end {
                return;
            }
            let max_entries = (self.map_end - init_array_addr) / size_of::<usize>();
            if max_entries == 0 {
                return;
            }
            let init_array_count = init_array_count.min(max_entries);
            let init_array = slice::from_raw_parts(init_array_ptr, init_array_count);
            #[cfg(debug_assertions)]
            {
                eprintln!(
                    "init: DT_INIT_ARRAY count={} ptr=0x{:016x}",
                    init_array_count, init_array_ptr as usize
                );
            }
            for &func_addr in init_array.iter() {
                if func_addr == 0 {
                    continue;
                }
                #[cfg(debug_assertions)]
                {
                    eprintln!("init: call 0x{func_addr:016x}");
                }
                let func: extern "C" fn(
                    usize,
                    *const *const u8,
                    *const *const u8,
                    *const crate::start::auxiliary_vector::AuxiliaryVectorItem,
                ) = core::mem::transmute(func_addr);
                func(arg_count, arg_pointer, env_pointer, auxv_pointer);
            }
        }
    }
}
