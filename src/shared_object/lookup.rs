use super::*;

impl SharedObject {
    #[inline(always)]
    fn lookup_tables_look_sane(&self) -> bool {
        if self.map_start >= self.map_end {
            return false;
        }

        let symbol_table_ptr = self.symbol_table.as_ptr() as usize;
        if self.symbol_count > 0 {
            if symbol_table_ptr == 0
                || symbol_table_ptr < self.map_start
                || symbol_table_ptr >= self.map_end
            {
                return false;
            }
        }

        let string_table_ptr = self.string_table.into_inner() as usize;
        if self.string_table_size > 0 {
            let Some(string_table_end) = string_table_ptr.checked_add(self.string_table_size) else {
                return false;
            };
            if string_table_ptr == 0
                || string_table_ptr < self.map_start
                || string_table_end > self.map_end
            {
                return false;
            }
        }

        true
    }

    #[inline(always)]
    fn should_try_non_default_version_fallback(symbol_name: &str) -> bool {
        matches!(
            symbol_name,
            "__res_nsearch"
                | "__res_nquery"
                | "__res_nquerydomain"
                | "__res_nsend"
                | "__res_nmkquery"
                | "__res_ninit"
                | "__res_nclose"
        )
    }

    #[inline(always)]
    pub(super) fn symbol_is_exported(symbol: &Symbol) -> bool {
        if symbol.st_name == 0 || symbol.st_shndx == Self::SHN_UNDEF {
            return false;
        }
        let binding = symbol.st_info >> 4;
        if binding != Self::STB_GLOBAL
            && binding != Self::STB_WEAK
            && binding != Self::STB_GNU_UNIQUE
        {
            return false;
        }
        matches!(
            symbol.st_other.symbol_visibility(),
            SymbolVisibility::Default | SymbolVisibility::Protected
        )
    }

    #[inline]
    pub unsafe fn symbol_version_is_exported(&self, symbol_index: usize) -> bool {
        if self.versym.is_null() {
            return true;
        }
        (*self.versym.add(symbol_index) & Self::VERSYM_HIDDEN) == 0
    }

    #[inline(always)]
    pub(super) unsafe fn symbol_version_is_exported_raw(versym: *const u16, symbol_index: usize) -> bool {
        if versym.is_null() {
            return true;
        }
        (*versym.add(symbol_index) & Self::VERSYM_HIDDEN) == 0
    }

    #[inline(always)]
    fn symbol_is_precomputed_exported(&self, symbol_index: usize) -> bool {
        let word_idx = symbol_index / Self::EXPORT_MASK_WORD_BITS;
        let bit_idx = symbol_index % Self::EXPORT_MASK_WORD_BITS;
        self.exportable_symbol_mask
            .get(word_idx)
            .is_some_and(|word| ((*word >> bit_idx) & 1) != 0)
    }

    #[inline(always)]
    fn gnu_hash_bytes(name: &[u8]) -> u32 {
        let mut hash: u32 = 5381;
        let mut idx = 0usize;
        while idx < name.len() {
            hash = hash.wrapping_mul(33).wrapping_add(name[idx] as u32);
            idx += 1;
        }
        hash
    }

    #[inline(always)]
    fn sysv_hash_bytes(name: &[u8]) -> u32 {
        let mut hash: u32 = 0;
        let mut idx = 0usize;
        while idx < name.len() {
            hash = hash.wrapping_shl(4).wrapping_add(name[idx] as u32);
            let high = hash & 0xF000_0000;
            if high != 0 {
                hash ^= high >> 24;
            }
            hash &= !high;
            idx += 1;
        }
        hash
    }

    unsafe fn lookup_exported_symbol_gnu(&self, symbol_name: &str) -> Option<Symbol> {
        if self.gnu_hash.is_null() || self.symbol_table.as_ptr().is_null() {
            return None;
        }
        let requested = symbol_name.as_bytes();

        let header = self.gnu_hash;
        let nbuckets = *header as usize;
        let symoffset = *header.add(1) as usize;
        let bloom_size = *header.add(2) as usize;
        let bloom_shift = *header.add(3) as usize;
        if nbuckets == 0 || bloom_size == 0 || self.symbol_count == 0 {
            return None;
        }

        let word_u32 = core::mem::size_of::<usize>() / core::mem::size_of::<u32>();
        let bloom_ptr = header.add(4) as *const usize;
        let buckets_ptr = header.add(4 + bloom_size * word_u32);
        let chains_ptr = buckets_ptr.add(nbuckets);

        let hash = Self::gnu_hash_bytes(symbol_name.as_bytes());
        let word_bits = usize::BITS as usize;
        let bloom_word = *bloom_ptr.add((hash as usize / word_bits) % bloom_size);
        let bloom_mask = (1usize << (hash as usize % word_bits))
            | (1usize << ((hash as usize >> bloom_shift) % word_bits));
        if (bloom_word & bloom_mask) != bloom_mask {
            return None;
        }

        let mut sym_idx = *buckets_ptr.add(hash as usize % nbuckets) as usize;
        if sym_idx < symoffset || sym_idx >= self.symbol_count {
            return None;
        }

        while sym_idx < self.symbol_count {
            let chain = *chains_ptr.add(sym_idx - symoffset);
            if (chain | 1) == (hash | 1) {
                let symbol = self.symbol_table.get_ref(sym_idx);
                if self.symbol_is_precomputed_exported(sym_idx) {
                    let name = self.string_table.get_bytes(symbol.st_name as usize);
                    if !name.is_empty() && symbol_name_matches_bytes(name, requested) {
                        return Some(*symbol);
                    }
                }
            }
            if (chain & 1) != 0 {
                break;
            }
            sym_idx += 1;
        }
        None
    }

    unsafe fn lookup_exported_symbol_sysv(&self, symbol_name: &str) -> Option<Symbol> {
        if self.sysv_hash.is_null() || self.symbol_table.as_ptr().is_null() {
            return None;
        }
        let requested = symbol_name.as_bytes();

        let table = self.sysv_hash;
        let nbucket = *table as usize;
        let nchain = *table.add(1) as usize;
        if nbucket == 0 || nchain == 0 {
            return None;
        }

        let buckets_ptr = table.add(2);
        let chains_ptr = buckets_ptr.add(nbucket);
        let hash = Self::sysv_hash_bytes(symbol_name.as_bytes()) as usize;
        let mut sym_idx = *buckets_ptr.add(hash % nbucket) as usize;

        let mut steps = 0usize;
        while sym_idx != 0 && sym_idx < nchain && sym_idx < self.symbol_count {
            let symbol = self.symbol_table.get_ref(sym_idx);
            if self.symbol_is_precomputed_exported(sym_idx) {
                let name = self.string_table.get_bytes(symbol.st_name as usize);
                if !name.is_empty() && symbol_name_matches_bytes(name, requested) {
                    return Some(*symbol);
                }
            }
            let next_sym_idx = *chains_ptr.add(sym_idx) as usize;
            // Guard against malformed/cyclic SYSV hash chains.
            if next_sym_idx == sym_idx {
                break;
            }
            sym_idx = next_sym_idx;
            steps = steps.saturating_add(1);
            if steps >= nchain {
                break;
            }
        }

        None
    }

    /// Linear scan over the symbol table. When `require_default_version` is
    /// set, symbols hidden by version (`symbol_version_is_exported_raw`) are
    /// skipped; otherwise any exported symbol matches.
    #[cold]
    unsafe fn lookup_exported_symbol_linear(
        &self,
        symbol_name: &str,
        require_default_version: bool,
    ) -> Option<Symbol> {
        if self.symbol_table.as_ptr().is_null() || self.symbol_count == 0 {
            return None;
        }
        let requested = symbol_name.as_bytes();

        for sym_idx in 0..self.symbol_count {
            let symbol = self.symbol_table.get_ref(sym_idx);
            if !Self::symbol_is_exported(symbol) {
                continue;
            }
            if require_default_version
                && !Self::symbol_version_is_exported_raw(self.versym, sym_idx)
            {
                continue;
            }
            let name = self.string_table.get_bytes(symbol.st_name as usize);
            if name.is_empty() {
                continue;
            }
            if symbol_name_matches_bytes(name, requested) {
                return Some(*symbol);
            }
        }
        None
    }

    /// SysV-hash bucket lookup. `any_version` selects the version-agnostic
    /// bucket table + exported predicate; otherwise the default-version table.
    #[inline(always)]
    unsafe fn lookup_exported_symbol_indexed(
        &self,
        symbol_name: &str,
        any_version: bool,
    ) -> Option<Symbol> {
        let buckets = if any_version {
            &self.sysv_export_any_version_buckets
        } else {
            &self.sysv_export_buckets
        };
        if buckets.is_empty() || symbol_name.is_empty() {
            return None;
        }
        let requested = symbol_name.as_bytes();

        let hash = Self::sysv_hash_bytes(strip_version_suffix(symbol_name).as_bytes()) as usize;
        let bucket_idx = hash % buckets.len();
        for &sym_idx_u32 in &buckets[bucket_idx] {
            let sym_idx = sym_idx_u32 as usize;
            if sym_idx >= self.symbol_count {
                continue;
            }
            let symbol = self.symbol_table.get_ref(sym_idx);
            let exported = if any_version {
                Self::symbol_is_exported(symbol)
            } else {
                self.symbol_is_precomputed_exported(sym_idx)
            };
            if !exported {
                continue;
            }
            let name = self.string_table.get_bytes(symbol.st_name as usize);
            if !name.is_empty() && symbol_name_matches_bytes(name, requested) {
                return Some(*symbol);
            }
        }
        None
    }

    #[inline(always)]
    pub(super) fn disable_indexed_export_lookup() -> bool {
        static DISABLE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        *DISABLE.get_or_init(|| std::env::var("RUSTLD_ENABLE_INDEXED_EXPORT_LOOKUP").is_err())
    }

    #[inline(always)]
    pub unsafe fn lookup_exported_symbol(&self, symbol_name: &str) -> Option<Symbol> {
        if symbol_name.is_empty() {
            return None;
        }
        if !self.lookup_tables_look_sane() {
            return None;
        }

        if !Self::disable_indexed_export_lookup() {
            if let Some(symbol) = self.lookup_exported_symbol_indexed(symbol_name, false) {
                return Some(symbol);
            }
        }

        if !self.gnu_hash.is_null() {
            if let Some(symbol) = self.lookup_exported_symbol_gnu(symbol_name) {
                return Some(symbol);
            }
        }

        if !self.sysv_hash.is_null() {
            if let Some(symbol) = self.lookup_exported_symbol_sysv(symbol_name) {
                return Some(symbol);
            }
        }

        // Only pay linear-scan cost when no hash tables are available.
        if self.gnu_hash.is_null() && self.sysv_hash.is_null() {
            if let Some(symbol) = self.lookup_exported_symbol_linear(symbol_name, true) {
                return Some(symbol);
            }
        }

        // Keep this fallback narrow: scanning full symbol tables on every miss
        // is expensive in relocation hot paths.
        if Self::should_try_non_default_version_fallback(symbol_name) {
            if !Self::disable_indexed_export_lookup() {
                if let Some(symbol) = self.lookup_exported_symbol_indexed(symbol_name, true) {
                    return Some(symbol);
                }
            }
            return self.lookup_exported_symbol_linear(symbol_name, false);
        }

        None
    }

    #[inline(always)]
    pub unsafe fn lookup_exported_symbol_slow(&self, symbol_name: &str) -> Option<Symbol> {
        if symbol_name.is_empty() {
            return None;
        }

        // The rtld/libdl "slow" lookup path is not latency-sensitive, but it is
        // exercised during glibc NSS runtime loading on newer hosts. Keep it on
        // the simplest implementation so it does not depend on hash-table state.
        if let Some(symbol) = self.lookup_exported_symbol_linear(symbol_name, true) {
            return Some(symbol);
        }

        if Self::should_try_non_default_version_fallback(symbol_name) {
            return self.lookup_exported_symbol_linear(symbol_name, false);
        }

        None
    }

    pub(super) unsafe fn gnu_hash_symbol_count(gnu_hash: *const u32) -> Option<usize> {
        if gnu_hash.is_null() {
            return None;
        }

        let nbuckets = *gnu_hash as usize;
        let symoffset = *gnu_hash.add(1) as usize;
        let bloom_size = *gnu_hash.add(2) as usize;
        if nbuckets == 0 {
            return Some(symoffset);
        }

        let bloom_words = bloom_size;
        let buckets_ptr = gnu_hash
            .add(4 + bloom_words * (core::mem::size_of::<usize>() / core::mem::size_of::<u32>()));
        let chains_ptr = buckets_ptr.add(nbuckets);

        let mut max_symbol = symoffset;
        for i in 0..nbuckets {
            let bucket = *buckets_ptr.add(i) as usize;
            if bucket < symoffset || bucket == 0 {
                continue;
            }

            let mut sym = bucket;
            loop {
                let chain_index = sym.wrapping_sub(symoffset);
                let chain = *chains_ptr.add(chain_index);
                sym = sym.wrapping_add(1);
                if chain & 1 != 0 {
                    break;
                }
                // Safety guard against malformed hash chains.
                if sym.wrapping_sub(symoffset) > (1 << 24) {
                    return None;
                }
            }

            if sym > max_symbol {
                max_symbol = sym;
            }
        }

        Some(max_symbol)
    }
}
