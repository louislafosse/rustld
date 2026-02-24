use core::ptr::null;
use core::slice;
use memchr::memchr;
use smallvec::SmallVec;
use std::cmp::{max, min};
use std::mem::MaybeUninit;
use std::ptr::null_mut;

use crate::elf::dynamic_array::{
    DynamicArrayItem, DT_FINI, DT_FINI_ARRAY, DT_FINI_ARRAYSZ, DT_GNU_HASH, DT_HASH, DT_INIT,
    DT_INIT_ARRAY, DT_INIT_ARRAYSZ, DT_JMPREL, DT_NEEDED, DT_PLTRELSZ, DT_RELR, DT_RELRENT,
    DT_RELRSZ, DT_RPATH, DT_RUNPATH, DT_SONAME, DT_STRSZ, DT_VERSYM,
};
use crate::elf::program_header::PT_LOAD;
use crate::elf::relocate::{Relocatable, RelocationSlices};
use crate::elf::symbol::{Symbol, SymbolTable, SymbolVisibility};
use crate::page_size;
use crate::{
    arch,
    elf::{
        dynamic_array::{DynamicArrayIter, DT_RELA, DT_RELASZ, DT_STRTAB, DT_SYMTAB},
        header::ElfHeader,
        program_header::{ProgramHeader, PT_DYNAMIC, PT_PHDR, PT_TLS},
        relocate::Rela,
        string_table::StringTable,
    },
    io_macros::syscall_debug_assert,
    libc::fs::write,
    syscall::{exit, mmap},
};

const PF_X: u32 = 0x1;
const PF_W: u32 = 0x2;
const PF_R: u32 = 0x4;
const PT_GNU_EH_FRAME: u32 = 0x6474e550;

fn calculate_virtual_address_bounds(program_header_table: &[ProgramHeader]) -> (usize, usize) {
    let mut min_addr = usize::MAX;
    let mut max_addr = 0;

    for header in program_header_table {
        // Skip non-loadable segments
        if header.p_type != PT_LOAD {
            continue;
        }

        let start = header.p_vaddr as usize;
        let end = start + header.p_memsz as usize;

        min_addr = min(min_addr, start);
        max_addr = max(max_addr, end);
    }

    // Align bounds to page boundaries
    unsafe {
        (
            page_size::get_page_start(min_addr),
            page_size::get_page_end(max_addr),
        )
    }
}

fn collect_load_segment_ranges(
    base_addr: usize,
    program_header_table: &[ProgramHeader],
) -> Vec<(usize, usize)> {
    let mut ranges = Vec::new();
    for header in program_header_table {
        if header.p_type != PT_LOAD || header.p_memsz == 0 {
            continue;
        }
        let start = unsafe { page_size::get_page_start(base_addr.wrapping_add(header.p_vaddr)) };
        let end = unsafe {
            page_size::get_page_end(
                base_addr
                    .wrapping_add(header.p_vaddr)
                    .wrapping_add(header.p_memsz),
            )
        };
        if end > start {
            ranges.push((start, end));
        }
    }
    ranges
}

#[inline]
fn segment_protection_from_flags(p_flags: u32) -> usize {
    let mut protection = 0usize;
    if (p_flags & PF_R) != 0 {
        protection |= mmap::PROT_READ;
    }
    if (p_flags & PF_W) != 0 {
        protection |= mmap::PROT_WRITE;
    }
    if (p_flags & PF_X) != 0 {
        protection |= mmap::PROT_EXEC;
    }
    protection
}

/// A struct repersenting a shared object in memory.
///
/// There are two ways to construct a `SharedObject`:
///
/// 1. From a slice of program headers:
///
/// 2. From a file descriptor:
pub struct SharedObject {
    pub base: usize,
    pub map_start: usize,
    pub map_end: usize,
    pub load_segments: Vec<(usize, usize)>,
    pub eh_frame_hdr: *const u8,
    pub global_scope: bool,
    pub dynamic: *const DynamicArrayItem,
    pub relocations: RelocationSlices,
    pub needed_libraries: Vec<usize>, // Indexs into the string table...
    pub soname: Option<usize>,
    pub rpath: Option<usize>,
    pub runpath: Option<usize>,
    pub symbol_table: SymbolTable,
    pub string_table: StringTable,
    pub tls: Option<TlsInfo>,
    pub sysv_hash: *const u32,
    pub gnu_hash: *const u32,
    pub versym: *const u16,
    pub symbol_count: usize, // Number of symbols in symbol table (from DT_HASH)
    pub string_table_size: usize, // Size of string table (from DT_STRSZ)
    exportable_symbol_mask: Vec<usize>,
    sysv_export_buckets: Vec<SmallVec<[u32; 4]>>,
}

#[derive(Clone, Copy)]
pub struct TlsInfo {
    pub init_image: *const u8,
    pub filesz: usize,
    pub memsz: usize,
    pub align: usize,
    pub module_id: usize,
    pub offset: isize,
    pub block_offset: usize,
}

impl TlsInfo {
    fn from_program_header(base_addr: usize, header: &ProgramHeader) -> Self {
        let align = if header.p_align == 0 {
            1
        } else {
            header.p_align as usize
        };
        Self {
            init_image: (base_addr.wrapping_add(header.p_vaddr)) as *const u8,
            filesz: header.p_filesz,
            memsz: header.p_memsz,
            align,
            module_id: 0,
            offset: 0,
            block_offset: 0,
        }
    }
}

impl SharedObject {
    const STB_GLOBAL: u8 = 1;
    const STB_WEAK: u8 = 2;
    const STB_GNU_UNIQUE: u8 = 10;
    const SHN_UNDEF: u16 = 0;
    const VERSYM_HIDDEN: u16 = 0x8000;
    const EXPORT_MASK_WORD_BITS: usize = usize::BITS as usize;

    #[inline(always)]
    fn symbol_name_matches_bytes(candidate: &[u8], requested: &[u8]) -> bool {
        let cand_len = candidate.len();
        let req_len = requested.len();

        if cand_len == req_len {
            candidate == requested
        } else if cand_len > req_len && candidate[req_len] == b'@' {
            &candidate[..req_len] == requested
        } else {
            false
        }
    }

    #[inline(always)]
    fn symbol_base_name(name: &str) -> &str {
        if let Some(at_pos) = memchr(b'@', name.as_bytes()) {
            &name[..at_pos]
        } else {
            name
        }
    }

    #[inline(always)]
    fn symbol_is_exported(symbol: &Symbol) -> bool {
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
    unsafe fn symbol_version_is_exported_raw(versym: *const u16, symbol_index: usize) -> bool {
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
    fn gnu_hash(name: &str) -> u32 {
        let mut hash: u32 = 5381;
        for byte in name.bytes() {
            hash = hash.wrapping_mul(33).wrapping_add(byte as u32);
        }
        hash
    }

    #[inline(always)]
    fn sysv_hash(name: &str) -> u32 {
        let mut hash: u32 = 0;
        for byte in name.bytes() {
            hash = hash.wrapping_shl(4).wrapping_add(byte as u32);
            let high = hash & 0xF000_0000;
            if high != 0 {
                hash ^= high >> 24;
            }
            hash &= !high;
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

        let hash = Self::gnu_hash(symbol_name);
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
                    if !name.is_empty() && Self::symbol_name_matches_bytes(name, requested) {
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
        let hash = Self::sysv_hash(symbol_name) as usize;
        let mut sym_idx = *buckets_ptr.add(hash % nbucket) as usize;

        let mut steps = 0usize;
        while sym_idx != 0 && sym_idx < nchain && sym_idx < self.symbol_count {
            let symbol = self.symbol_table.get_ref(sym_idx);
            if self.symbol_is_precomputed_exported(sym_idx) {
                let name = self.string_table.get_bytes(symbol.st_name as usize);
                if !name.is_empty() && Self::symbol_name_matches_bytes(name, requested) {
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

    #[cold]
    unsafe fn lookup_exported_symbol_linear(&self, symbol_name: &str) -> Option<Symbol> {
        if self.symbol_table.as_ptr().is_null() || self.symbol_count == 0 {
            return None;
        }
        let requested = symbol_name.as_bytes();

        for sym_idx in 0..self.symbol_count {
            let symbol = self.symbol_table.get_ref(sym_idx);
            if !self.symbol_is_precomputed_exported(sym_idx) {
                continue;
            }
            let name = self.string_table.get_bytes(symbol.st_name as usize);
            if name.is_empty() {
                continue;
            }
            if Self::symbol_name_matches_bytes(name, requested) {
                return Some(*symbol);
            }
        }
        None
    }

    #[inline(always)]
    unsafe fn lookup_exported_symbol_indexed(&self, symbol_name: &str) -> Option<Symbol> {
        if self.sysv_export_buckets.is_empty() || symbol_name.is_empty() {
            return None;
        }
        let requested = symbol_name.as_bytes();

        let hash = Self::sysv_hash(Self::symbol_base_name(symbol_name)) as usize;
        let bucket_idx = hash % self.sysv_export_buckets.len();
        let candidates = &self.sysv_export_buckets[bucket_idx];
        for &sym_idx_u32 in candidates {
            let sym_idx = sym_idx_u32 as usize;
            if sym_idx >= self.symbol_count || !self.symbol_is_precomputed_exported(sym_idx) {
                continue;
            }
            let symbol = self.symbol_table.get_ref(sym_idx);
            let name = self.string_table.get_bytes(symbol.st_name as usize);
            if !name.is_empty() && Self::symbol_name_matches_bytes(name, requested) {
                return Some(*symbol);
            }
        }
        None
    }

    #[inline(always)]
    pub unsafe fn lookup_exported_symbol(&self, symbol_name: &str) -> Option<Symbol> {
        if symbol_name.is_empty() {
            return None;
        }

        if let Some(symbol) = self.lookup_exported_symbol_indexed(symbol_name) {
            return Some(symbol);
        }

        if !self.gnu_hash.is_null() {
            if let Some(symbol) = self.lookup_exported_symbol_gnu(symbol_name) {
                return Some(symbol);
            }
            if !self.sysv_hash.is_null() {
                return self.lookup_exported_symbol_sysv(symbol_name);
            }
            return None;
        }

        if !self.sysv_hash.is_null() {
            return self.lookup_exported_symbol_sysv(symbol_name);
        }

        self.lookup_exported_symbol_linear(symbol_name)
    }

    unsafe fn gnu_hash_symbol_count(gnu_hash: *const u32) -> Option<usize> {
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

    #[inline(always)]
    pub unsafe fn from_loaded(base_addr: usize, program_header_table: &[ProgramHeader]) -> Self {
        let (min_addr, max_addr) = calculate_virtual_address_bounds(program_header_table);
        let map_start = base_addr.wrapping_add(min_addr);
        let map_end = base_addr.wrapping_add(max_addr);
        let load_segments = collect_load_segment_ranges(base_addr, program_header_table);

        let (mut dynamic_header, mut tls_program_header, mut eh_frame_header) = (None, None, None);
        for header in program_header_table {
            match header.p_type {
                PT_DYNAMIC => dynamic_header = Some(header),
                PT_TLS => tls_program_header = Some(header),
                PT_GNU_EH_FRAME => eh_frame_header = Some(header),
                _ => (),
            }
        }

        let tls = tls_program_header.map(|header| TlsInfo::from_program_header(base_addr, header));
        let eh_frame = eh_frame_header
            .map(|header| (base_addr.wrapping_add(header.p_vaddr)) as *const u8)
            .unwrap_or(null());

        match dynamic_header {
            Some(dynamic) => Self::build(
                base_addr,
                dynamic,
                tls,
                map_start,
                map_end,
                load_segments,
                eh_frame,
            ),
            None => Self::build_static(base_addr, tls, map_start, map_end, load_segments, eh_frame),
        }
    }

    pub unsafe fn from_headers(
        program_header_table: &[ProgramHeader],
        _pseudorandom_bytes: *const [u8; 16],
    ) -> Self {
        let (mut base_addr, mut dynamic_header, mut tls_program_header, mut eh_frame_header) =
            (0usize, None, None, None);
        for header in program_header_table {
            match header.p_type {
                PT_PHDR => {
                    base_addr =
                        (program_header_table.as_ptr() as usize).wrapping_sub(header.p_vaddr);
                }
                PT_DYNAMIC => {
                    dynamic_header = Some(header);
                }
                PT_TLS => {
                    tls_program_header = Some(header);
                }
                PT_GNU_EH_FRAME => {
                    eh_frame_header = Some(header);
                }
                _ => (),
            }
        }
        syscall_debug_assert!(dynamic_header.is_some());

        let (min_addr, max_addr) = calculate_virtual_address_bounds(program_header_table);
        let map_start = base_addr.wrapping_add(min_addr);
        let map_end = base_addr.wrapping_add(max_addr);
        let load_segments = collect_load_segment_ranges(base_addr, program_header_table);
        let tls = tls_program_header.map(|header| TlsInfo::from_program_header(base_addr, header));
        let eh_frame = eh_frame_header
            .map(|header| (base_addr.wrapping_add(header.p_vaddr)) as *const u8)
            .unwrap_or(null());

        Self::build(
            base_addr,
            dynamic_header.unwrap_unchecked(),
            tls,
            map_start,
            map_end,
            load_segments,
            eh_frame,
        )
    }

    pub unsafe fn from_fd(fd: i32) -> Self {
        #[cfg(debug_assertions)]
        {
            write::write_str(write::STD_OUT, "from_fd: Reading ELF header...\n");
        }

        // Read ELF Header using pread syscall
        let mut uninit_header: MaybeUninit<ElfHeader> = MaybeUninit::uninit();
        let as_bytes = slice::from_raw_parts_mut(
            uninit_header.as_mut_ptr() as *mut u8,
            size_of::<ElfHeader>(),
        );

        let mut result = arch::pread(fd, as_bytes.as_mut_ptr(), as_bytes.len(), 0);

        if result != size_of::<ElfHeader>() as isize {
            write::write_str(
                write::STD_ERR,
                "Error: could not read ElfHeader from file\n",
            );
            exit::exit(1);
        }

        let header = uninit_header.assume_init();
        #[cfg(debug_assertions)]
        {
            write::write_str(write::STD_OUT, "from_fd: Read ELF header\n");
        }

        // Read Program Headers
        let mut program_header_table: Vec<ProgramHeader> =
            Vec::with_capacity(header.e_phnum as usize);
        let as_bytes = slice::from_raw_parts_mut(
            program_header_table.as_mut_ptr() as *mut u8,
            header.e_phnum as usize * size_of::<ProgramHeader>(),
        );

        result = arch::pread(
            fd,
            as_bytes.as_mut_ptr(),
            as_bytes.len(),
            header.e_phoff as usize,
        );

        if result != (header.e_phnum as usize * size_of::<ProgramHeader>()) as isize {
            write::write_str(
                write::STD_ERR,
                "Error: could not read &[ProgramHeader] from file\n",
            );
            exit::exit(1);
        }

        program_header_table.set_len(header.e_phnum as usize);
        #[cfg(debug_assertions)]
        {
            write::write_str(write::STD_OUT, "from_fd: Read program headers\n");
        }

        let (min_addr, max_addr) = calculate_virtual_address_bounds(&program_header_table);
        #[cfg(debug_assertions)]
        {
            write::write_str(
                write::STD_OUT,
                "from_fd: Calculated virtual address bounds\n",
            );
        }

        let reservation = mmap::mmap(
            null_mut(),
            max_addr - min_addr,
            mmap::PROT_NONE,
            mmap::MAP_PRIVATE | mmap::MAP_ANONYMOUS,
            -1,
            0,
        );
        if reservation.is_null() || (reservation as isize) < 0 {
            write::write_str(
                write::STD_ERR,
                "Error: could not reserve memory for PT_LOAD segments\n",
            );
            exit::exit(1);
        }

        // `base_addr + p_vaddr` yields the in-memory address for each ELF virtual address.
        let base_addr = (reservation as usize).wrapping_sub(min_addr);

        #[cfg(debug_assertions)]
        {
            write::write_str(write::STD_OUT, "from_fd: Allocated memory for library\n");
        }

        let map_start = base_addr.wrapping_add(min_addr);
        let map_end = base_addr.wrapping_add(max_addr);
        let load_segments = collect_load_segment_ranges(base_addr, &program_header_table);
        let (mut dynamic_header, mut tls_program_header, mut eh_frame_header) = (None, None, None);
        for header in &program_header_table {
            match header.p_type {
                PT_DYNAMIC => dynamic_header = Some(header),
                PT_TLS => tls_program_header = Some(header),
                PT_GNU_EH_FRAME => eh_frame_header = Some(header),
                PT_LOAD => {
                    let segment_map_start = page_size::get_page_start(header.p_vaddr);
                    let segment_file_offset = page_size::get_page_start(header.p_offset);
                    let segment_file_map_end =
                        page_size::get_page_end(header.p_vaddr + header.p_filesz);
                    let segment_mem_map_end =
                        page_size::get_page_end(header.p_vaddr + header.p_memsz);
                    let protection = segment_protection_from_flags(header.p_flags);

                    if header.p_filesz > 0 {
                        let file_map_len = segment_file_map_end.saturating_sub(segment_map_start);
                        let file_map_addr = (base_addr + segment_map_start) as *mut u8;
                        let mapped = mmap::mmap(
                            file_map_addr,
                            file_map_len,
                            protection,
                            mmap::MAP_PRIVATE | mmap::MAP_FIXED,
                            fd as isize,
                            segment_file_offset,
                        );
                        if mapped != file_map_addr {
                            write::write_str(
                                write::STD_ERR,
                                "Error: could not mmap PT_LOAD file segment\n",
                            );
                            exit::exit(1);
                        }
                    }

                    if header.p_filesz == 0 && header.p_memsz > 0 {
                        let bss_map_len = segment_mem_map_end.saturating_sub(segment_map_start);
                        let bss_map_addr = (base_addr + segment_map_start) as *mut u8;
                        let mapped = mmap::mmap(
                            bss_map_addr,
                            bss_map_len,
                            protection,
                            mmap::MAP_PRIVATE | mmap::MAP_ANONYMOUS | mmap::MAP_FIXED,
                            -1,
                            0,
                        );
                        if mapped != bss_map_addr {
                            write::write_str(
                                write::STD_ERR,
                                "Error: could not mmap PT_LOAD bss segment\n",
                            );
                            exit::exit(1);
                        }
                        // Keep bss pages explicitly initialized so tools like
                        // valgrind do not treat demand-zero pages as undefined.
                        core::ptr::write_bytes(bss_map_addr, 0, bss_map_len);
                    } else if header.p_memsz > header.p_filesz {
                        let zero_start = base_addr + header.p_vaddr + header.p_filesz;
                        let zero_end = base_addr + header.p_vaddr + header.p_memsz;
                        let zero_page_start = page_size::get_page_end(zero_start);

                        if zero_start < zero_page_start {
                            let partial_zero_end = min(zero_page_start, zero_end);
                            core::ptr::write_bytes(
                                zero_start as *mut u8,
                                0,
                                partial_zero_end.saturating_sub(zero_start),
                            );
                        }

                        if zero_end > zero_page_start {
                            let anon_map_len =
                                page_size::get_page_end(zero_end).saturating_sub(zero_page_start);
                            let anon_map_addr = zero_page_start as *mut u8;
                            let mapped = mmap::mmap(
                                anon_map_addr,
                                anon_map_len,
                                protection,
                                mmap::MAP_PRIVATE | mmap::MAP_ANONYMOUS | mmap::MAP_FIXED,
                                -1,
                                0,
                            );
                            if mapped != anon_map_addr {
                                write::write_str(
                                    write::STD_ERR,
                                    "Error: could not mmap PT_LOAD bss tail\n",
                                );
                                exit::exit(1);
                            }
                            // Keep bss pages explicitly initialized so tools like
                            // valgrind do not treat demand-zero pages as undefined.
                            core::ptr::write_bytes(anon_map_addr, 0, anon_map_len);
                        }
                    }
                }
                _ => (),
            }
        }

        #[cfg(debug_assertions)]
        {
            write::write_str(write::STD_OUT, "from_fd: Loaded all segments\n");
        }

        let tls = tls_program_header.map(|header| TlsInfo::from_program_header(base_addr, header));
        let eh_frame = eh_frame_header
            .map(|header| (base_addr.wrapping_add(header.p_vaddr)) as *const u8)
            .unwrap_or(null());

        Self::build(
            base_addr,
            dynamic_header.unwrap(),
            tls,
            map_start,
            map_end,
            load_segments,
            eh_frame,
        )
    }

    #[inline(always)]
    unsafe fn build(
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
        if symbol_count > 0 && !symbol_table_pointer.is_null() {
            let symbol_table = SymbolTable::new(symbol_table_pointer);
            for sym_idx in 0..symbol_count {
                let symbol = symbol_table.get_ref(sym_idx);
                if !Self::symbol_is_exported(symbol)
                    || !Self::symbol_version_is_exported_raw(versym_pointer, sym_idx)
                {
                    continue;
                }
                let word_idx = sym_idx / Self::EXPORT_MASK_WORD_BITS;
                let bit_idx = sym_idx % Self::EXPORT_MASK_WORD_BITS;
                exportable_symbol_mask[word_idx] |= 1usize << bit_idx;
            }
        }

        let mut sysv_export_buckets: Vec<SmallVec<[u32; 4]>> = Vec::new();
        if !sysv_hash_pointer.is_null() && symbol_count > 0 {
            let table = sysv_hash_pointer;
            let nbucket = *table as usize;
            let nchain = *table.add(1) as usize;
            if nbucket > 0 && nchain > 0 {
                sysv_export_buckets.resize_with(nbucket, SmallVec::new);
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
        }
    }

    fn build_static(
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

    pub unsafe fn call_fini_functions(&self) {
        if self.dynamic.is_null() {
            return;
        }

        let mut fini_fn: Option<usize> = None;
        let mut fini_array_ptr: *const usize = null();
        let mut fini_array_count = 0usize;

        for item in DynamicArrayIter::new(self.dynamic) {
            match item.d_tag {
                DT_FINI => fini_fn = Some(item.d_un.d_ptr.addr()),
                DT_FINI_ARRAY => {
                    fini_array_ptr =
                        (self.base.wrapping_add(item.d_un.d_ptr.addr())) as *const usize;
                }
                DT_FINI_ARRAYSZ => fini_array_count = item.d_un.d_val / size_of::<usize>(),
                _ => (),
            }
        }

        if !fini_array_ptr.is_null() && fini_array_count > 0 {
            let fini_array_addr = fini_array_ptr as usize;
            if fini_array_addr < self.map_start || fini_array_addr >= self.map_end {
                return;
            }
            let max_entries = (self.map_end - fini_array_addr) / size_of::<usize>();
            if max_entries == 0 {
                return;
            }
            let fini_array_count = fini_array_count.min(max_entries);
            let fini_array = slice::from_raw_parts(fini_array_ptr, fini_array_count);
            for &func_addr in fini_array.iter().rev() {
                if func_addr == 0 {
                    continue;
                }
                let func: extern "C" fn() = core::mem::transmute(func_addr);
                func();
            }
        }

        if let Some(fini_offset) = fini_fn {
            let addr = self.base.wrapping_add(fini_offset);
            let func: extern "C" fn() = core::mem::transmute(addr);
            func();
        }
    }
}

impl Relocatable for SharedObject {
    fn base(&self) -> usize {
        self.base
    }

    fn symbol(&self, symbol_index: usize) -> Symbol {
        unsafe { *self.symbol_table.get_ref(symbol_index) }
    }

    fn relocation_slices(&self) -> RelocationSlices {
        self.relocations
    }
}
