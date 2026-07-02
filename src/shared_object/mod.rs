use core::ptr::null;
use core::slice;
use smallvec::SmallVec;
use std::cmp::min;
use std::mem::MaybeUninit;
use std::ptr::null_mut;

use crate::utils::{calculate_virtual_address_bounds, strip_version_suffix, symbol_name_matches_bytes};

use crate::elf::dynamic_array::{
    DynamicArrayItem, DT_GNU_HASH, DT_HASH, DT_INIT, DT_INIT_ARRAY, DT_INIT_ARRAYSZ, DT_JMPREL,
    DT_NEEDED, DT_PLTRELSZ, DT_RELR, DT_RELRENT, DT_RELRSZ, DT_RPATH, DT_RUNPATH, DT_SONAME,
    DT_STRSZ, DT_VERSYM,
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
        program_header::{ProgramHeader, PT_DYNAMIC, PT_TLS},
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

fn collect_load_segment_ranges(
    base_addr: usize,
    program_header_table: &[ProgramHeader],
) -> Vec<(usize, usize)> {
    let mut ranges = Vec::new();
    for header in program_header_table {
        if header.p_type != PT_LOAD || header.p_memsz == 0 {
            continue;
        }
        let start = page_size::get_page_start(base_addr.wrapping_add(header.p_vaddr));
        let end = page_size::get_page_end(
            base_addr
                .wrapping_add(header.p_vaddr)
                .wrapping_add(header.p_memsz),
        );
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
#[derive(Clone)]
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
    pub resolved_dependencies: Vec<usize>,
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
    sysv_export_any_version_buckets: Vec<SmallVec<[u32; 4]>>,
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

mod lookup;
mod load;
mod build;
