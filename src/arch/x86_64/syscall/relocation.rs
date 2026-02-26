use core::mem::size_of;
use memchr::memchr;
use phf::phf_map;
use rustc_hash::FxHashMap;

use crate::{
    elf::{relocate::Relocatable, symbol::Symbol},
    io_macros::syscall_assert,
    linking::DynamicLinker,
    page_size::get_page_size,
    syscall::exit,
};

use super::mmap::{mprotect, PROT_READ, PROT_WRITE};

pub struct IrelativeReloc {
    pub relocate_address: usize,
    pub function_pointer: usize,
}

pub struct CopyReloc {
    pub destination_address: usize,
    pub source_address: usize,
    pub size: usize,
}

/// Get the address of a stub symbol provided by the dynamic linker
#[inline(always)]
fn get_stub_symbol(name: &str) -> Option<usize> {
    use crate::ld_stubs::*;

    static STUB_SYMBOLS: phf::Map<&'static str, fn() -> usize> = phf_map! {
        "_dl_find_object" => || _dl_find_object as *const () as usize,
        "_dl_audit_preinit" => || _dl_audit_preinit as *const () as usize,
        "_dl_find_dso_for_object" => || _dl_find_dso_for_object as *const () as usize,
        "_dl_allocate_tls" => || _dl_allocate_tls as *const () as usize,
        "_dl_allocate_tls_init" => || _dl_allocate_tls_init as *const () as usize,
        "_dl_deallocate_tls" => || _dl_deallocate_tls as *const () as usize,
        "_dl_signal_error" => || _dl_signal_error as *const () as usize,
        "_dl_signal_exception" => || _dl_signal_exception as *const () as usize,
        "_dl_catch_exception" => || _dl_catch_exception as *const () as usize,
        "_dl_catch_error" => || _dl_catch_error as *const () as usize,
        "_dl_audit_symbind_alt" => || _dl_audit_symbind_alt as *const () as usize,
        "_dl_rtld_di_serinfo" => || _dl_rtld_di_serinfo as *const () as usize,
        "__tunable_is_initialized" => || __tunable_is_initialized as *const () as usize,
        "__tunable_get_val" => || __tunable_get_val as *const () as usize,
        "__tls_get_addr" => || __tls_get_addr as *const () as usize,
        "dlopen" => || dlopen as *const () as usize,
        "dlsym" => || dlsym as *const () as usize,
        "dlvsym" => || dlvsym as *const () as usize,
        "dlclose" => || dlclose as *const () as usize,
        "dlerror" => || dlerror as *const () as usize,
        "dladdr" => || dladdr as *const () as usize,
        "dladdr1" => || dladdr1 as *const () as usize,
        "dl_iterate_phdr" => || dl_iterate_phdr as *const () as usize,
        "is_selinux_enabled" => || is_selinux_enabled as *const () as usize,
        "freecon" => || freecon as *const () as usize,
        "getcon" => || getcon as *const () as usize,
        "getfilecon" => || getfilecon as *const () as usize,
        "lgetfilecon" => || lgetfilecon as *const () as usize,
        "getfilecon_raw" => || getfilecon_raw as *const () as usize,
    };

    STUB_SYMBOLS.get(name).map(|f| f())
}

/// Check if a symbol should prefer stub resolution
#[inline(always)]
fn is_stub_preferred(name: &str) -> bool {
    name.starts_with("_dl_")
        || name.starts_with("__tunable_")
        || matches!(
            name,
            "__tls_get_addr"
                | "dlsym"
                | "dlvsym"
                | "dlopen"
                | "dlclose"
                | "dlerror"
                | "dladdr"
                | "dladdr1"
                | "dl_iterate_phdr"
                | "is_selinux_enabled"
                | "freecon"
                | "getcon"
                | "getfilecon"
                | "lgetfilecon"
                | "getfilecon_raw"
        )
}

const SHN_UNDEF: u16 = 0;
const SHN_ABS: u16 = 0xfff1;
const STT_GNU_IFUNC: u8 = 10;
const STB_WEAK: u8 = 2;

pub struct SymbolLookupCache {
    entries: FxHashMap<SymbolLookupKey, Option<(usize, Symbol)>>,
    entries_no_exclude: FxHashMap<NoExcludeLookupKey, Option<(usize, Symbol)>>,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct SymbolLookupKey {
    requester_object: usize,
    exclude_key: usize,
    symbol_key: SymbolCacheKey,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct NoExcludeLookupKey {
    requester_object: usize,
    symbol_key: SymbolCacheKey,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct SymbolCacheKey {
    ptr: usize,
    len: usize,
}

impl SymbolLookupCache {
    pub fn new() -> Self {
        Self::with_capacity(4096)
    }

    pub fn with_capacity(capacity: usize) -> Self {
        let capacity = capacity.max(256);
        Self {
            entries: FxHashMap::with_capacity_and_hasher(capacity, Default::default()),
            entries_no_exclude: FxHashMap::with_capacity_and_hasher(capacity, Default::default()),
        }
    }

    #[inline(always)]
    fn symbol_key(symbol_name: &str) -> SymbolCacheKey {
        SymbolCacheKey {
            ptr: symbol_name.as_ptr() as usize,
            len: symbol_name.len(),
        }
    }

    fn lookup(
        &mut self,
        linker: &DynamicLinker,
        requester_object: usize,
        symbol_name: &str,
        exclude_object: Option<usize>,
    ) -> Option<(usize, Symbol)> {
        let symbol_key = Self::symbol_key(symbol_name);
        let symbol_base = symbol_without_version(symbol_name);
        let base_differs = symbol_base.len() != symbol_name.len();

        let resolve = |exclude: Option<usize>| unsafe {
            let lookup = |candidate: &str| {
                if requester_object < linker.objects.len() {
                    linker.lookup_symbol_for_object_excluding(requester_object, candidate, exclude)
                } else {
                    linker.lookup_symbol_excluding(candidate, exclude)
                }
            };
            lookup(symbol_name).or_else(|| base_differs.then(|| lookup(symbol_base)).flatten())
        };

        if exclude_object.is_none() {
            let key = NoExcludeLookupKey {
                requester_object,
                symbol_key,
            };
            return match self.entries_no_exclude.entry(key) {
                std::collections::hash_map::Entry::Occupied(entry) => *entry.get(),
                std::collections::hash_map::Entry::Vacant(entry) => {
                    let resolved = resolve(None);
                    entry.insert(resolved);
                    resolved
                }
            };
        }

        let key = SymbolLookupKey {
            requester_object,
            exclude_key: exclude_object.unwrap_or(usize::MAX),
            symbol_key,
        };
        match self.entries.entry(key) {
            std::collections::hash_map::Entry::Occupied(entry) => *entry.get(),
            std::collections::hash_map::Entry::Vacant(entry) => {
                let resolved = resolve(exclude_object);
                entry.insert(resolved);
                resolved
            }
        }
    }
}

fn resolve_tls_symbol(
    object_index: usize,
    symbol: Symbol,
    symbol_name: &str,
    linker: &DynamicLinker,
    lookup_cache: &mut SymbolLookupCache,
) -> (usize, Symbol) {
    if symbol.st_shndx != SHN_UNDEF {
        return (object_index, symbol);
    }

    if !symbol_name.is_empty() {
        if let Some((lib_idx, resolved_symbol)) =
            unsafe { lookup_symbol_any(linker, object_index, symbol_name, None, lookup_cache) }
        {
            return (lib_idx, resolved_symbol);
        }
    }

    (object_index, symbol)
}

#[inline(always)]
fn symbol_without_version<'a>(name: &'a str) -> &'a str {
    if let Some(idx) = memchr(b'@', name.as_bytes()) {
        &name[..idx]
    } else {
        name
    }
}

#[inline(always)]
unsafe fn lookup_symbol_any(
    linker: &DynamicLinker,
    requester_object: usize,
    symbol_name: &str,
    exclude_object: Option<usize>,
    lookup_cache: &mut SymbolLookupCache,
) -> Option<(usize, Symbol)> {
    lookup_cache.lookup(linker, requester_object, symbol_name, exclude_object)
}

#[inline(always)]
fn get_stub_symbol_any(symbol_name: &str) -> Option<usize> {
    if let Some(addr) = get_stub_symbol(symbol_name) {
        return Some(addr);
    }
    let base = symbol_without_version(symbol_name);
    if base != symbol_name {
        return get_stub_symbol(base);
    }
    None
}

#[inline(always)]
fn symbol_binding(symbol: Symbol) -> u8 {
    symbol.st_info >> 4
}

#[cold]
unsafe fn unresolved_nonweak_symbol(
    linker: &DynamicLinker,
    object_index: usize,
    symbol_name: &str,
    reloc_kind: &str,
) -> ! {
    use crate::libc::fs::write;

    write::write_str(write::STD_ERR, "rustld: unresolved non-weak symbol '");
    write::write_str(write::STD_ERR, symbol_name);
    write::write_str(write::STD_ERR, "' in ");
    if let Some(path) = linker.object_path(object_index) {
        write::write_str(write::STD_ERR, path);
    } else {
        write::write_str(write::STD_ERR, "<unknown object>");
    }
    write::write_str(write::STD_ERR, " (");
    write::write_str(write::STD_ERR, reloc_kind);
    write::write_str(write::STD_ERR, ")\n");
    exit::exit(127);
}

fn relr_address_range(base: usize, relr_slice: &[usize]) -> Option<(usize, usize)> {
    if relr_slice.is_empty() {
        return None;
    }

    let word_size = size_of::<usize>();
    let addr_bits = usize::BITS as usize;
    let mut min_addr = usize::MAX;
    let mut max_addr = 0usize;
    let mut where_addr = 0usize;

    for &entry in relr_slice {
        if entry & 1 == 0 {
            where_addr = base.wrapping_add(entry);
            min_addr = min_addr.min(where_addr);
            max_addr = max_addr.max(where_addr);
            where_addr = where_addr.wrapping_add(word_size);
        } else {
            let mut bitmap = entry >> 1;
            let mut bit = 0usize;
            while bitmap != 0 {
                if bitmap & 1 != 0 {
                    let addr = where_addr.wrapping_add(bit * word_size);
                    min_addr = min_addr.min(addr);
                    max_addr = max_addr.max(addr);
                }
                bitmap >>= 1;
                bit += 1;
            }
            where_addr = where_addr.wrapping_add((addr_bits - 1) * word_size);
        }
    }

    if min_addr == usize::MAX {
        None
    } else {
        Some((min_addr, max_addr + word_size - 1))
    }
}

fn apply_relr_relocations(base: usize, relr_slice: &[usize]) {
    if relr_slice.is_empty() {
        return;
    }

    let word_size = size_of::<usize>();
    let addr_bits = usize::BITS as usize;
    let mut where_addr = 0usize;

    for &entry in relr_slice {
        if entry & 1 == 0 {
            where_addr = base.wrapping_add(entry);
            unsafe {
                let value = core::ptr::read(where_addr as *const usize);
                core::ptr::write(where_addr as *mut usize, value.wrapping_add(base));
            }
            where_addr = where_addr.wrapping_add(word_size);
        } else {
            let mut bitmap = entry >> 1;
            let mut bit = 0usize;
            while bitmap != 0 {
                if bitmap & 1 != 0 {
                    let addr = where_addr.wrapping_add(bit * word_size);
                    unsafe {
                        let value = core::ptr::read(addr as *const usize);
                        core::ptr::write(addr as *mut usize, value.wrapping_add(base));
                    }
                }
                bitmap >>= 1;
                bit += 1;
            }
            where_addr = where_addr.wrapping_add((addr_bits - 1) * word_size);
        }
    }
}

/// Relocate an object with cross-library symbol resolution
pub unsafe fn relocate_with_linker(
    object: &impl Relocatable,
    object_index: usize,
    linker: &DynamicLinker,
    ifuncs: &mut Vec<IrelativeReloc>,
    copies: &mut Vec<CopyReloc>,
    lookup_cache: &mut SymbolLookupCache,
) {
    let relocation_slices = object.relocation_slices();

    #[cfg(debug_assertions)]
    {
        use crate::libc::fs::write;
        if let Some((name, _idx)) = linker
            .library_map
            .iter()
            .find(|(_, idx)| *idx == object_index)
        {
            if name == "libc.so.6" {
                write::write_str(write::STD_ERR, "libc relr count=");
                write_hex(write::STD_ERR, relocation_slices.relr_slice.len());
                write::write_str(write::STD_ERR, "\n");
            }
        }
    }

    // Make the memory writable before relocations
    // (in case RELRO or other protections made it read-only)
    if !relocation_slices.rela_slice.is_empty() || !relocation_slices.relr_slice.is_empty() {
        let page_size = get_page_size();

        // Find the range of addresses we'll be writing to
        let mut min_addr = usize::MAX;
        let mut max_addr = 0usize;

        for rela in relocation_slices.rela_slice {
            let addr = rela.r_offset.wrapping_add(object.base());
            if addr < min_addr {
                min_addr = addr;
            }
            if addr > max_addr {
                max_addr = addr;
            }
        }

        if let Some((relr_min, relr_max)) =
            relr_address_range(object.base(), relocation_slices.relr_slice)
        {
            if relr_min < min_addr {
                min_addr = relr_min;
            }
            if relr_max > max_addr {
                max_addr = relr_max;
            }
        }

        // Round to page boundaries
        if min_addr != usize::MAX {
            let start_page = (min_addr / page_size) * page_size;
            let end_page = ((max_addr + 7 + page_size - 1) / page_size) * page_size; // +7 for 8-byte relocation
            let length = end_page - start_page;

            // Make the region writable
            let result = mprotect(start_page as *mut u8, length, PROT_READ | PROT_WRITE);

            if result < 0 {
                use crate::libc::fs::write;
                write::write_str(write::STD_ERR, "mprotect failed with error code: ");
                // Print error code
                let err = -result as usize;
                if err < 10 {
                    let digit = [b'0' + err as u8];
                    write::write_str(write::STD_ERR, core::str::from_utf8_unchecked(&digit));
                } else {
                    write::write_str(write::STD_ERR, ">=10");
                }
                write::write_str(write::STD_ERR, "\n");
            }
        }
    }

    // Variables in relocation formulae:
    // - A(rela.r_addend): This is the addend used to compute the value of the relocatable field.
    // - B(self.base.addr): This is the base address at which a shared object has been loaded into memory during execution.
    // - G(??): This is the offset into the global offset table at which the address of the relocation entry’s symbol will reside during execution.
    // - GOT(global_offset_table_address): This is the address of the global offset table.
    // - L(??): ??
    // - P(relocate_address): This is the address of the storage unit being relocated.
    // - S(self.symbol.st_value): This is the value of the symbol table entry indexed at `rela.r_sym()`.
    //   NOTE: In the ELF specification `S` is equal to (symbol.st_value + base_address) but that doesn't make any sense to me.
    // - Z(??): ??

    // x86_64 relocation types:
    /// | None
    const R_X86_64_NONE: u32 = 0;
    /// S + B + A | u64
    const R_X86_64_64: u32 = 1;
    /// S + B + A - P | u32
    const R_X86_64_PC32: u32 = 2;
    /// G + A | u32
    const R_X86_64_GOT32: u32 = 3;
    /// L + A - P | u32
    const R_X86_64_PLT32: u32 = 4;
    /// | None
    const R_X86_64_COPY: u32 = 5;
    /// S + B | u64
    const R_X86_64_GLOB_DAT: u32 = 6;
    /// S + B | u64
    const R_X86_64_JUMP_SLOT: u32 = 7;
    /// B + A | u64
    const R_X86_64_RELATIVE: u32 = 8;
    /// G + GOT + A - P | u32
    const R_X86_64_GOTPCREL: u32 = 9;
    /// S + B + A | u32
    const R_X86_64_32: u32 = 10;
    /// S + B + A | u32
    const R_X86_64_32S: u32 = 11;
    /// S + B + A | u16
    const R_X86_64_16: u32 = 12;
    /// S + B + A - P | u16
    const R_X86_64_PC16: u32 = 13;
    /// S + B + A | u8
    const R_X86_64_8: u32 = 14;
    /// S + B + A - P | u8
    const R_X86_64_PC8: u32 = 15;
    /// S + B + A - P | u64
    const R_X86_64_PC64: u32 = 24;
    /// S + B + A - GOT | u64
    const R_X86_64_GOTOFF64: u32 = 25;
    /// GOT + A - P | u32
    const R_X86_64_GOTPC32: u32 = 26;
    /// Z + A | u32
    const R_X86_64_SIZE32: u32 = 32;
    /// Z + A | u64
    const R_X86_64_SIZE64: u32 = 33;
    /// The returned value from the function located at (B + A) | u64
    const R_X86_64_IRELATIVE: u32 = 37; // This one is fucking awesome... I mean, it's a little annoying but really cool.

    // You may notice some are missing values; those are part of the Thread-Local Storage ABI see "ELF Handling for Thread-Local Storage":
    const R_X86_64_DTPMOD64: u32 = 16; // Module ID for TLS
    const R_X86_64_DTPOFF64: u32 = 17; // Offset in TLS block
    const R_X86_64_TPOFF64: u32 = 18; // Offset in static TLS block
    const R_X86_64_TLSGD: u32 = 19; // PC-relative offset to GD GOT entry
    const R_X86_64_TLSLD: u32 = 20; // PC-relative offset to LD GOT entry
    const R_X86_64_DTPOFF32: u32 = 21; // Offset in TLS block (32-bit)
    const R_X86_64_GOTTPOFF: u32 = 22; // PC-relative offset to IE GOT entry
    const R_X86_64_TPOFF32: u32 = 23; // Offset in static TLS block (32-bit)
    const R_X86_64_TLSDESC: u32 = 36; // TLS descriptor

    for rela in relocation_slices.rela_slice {
        let relocate_address = rela.r_offset.wrapping_add(object.base());

        match rela.r_type() {
            R_X86_64_NONE => {}
            R_X86_64_64 => {
                let symbol = object.symbol(rela.r_sym() as usize);
                let symbol_name = linker.objects[object_index]
                    .string_table
                    .get(symbol.st_name as usize);
                let base_symbol_name = symbol_without_version(symbol_name);
                let prefer_stub = is_stub_preferred(base_symbol_name);

                let (symbol_addr, symbol_type) = if prefer_stub {
                    if let Some(stub_addr) = get_stub_symbol_any(symbol_name) {
                        (stub_addr, 0)
                    } else if let Some((lib_idx, resolved_symbol)) =
                        lookup_symbol_any(linker, object_index, symbol_name, None, lookup_cache)
                    {
                        let base = if resolved_symbol.st_shndx == SHN_ABS {
                            0
                        } else {
                            linker.get_base(lib_idx)
                        };
                        (
                            resolved_symbol.st_value.wrapping_add(base),
                            resolved_symbol.st_info & 0x0f,
                        )
                    } else if symbol.st_shndx == SHN_UNDEF {
                        if symbol_binding(symbol) != STB_WEAK {
                            unresolved_nonweak_symbol(
                                linker,
                                object_index,
                                symbol_name,
                                "R_X86_64_64",
                            );
                        }
                        (0usize, symbol.st_info & 0x0f)
                    } else {
                        let base = if symbol.st_shndx == SHN_ABS {
                            0
                        } else {
                            object.base()
                        };
                        (symbol.st_value.wrapping_add(base), symbol.st_info & 0x0f)
                    }
                } else if let Some((lib_idx, resolved_symbol)) =
                    lookup_symbol_any(linker, object_index, symbol_name, None, lookup_cache)
                {
                    let base = if resolved_symbol.st_shndx == SHN_ABS {
                        0
                    } else {
                        linker.get_base(lib_idx)
                    };
                    (
                        resolved_symbol.st_value.wrapping_add(base),
                        resolved_symbol.st_info & 0x0f,
                    )
                } else if symbol.st_shndx == SHN_UNDEF {
                    // Undefined (often weak) symbols resolve to 0.
                    (0usize, symbol.st_info & 0x0f)
                } else {
                    let base = if symbol.st_shndx == SHN_ABS {
                        0
                    } else {
                        object.base()
                    };
                    (symbol.st_value.wrapping_add(base), symbol.st_info & 0x0f)
                };

                let relocate_value = symbol_addr.wrapping_add_signed(rela.r_addend);
                if symbol_type == STT_GNU_IFUNC {
                    ifuncs.push(IrelativeReloc {
                        relocate_address,
                        function_pointer: relocate_value,
                    });
                } else {
                    core::ptr::write(relocate_address as *mut usize, relocate_value);
                }
            }
            R_X86_64_GLOB_DAT | R_X86_64_JUMP_SLOT => {
                let symbol = object.symbol(rela.r_sym() as usize);

                // Get symbol name and look it up across all loaded libraries
                let symbol_name = linker.objects[object_index]
                    .string_table
                    .get(symbol.st_name as usize);

                let base_symbol_name = symbol_without_version(symbol_name);
                let prefer_stub = is_stub_preferred(base_symbol_name);

                let (relocate_value, symbol_type, _resolved_idx) = if prefer_stub {
                    if let Some(stub_addr) = get_stub_symbol_any(symbol_name) {
                        (stub_addr, 0, None)
                    } else if let Some((lib_idx, resolved_symbol)) =
                        lookup_symbol_any(linker, object_index, symbol_name, None, lookup_cache)
                    {
                        let base = if resolved_symbol.st_shndx == SHN_ABS {
                            0
                        } else {
                            linker.get_base(lib_idx)
                        };
                        (
                            resolved_symbol.st_value.wrapping_add(base),
                            resolved_symbol.st_info & 0x0f,
                            Some(lib_idx),
                        )
                    } else if symbol.st_shndx == 0 {
                        if symbol_binding(symbol) != STB_WEAK {
                            unresolved_nonweak_symbol(
                                linker,
                                object_index,
                                symbol_name,
                                "R_X86_64_GLOB_DAT/JUMP_SLOT",
                            );
                        }
                        (0usize, symbol.st_info & 0x0f, None)
                    } else {
                        (
                            symbol.st_value.wrapping_add(object.base()),
                            symbol.st_info & 0x0f,
                            Some(object_index),
                        )
                    }
                } else if let Some((lib_idx, resolved_symbol)) =
                    lookup_symbol_any(linker, object_index, symbol_name, None, lookup_cache)
                {
                    // Symbol found — compute absolute address
                    let base = if resolved_symbol.st_shndx == SHN_ABS {
                        0
                    } else {
                        linker.get_base(lib_idx)
                    };
                    (
                        resolved_symbol.st_value.wrapping_add(base),
                        resolved_symbol.st_info & 0x0f,
                        Some(lib_idx),
                    )
                } else if symbol.st_shndx == 0 {
                    if symbol_binding(symbol) != STB_WEAK {
                        unresolved_nonweak_symbol(
                            linker,
                            object_index,
                            symbol_name,
                            "R_X86_64_GLOB_DAT/JUMP_SLOT",
                        );
                    }
                    // Symbol not found — undefined symbol resolves to NULL.
                    (0usize, symbol.st_info & 0x0f, None)
                } else {
                    (
                        symbol.st_value.wrapping_add(object.base()),
                        symbol.st_info & 0x0f,
                        Some(object_index),
                    )
                };

                // Debug: show what we're writing where
                #[cfg(debug_assertions)]
                {
                    use crate::libc::fs::write;
                    write::write_str(write::STD_ERR, "  GOT[");
                    // print relocate_address as hex
                    let mut buf = [0u8; 18];
                    buf[0] = b'0';
                    buf[1] = b'x';
                    let hex = b"0123456789abcdef";
                    let mut addr = relocate_address;
                    for i in (0..16).rev() {
                        buf[2 + i] = hex[addr & 0xF];
                        addr >>= 4;
                    }
                    write::write_str(write::STD_ERR, core::str::from_utf8_unchecked(&buf));
                    write::write_str(write::STD_ERR, "] = ");
                    // print value
                    let mut buf2 = [0u8; 18];
                    buf2[0] = b'0';
                    buf2[1] = b'x';
                    let mut val = relocate_value;
                    for i in (0..16).rev() {
                        buf2[2 + i] = hex[val & 0xF];
                        val >>= 4;
                    }
                    write::write_str(write::STD_ERR, core::str::from_utf8_unchecked(&buf2));
                    write::write_str(write::STD_ERR, " ");
                    write::write_str(write::STD_ERR, symbol_name);
                    if symbol_type == STT_GNU_IFUNC {
                        write::write_str(write::STD_ERR, " (IFUNC)");
                    }
                    write::write_str(write::STD_ERR, "\n");
                }

                if symbol_type == STT_GNU_IFUNC {
                    // IFUNC symbols resolve to executable code addresses only after
                    // calling the resolver function. Defer this to the global IFUNC
                    // pass so all objects are relocated first.
                    ifuncs.push(IrelativeReloc {
                        relocate_address,
                        function_pointer: relocate_value,
                    });
                } else {
                    core::ptr::write(relocate_address as *mut usize, relocate_value);
                }
            }
            R_X86_64_RELATIVE => {
                let relocate_value = object.base().wrapping_add_signed(rela.r_addend);
                core::ptr::write(relocate_address as *mut usize, relocate_value);
            }
            R_X86_64_COPY => {
                let symbol = object.symbol(rela.r_sym() as usize);
                let symbol_name = linker.objects[object_index]
                    .string_table
                    .get(symbol.st_name as usize);

                if let Some((lib_idx, resolved_symbol)) = lookup_symbol_any(
                    linker,
                    object_index,
                    symbol_name,
                    Some(object_index),
                    lookup_cache,
                ) {
                    let base = if resolved_symbol.st_shndx == SHN_ABS {
                        0
                    } else {
                        linker.get_base(lib_idx)
                    };
                    let source_address = resolved_symbol.st_value.wrapping_add(base);
                    let size = if symbol.st_size != 0 {
                        symbol.st_size as usize
                    } else {
                        resolved_symbol.st_size as usize
                    };
                    copies.push(CopyReloc {
                        destination_address: relocate_address,
                        source_address,
                        size,
                    });
                }
            }
            R_X86_64_IRELATIVE => {
                let function_pointer = object.base().wrapping_add_signed(rela.r_addend);
                ifuncs.push(IrelativeReloc {
                    relocate_address,
                    function_pointer,
                });
            }
            // TLS relocations
            R_X86_64_DTPMOD64 => {
                let symbol = object.symbol(rela.r_sym() as usize);
                let symbol_name = linker.objects[object_index]
                    .string_table
                    .get(symbol.st_name as usize);
                let (def_idx, _def_sym) =
                    resolve_tls_symbol(object_index, symbol, symbol_name, linker, lookup_cache);
                let module_id = linker.objects[def_idx]
                    .tls
                    .as_ref()
                    .map(|tls| tls.module_id)
                    .unwrap_or(0);
                core::ptr::write(relocate_address as *mut usize, module_id);
            }
            R_X86_64_DTPOFF64 | R_X86_64_DTPOFF32 => {
                // Offset in TLS block: S + A
                let symbol = object.symbol(rela.r_sym() as usize);
                let symbol_name = linker.objects[object_index]
                    .string_table
                    .get(symbol.st_name as usize);
                let (_def_idx, def_sym) =
                    resolve_tls_symbol(object_index, symbol, symbol_name, linker, lookup_cache);
                let relocate_value = def_sym.st_value.wrapping_add_signed(rela.r_addend);
                if rela.r_type() == R_X86_64_DTPOFF32 {
                    let value32 = relocate_value as u32;
                    core::ptr::write(relocate_address as *mut u32, value32);
                } else {
                    core::ptr::write(relocate_address as *mut usize, relocate_value);
                }
            }
            R_X86_64_TPOFF64 | R_X86_64_TPOFF32 => {
                // Offset from TP to TLS variable: tls_offset + S + A
                let symbol = object.symbol(rela.r_sym() as usize);
                let symbol_name = linker.objects[object_index]
                    .string_table
                    .get(symbol.st_name as usize);
                let (def_idx, def_sym) =
                    resolve_tls_symbol(object_index, symbol, symbol_name, linker, lookup_cache);
                let tls_offset = linker.objects[def_idx]
                    .tls
                    .as_ref()
                    .map(|tls| tls.offset)
                    .unwrap_or(0);
                let relocate_value = tls_offset
                    .wrapping_add(def_sym.st_value as isize)
                    .wrapping_add(rela.r_addend);
                #[cfg(debug_assertions)]
                {
                    use crate::libc::fs::write;
                    write::write_str(write::STD_ERR, "  TLS TPOFF ");
                    write::write_str(write::STD_ERR, symbol_name);
                    write::write_str(write::STD_ERR, " = ");
                    write_hex(write::STD_ERR, relocate_value as usize);
                    write::write_str(write::STD_ERR, "\n");
                }
                if rela.r_type() == R_X86_64_TPOFF32 {
                    let value32 = relocate_value as u32;
                    core::ptr::write(relocate_address as *mut u32, value32);
                } else {
                    core::ptr::write(relocate_address as *mut usize, relocate_value as usize);
                }
            }
            R_X86_64_TLSGD => {
                // TLS General Dynamic: write TLS index (module, offset) pair
                let symbol = object.symbol(rela.r_sym() as usize);
                let symbol_name = linker.objects[object_index]
                    .string_table
                    .get(symbol.st_name as usize);
                let (def_idx, def_sym) =
                    resolve_tls_symbol(object_index, symbol, symbol_name, linker, lookup_cache);
                let module_id = linker.objects[def_idx]
                    .tls
                    .as_ref()
                    .map(|tls| tls.module_id)
                    .unwrap_or(0);
                let dtpoff = def_sym.st_value.wrapping_add_signed(rela.r_addend);
                core::ptr::write(relocate_address as *mut usize, module_id);
                core::ptr::write(
                    (relocate_address + size_of::<usize>()) as *mut usize,
                    dtpoff as usize,
                );
            }
            R_X86_64_TLSLD => {
                // TLS Local Dynamic: module only, offset = 0
                let module_id = linker.objects[object_index]
                    .tls
                    .as_ref()
                    .map(|tls| tls.module_id)
                    .unwrap_or(0);
                core::ptr::write(relocate_address as *mut usize, module_id);
                core::ptr::write((relocate_address + size_of::<usize>()) as *mut usize, 0);
            }
            R_X86_64_GOTTPOFF => {
                // GOT entry with offset from TP to TLS variable
                let symbol = object.symbol(rela.r_sym() as usize);
                let symbol_name = linker.objects[object_index]
                    .string_table
                    .get(symbol.st_name as usize);
                let (def_idx, def_sym) =
                    resolve_tls_symbol(object_index, symbol, symbol_name, linker, lookup_cache);
                let tls_offset = linker.objects[def_idx]
                    .tls
                    .as_ref()
                    .map(|tls| tls.offset)
                    .unwrap_or(0);
                let relocate_value = tls_offset
                    .wrapping_add(def_sym.st_value as isize)
                    .wrapping_add(rela.r_addend);
                core::ptr::write(relocate_address as *mut usize, relocate_value as usize);
            }
            R_X86_64_TLSDESC => {
                // TLSDESC:
                // - static TLS modules can use a pure TP-relative return fast-path
                // - runtime (dynamic) TLS modules must call __tls_get_addr
                let symbol = object.symbol(rela.r_sym() as usize);
                let symbol_name = linker.objects[object_index]
                    .string_table
                    .get(symbol.st_name as usize);
                let (def_idx, def_sym) =
                    resolve_tls_symbol(object_index, symbol, symbol_name, linker, lookup_cache);
                let (module_id, tls_offset) = linker.objects[def_idx]
                    .tls
                    .as_ref()
                    .map(|tls| (tls.module_id, tls.offset))
                    .unwrap_or((0, 0));
                let dtpoff = def_sym.st_value.wrapping_add_signed(rela.r_addend);
                let desc = relocate_address as *mut usize;
                if module_id != 0 && tls_offset == 0 {
                    let ti = std::boxed::Box::new(crate::ld_stubs::TlsIndex {
                        ti_module: module_id,
                        ti_offset: dtpoff,
                    });
                    core::ptr::write(desc, crate::arch::tlsdesc_resolver_addr());
                    core::ptr::write(desc.add(1), std::boxed::Box::into_raw(ti) as usize);
                } else {
                    let tprel = tls_offset
                        .wrapping_add(def_sym.st_value as isize)
                        .wrapping_add(rela.r_addend);
                    core::ptr::write(desc, crate::arch::tlsdesc_return_addr());
                    core::ptr::write(desc.add(1), tprel as usize);
                }
            }
            reloc_type => {
                use crate::libc::fs::write;
                write::write_str(write::STD_ERR, "Unsupported relocation type: ");
                // Print the actual numeric value followed by name
                if reloc_type < 10 {
                    let digit = [b'0' + reloc_type as u8];
                    write::write_str(write::STD_ERR, core::str::from_utf8_unchecked(&digit));
                } else if reloc_type < 100 {
                    let tens = b'0' + (reloc_type / 10) as u8;
                    let ones = b'0' + (reloc_type % 10) as u8;
                    write::write_str(
                        write::STD_ERR,
                        core::str::from_utf8_unchecked(&[tens, ones]),
                    );
                } else {
                    write::write_str(write::STD_ERR, ">=100");
                }
                write::write_str(write::STD_ERR, " ");
                match reloc_type {
                    0 => write::write_str(write::STD_ERR, "(NONE)"),
                    1 => write::write_str(write::STD_ERR, "(64)"),
                    2 => write::write_str(write::STD_ERR, "(PC32)"),
                    3 => write::write_str(write::STD_ERR, "(GOT32)"),
                    4 => write::write_str(write::STD_ERR, "(PLT32)"),
                    5 => write::write_str(write::STD_ERR, "(COPY)"),
                    6 => write::write_str(write::STD_ERR, "(GLOB_DAT)"),
                    7 => write::write_str(write::STD_ERR, "(JUMP_SLOT)"),
                    8 => write::write_str(write::STD_ERR, "(RELATIVE)"),
                    9 => write::write_str(write::STD_ERR, "(GOTPCREL)"),
                    10 => write::write_str(write::STD_ERR, "(32)"),
                    11 => write::write_str(write::STD_ERR, "(32S)"),
                    16 => write::write_str(write::STD_ERR, "(DTPMOD64)"),
                    24 => write::write_str(write::STD_ERR, "(PC64)"),
                    37 => write::write_str(write::STD_ERR, "(IRELATIVE)"),
                    _ => write::write_str(write::STD_ERR, "(unknown)"),
                }
                write::write_str(write::STD_ERR, "\n");
                syscall_assert!(false, "unsupported relocation");
            }
        }
    }

    // Apply packed RELR relocations (R_*_RELATIVE)
    apply_relr_relocations(object.base(), relocation_slices.relr_slice);

    #[cfg(debug_assertions)]
    {
        use crate::libc::fs::write;
        if let Some((name, _)) = linker
            .library_map
            .iter()
            .find(|(_, idx)| *idx == object_index)
        {
            if name == "libc.so.6" {
                let base = object.base();
                let addr = base.wrapping_add(0x1ea3c0);
                write::write_str(write::STD_ERR, "libc _nl_global_locale@");
                write_hex(write::STD_ERR, addr);
                write::write_str(write::STD_ERR, " =");
                for i in 0..8usize {
                    let val = unsafe { core::ptr::read((addr + i * 8) as *const usize) };
                    write::write_str(write::STD_ERR, " ");
                    write_hex(write::STD_ERR, val);
                }
                write::write_str(write::STD_ERR, "\n");

                let main_arena = base.wrapping_add(0x1e9ac0);
                write::write_str(write::STD_ERR, "libc main_arena@");
                write_hex(write::STD_ERR, main_arena);
                write::write_str(write::STD_ERR, " =");
                for i in 0..16usize {
                    let val = unsafe { core::ptr::read((main_arena + i * 8) as *const usize) };
                    write::write_str(write::STD_ERR, " ");
                    write_hex(write::STD_ERR, val);
                }
                write::write_str(write::STD_ERR, "\n");

                let scan_region = |label: &str, start_off: usize, size: usize| {
                    let start = base.wrapping_add(start_off);
                    let end = start.wrapping_add(size);
                    let mut cursor = start;
                    while cursor < end {
                        let val = unsafe { core::ptr::read(cursor as *const usize) };
                        if val == 0x1ea3c0 {
                            write::write_str(write::STD_ERR, "libc ");
                            write::write_str(write::STD_ERR, label);
                            write::write_str(write::STD_ERR, " has raw _nl_global_locale ptr at ");
                            write_hex(write::STD_ERR, cursor);
                            write::write_str(write::STD_ERR, "\n");
                            break;
                        }
                        cursor = cursor.wrapping_add(core::mem::size_of::<usize>());
                    }
                };

                scan_region("RELRO", 0x1e5bc0, 0x2d60);
                scan_region("DATA", 0x1e9000, 0x16c8);
            }
        }
    }
}

pub unsafe fn apply_irelative_relocations(ifuncs: &[IrelativeReloc]) {
    for ifunc in ifuncs {
        #[cfg(debug_assertions)]
        {
            use crate::libc::fs::write;
            write::write_str(write::STD_ERR, "IRELATIVE resolver=");
            write_hex(write::STD_ERR, ifunc.function_pointer);
            write::write_str(write::STD_ERR, " reloc=");
            write_hex(write::STD_ERR, ifunc.relocate_address);
            write::write_str(write::STD_ERR, "\n");
        }
        let function: extern "C" fn() -> usize = core::mem::transmute(ifunc.function_pointer);
        let relocate_value = function();
        core::ptr::write(ifunc.relocate_address as *mut usize, relocate_value);
    }
}

pub unsafe fn apply_copy_relocations(copies: &[CopyReloc]) {
    for copy in copies {
        if copy.size == 0 {
            continue;
        }
        core::ptr::copy_nonoverlapping(
            copy.source_address as *const u8,
            copy.destination_address as *mut u8,
            copy.size,
        );
    }
}

fn write_hex(fd: i32, mut value: usize) {
    use crate::libc::fs::write;
    let mut buf = [0u8; 18];
    buf[0] = b'0';
    buf[1] = b'x';
    let hex = b"0123456789abcdef";
    for i in (0..16).rev() {
        buf[2 + i] = hex[value & 0xF];
        value >>= 4;
    }
    unsafe {
        write::write_str(fd, core::str::from_utf8_unchecked(&buf));
    }
}

/// Original relocate function for self-contained objects (like static PIE)
pub unsafe fn relocate(object: &impl Relocatable) {
    let relocation_slices = object.relocation_slices();

    // Make the memory writable before relocations
    if !relocation_slices.rela_slice.is_empty() || !relocation_slices.relr_slice.is_empty() {
        let page_size = get_page_size();

        // Find the range of addresses we'll be writing to
        let mut min_addr = usize::MAX;
        let mut max_addr = 0usize;

        for rela in relocation_slices.rela_slice {
            let addr = rela.r_offset.wrapping_add(object.base());
            if addr < min_addr {
                min_addr = addr;
            }
            if addr > max_addr {
                max_addr = addr;
            }
        }

        if let Some((relr_min, relr_max)) =
            relr_address_range(object.base(), relocation_slices.relr_slice)
        {
            if relr_min < min_addr {
                min_addr = relr_min;
            }
            if relr_max > max_addr {
                max_addr = relr_max;
            }
        }

        // Round to page boundaries
        if min_addr != usize::MAX {
            let start_page = (min_addr / page_size) * page_size;
            let end_page = ((max_addr + 7 + page_size - 1) / page_size) * page_size;
            let length = end_page - start_page;

            // Make the region writable
            mprotect(start_page as *mut u8, length, PROT_READ | PROT_WRITE);
        }
    }

    const R_X86_64_RELATIVE: u32 = 8;
    const R_X86_64_IRELATIVE: u32 = 37;
    const R_X86_64_64: u32 = 1;

    for rela in relocation_slices.rela_slice {
        let relocate_address = rela.r_offset.wrapping_add(object.base());

        match rela.r_type() {
            R_X86_64_64 => {
                let relocate_value = object
                    .symbol(rela.r_sym() as usize)
                    .st_value
                    .wrapping_add(object.base())
                    .wrapping_add_signed(rela.r_addend);
                core::ptr::write(relocate_address as *mut usize, relocate_value);
            }
            R_X86_64_RELATIVE => {
                let relocate_value = object.base().wrapping_add_signed(rela.r_addend);
                core::ptr::write(relocate_address as *mut usize, relocate_value);
            }
            R_X86_64_IRELATIVE => {
                let function_pointer = object.base().wrapping_add_signed(rela.r_addend);
                let function: extern "C" fn() -> usize = core::mem::transmute(function_pointer);
                let relocate_value = function();
                core::ptr::write(relocate_address as *mut usize, relocate_value);
            }
            _ => (),
        }
    }

    // Apply packed RELR relocations (R_*_RELATIVE)
    apply_relr_relocations(object.base(), relocation_slices.relr_slice);
}
