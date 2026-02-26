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
fn symbol_without_version(name: &str) -> &str {
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
fn prefer_stub_first(symbol_name: &str) -> bool {
    matches!(
        symbol_without_version(symbol_name),
        "__tls_get_addr"
            | "dlsym"
            | "dlvsym"
            | "dlopen"
            | "dlclose"
            | "dlerror"
            | "dladdr"
            | "dladdr1"
            | "dl_iterate_phdr"
    ) || symbol_without_version(symbol_name).starts_with("_dl_")
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
            let addr = base.wrapping_add(entry);
            if addr < min_addr {
                min_addr = addr;
            }
            if addr > max_addr {
                max_addr = addr;
            }
            where_addr = addr.wrapping_add(word_size);
        } else {
            let mut bits = entry >> 1;
            for bit in 0..(addr_bits - 1) {
                if bits & 1 != 0 {
                    let addr = where_addr.wrapping_add(bit * word_size);
                    if addr < min_addr {
                        min_addr = addr;
                    }
                    if addr > max_addr {
                        max_addr = addr;
                    }
                }
                bits >>= 1;
            }
            where_addr = where_addr.wrapping_add((addr_bits - 1) * word_size);
        }
    }

    if min_addr == usize::MAX {
        None
    } else {
        Some((min_addr, max_addr))
    }
}

#[inline(always)]
fn apply_relr_relocations(base: usize, relr_slice: &[usize]) {
    if relr_slice.is_empty() {
        return;
    }

    let word_size = size_of::<usize>();
    let addr_bits = usize::BITS as usize;
    let mut where_addr = 0usize;

    for &entry in relr_slice {
        if entry & 1 == 0 {
            let relocate_address = base.wrapping_add(entry);
            let relocate_value =
                unsafe { core::ptr::read(relocate_address as *const usize) }.wrapping_add(base);
            unsafe { core::ptr::write(relocate_address as *mut usize, relocate_value) };
            where_addr = relocate_address.wrapping_add(word_size);
        } else {
            let mut bits = entry >> 1;
            for bit in 0..(addr_bits - 1) {
                if bits & 1 != 0 {
                    let relocate_address = where_addr.wrapping_add(bit * word_size);
                    let relocate_value =
                        unsafe { core::ptr::read(relocate_address as *const usize) }
                            .wrapping_add(base);
                    unsafe { core::ptr::write(relocate_address as *mut usize, relocate_value) };
                }
                bits >>= 1;
            }
            where_addr = where_addr.wrapping_add((addr_bits - 1) * word_size);
        }
    }
}

pub unsafe fn relocate_with_linker(
    object: &impl Relocatable,
    object_index: usize,
    linker: &DynamicLinker,
    ifuncs: &mut Vec<IrelativeReloc>,
    copies: &mut Vec<CopyReloc>,
    lookup_cache: &mut SymbolLookupCache,
) {
    let relocation_slices = object.relocation_slices();

    if !relocation_slices.rela_slice.is_empty() || !relocation_slices.relr_slice.is_empty() {
        let page_size = get_page_size();
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

        if min_addr != usize::MAX {
            let start_page = (min_addr / page_size) * page_size;
            let end_page = ((max_addr + 15 + page_size - 1) / page_size) * page_size;
            let length = end_page - start_page;
            let _ = mprotect(start_page as *mut u8, length, PROT_READ | PROT_WRITE);
        }
    }

    const R_AARCH64_NONE: u32 = 0;
    const R_AARCH64_ABS64: u32 = 257;
    const R_AARCH64_ABS32: u32 = 258;
    const R_AARCH64_ABS16: u32 = 259;
    const R_AARCH64_COPY: u32 = 1024;
    const R_AARCH64_GLOB_DAT: u32 = 1025;
    const R_AARCH64_JUMP_SLOT: u32 = 1026;
    const R_AARCH64_RELATIVE: u32 = 1027;
    const R_AARCH64_TLS_DTPMOD64: u32 = 1028;
    const R_AARCH64_TLS_DTPREL64: u32 = 1029;
    const R_AARCH64_TLS_TPREL64: u32 = 1030;
    const R_AARCH64_TLSDESC: u32 = 1031;
    const R_AARCH64_IRELATIVE: u32 = 1032;

    for rela in relocation_slices.rela_slice {
        let relocate_address = rela.r_offset.wrapping_add(object.base());

        match rela.r_type() {
            R_AARCH64_NONE => {}
            R_AARCH64_ABS64 | R_AARCH64_GLOB_DAT | R_AARCH64_JUMP_SLOT => {
                let symbol = object.symbol(rela.r_sym() as usize);
                let symbol_name = linker.objects[object_index]
                    .string_table
                    .get(symbol.st_name as usize);
                let (mut symbol_addr, symbol_type) = if prefer_stub_first(symbol_name) {
                    if let Some(stub_addr) = get_stub_symbol_any(symbol_name) {
                        #[cfg(debug_assertions)]
                        {
                            if symbol_name.starts_with("_dl_")
                                || symbol_name.starts_with("__tunable_")
                                || symbol_name == "__tls_get_addr"
                            {
                                use crate::libc::fs::write;
                                write::write_str(write::STD_ERR, "symbind ");
                                write::write_str(write::STD_ERR, symbol_name);
                                write::write_str(write::STD_ERR, " -> <stub-pre>\n");
                            }
                        }
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
                                "R_AARCH64_ABS64/GLOB_DAT/JUMP_SLOT",
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
                    #[cfg(debug_assertions)]
                    {
                        if symbol_name.starts_with("_dl_")
                            || symbol_name.starts_with("__tunable_")
                            || symbol_name == "__tls_get_addr"
                        {
                            use crate::libc::fs::write;
                            write::write_str(write::STD_ERR, "symbind ");
                            write::write_str(write::STD_ERR, symbol_name);
                            write::write_str(write::STD_ERR, " -> obj=");
                            if let Some(path) = linker.object_path(lib_idx) {
                                write::write_str(write::STD_ERR, path);
                            } else {
                                write::write_str(write::STD_ERR, "<unknown>");
                            }
                            write::write_str(write::STD_ERR, "\n");
                        }
                    }
                    let base = if resolved_symbol.st_shndx == SHN_ABS {
                        0
                    } else {
                        linker.get_base(lib_idx)
                    };
                    (
                        resolved_symbol.st_value.wrapping_add(base),
                        resolved_symbol.st_info & 0x0f,
                    )
                } else if let Some(stub_addr) = get_stub_symbol_any(symbol_name) {
                    #[cfg(debug_assertions)]
                    {
                        if symbol_name.starts_with("_dl_")
                            || symbol_name.starts_with("__tunable_")
                            || symbol_name == "__tls_get_addr"
                        {
                            use crate::libc::fs::write;
                            write::write_str(write::STD_ERR, "symbind ");
                            write::write_str(write::STD_ERR, symbol_name);
                            write::write_str(write::STD_ERR, " -> <stub>\n");
                        }
                    }
                    (stub_addr, 0)
                } else if symbol.st_shndx == SHN_UNDEF {
                    if symbol_binding(symbol) != STB_WEAK {
                        unresolved_nonweak_symbol(
                            linker,
                            object_index,
                            symbol_name,
                            "R_AARCH64_ABS64/GLOB_DAT/JUMP_SLOT",
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
                };

                if rela.r_type() == R_AARCH64_ABS64 {
                    symbol_addr = symbol_addr.wrapping_add_signed(rela.r_addend);
                }

                if symbol_type == STT_GNU_IFUNC {
                    ifuncs.push(IrelativeReloc {
                        relocate_address,
                        function_pointer: symbol_addr,
                    });
                } else {
                    core::ptr::write(relocate_address as *mut usize, symbol_addr);
                }
            }
            R_AARCH64_ABS32 => {
                let symbol = object.symbol(rela.r_sym() as usize);
                let symbol_name = linker.objects[object_index]
                    .string_table
                    .get(symbol.st_name as usize);
                let resolved =
                    lookup_symbol_any(linker, object_index, symbol_name, None, lookup_cache);
                let symbol_addr = if let Some((lib_idx, resolved_symbol)) = resolved {
                    let base = if resolved_symbol.st_shndx == SHN_ABS {
                        0
                    } else {
                        linker.get_base(lib_idx)
                    };
                    resolved_symbol.st_value.wrapping_add(base)
                } else if symbol.st_shndx == SHN_UNDEF {
                    0
                } else {
                    object.base().wrapping_add(symbol.st_value)
                };
                core::ptr::write(
                    relocate_address as *mut u32,
                    symbol_addr.wrapping_add_signed(rela.r_addend) as u32,
                );
            }
            R_AARCH64_ABS16 => {
                let symbol = object.symbol(rela.r_sym() as usize);
                let symbol_name = linker.objects[object_index]
                    .string_table
                    .get(symbol.st_name as usize);
                let resolved =
                    lookup_symbol_any(linker, object_index, symbol_name, None, lookup_cache);
                let symbol_addr = if let Some((lib_idx, resolved_symbol)) = resolved {
                    let base = if resolved_symbol.st_shndx == SHN_ABS {
                        0
                    } else {
                        linker.get_base(lib_idx)
                    };
                    resolved_symbol.st_value.wrapping_add(base)
                } else if symbol.st_shndx == SHN_UNDEF {
                    0
                } else {
                    object.base().wrapping_add(symbol.st_value)
                };
                core::ptr::write(
                    relocate_address as *mut u16,
                    symbol_addr.wrapping_add_signed(rela.r_addend) as u16,
                );
            }
            R_AARCH64_RELATIVE => {
                let relocate_value = object.base().wrapping_add_signed(rela.r_addend);
                core::ptr::write(relocate_address as *mut usize, relocate_value);
            }
            R_AARCH64_COPY => {
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
            R_AARCH64_IRELATIVE => {
                let function_pointer = object.base().wrapping_add_signed(rela.r_addend);
                ifuncs.push(IrelativeReloc {
                    relocate_address,
                    function_pointer,
                });
            }
            R_AARCH64_TLS_DTPMOD64 => {
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
            R_AARCH64_TLS_DTPREL64 => {
                let symbol = object.symbol(rela.r_sym() as usize);
                let symbol_name = linker.objects[object_index]
                    .string_table
                    .get(symbol.st_name as usize);
                let (_def_idx, def_sym) =
                    resolve_tls_symbol(object_index, symbol, symbol_name, linker, lookup_cache);
                let relocate_value = def_sym.st_value.wrapping_add_signed(rela.r_addend);
                core::ptr::write(relocate_address as *mut usize, relocate_value);
            }
            R_AARCH64_TLS_TPREL64 => {
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
                #[cfg(debug_assertions)]
                {
                    if let Some(path) = linker.object_path(object_index) {
                        if path.contains("libc.so.6")
                            && matches!(
                                rela.r_addend as usize,
                                0x0 | 0x8 | 0x10 | 0x18 | 0x20 | 0x30 | 0x38 | 0x50 | 0x58
                            )
                        {
                            use crate::libc::fs::write;
                            write::write_str(write::STD_ERR, "tls-tprel libc addend=");
                            write_hex(write::STD_ERR, rela.r_addend as usize);
                            write::write_str(write::STD_ERR, " value=");
                            write_hex(write::STD_ERR, relocate_value as usize);
                            write::write_str(write::STD_ERR, "\n");
                        }
                    }
                }
            }
            R_AARCH64_TLSDESC => {
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
                if module_id != 0 {
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
                write::write_str(write::STD_ERR, "Unsupported AArch64 relocation type: ");
                write_hex(write::STD_ERR, reloc_type as usize);
                write::write_str(write::STD_ERR, " object=");
                if let Some(path) = linker.object_path(object_index) {
                    write::write_str(write::STD_ERR, path);
                } else {
                    write::write_str(write::STD_ERR, "<unknown>");
                }
                write::write_str(write::STD_ERR, " r_offset=");
                write_hex(write::STD_ERR, rela.r_offset);
                write::write_str(write::STD_ERR, " r_info=");
                write_hex(write::STD_ERR, rela.r_info);
                write::write_str(write::STD_ERR, "\n");
                syscall_assert!(false, "unsupported relocation");
            }
        }
    }

    apply_relr_relocations(object.base(), relocation_slices.relr_slice);
}

pub unsafe fn apply_irelative_relocations(ifuncs: &[IrelativeReloc]) {
    for ifunc in ifuncs {
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

pub unsafe fn relocate(object: &impl Relocatable) {
    let relocation_slices = object.relocation_slices();

    if !relocation_slices.rela_slice.is_empty() || !relocation_slices.relr_slice.is_empty() {
        let page_size = get_page_size();
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

        if min_addr != usize::MAX {
            let start_page = (min_addr / page_size) * page_size;
            let end_page = ((max_addr + 15 + page_size - 1) / page_size) * page_size;
            let length = end_page - start_page;
            let _ = mprotect(start_page as *mut u8, length, PROT_READ | PROT_WRITE);
        }
    }

    const R_AARCH64_ABS64: u32 = 257;
    const R_AARCH64_RELATIVE: u32 = 1027;
    const R_AARCH64_IRELATIVE: u32 = 1032;

    for rela in relocation_slices.rela_slice {
        let relocate_address = rela.r_offset.wrapping_add(object.base());

        match rela.r_type() {
            R_AARCH64_ABS64 => {
                let relocate_value = object
                    .symbol(rela.r_sym() as usize)
                    .st_value
                    .wrapping_add(object.base())
                    .wrapping_add_signed(rela.r_addend);
                core::ptr::write(relocate_address as *mut usize, relocate_value);
            }
            R_AARCH64_RELATIVE => {
                let relocate_value = object.base().wrapping_add_signed(rela.r_addend);
                core::ptr::write(relocate_address as *mut usize, relocate_value);
            }
            R_AARCH64_IRELATIVE => {
                let function_pointer = object.base().wrapping_add_signed(rela.r_addend);
                let function: extern "C" fn() -> usize = core::mem::transmute(function_pointer);
                let relocate_value = function();
                core::ptr::write(relocate_address as *mut usize, relocate_value);
            }
            _ => {}
        }
    }

    apply_relr_relocations(object.base(), relocation_slices.relr_slice);
}
