//! Architecture-independent relocation helpers shared by the per-arch
//! `syscall::relocation` modules. Only the relocation-type match arms and the
//! bounds-checked write path remain arch-specific; everything here is common.

use core::mem::size_of;

use rustc_hash::FxHashMap;

use crate::{elf::symbol::Symbol, linking::DynamicLinker, syscall::exit};

/// Page-address span `[min, max]` (inclusive of the final word) touched by a
/// RELR block, for computing an mprotect/patch window. Returns `None` when the
/// block is empty.
pub(crate) fn relr_address_range(base: usize, relr_slice: &[usize]) -> Option<(usize, usize)> {
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

/// Apply a RELR-encoded relative relocation block: add `base` to every word it
/// designates. Unchecked; callers that need bounds validation use the arch
/// `_checked` variant.
pub(crate) fn apply_relr_relocations(base: usize, relr_slice: &[usize]) {
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

pub(crate) use crate::utils::strip_version_suffix as symbol_without_version;

pub(crate) const SHN_UNDEF: u16 = 0;
pub(crate) const SHN_ABS: u16 = 0xfff1;
pub(crate) const STT_GNU_IFUNC: u8 = 10;
pub(crate) const STB_WEAK: u8 = 2;

pub struct IrelativeReloc {
    pub relocate_address: usize,
    pub function_pointer: usize,
}

pub struct CopyReloc {
    pub destination_address: usize,
    pub source_address: usize,
    pub size: usize,
}

pub(crate) fn get_stub_symbol(name: &str) -> Option<usize> {
    use crate::ld_stubs::*;
    use phf::phf_map;

    static STUB_SYMBOLS: phf::Map<&'static str, fn() -> usize> = phf_map! {
        "_dl_find_object" => || _dl_find_object as *const () as usize,
        "_dl_audit_preinit" => || _dl_audit_preinit as *const () as usize,
        "_dl_find_dso_for_object" => || _dl_find_dso_for_object as *const () as usize,
        "_dl_allocate_tls" => || _dl_allocate_tls as *const () as usize,
        "_dl_allocate_tls_init" => || _dl_allocate_tls_init as *const () as usize,
        "_dl_deallocate_tls" => || _dl_deallocate_tls as *const () as usize,
        "_dl_signal_error" => || _dl_signal_error as *const () as usize,
        "_dl_signal_exception" => || _dl_signal_exception as *const () as usize,
        "_dl_exception_create" => || _dl_exception_create as *const () as usize,
        "_dl_exception_create_format" => || _dl_exception_create_format as *const () as usize,
        "_dl_exception_free" => || _dl_exception_free as *const () as usize,
        "_dl_catch_exception" => || _dl_catch_exception as *const () as usize,
        "_dl_catch_error" => || _dl_catch_error as *const () as usize,
        "_dl_audit_symbind_alt" => || _dl_audit_symbind_alt as *const () as usize,
        "_dl_rtld_di_serinfo" => || _dl_rtld_di_serinfo as *const () as usize,
        "_dl_make_stack_executable" => || _dl_make_stack_executable as *const () as usize,
        "_dl_get_tls_static_info" => || _dl_get_tls_static_info as *const () as usize,
        "__tunable_is_initialized" => || __tunable_is_initialized as *const () as usize,
        "__tunable_get_val" => || __tunable_get_val as *const () as usize,
        "__nptl_change_stack_perm" => || __nptl_change_stack_perm as *const () as usize,
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
        "fgetfilecon" => || fgetfilecon as *const () as usize,
        "getfilecon_raw" => || getfilecon_raw as *const () as usize,
    };

    STUB_SYMBOLS.get(name).map(|f| f())
}

#[inline(always)]
pub(crate) fn get_stub_symbol_any(symbol_name: &str) -> Option<usize> {
    if let Some(addr) = get_stub_symbol(symbol_name) {
        return Some(addr);
    }
    let base = symbol_without_version(symbol_name);
    if base != symbol_name {
        return get_stub_symbol(base);
    }
    None
}

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

#[inline(always)]
pub(crate) unsafe fn lookup_symbol_any(
    linker: &DynamicLinker,
    requester_object: usize,
    symbol_name: &str,
    exclude_object: Option<usize>,
    lookup_cache: &mut SymbolLookupCache,
) -> Option<(usize, Symbol)> {
    lookup_cache.lookup(linker, requester_object, symbol_name, exclude_object)
}

pub(crate) fn resolve_tls_symbol(
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
pub(crate) fn symbol_binding(symbol: Symbol) -> u8 {
    symbol.st_info >> 4
}

#[inline(always)]
pub(crate) fn should_keep_weak_init_fini_undef(symbol: Symbol, symbol_name: &str) -> bool {
    if symbol.st_shndx != SHN_UNDEF || symbol_binding(symbol) != STB_WEAK {
        return false;
    }
    matches!(symbol_without_version(symbol_name), "_init" | "_fini")
}

#[cold]
pub(crate) unsafe fn unresolved_nonweak_symbol(
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

pub(crate) fn write_hex(fd: i32, mut value: usize) {
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
