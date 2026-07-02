#[cfg(target_arch = "x86_64")]
use super::*;

#[cfg(target_arch = "x86_64")]
#[inline(always)]
fn allow_tunable_forwarding() -> bool {
    std::env::var("RUSTLD_FORWARD_GLIBC_TUNABLES")
        .ok()
        .map(|raw| {
            matches!(
                raw.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
pub(crate) fn resolve_tunable_forward_addr(
    cache: &AtomicUsize,
    symbol_name: &str,
    self_addr: usize,
) -> Option<usize> {
    if !allow_tunable_forwarding() {
        return None;
    }

    let cached = cache.load(Ordering::Relaxed);
    if cached == TUNABLE_FORWARD_NONE {
        return None;
    }
    if cached > TUNABLE_FORWARD_NONE {
        return Some(cached);
    }

    let resolved = (unsafe { linking::lookup_active_symbol(symbol_name) })
        .or_else(|| resolve_host_rtld_symbol(symbol_name));

    let Some(resolved) = resolved else {
        cache.store(TUNABLE_FORWARD_NONE, Ordering::Relaxed);
        return None;
    };
    if resolved == self_addr {
        cache.store(TUNABLE_FORWARD_NONE, Ordering::Relaxed);
        return None;
    }

    cache.store(resolved, Ordering::Relaxed);
    Some(resolved)
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
pub(crate) fn seed_current_glibc_thread_locale() {
    type UselocaleFn = extern "C" fn(*mut c_void) -> *mut c_void;
    type CTypeInitFn = extern "C" fn();

    let uselocale_addr = unsafe {
        linking::lookup_active_symbol("__uselocale")
            .or_else(|| linking::lookup_active_symbol("uselocale"))
    };
    if let Some(addr) = uselocale_addr {
        let uselocale_fn: UselocaleFn = unsafe { core::mem::transmute(addr) };
        let _ = uselocale_fn(usize::MAX as *mut c_void);
    }

    let ctype_init_addr = unsafe { linking::lookup_active_symbol("__ctype_init") };
    if let Some(addr) = ctype_init_addr {
        let ctype_init_fn: CTypeInitFn = unsafe { core::mem::transmute(addr) };
        ctype_init_fn();
    }
}

#[cfg(not(target_arch = "x86_64"))]
#[inline(always)]
pub(crate) fn seed_current_glibc_thread_locale() {}

#[cfg(target_arch = "x86_64")]
#[repr(C)]
#[derive(Clone, Copy)]
struct Elf64SectionHeader {
    sh_name: u32,
    sh_type: u32,
    sh_flags: u64,
    sh_addr: u64,
    sh_offset: u64,
    sh_size: u64,
    sh_link: u32,
    sh_info: u32,
    sh_addralign: u64,
    sh_entsize: u64,
}

#[cfg(target_arch = "x86_64")]
#[repr(C)]
#[derive(Clone, Copy)]
struct Elf64Sym {
    st_name: u32,
    st_info: u8,
    st_other: u8,
    st_shndx: u16,
    st_value: u64,
    st_size: u64,
}

#[cfg(target_arch = "x86_64")]
const SHT_DYNSYM: u32 = 11;

#[cfg(target_arch = "x86_64")]
fn parse_maps_hex(raw: &str) -> Option<usize> {
    usize::from_str_radix(raw, 16).ok()
}

#[cfg(target_arch = "x86_64")]
fn find_host_rtld_base_and_path() -> Option<(usize, String)> {
    let maps = std::fs::read_to_string("/proc/self/maps").ok()?;
    for line in maps.lines() {
        if !line.contains("ld-linux") {
            continue;
        }

        let mut fields = line.split_whitespace();
        let range = fields.next()?;
        let _perms = fields.next()?;
        let file_offset = fields.next()?;
        let _dev = fields.next()?;
        let _inode = fields.next()?;
        let path = fields.next()?;

        if !path.contains("ld-linux") {
            continue;
        }

        let start_hex = range.split('-').next()?;
        let start = parse_maps_hex(start_hex)?;
        let offset = parse_maps_hex(file_offset)?;
        let base = start.checked_sub(offset)?;
        return Some((base, path.to_string()));
    }
    None
}

#[cfg(target_arch = "x86_64")]
fn dynsym_name_matches(candidate: &[u8], wanted: &str) -> bool {
    if candidate == wanted.as_bytes() {
        return true;
    }
    candidate.len() > wanted.len()
        && candidate[wanted.len()] == b'@'
        && &candidate[..wanted.len()] == wanted.as_bytes()
}

#[cfg(target_arch = "x86_64")]
fn resolve_dynsym_value(path: &str, symbol_name: &str) -> Option<usize> {
    let bytes = std::fs::read(path).ok()?;
    if bytes.len() < size_of::<ElfHeader>() {
        return None;
    }

    let header = unsafe { core::ptr::read_unaligned(bytes.as_ptr().cast::<ElfHeader>()) };
    if header.e_ident[0..4] != [0x7f, b'E', b'L', b'F'] {
        return None;
    }

    let shoff = header.e_shoff;
    let shentsize = header.e_shentsize as usize;
    let shnum = header.e_shnum as usize;
    if shentsize < size_of::<Elf64SectionHeader>() || shnum == 0 {
        return None;
    }

    let read_shdr = |index: usize| -> Option<Elf64SectionHeader> {
        if index >= shnum {
            return None;
        }
        let off = shoff.checked_add(index.checked_mul(shentsize)?)?;
        let end = off.checked_add(size_of::<Elf64SectionHeader>())?;
        if end > bytes.len() {
            return None;
        }
        Some(unsafe {
            core::ptr::read_unaligned(bytes.as_ptr().add(off).cast::<Elf64SectionHeader>())
        })
    };

    for sec_idx in 0..shnum {
        let shdr = read_shdr(sec_idx)?;
        if shdr.sh_type != SHT_DYNSYM {
            continue;
        }

        let strtab = read_shdr(shdr.sh_link as usize)?;
        let strtab_start = strtab.sh_offset as usize;
        let strtab_len = strtab.sh_size as usize;
        if strtab_start
            .checked_add(strtab_len)
            .is_none_or(|end| end > bytes.len())
        {
            continue;
        }
        let strtab_bytes = &bytes[strtab_start..strtab_start + strtab_len];

        let sym_size = if shdr.sh_entsize == 0 {
            size_of::<Elf64Sym>()
        } else {
            shdr.sh_entsize as usize
        };
        if sym_size < size_of::<Elf64Sym>() {
            continue;
        }

        let sym_start = shdr.sh_offset as usize;
        let sym_len = shdr.sh_size as usize;
        if sym_start
            .checked_add(sym_len)
            .is_none_or(|end| end > bytes.len())
        {
            continue;
        }
        let sym_count = sym_len / sym_size;

        for sym_idx in 0..sym_count {
            let off = sym_start + sym_idx * sym_size;
            if off
                .checked_add(size_of::<Elf64Sym>())
                .is_none_or(|end| end > bytes.len())
            {
                break;
            }
            let sym = unsafe { core::ptr::read_unaligned(bytes.as_ptr().add(off).cast::<Elf64Sym>()) };
            if sym.st_name == 0 {
                continue;
            }

            let name_off = sym.st_name as usize;
            if name_off >= strtab_bytes.len() {
                continue;
            }
            let tail = &strtab_bytes[name_off..];
            let nul = tail.iter().position(|&b| b == 0)?;
            let name = &tail[..nul];
            if dynsym_name_matches(name, symbol_name) {
                return Some(sym.st_value as usize);
            }
        }
    }

    None
}

#[cfg(target_arch = "x86_64")]
fn resolve_host_rtld_symbol(symbol_name: &str) -> Option<usize> {
    let (base, path) = find_host_rtld_base_and_path()?;
    let value = resolve_dynsym_value(&path, symbol_name)?;
    Some(base.wrapping_add(value))
}

#[cfg(target_arch = "x86_64")]
pub(crate) fn host_rtld_global_ro_ptr() -> Option<*const u8> {
    resolve_host_rtld_symbol("_rtld_global_ro").map(|addr| addr as *const u8)
}

#[cfg(not(target_arch = "x86_64"))]
pub(crate) fn host_rtld_global_ro_ptr() -> Option<*const u8> {
    None
}
