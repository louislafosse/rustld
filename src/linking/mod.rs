use core::{
    ffi::{c_char, c_void},
    mem::{size_of, MaybeUninit},
};
use rustc_hash::{FxHashMap, FxHashSet};
use smallvec::SmallVec;
use std::{
    borrow::Cow,
    ffi::CStr,
    ffi::CString,
    fs,
    path::{Path, PathBuf},
    ptr::null_mut,
    sync::OnceLock,
};

use crate::syscall::relocation;
use crate::{
    arch,
    elf::{
        dynamic_array::{
            DynamicArrayItem, DT_DEBUG, DT_FINI, DT_FINI_ARRAY, DT_GNU_HASH, DT_HASH, DT_INIT,
            DT_INIT_ARRAY, DT_JMPREL, DT_NULL, DT_PLTGOT, DT_REL, DT_RELA, DT_RELR, DT_STRTAB,
            DT_SYMTAB, DT_VERSYM,
        },
        header::ElfHeader,
        relocate::Relocatable,
        symbol::{Symbol, SymbolVisibility},
    },
    ld_stubs,
    libc::fs::write,
    shared_object::SharedObject,
    start::auxiliary_vector::{AuxiliaryVectorItem, AT_NULL, AT_RANDOM, AT_SECURE},
    syscall::{
        exit,
        mmap::{mmap, MAP_ANONYMOUS, MAP_PRIVATE, PROT_READ, PROT_WRITE},
    },
    tls,
    utils::{
        running_under_valgrind, skip_selinux_ctors, strip_version_suffix, symbol_name_matches_bytes,
    },
};

/// ELF symbol binding constants
const STB_GLOBAL: u8 = 1;
const STB_WEAK: u8 = 2;
const STB_GNU_UNIQUE: u8 = 10;

/// ELF special section index
const SHN_UNDEF: u16 = 0;
const SHN_ABS: u16 = 0xfff1;

// glibc's internal `struct link_map` offsets on x86_64 that we need for
// libc/libdl symbol lookup paths.
const LINK_MAP_SIZE: usize = 4096;
const LINK_MAP_L_ADDR_OFFSET: usize = 0x00;
const LINK_MAP_L_NAME_OFFSET: usize = 0x08;
const LINK_MAP_L_LD_OFFSET: usize = 0x10;
const LINK_MAP_L_NEXT_OFFSET: usize = 0x18;
const LINK_MAP_L_PREV_OFFSET: usize = 0x20;
const LINK_MAP_L_REAL_OFFSET: usize = 0x28;
const LINK_MAP_L_INFO_OFFSET: usize = 0x40;
const LINK_MAP_L_INFO_COUNT: usize = 96;

const DT_NUM: usize = 38;
const DT_VALRNGLO: usize = 0x6ffffd00;
const DT_VALRNGHI: usize = 0x6ffffdff;
const DT_VALNUM: usize = 12;
const DT_ADDRRNGLO: usize = 0x6ffffe00;
const DT_ADDRRNGHI: usize = 0x6ffffeff;
const DT_ADDRNUM: usize = 11;
const DT_VERNEEDNUM: usize = 0x6fffffff;
const DT_VERSIONTAGNUM: usize = 16;
const DT_EXTRANUM: usize = 3;
const DT_PREINIT_ARRAY: usize = 32;
const DT_VERDEF: usize = 0x6ffffffc;
const DT_VERNEED: usize = 0x6ffffffe;
const LINK_MAP_DYNAMIC_COPY_CAPACITY: usize = 256;

const L_INFO_VERSION_BASE: usize = DT_NUM;
const L_INFO_EXTRA_BASE: usize = L_INFO_VERSION_BASE + DT_VERSIONTAGNUM;
const L_INFO_VAL_BASE: usize = L_INFO_EXTRA_BASE + DT_EXTRANUM;
const L_INFO_ADDR_BASE: usize = L_INFO_VAL_BASE + DT_VALNUM;

const DEFAULT_LIBRARY_PATHS: &[&str] = &[
    "/lib64",
    "/usr/lib64",
    "/lib",
    "/usr/lib",
    "/usr/local/lib64",
    "/usr/local/lib",
];

#[cfg(target_arch = "x86_64")]
const RTLD_RO_LOOKUP_SYMBOL_X_OFFSET: usize = 0x340;
#[cfg(target_arch = "x86_64")]
const RTLD_RO_DLOPEN_OFFSET: usize = 0x348;
#[cfg(target_arch = "x86_64")]
const RTLD_RO_DLCLOSE_OFFSET: usize = 0x350;
#[cfg(target_arch = "x86_64")]
const RTLD_RO_CATCH_ERROR_OFFSET: usize = 0x358;
#[cfg(target_arch = "x86_64")]
const RTLD_RO_ERROR_FREE_OFFSET: usize = 0x360;
#[cfg(target_arch = "x86_64")]
const RTLD_GLOBAL_LEGACY_LOCK_OFFSET: usize = 0x908;
#[cfg(target_arch = "x86_64")]
const RTLD_GLOBAL_LEGACY_LOCK_ACQUIRE_OFFSET: usize = 0xf08;
#[cfg(target_arch = "x86_64")]
const RTLD_GLOBAL_LEGACY_LOCK_RELEASE_OFFSET: usize = 0xf10;

#[cfg(target_arch = "aarch64")]
const RTLD_RO_LOOKUP_SYMBOL_X_OFFSET: usize = 0x128;
#[cfg(target_arch = "aarch64")]
const RTLD_RO_DLOPEN_OFFSET: usize = 0x130;
#[cfg(target_arch = "aarch64")]
const RTLD_RO_DLCLOSE_OFFSET: usize = 0x138;
#[cfg(target_arch = "aarch64")]
const RTLD_RO_CATCH_ERROR_OFFSET: usize = 0x140;
#[cfg(target_arch = "aarch64")]
const RTLD_RO_ERROR_FREE_OFFSET: usize = 0x148;

static mut ACTIVE_LINKER: *mut DynamicLinker = core::ptr::null_mut();
static CONFIGURED_LIBRARY_PATHS: OnceLock<Vec<String>> = OnceLock::new();
static LD_LIBRARY_PATH: OnceLock<Option<String>> = OnceLock::new();
static RUSTLD_LIBRARY_PATH: OnceLock<Option<String>> = OnceLock::new();

#[inline(always)]
fn write_trace_hex(mut value: usize) {
    let mut buf = [0u8; 2 + (size_of::<usize>() * 2)];
    buf[0] = b'0';
    buf[1] = b'x';
    for idx in (2..buf.len()).rev() {
        let digit = (value & 0xf) as u8;
        buf[idx] = if digit < 10 {
            b'0' + digit
        } else {
            b'a' + (digit - 10)
        };
        value >>= 4;
    }
    unsafe { write::write_str(write::STD_ERR, core::str::from_utf8_unchecked(&buf)) };
}

#[inline(always)]
fn write_trace_dec(mut value: usize) {
    let mut buf = [0u8; 32];
    let mut idx = buf.len();
    if value == 0 {
        idx -= 1;
        buf[idx] = b'0';
    } else {
        while value > 0 {
            idx -= 1;
            buf[idx] = b'0' + (value % 10) as u8;
            value /= 10;
        }
    }
    unsafe { write::write_str(write::STD_ERR, core::str::from_utf8_unchecked(&buf[idx..])) };
}

#[inline(always)]
fn write_trace_i32(value: i32) {
    if value < 0 {
        unsafe { write::write_str(write::STD_ERR, "-") };
        write_trace_dec(value.unsigned_abs() as usize);
    } else {
        write_trace_dec(value as usize);
    }
}

pub unsafe fn set_active_linker(linker: *mut DynamicLinker) {
    // Read/writes are volatile so release builds cannot fold this global to
    // a compile-time constant across exported dlfcn entry points.
    core::ptr::write_volatile(core::ptr::addr_of_mut!(ACTIVE_LINKER), linker);
}

pub unsafe fn lookup_active_symbol(symbol_name: &str) -> Option<usize> {
    let linker_ptr = core::ptr::read_volatile(core::ptr::addr_of!(ACTIVE_LINKER));
    let linker = linker_ptr.as_ref()?;

    let resolve = |name: &str| -> Option<usize> {
        if let Some((obj_idx, symbol)) = unsafe { linker.lookup_symbol(name) } {
            let base = if symbol.st_shndx == SHN_ABS {
                0
            } else {
                linker.get_base(obj_idx)
            };
            return Some(base.wrapping_add(symbol.st_value));
        }
        None
    };

    if let Some(address) = resolve(symbol_name) {
        return Some(address);
    }
    let base_name = strip_version_suffix(symbol_name);
    if base_name != symbol_name {
        return resolve(base_name);
    }
    None
}

#[inline]
fn link_map_info_index(tag: usize) -> Option<usize> {
    if tag < DT_NUM {
        return Some(tag);
    }

    if (DT_VERNEEDNUM + 1 - DT_VERSIONTAGNUM..=DT_VERNEEDNUM).contains(&tag) {
        return Some(L_INFO_VERSION_BASE + (DT_VERNEEDNUM - tag));
    }

    if (DT_VALRNGLO..=DT_VALRNGHI).contains(&tag) {
        let idx = DT_VALRNGHI - tag;
        if idx < DT_VALNUM {
            return Some(L_INFO_VAL_BASE + idx);
        }
        return None;
    }

    if (DT_ADDRRNGLO..=DT_ADDRRNGHI).contains(&tag) {
        let idx = DT_ADDRRNGHI - tag;
        if idx < DT_ADDRNUM {
            return Some(L_INFO_ADDR_BASE + idx);
        }
        return None;
    }

    if (0x7ffffffd..=0x7fffffff).contains(&tag) {
        // DT_EXTRATAGIDX(tag): ((Elf32_Word)-((Elf32_Sword)(tag) << 1 >> 1) - 1)
        let signed = ((tag as i32) << 1) >> 1;
        let extra = (-(signed as isize) - 1) as usize;
        if extra < DT_EXTRANUM {
            return Some(L_INFO_EXTRA_BASE + extra);
        }
    }

    None
}

unsafe fn populate_link_map_dynamic_info(map: *mut u8, dynamic: *const DynamicArrayItem) {
    if dynamic.is_null() || (dynamic as usize) % core::mem::align_of::<DynamicArrayItem>() != 0 {
        return;
    }

    let mut cursor = dynamic;
    let mut scanned = 0usize;
    loop {
        if scanned >= 4096 {
            break;
        }
        let item = *cursor;
        if item.d_tag == crate::elf::dynamic_array::DT_NULL {
            break;
        }
        if let Some(info_index) = link_map_info_index(item.d_tag) {
            if info_index < LINK_MAP_L_INFO_COUNT {
                let slot = map
                    .byte_add(LINK_MAP_L_INFO_OFFSET + info_index * core::mem::size_of::<usize>())
                    as *mut usize;
                *slot = cursor as usize;
            }
        }
        cursor = cursor.add(1);
        scanned = scanned.saturating_add(1);
    }
}

#[inline]
fn dynamic_tag_uses_runtime_pointer(tag: usize) -> bool {
    matches!(
        tag,
        DT_PLTGOT
            | DT_HASH
            | DT_STRTAB
            | DT_SYMTAB
            | DT_RELA
            | DT_REL
            | DT_INIT
            | DT_FINI
            | DT_DEBUG
            | DT_JMPREL
            | DT_INIT_ARRAY
            | DT_FINI_ARRAY
            | DT_PREINIT_ARRAY
            | DT_RELR
            | DT_GNU_HASH
            | DT_VERSYM
            | DT_VERDEF
            | DT_VERNEED
    ) || (DT_ADDRRNGLO..=DT_ADDRRNGHI).contains(&tag)
}

fn glibc_dso_version_candidate(path: &Path) -> Option<PathBuf> {
    let file_name = path.file_name().map(PathBuf::from);
    if let Ok(target) = fs::read_link(path) {
        if let Some(name) = target.file_name() {
            return Some(PathBuf::from(name));
        }
    }
    file_name
}

fn glibc_dso_version(path_hint: &str) -> Option<(u32, u32)> {
    // The version probe does a `readlink` on the DSO path; the same handful of
    // paths (libc.so.6, libm.so.6, the executable) are queried several times
    // during a load, so memoize to avoid repeating the syscall.
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};
    static CACHE: OnceLock<Mutex<HashMap<String, Option<(u32, u32)>>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Some(cached) = cache.lock().unwrap().get(path_hint) {
        return *cached;
    }
    let result = glibc_dso_version_uncached(path_hint);
    cache.lock().unwrap().insert(path_hint.to_string(), result);
    result
}

fn glibc_dso_version_uncached(path_hint: &str) -> Option<(u32, u32)> {
    let candidate_buf = glibc_dso_version_candidate(Path::new(path_hint));
    let candidate = candidate_buf
        .as_ref()
        .and_then(|path| path.to_str())
        .unwrap_or(path_hint);

    for prefix in ["libc-", "libpthread-", "libdl-", "ld-"] {
        let Some(rest) = candidate.strip_prefix(prefix) else {
            continue;
        };
        let Some(rest) = rest.strip_suffix(".so") else {
            continue;
        };
        let mut parts = rest.split('.');
        let Some(major_raw) = parts.next() else {
            continue;
        };
        let Some(minor_raw) = parts.next() else {
            continue;
        };
        let Ok(major) = major_raw.parse::<u32>() else {
            continue;
        };
        let Ok(minor) = minor_raw.parse::<u32>() else {
            continue;
        };
        return Some((major, minor));
    }

    None
}

fn legacy_glibc_link_map_needs_absolute_dynamic(path_hint: &str) -> bool {
    matches!(glibc_dso_version(path_hint), Some((2, minor)) if minor <= 31)
}

unsafe fn create_link_map_dynamic_copy(
    base: usize,
    dynamic: *const DynamicArrayItem,
) -> *mut DynamicArrayItem {
    if dynamic.is_null() || (dynamic as usize) % core::mem::align_of::<DynamicArrayItem>() != 0 {
        return core::ptr::null_mut();
    }

    let allocation_size = LINK_MAP_DYNAMIC_COPY_CAPACITY * size_of::<DynamicArrayItem>();
    let copy = mmap(
        null_mut(),
        allocation_size,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    ) as *mut DynamicArrayItem;
    if copy.is_null() || (copy as isize) < 0 {
        return core::ptr::null_mut();
    }
    core::ptr::write_bytes(copy.cast::<u8>(), 0, allocation_size);

    let mut src = dynamic;
    let mut dst = copy;
    for _ in 0..LINK_MAP_DYNAMIC_COPY_CAPACITY.saturating_sub(1) {
        let item = *src;
        *dst = item;
        if item.d_tag == DT_NULL {
            return copy;
        }

        if item.d_tag == DT_DEBUG {
            (*dst).d_un.d_ptr = ld_stubs::r_debug_ptr();
        } else if dynamic_tag_uses_runtime_pointer(item.d_tag) {
            (*dst).d_un.d_ptr = base.wrapping_add(item.d_un.d_val) as *mut c_void;
        }

        src = src.add(1);
        dst = dst.add(1);
    }

    (*dst).d_tag = DT_NULL;
    (*dst).d_un.d_val = 0;
    copy
}

/// Minimal stub for _rtld_global.
/// _dl_ns[0]._ns_loaded (offset 0) must point to a valid link_map so
/// __libc_start_main can read l_info[].
///
/// glibc accesses fields well beyond the small subset we populate, so
/// allocate a generously-sized zeroed block to avoid invalid reads.
struct RtldStubs {
    /// Pointer to our fake _rtld_global (2120+ bytes, page-aligned)
    rtld_global: *mut u8,
    /// Pointer to our fake _rtld_global_ro (928+ bytes)
    rtld_global_ro: *mut u8,
    /// Pointer to a zeroed dummy link_map (≥ 0x300 bytes)
    link_map: *mut u8,
    /// Runtime-adjusted copy of the executable `_DYNAMIC`.
    link_map_dynamic: *mut DynamicArrayItem,
    /// Legacy glibc dlfcn hook table used by glibc 2.31-era __libc_dlopen_mode.
    dlfcn_hook: *mut usize,
    /// Storage for standalone ld.so globals referenced by libc.
    libc_enable_secure: *mut u32,
    libc_stack_end: *mut *const u8,
    dl_argv: *mut *const *const u8,
    rseq_offset: *mut isize,
    rseq_size: *mut u32,
    rseq_flags: *mut u32,
    pointer_chk_guard: *mut usize,
    pointer_chk_guard_local: *mut usize,
    stack_chk_guard: *mut usize,
    auxv: *const AuxiliaryVectorItem,
    hwcap: usize,
    hwcap2: usize,
}

/// Dynamic linker state - manages all loaded shared objects and symbol resolution
pub struct DynamicLinker {
    /// All loaded shared objects (executable + libraries)
    pub objects: Vec<SharedObject>,
    /// Stable alias list used for diagnostics/debug output.
    pub library_map: Vec<(String, usize)>,
    /// Fast lookup table from alias/path to object index.
    library_alias_index: FxHashMap<String, usize>,
    /// Canonical filesystem path per object index (if known).
    object_paths: Vec<Option<String>>,
    /// Stable `struct link_map` stand-ins for loaded objects.
    object_link_maps: Vec<*mut u8>,
    /// Runtime-adjusted `_DYNAMIC` copies backing the link_maps.
    object_link_map_dynamics: Vec<*mut DynamicArrayItem>,
    /// Owned C-strings backing `l_name` pointers.
    object_link_map_names: Vec<*mut c_char>,
    /// Precomputed lookup order per requester object index.
    lookup_scopes: Vec<Vec<usize>>,
    /// Stubs for ld-linux symbols we provide ourselves
    rtld_stubs: Option<RtldStubs>,
}


pub unsafe fn active_linker() -> Option<&'static DynamicLinker> {
    let linker_ptr = core::ptr::read_volatile(core::ptr::addr_of!(ACTIVE_LINKER));
    linker_ptr.as_ref()
}

#[inline(always)]
fn disable_rseq_metadata() -> bool {
    running_under_valgrind() || std::env::var("RUSTLD_DISABLE_RSEQ").is_ok()
}

pub unsafe fn active_linker_mut() -> Option<&'static mut DynamicLinker> {
    let linker_ptr = core::ptr::read_volatile(core::ptr::addr_of!(ACTIVE_LINKER));
    linker_ptr.as_mut()
}

mod rtld_stubs;
mod paths;
mod dlopen;
mod lookup;
