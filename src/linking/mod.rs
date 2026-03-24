use core::{
    ffi::{c_char, c_void},
    mem::{size_of, MaybeUninit},
};
use memchr::memchr;
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

#[inline(always)]
fn strip_version_suffix(name: &str) -> &str {
    if let Some(idx) = memchr(b'@', name.as_bytes()) {
        &name[..idx]
    } else {
        name
    }
}

#[inline(always)]
fn symbol_name_matches_bytes(candidate: &[u8], requested: &[u8]) -> bool {
    if candidate.len() == requested.len() {
        return candidate == requested;
    }
    candidate.len() > requested.len()
        && candidate[requested.len()] == b'@'
        && &candidate[..requested.len()] == requested
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

impl RtldStubs {
    unsafe fn new(
        exec_base: usize,
        exec_dynamic: *const u8,
        minsigstacksize: usize,
        auxv: *const AuxiliaryVectorItem,
        auxv_count: usize,
        hwcap: usize,
        hwcap2: usize,
    ) -> Self {
        const PAGE: usize = 4096;
        // Some glibc builds access fields far into struct rtld_global
        // during freeres; allocate a large zeroed block to be safe.
        const RTLD_GLOBAL_SIZE: usize = PAGE * 16;
        const RTLD_GLOBAL_RO_SIZE: usize = PAGE * 16;
        const STUB_LINK_MAP_SIZE: usize = PAGE;
        const RTLD_DATA_SIZE: usize = PAGE;
        const TOTAL_SIZE: usize =
            RTLD_GLOBAL_SIZE + RTLD_GLOBAL_RO_SIZE + STUB_LINK_MAP_SIZE + RTLD_DATA_SIZE;

        // Allocate memory for stubs.
        let page = mmap(
            null_mut(),
            TOTAL_SIZE,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS,
            -1,
            0,
        );
        // Ensure memory is initialized for tools like valgrind.
        core::ptr::write_bytes(page, 0, TOTAL_SIZE);

        let rtld_global = page;
        let rtld_global_ro = page.byte_add(RTLD_GLOBAL_SIZE);
        let link_map = page.byte_add(RTLD_GLOBAL_SIZE + RTLD_GLOBAL_RO_SIZE);
        let rtld_data = page.byte_add(RTLD_GLOBAL_SIZE + RTLD_GLOBAL_RO_SIZE + STUB_LINK_MAP_SIZE);
        let dlfcn_hook = link_map.byte_add(0x380) as *mut usize;

        #[cfg(target_arch = "x86_64")]
        {
            // Newer glibc IFUNC resolvers read an x86 CPU-feature block from
            // _rtld_global_ro. Seed our synthetic object from the host loader's
            // real bytes first, then override the handful of fields rustld must
            // virtualize (auxv, hooks, TLS metadata, etc.).
            if let Some(host_rtld_global_ro) = ld_stubs::host_rtld_global_ro_ptr() {
                core::ptr::copy_nonoverlapping(host_rtld_global_ro, rtld_global_ro, 928);
            }
        }

        let libc_enable_secure = rtld_data as *mut u32;
        let libc_stack_end = rtld_data.byte_add(0x08) as *mut *const u8;
        let dl_argv = rtld_data.byte_add(0x10) as *mut *const *const u8;
        let rseq_offset = rtld_data.byte_add(0x18) as *mut isize;
        let rseq_size = rtld_data.byte_add(0x20) as *mut u32;
        let rseq_flags = rtld_data.byte_add(0x24) as *mut u32;
        let pointer_chk_guard = rtld_data.byte_add(0x28) as *mut usize;
        let pointer_chk_guard_local = rtld_data.byte_add(0x30) as *mut usize;
        let stack_chk_guard = rtld_data.byte_add(0x38) as *mut usize;
        let auxv_storage = rtld_data.byte_add(0x40) as *mut AuxiliaryVectorItem;

        #[cfg(target_arch = "x86_64")]
        {
            if disable_rseq_metadata() {
                // Valgrind does not model rseq registration like native glibc
                // startup expects; advertise rseq as disabled in this mode.
                *rseq_offset = 0;
                *rseq_size = 0;
                *rseq_flags = 0;
            } else {
                // Match glibc x86_64 ABI: rseq state lives below TP.
                // offset=0 causes child threads to overwrite the TCB.
                *rseq_offset = -192;
                *rseq_size = 32;
                *rseq_flags = 0;
            }
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            // Keep conservative defaults on other architectures until their
            // exact glibc layout is wired here.
            *rseq_offset = 0;
            *rseq_size = 0;
            *rseq_flags = 0;
        }
        *pointer_chk_guard = 0x9e37_79b9_7f4a_7c15usize;
        *pointer_chk_guard_local = *pointer_chk_guard;
        *stack_chk_guard = 0xd00d_f00d_d00d_f00dusize;

        // Set up a minimal link_map for the executable:
        //   offset 0x00: l_addr (base address)
        //   offset 0x08: l_name (pointer to empty string)
        //   offset 0x10: l_ld (pointer to dynamic section)
        //   offset 0x18: l_next = NULL
        //   offset 0x20: l_prev = NULL
        //   offset 0x28: l_real = self pointer
        //   offset 0x40..0x2E0: l_info[] — pointers to DT entries (leave NULL)
        let link_map_dynamic = exec_dynamic.cast::<DynamicArrayItem>() as *mut DynamicArrayItem;
        *(link_map.byte_add(LINK_MAP_L_ADDR_OFFSET) as *mut usize) = exec_base;
        *(link_map.byte_add(LINK_MAP_L_NAME_OFFSET) as *mut *const u8) = b"\0".as_ptr();
        *(link_map.byte_add(LINK_MAP_L_LD_OFFSET) as *mut *const u8) = link_map_dynamic.cast();
        *(link_map.byte_add(LINK_MAP_L_REAL_OFFSET) as *mut *mut u8) = link_map;
        populate_link_map_dynamic_info(link_map, link_map_dynamic.cast_const());
        *dlfcn_hook.add(0) = ld_stubs::dlopen as *const () as usize;
        *dlfcn_hook.add(1) = ld_stubs::dlsym as *const () as usize;
        *dlfcn_hook.add(2) = ld_stubs::dlclose as *const () as usize;
        *dlfcn_hook.add(3) = ld_stubs::dlvsym as *const () as usize;

        // Set up _rtld_global:
        //   offset 0x00: _dl_ns[0]._ns_loaded = &link_map
        //   offset 0x08: _dl_ns[0]._ns_nloaded = 1
        //   All 16 namespaces: 112 bytes each, total 1792 (0x700)
        //   offset 0x700: _dl_nns = 1
        #[cfg(target_arch = "x86_64")]
        {
            *(rtld_global as *mut *mut u8) = link_map; // _dl_ns[0]._ns_loaded
            *(rtld_global.byte_add(0x08) as *mut u32) = 1; // _dl_ns[0]._ns_nloaded
            *(rtld_global.byte_add(0x700) as *mut usize) = 1; // _dl_nns
            // Older x86_64 glibc releases (for example Ubuntu 20.04 / glibc
            // 2.31) call a pair of tiny lock helpers via `_rtld_global +
            // 0xf08` / `+0xf10` from `_dl_addr@@GLIBC_PRIVATE`.
            // The real loader wires these to increment/decrement the counter
            // at `_rtld_global + 0x908 + 4`.
            *(rtld_global.byte_add(RTLD_GLOBAL_LEGACY_LOCK_OFFSET + 4) as *mut i32) = 0;
            *(rtld_global.byte_add(RTLD_GLOBAL_LEGACY_LOCK_ACQUIRE_OFFSET) as *mut usize) =
                ld_stubs::__rustld_rtld_legacy_lock_acquire as *const () as usize;
            *(rtld_global.byte_add(RTLD_GLOBAL_LEGACY_LOCK_RELEASE_OFFSET) as *mut usize) =
                ld_stubs::__rustld_rtld_legacy_lock_release as *const () as usize;
        }
        // libpthread/glibc fork paths consult multiple rtld-managed intrusive
        // list heads in this region. Model each head as an empty self-linked
        // list to prevent null traversal after fork in child processes.
        #[cfg(target_arch = "x86_64")]
        {
            for offset in [0x800usize, 0x810, 0x820] {
                let head = rtld_global.byte_add(offset) as *mut usize;
                let self_ptr = head as usize;
                *head = self_ptr;
                *head.add(1) = self_ptr;
            }
        }

        // Set up minimal _rtld_global_ro:
        //   offset 0x00: _dl_debug_mask = 0 (no debug)
        //   offset 0x18: _dl_pagesize = 4096
        *(rtld_global_ro.byte_add(0x18) as *mut usize) = 4096; // _dl_pagesize
        // x86_64 glibc changed _rtld_global_ro getauxval-related offsets
        // across releases. Populate both the old 2.31-era layout and the
        // newer layout so distro-specific libc builds can use either path:
        //
        //   glibc 2.31: HWCAP @ +0x58, auxv @ +0x60, HWCAP2 @ +0x1c8
        //   newer glibc: HWCAP @ +0x60, auxv @ +0x68, HWCAP2 @ +0x310
        //
        // Default to the newer layout and switch to the legacy one after
        // we identify an old target glibc family during object loading.
        *(rtld_global_ro.byte_add(0x60) as *mut usize) = hwcap;
        *(rtld_global_ro.byte_add(0x68) as *mut usize) = auxv_storage as usize;
        *(rtld_global_ro.byte_add(0x310) as *mut usize) = hwcap2;
        // glibc sysconf(_SC_MINSIGSTKSZ/_SC_SIGSTKSZ) asserts this is non-zero.
        *(rtld_global_ro.byte_add(0x20) as *mut usize) = minsigstacksize.max(2048);
        // libc dispatches dlfcn helpers through callback slots in
        // _rtld_global_ro. Offsets are architecture-specific.
        *(rtld_global_ro.byte_add(RTLD_RO_LOOKUP_SYMBOL_X_OFFSET) as *mut usize) =
            ld_stubs::__rustld_rtld_lookup_symbol_x_stub as *const () as usize;
        *(rtld_global_ro.byte_add(RTLD_RO_DLOPEN_OFFSET) as *mut usize) =
            ld_stubs::__rustld_rtld_dlopen_stub as *const () as usize;
        *(rtld_global_ro.byte_add(RTLD_RO_DLCLOSE_OFFSET) as *mut usize) =
            ld_stubs::__rustld_rtld_dlclose_stub as *const () as usize;
        *(rtld_global_ro.byte_add(RTLD_RO_CATCH_ERROR_OFFSET) as *mut usize) =
            ld_stubs::__rustld_rtld_catch_error as *const () as usize;
        *(rtld_global_ro.byte_add(RTLD_RO_ERROR_FREE_OFFSET) as *mut usize) =
            ld_stubs::__rustld_rtld_error_free as *const () as usize;
        // __libc_early_init reads static TLS size/alignment from these fields.
        // Keep non-zero defaults to avoid division-by-zero before TLS layout is known.
        *(rtld_global_ro.byte_add(0x2A0) as *mut usize) = 0x1000; // _dl_tls_static_size (default)
        *(rtld_global_ro.byte_add(0x2A8) as *mut usize) = 0x10; // _dl_tls_static_align (default)

        // Snapshot auxv into stable writable storage for libc getauxval().
        let max_auxv_items = (RTLD_DATA_SIZE - 0x40) / core::mem::size_of::<AuxiliaryVectorItem>();
        let copy_count = auxv_count.min(max_auxv_items.saturating_sub(1));
        if copy_count != 0 && !auxv.is_null() {
            core::ptr::copy_nonoverlapping(auxv, auxv_storage, copy_count);
        }
        let terminator = auxv_storage.add(copy_count);
        (*terminator).a_type = AT_NULL;
        core::ptr::write_bytes(
            core::ptr::addr_of_mut!((*terminator).a_un) as *mut u8,
            0,
            core::mem::size_of_val(&(*terminator).a_un),
        );

        let mut secure = 0u32;
        if copy_count != 0 {
            let mut cursor = auxv_storage;
            while (*cursor).a_type != AT_NULL {
                if (*cursor).a_type == AT_RANDOM {
                    let random = (*cursor).a_un.a_val as *const usize;
                    if !random.is_null() {
                        let mut stack_guard = core::ptr::read_unaligned(random);
                        stack_guard &= !0xffusize;
                        *stack_chk_guard = stack_guard;
                        let pointer_guard = core::ptr::read_unaligned(random.add(1));
                        *pointer_chk_guard = pointer_guard;
                        *pointer_chk_guard_local = pointer_guard;
                    }
                }
                if (*cursor).a_type == AT_SECURE {
                    secure = ((*cursor).a_un.a_val != 0) as u32;
                }
                cursor = cursor.add(1);
            }
        }
        *libc_enable_secure = secure;

        Self {
            rtld_global,
            rtld_global_ro,
            link_map,
            link_map_dynamic,
            dlfcn_hook,
            libc_enable_secure,
            libc_stack_end,
            dl_argv,
            rseq_offset,
            rseq_size,
            rseq_flags,
            pointer_chk_guard,
            pointer_chk_guard_local,
            stack_chk_guard,
            auxv: auxv_storage as *const AuxiliaryVectorItem,
            hwcap,
            hwcap2,
        }
    }

    unsafe fn set_argv_and_stack_end(&self, argv: *const *const u8, stack_end: *const u8) {
        *self.dl_argv = argv;
        *self.libc_stack_end = stack_end;
    }

    unsafe fn set_stack_end(&self, stack_end: *const u8) {
        *self.libc_stack_end = stack_end;
    }

    unsafe fn set_tls_static_metadata(&self, tls_static_size: usize, tls_static_align: usize) {
        *(self.rtld_global_ro.byte_add(0x2A0) as *mut usize) = tls_static_size;
        *(self.rtld_global_ro.byte_add(0x2A8) as *mut usize) = tls_static_align.max(1);
    }

    unsafe fn set_rseq_metadata(&self, offset: isize, size: u32, flags: u32) {
        *self.rseq_offset = offset;
        *self.rseq_size = size;
        *self.rseq_flags = flags;
    }

    unsafe fn set_glibc_getauxval_layout(&self, legacy: bool) {
        if legacy {
            *(self.rtld_global_ro.byte_add(0x58) as *mut usize) = self.hwcap;
            *(self.rtld_global_ro.byte_add(0x60) as *mut usize) = self.auxv as usize;
            *(self.rtld_global_ro.byte_add(0x1C8) as *mut usize) = self.hwcap2;
        } else {
            *(self.rtld_global_ro.byte_add(0x60) as *mut usize) = self.hwcap;
            *(self.rtld_global_ro.byte_add(0x68) as *mut usize) = self.auxv as usize;
            *(self.rtld_global_ro.byte_add(0x310) as *mut usize) = self.hwcap2;
        }
    }

    unsafe fn tls_static_metadata(&self) -> (usize, usize) {
        (
            *(self.rtld_global_ro.byte_add(0x2A0) as *const usize),
            *(self.rtld_global_ro.byte_add(0x2A8) as *const usize),
        )
    }

    unsafe fn set_ns_loaded_head(&self, map: *mut u8) {
        *(self.rtld_global.byte_add(0x00) as *mut *mut u8) = map;
    }

    #[inline(always)]
    fn dlfcn_hook_ptr(&self) -> usize {
        self.dlfcn_hook as usize
    }
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

impl DynamicLinker {
    #[inline(always)]
    fn trace_rtld_lookup() -> bool {
        static TRACE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        *TRACE.get_or_init(|| std::env::var("RUSTLD_TRACE_RTLD_LOOKUP").is_ok())
    }

    #[inline(always)]
    fn trace_runtime_nss() -> bool {
        static TRACE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        *TRACE.get_or_init(|| std::env::var("RUSTLD_TRACE_RUNTIME_NSS").is_ok())
    }

    #[inline(always)]
    fn trace_runtime_all() -> bool {
        static TRACE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        *TRACE.get_or_init(|| std::env::var("RUSTLD_TRACE_RUNTIME_ALL").is_ok())
    }

    #[inline(always)]
    fn is_runtime_nss_name(name: &str) -> bool {
        let file_name = Path::new(name)
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or(name);
        file_name.starts_with("libnss_")
    }

    #[inline(always)]
    fn allow_unsafe_systemd_nss() -> bool {
        static ALLOW: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        *ALLOW.get_or_init(|| std::env::var("RUSTLD_ALLOW_UNSAFE_SYSTEMD_NSS").is_ok())
    }

    #[inline(always)]
    fn should_skip_runtime_nss_backend(name: &str) -> bool {
        if Self::allow_unsafe_systemd_nss() {
            return false;
        }

        let file_name = Path::new(name)
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or(name);

        if !file_name.starts_with("libnss_") {
            return false;
        }

        !matches!(file_name, "libnss_files.so.2" | "libnss_dns.so.2")
    }

    fn trace_runtime_nss_object_state(&self, stage: &str, object_index: usize) {
        if !(Self::trace_runtime_nss() || Self::trace_runtime_all()) || object_index >= self.objects.len() {
            return;
        }

        let path = self.object_path(object_index).unwrap_or("<unknown>");
        let soname = unsafe { self.objects[object_index].soname_str() }.unwrap_or("<none>");
        if !Self::trace_runtime_all()
            && !Self::is_runtime_nss_name(path)
            && !Self::is_runtime_nss_name(soname)
        {
            return;
        }

        let object = &self.objects[object_index];
        let relocations = object.relocation_slices();
        let tls = object.tls.as_ref();
        unsafe {
            write::write_str(write::STD_ERR, "runtime_nss:");
            write::write_str(write::STD_ERR, stage);
            write::write_str(write::STD_ERR, ": idx=");
            write_trace_dec(object_index);
            write::write_str(write::STD_ERR, " path=");
            write::write_str(write::STD_ERR, path);
            write::write_str(write::STD_ERR, " soname=");
            write::write_str(write::STD_ERR, soname);
            write::write_str(write::STD_ERR, " base=");
            write_trace_hex(object.base);
            write::write_str(write::STD_ERR, " map=");
            write_trace_hex(object.map_start);
            write::write_str(write::STD_ERR, "-");
            write_trace_hex(object.map_end);
            write::write_str(write::STD_ERR, " tls_module=");
            write_trace_dec(tls.map(|value| value.module_id).unwrap_or(0));
            write::write_str(write::STD_ERR, " tls_memsz=");
            write_trace_hex(tls.map(|value| value.memsz).unwrap_or(0));
            write::write_str(write::STD_ERR, " rela=");
            write_trace_dec(relocations.rela_slice.len());
            write::write_str(write::STD_ERR, " relr=");
            write_trace_dec(relocations.relr_slice.len());
            write::write_str(write::STD_ERR, "\n");
        }
    }

    #[inline(always)]
    fn musl_libc_fallback_candidates(name: &str) -> &'static [&'static str] {
        if name != "libc.so" {
            return &[];
        }

        #[cfg(target_arch = "x86_64")]
        {
            return &[
                "/lib/ld-musl-x86_64.so.1",
                "/lib64/ld-musl-x86_64.so.1",
                "/usr/x86_64-linux-musl/lib/ld-musl-x86_64.so.1",
                "/usr/x86_64-linux-musl/lib64/ld-musl-x86_64.so.1",
                "/usr/lib/ld-musl-x86_64.so.1",
            ];
        }

        #[cfg(target_arch = "aarch64")]
        {
            return &[
                "/lib/ld-musl-aarch64.so.1",
                "/lib64/ld-musl-aarch64.so.1",
                "/usr/aarch64-linux-musl/lib/ld-musl-aarch64.so.1",
                "/usr/aarch64-linux-musl/lib64/ld-musl-aarch64.so.1",
                "/usr/lib/ld-musl-aarch64.so.1",
            ];
        }

        #[allow(unreachable_code)]
        &[]
    }

    #[inline(always)]
    fn is_system_bin_dir(dir: &str) -> bool {
        matches!(dir, "/bin" | "/usr/bin" | "/sbin" | "/usr/sbin")
    }

    #[inline(always)]
    fn is_shared_object_soname(name: &str) -> bool {
        let bytes = name.as_bytes();
        for &byte in bytes {
            if byte == b'/' {
                return false;
            }
        }
        let base = name.rsplit('/').next().unwrap_or(name);
        if base.starts_with("ld-linux") || base.starts_with("ld-musl") {
            return true;
        }
        if !base.starts_with("lib") {
            return false;
        }
        let base = base.as_bytes();
        let mut i = 0usize;
        while i + 2 < base.len() {
            if base[i] == b'.' && base[i + 1] == b's' && base[i + 2] == b'o' {
                return true;
            }
            i += 1;
        }
        false
    }

    #[inline(always)]
    fn host_elf_machine() -> u16 {
        #[cfg(target_arch = "x86_64")]
        {
            62 // EM_X86_64
        }
        #[cfg(target_arch = "aarch64")]
        {
            183 // EM_AARCH64
        }
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        {
            0
        }
    }

    #[inline(always)]
    unsafe fn fd_matches_host_arch(fd: i32) -> bool {
        let mut uninit = MaybeUninit::<ElfHeader>::uninit();
        let header_bytes =
            core::slice::from_raw_parts_mut(uninit.as_mut_ptr() as *mut u8, size_of::<ElfHeader>());

        let read = arch::pread(fd, header_bytes.as_mut_ptr(), header_bytes.len(), 0);
        if read != size_of::<ElfHeader>() as isize {
            return false;
        }

        let header = uninit.assume_init();
        if header.e_ident[0..4] != [0x7f, b'E', b'L', b'F'] {
            return false;
        }

        // rustld only supports little-endian 64-bit ELF objects here.
        if header.e_ident[4] != 2 || header.e_ident[5] != 1 {
            return false;
        }

        let expected_machine = Self::host_elf_machine();
        expected_machine == 0 || header.e_machine == expected_machine
    }

    fn parse_ld_so_conf_file(
        path: &Path,
        out_paths: &mut Vec<String>,
        seen_files: &mut FxHashSet<String>,
        depth: usize,
    ) {
        if depth == 0 {
            return;
        }

        let path_key = path.to_string_lossy().into_owned();
        if !seen_files.insert(path_key) {
            return;
        }

        let Ok(content) = fs::read_to_string(path) else {
            return;
        };

        for raw_line in content.lines() {
            let line = raw_line.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }

            if let Some(include_pattern) = line.strip_prefix("include ") {
                let include_pattern = include_pattern.trim();
                if include_pattern.is_empty() {
                    continue;
                }
                Self::parse_ld_so_conf_include(include_pattern, out_paths, seen_files, depth - 1);
                continue;
            }

            if line.starts_with('/') {
                let dir = line.trim_end_matches('/').to_string();
                if !out_paths.iter().any(|existing| existing == &dir) {
                    out_paths.push(dir);
                }
            }
        }
    }

    fn parse_ld_so_conf_include(
        pattern: &str,
        out_paths: &mut Vec<String>,
        seen_files: &mut FxHashSet<String>,
        depth: usize,
    ) {
        let path = Path::new(pattern);
        if !pattern.contains('*') {
            Self::parse_ld_so_conf_file(path, out_paths, seen_files, depth);
            return;
        }

        let parent = path.parent().unwrap_or_else(|| Path::new("/"));
        let file_pattern = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("");
        let (prefix, suffix) = file_pattern
            .split_once('*')
            .map(|(p, s)| (p.to_string(), s.to_string()))
            .unwrap_or_else(|| (file_pattern.to_string(), String::new()));

        let Ok(entries) = fs::read_dir(parent) else {
            return;
        };

        for entry in entries.flatten() {
            let entry_path = entry.path();
            let file_name = entry_path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("");
            if file_name.starts_with(&prefix) && file_name.ends_with(&suffix) {
                Self::parse_ld_so_conf_file(&entry_path, out_paths, seen_files, depth);
            }
        }
    }

    fn configured_library_paths() -> &'static [String] {
        CONFIGURED_LIBRARY_PATHS.get_or_init(|| {
            let mut paths = Vec::new();
            let mut seen_files = FxHashSet::default();

            Self::parse_ld_so_conf_file(
                Path::new("/etc/ld.so.conf"),
                &mut paths,
                &mut seen_files,
                8,
            );

            // Fallback for setups where /etc/ld.so.conf is missing.
            if paths.is_empty() {
                Self::parse_ld_so_conf_include(
                    "/etc/ld.so.conf.d/*.conf",
                    &mut paths,
                    &mut seen_files,
                    8,
                );
            }

            paths
        })
    }

    unsafe fn runtime_init_args(
        &self,
    ) -> (
        usize,
        *const *const u8,
        *const *const u8,
        *const AuxiliaryVectorItem,
    ) {
        let argv = self
            .rtld_stubs
            .as_ref()
            .map(|stubs| *stubs.dl_argv)
            .unwrap_or(core::ptr::null());
        let mut argc = 0usize;
        if !argv.is_null() {
            while argc < 4096 {
                let current = *argv.add(argc);
                if current.is_null() {
                    break;
                }
                argc += 1;
            }
        }
        let env = crate::libc::environ::get_environ_pointer() as *const *const u8;
        let auxv = self
            .rtld_stubs
            .as_ref()
            .map(|stubs| stubs.auxv)
            .unwrap_or(core::ptr::null());
        (argc, argv, env, auxv)
    }

    pub unsafe fn rtld_dlfcn_hook(&self) -> Option<usize> {
        self.rtld_stubs
            .as_ref()
            .map(|stubs| stubs.dlfcn_hook_ptr())
    }

    fn resolve_object_dependency_indices(&self, idx: usize) -> SmallVec<[usize; 16]> {
        let mut deps = SmallVec::<[usize; 16]>::new();
        if idx >= self.objects.len() {
            return deps;
        }

        let object = &self.objects[idx];
        for &needed_offset in &object.needed_libraries {
            let needed_name = unsafe { object.string_table.get(needed_offset) };
            if needed_name.is_empty() {
                continue;
            }
            let Some(dep_idx) = self.loaded_index(needed_name) else {
                continue;
            };
            if dep_idx >= self.objects.len() || dep_idx == idx || deps.contains(&dep_idx) {
                continue;
            }
            deps.push(dep_idx);
        }

        deps
    }

    unsafe fn dependency_init_order(&self, start_idx: usize) -> SmallVec<[usize; 32]> {
        fn visit(
            idx: usize,
            start_idx: usize,
            linker: &DynamicLinker,
            state: &mut [u8],
            order: &mut SmallVec<[usize; 32]>,
        ) {
            if idx < start_idx || idx >= linker.objects.len() {
                return;
            }
            match state[idx] {
                1 | 2 => return,
                _ => {}
            }
            state[idx] = 1;

            for dep_idx in linker.resolve_object_dependency_indices(idx) {
                if dep_idx < linker.objects.len() && dep_idx != idx {
                    visit(dep_idx, start_idx, linker, state, order);
                }
            }

            state[idx] = 2;
            order.push(idx);
        }

        let mut state = vec![0u8; self.objects.len()];
        let mut order = SmallVec::<[usize; 32]>::new();
        order.reserve(self.objects.len().saturating_sub(start_idx));
        for idx in start_idx..self.objects.len() {
            visit(idx, start_idx, self, &mut state, &mut order);
        }
        order
    }

    pub unsafe fn new() -> Self {
        Self {
            objects: Vec::new(),
            library_map: Vec::new(),
            library_alias_index: FxHashMap::default(),
            object_paths: Vec::new(),
            object_link_maps: Vec::new(),
            object_link_map_dynamics: Vec::new(),
            object_link_map_names: Vec::new(),
            lookup_scopes: Vec::new(),
            rtld_stubs: None,
        }
    }

    fn visit_scope_indices(&self, idx: usize, seen: &mut [u8], order: &mut Vec<usize>) {
        if idx >= self.objects.len() || seen[idx] != 0 {
            return;
        }
        seen[idx] = 1;
        if idx != 0 {
            order.push(idx);
        }

        for dep_idx in self.resolve_object_dependency_indices(idx) {
            if dep_idx < self.objects.len() && dep_idx != idx {
                self.visit_scope_indices(dep_idx, seen, order);
            }
        }
    }

    pub fn rebuild_lookup_scopes(&mut self) {
        let object_count = self.objects.len();
        let mut new_lookup_scopes = Vec::with_capacity(object_count);
        new_lookup_scopes.resize_with(object_count, Vec::new);
        if object_count == 0 {
            let old_lookup_scopes = core::mem::replace(&mut self.lookup_scopes, new_lookup_scopes);
            core::mem::forget(old_lookup_scopes);
            return;
        }

        let mut seen = vec![0u8; object_count];
        for requester in 0..object_count {
            seen.fill(0);
            let mut order = Vec::with_capacity(object_count);

            // glibc-style global preemption: executable first.
            seen[0] = 1;
            order.push(0);

            self.visit_scope_indices(requester, &mut seen, &mut order);

            // Then remaining globals in load order.
            for idx in 1..object_count {
                if seen[idx] == 0 {
                    seen[idx] = 1;
                    order.push(idx);
                }
            }
            new_lookup_scopes[requester] = order;
        }

        let old_lookup_scopes = core::mem::replace(&mut self.lookup_scopes, new_lookup_scopes);
        core::mem::forget(old_lookup_scopes);
    }

    /// Initialize the rtld stubs using the executable's base and dynamic section.
    #[inline(always)]
    pub unsafe fn init_rtld_stubs(
        &mut self,
        exec_base: usize,
        exec_dynamic: *const u8,
        argv: *const *const u8,
        stack_end: *const u8,
        minsigstacksize: usize,
        auxv: *const AuxiliaryVectorItem,
        auxv_count: usize,
        hwcap: usize,
        hwcap2: usize,
    ) {
        let stubs = RtldStubs::new(
            exec_base,
            exec_dynamic,
            minsigstacksize,
            auxv,
            auxv_count,
            hwcap,
            hwcap2,
        );
        stubs.set_argv_and_stack_end(argv, stack_end);
        ld_stubs::set_r_debug_ldbase(exec_base);
        self.rtld_stubs = Some(stubs);
    }

    /// Initialize TLS for all loaded objects and install the thread pointer.
    pub unsafe fn prepare_tls_layout(&mut self) {
        tls::prepare_tls_layout(&mut self.objects);
        let layout = tls::tls_layout();
        if let Some(stubs) = self.rtld_stubs.as_ref() {
            #[cfg(target_arch = "x86_64")]
            if disable_rseq_metadata() || self.loaded_legacy_glibc_family() {
                stubs.set_rseq_metadata(0, 0, 0);
            } else {
                stubs.set_rseq_metadata(-192, 32, 0);
            }
            #[cfg(not(target_arch = "x86_64"))]
            stubs.set_rseq_metadata(0, 0, 0);
        }
        if let (Some(stubs), Some(layout)) = (self.rtld_stubs.as_ref(), layout) {
            let tls_static_size = layout.tls_size
                + core::mem::size_of::<crate::elf::thread_local_storage::ThreadControlBlock>();
            #[cfg(debug_assertions)]
            {
                eprintln!(
                    "loader: tls metadata size={} align={} modules={}",
                    tls_static_size, layout.max_align, layout.module_count
                );
            }
            stubs.set_tls_static_metadata(tls_static_size, layout.max_align);
        }
    }

    pub unsafe fn install_tls(&self, pseudorandom_bytes: *const [u8; 16]) {
        tls::install_tls(&self.objects, pseudorandom_bytes);
    }

    pub unsafe fn update_rtld_stack_end(&self, stack_end: *const u8) {
        if let Some(stubs) = self.rtld_stubs.as_ref() {
            stubs.set_stack_end(stack_end);
        }
    }

    fn map_alias(&mut self, alias: String, index: usize) {
        // Preserve first-seen alias resolution semantics.
        let base_name = Path::new(alias.as_str())
            .file_name()
            .and_then(|name| name.to_str())
            .map(|value| value.to_owned());
        if self.library_alias_index.insert(alias.clone(), index).is_none() {
            self.library_map.push((alias, index));
        }

        if let Some(base) = base_name {
            self.library_alias_index.entry(base).or_insert(index);
        }
    }

    fn normalize_existing_path(path: &str) -> String {
        path.to_string()
    }

    fn alternate_system_lib_prefix(path: &str) -> Option<String> {
        if let Some(suffix) = path.strip_prefix("/lib64/") {
            return Some(format!("/usr/lib64/{suffix}"));
        }
        if let Some(suffix) = path.strip_prefix("/usr/lib64/") {
            return Some(format!("/lib64/{suffix}"));
        }
        if let Some(suffix) = path.strip_prefix("/lib/") {
            return Some(format!("/usr/lib/{suffix}"));
        }
        if let Some(suffix) = path.strip_prefix("/usr/lib/") {
            return Some(format!("/lib/{suffix}"));
        }
        None
    }

    unsafe fn publish_dt_debug(&mut self, index: usize) {
        if index >= self.objects.len() {
            return;
        }
        let dynamic = self.objects[index].dynamic as *mut DynamicArrayItem;
        if dynamic.is_null() {
            return;
        }
        let mut cursor = dynamic;
        loop {
            let item = *cursor;
            if item.d_tag == DT_NULL {
                break;
            }
            if item.d_tag == DT_DEBUG {
                (*cursor).d_un.d_ptr = ld_stubs::r_debug_ptr();
                break;
            }
            cursor = cursor.add(1);
        }
    }

    fn install_link_map_for_object(&mut self, index: usize, name_hint: &str) {
        let c_name = CString::new(name_hint).unwrap_or_else(|_| CString::new("<invalid>").unwrap());
        let raw_name = c_name.into_raw();

        let mut previous = self
            .object_link_maps
            .last()
            .copied()
            .unwrap_or(core::ptr::null_mut());
        if !previous.is_null() && (previous as usize) % core::mem::align_of::<usize>() != 0 {
            previous = core::ptr::null_mut();
        }
        let map = unsafe {
            mmap(
                null_mut(),
                LINK_MAP_SIZE,
                PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if map.is_null() || (map as isize) < 0 {
            unsafe {
                write::write_str(
                    write::STD_ERR,
                    "Error: could not allocate runtime link_map\n",
                );
            }
            exit::exit(1);
        }
        unsafe {
            let dynamic_ptr = self.objects[index].dynamic as usize;
            let dynamic_for_link_map = if dynamic_ptr == 0
                || (dynamic_ptr % core::mem::align_of::<DynamicArrayItem>() != 0)
            {
                core::ptr::null()
            } else {
                self.objects[index].dynamic
            };
            let dynamic_copy =
                if legacy_glibc_link_map_needs_absolute_dynamic(name_hint) {
                    create_link_map_dynamic_copy(self.objects[index].base, dynamic_for_link_map)
                } else {
                    core::ptr::null_mut()
                };
            let link_map_dynamic = if dynamic_copy.is_null() {
                dynamic_for_link_map as *mut DynamicArrayItem
            } else {
                dynamic_copy
            };
            *(map.byte_add(LINK_MAP_L_ADDR_OFFSET) as *mut usize) = self.objects[index].base;
            *(map.byte_add(LINK_MAP_L_NAME_OFFSET) as *mut *const c_char) = raw_name;
            *(map.byte_add(LINK_MAP_L_LD_OFFSET) as *mut *const c_void) =
                link_map_dynamic as *const c_void;
            *(map.byte_add(LINK_MAP_L_NEXT_OFFSET) as *mut *mut u8) = core::ptr::null_mut();
            *(map.byte_add(LINK_MAP_L_PREV_OFFSET) as *mut *mut u8) = previous;
            *(map.byte_add(LINK_MAP_L_REAL_OFFSET) as *mut *mut u8) = map;
            populate_link_map_dynamic_info(map, link_map_dynamic.cast_const());

            if !previous.is_null() {
                *(previous.byte_add(LINK_MAP_L_NEXT_OFFSET) as *mut *mut u8) = map;
            }
            if index == 0 {
                if let Some(stubs) = self.rtld_stubs.as_ref() {
                    *(stubs.rtld_global as *mut *mut u8) = map;
                }
                ld_stubs::set_r_debug_map(map.cast());
                self.publish_dt_debug(index);
            }
        }

        self.object_link_maps.push(map);
        self.object_link_map_dynamics.push(unsafe {
            *(map.byte_add(LINK_MAP_L_LD_OFFSET) as *const *mut DynamicArrayItem)
        });
        self.object_link_map_names.push(raw_name);

        // Expose the real loaded-object list head to libc/libdl helpers.
        if index == 0 {
            if let Some(stubs) = self.rtld_stubs.as_ref() {
                unsafe {
                    stubs.set_ns_loaded_head(map);
                }
            }
        }
    }

    pub fn add_object_with_path(
        &mut self,
        name: String,
        object_path: Option<String>,
        object: SharedObject,
    ) -> usize {
        let index = self.objects.len();
        self.objects.push(object);
        self.object_paths.push(object_path.clone());
        let link_name = object_path
            .as_ref()
            .map(|path| path.as_str())
            .unwrap_or(name.as_str())
            .to_string();
        if let Some(stubs) = self.rtld_stubs.as_ref() {
            if matches!(glibc_dso_version(&link_name), Some((2, minor)) if minor <= 31) {
                unsafe {
                    stubs.set_glibc_getauxval_layout(true);
                    stubs.set_rseq_metadata(0, 0, 0);
                }
            }
        }
        if self.rtld_stubs.is_some() {
            self.install_link_map_for_object(index, &link_name);
        } else {
            // musl-target path: runtime dl* stubs can use synthetic handles.
            self.object_link_maps.push(core::ptr::null_mut());
            self.object_link_map_dynamics.push(core::ptr::null_mut());
            self.object_link_map_names.push(core::ptr::null_mut());
        }
        self.map_alias(name, index);
        if let Some(path) = object_path {
            self.map_alias(path.clone(), index);
            if let Some(alt) = Self::alternate_system_lib_prefix(&path) {
                self.map_alias(alt, index);
            }
        }
        if let Some(soname) = unsafe { self.objects[index].soname_str() } {
            self.map_alias(soname.to_string(), index);
        }
        // Topology changed; caller should rebuild scopes before heavy lookup phase.
        let old_lookup_scopes = core::mem::take(&mut self.lookup_scopes);
        core::mem::forget(old_lookup_scopes);
        index
    }

    pub fn loaded_index(&self, name: &str) -> Option<usize> {
        let base_name = strip_version_suffix(name);
        if base_name != name {
            if let Some(idx) = self.library_alias_index.get(base_name).copied() {
                return Some(idx);
            }
        }

        if let Some(idx) = self.library_alias_index.get(name).copied() {
            return Some(idx);
        }

        if let Some(alt_name) = Self::alternate_system_lib_prefix(name) {
            if let Some(idx) = self.library_alias_index.get(alt_name.as_str()).copied() {
                return Some(idx);
            }
        }
        None
    }

    pub fn object_path(&self, index: usize) -> Option<&str> {
        self.object_paths.get(index)?.as_deref()
    }

    fn is_loaded(&self, name: &str) -> bool {
        self.library_alias_index.contains_key(name)
    }

    fn open_path(path: &str) -> Option<i32> {
        let mut stack_buf = [0u8; 512];
        let path_bytes = path.as_bytes();
        let (ptr, _owned);
        if path_bytes.len() + 1 <= stack_buf.len() {
            stack_buf[..path_bytes.len()].copy_from_slice(path_bytes);
            stack_buf[path_bytes.len()] = 0;
            ptr = stack_buf.as_ptr() as *const c_char;
            _owned = None;
        } else {
            let owned = CString::new(path).ok()?;
            ptr = owned.as_ptr();
            _owned = Some(owned);
        }

        let fd = unsafe { Self::openat_raw(ptr) };
        if fd < 0 {
            return None;
        }
        let fd = fd as i32;
        if unsafe { !Self::fd_matches_host_arch(fd) } {
            unsafe { Self::close_fd(fd) };
            return None;
        }
        Some(fd)
    }

    unsafe fn close_fd(fd: i32) {
        arch::close_fd(fd);
    }

    fn object_origin_dir(&self, object_idx: usize) -> Option<&str> {
        let path = self.object_paths.get(object_idx)?.as_ref()?;
        Path::new(path).parent().and_then(|parent| parent.to_str())
    }

    fn resolve_absolute_runtime_dlopen_fallback(&self, requested: &str) -> Option<(String, i32)> {
        let requested_path = Path::new(requested);
        if !requested_path.is_absolute() {
            return None;
        }

        // Runtime launchers (for example jpackage-style binaries) often derive
        // "<self>/../lib/<launcher>.so" from /proc/self/exe. In rustld
        // in-process mode, /proc/self/exe is still rustld, so retry relative
        // to the mapped target executable directory when that shape fails.
        let requested_parent = requested_path.parent()?;
        let requested_dir = requested_parent.file_name()?.to_str()?;
        if requested_dir != "lib" && requested_dir != "lib64" {
            return None;
        }

        let soname = requested_path.file_name()?.to_str()?;
        let executable_path = self.object_path(0)?;
        let executable_dir = Path::new(executable_path).parent()?;
        let candidate_dirs = [
            executable_dir.join("lib"),
            executable_dir.join("lib64"),
            executable_dir.join("..").join("lib"),
            executable_dir.join("..").join("lib64"),
        ];

        for dir in candidate_dirs {
            let candidate = dir.join(soname);
            let Some(candidate_str) = candidate.to_str() else {
                continue;
            };
            if let Some(fd) = Self::open_path(candidate_str) {
                #[cfg(debug_assertions)]
                {
                    use crate::libc::fs::write;
                    unsafe {
                        write::write_str(write::STD_ERR, "loader: dlopen path fallback ");
                        write::write_str(write::STD_ERR, requested);
                        write::write_str(write::STD_ERR, " -> ");
                        write::write_str(write::STD_ERR, candidate_str);
                        write::write_str(write::STD_ERR, "\n");
                    }
                }
                return Some((Self::normalize_existing_path(candidate_str), fd));
            }
        }
        None
    }

    fn expand_origin_token<'a>(path: &'a str, origin: Option<&str>) -> Option<Cow<'a, str>> {
        if !path.contains("$ORIGIN") && !path.contains("${ORIGIN}") {
            return Some(Cow::Borrowed(path));
        }
        let origin = origin?;
        Some(Cow::Owned(
            path.replace("${ORIGIN}", origin).replace("$ORIGIN", origin),
        ))
    }

    fn try_open_from_search_list(
        &self,
        raw_list: &str,
        origin: Option<&str>,
        name: &str,
    ) -> Option<(String, i32)> {
        for entry in raw_list.split(':') {
            if entry.is_empty() {
                continue;
            }
            if let Some(expanded) = Self::expand_origin_token(entry, origin) {
                if let Some(found) = Self::open_joined_path(expanded.as_ref(), name) {
                    return Some(found);
                }
            }
        }
        None
    }

    fn env_var_from_environ(cache: &'static OnceLock<Option<String>>, key: &str) -> Option<&'static str> {
        cache
            .get_or_init(|| {
                let env_pointer = unsafe { crate::libc::environ::get_environ_pointer() };
                if env_pointer.is_null() {
                    return None;
                }

                let mut prefix = String::with_capacity(key.len() + 1);
                prefix.push_str(key);
                prefix.push('=');
                let prefix = prefix.into_bytes();

                let mut cursor = env_pointer;
                while unsafe { !(*cursor).is_null() } {
                    let entry_ptr = unsafe { *cursor } as *const c_char;
                    let entry = unsafe { CStr::from_ptr(entry_ptr).to_bytes() };
                    if let Some(value) = entry.strip_prefix(prefix.as_slice()) {
                        if let Ok(text) = core::str::from_utf8(value) {
                            return Some(text.to_string());
                        }
                    }
                    cursor = unsafe { cursor.add(1) };
                }
                None
            })
            .as_deref()
    }

    fn rustld_library_path_from_env() -> Option<&'static str> {
        Self::env_var_from_environ(&RUSTLD_LIBRARY_PATH, "RUSTLD_LIBRARY_PATH")
    }

    fn ld_library_path_from_env() -> Option<&'static str> {
        Self::env_var_from_environ(&LD_LIBRARY_PATH, "LD_LIBRARY_PATH")
    }

    unsafe fn openat_raw(path_ptr: *const c_char) -> isize {
        arch::openat_readonly(path_ptr) as isize
    }

    fn resolve_library_path_with_fd(
        &self,
        name: &str,
        requester_idx: Option<usize>,
    ) -> Option<(String, i32)> {
        if name.contains('/') {
            if let Some(fd) = Self::open_path(name) {
                return Some((Self::normalize_existing_path(name), fd));
            }
            return self.resolve_absolute_runtime_dlopen_fallback(name);
        }

        let origin = requester_idx.and_then(|idx| self.object_origin_dir(idx));
        let (runpath, rpath) = if let Some(idx) = requester_idx {
            let object = &self.objects[idx];
            unsafe { (object.runpath_str(), object.rpath_str()) }
        } else {
            (None, None)
        };

        if runpath.is_none() {
            if let Some(rpath_value) = rpath {
                if let Some(found) = self.try_open_from_search_list(rpath_value, origin, name) {
                    return Some(found);
                }
            }
        }

        if let Some(rustld_library_path) = Self::rustld_library_path_from_env() {
            if let Some(found) = self.try_open_from_search_list(rustld_library_path, origin, name) {
                return Some(found);
            }
        }

        if let Some(ld_library_path) = Self::ld_library_path_from_env() {
            if let Some(found) = self.try_open_from_search_list(ld_library_path, origin, name) {
                return Some(found);
            }
        }

        if let Some(runpath_value) = runpath {
            if let Some(found) = self.try_open_from_search_list(runpath_value, origin, name) {
                return Some(found);
            }
        }

        let skip_system_origin_probe =
            Self::is_shared_object_soname(name) && origin.is_some_and(Self::is_system_bin_dir);

        if let Some(origin_dir) = origin {
            if !skip_system_origin_probe {
                if let Some(found) = Self::open_joined_path(origin_dir, name) {
                    return Some(found);
                }
            }
        }
        if let Some(main_origin) = self.object_origin_dir(0) {
            let skip_main_origin_probe =
                Self::is_shared_object_soname(name) && Self::is_system_bin_dir(main_origin);
            if origin != Some(main_origin) && !skip_main_origin_probe {
                if let Some(found) = Self::open_joined_path(main_origin, name) {
                    return Some(found);
                }
            }
        }

        for default_dir in DEFAULT_LIBRARY_PATHS {
            if let Some(found) = Self::open_joined_path(default_dir, name) {
                return Some(found);
            }
        }

        for configured_dir in Self::configured_library_paths() {
            if let Some(found) = Self::open_joined_path(configured_dir, name) {
                return Some(found);
            }
        }

        for fallback in Self::musl_libc_fallback_candidates(name) {
            if let Some(fd) = Self::open_path(fallback) {
                return Some(((*fallback).to_string(), fd));
            }
        }

        None
    }

    fn open_joined_path(dir: &str, file: &str) -> Option<(String, i32)> {
        let needs_sep = !dir.ends_with('/');
        let total_len = dir.len() + usize::from(needs_sep) + file.len();
        if total_len + 1 <= 1024 {
            let mut stack_buf = [0u8; 1024];
            let mut pos = 0usize;
            stack_buf[..dir.len()].copy_from_slice(dir.as_bytes());
            pos += dir.len();
            if needs_sep {
                stack_buf[pos] = b'/';
                pos += 1;
            }
            stack_buf[pos..pos + file.len()].copy_from_slice(file.as_bytes());
            pos += file.len();
            stack_buf[pos] = 0;

            let fd = unsafe { Self::openat_raw(stack_buf.as_ptr() as *const c_char) };
            if fd >= 0 {
                let fd = fd as i32;
                if unsafe { !Self::fd_matches_host_arch(fd) } {
                    unsafe { Self::close_fd(fd) };
                    return None;
                }
                let path = unsafe { core::str::from_utf8_unchecked(&stack_buf[..pos]) }.to_string();
                return Some((path, fd));
            }
            return None;
        }

        let mut candidate = String::with_capacity(total_len);
        candidate.push_str(dir);
        if needs_sep {
            candidate.push('/');
        }
        candidate.push_str(file);
        Self::open_path(&candidate).map(|fd| (candidate, fd))
    }

    pub(crate) unsafe fn load_library_with_requester(
        &mut self,
        name: &str,
        requester_idx: Option<usize>,
        allow_selinux_stub: bool,
    ) -> Result<usize, &'static str> {
        if let Some(idx) = self.loaded_index(name) {
            #[cfg(debug_assertions)]
            {
                use crate::libc::fs::write;
                write::write_str(write::STD_ERR, "loader: load_library hit ");
                write::write_str(write::STD_ERR, name);
                write::write_str(write::STD_ERR, " -> existing\n");
            }
            return Ok(idx);
        }

        if allow_selinux_stub
            && Self::selinux_stub_enabled()
            && Self::should_stub_selinux_library(name)
        {
            self.map_alias(name.to_string(), usize::MAX);
            return Ok(usize::MAX);
        }

        if cfg!(target_arch = "x86_64") && name.starts_with("ld-linux") {
            self.map_alias(name.to_string(), usize::MAX);
            return Ok(usize::MAX);
        }

        let (path, fd) = match self.resolve_library_path_with_fd(name, requester_idx) {
            Some(found) => found,
            None => {
                #[cfg(debug_assertions)]
                {
                    use crate::libc::fs::write;
                    write::write_str(write::STD_ERR, "loader: resolve failed name=");
                    write::write_str(write::STD_ERR, name);
                    write::write_str(write::STD_ERR, " requester=");
                    if let Some(idx) = requester_idx {
                        if let Some(path) = self.object_path(idx) {
                            write::write_str(write::STD_ERR, path);
                        } else {
                            write::write_str(write::STD_ERR, "<none>");
                        }
                    } else {
                        write::write_str(write::STD_ERR, "<root>");
                    }
                    write::write_str(write::STD_ERR, "\n");
                }
                return Err("library not found");
            }
        };
        if let Some(idx) = self.loaded_index(&path) {
            Self::close_fd(fd);
            #[cfg(debug_assertions)]
            {
                use crate::libc::fs::write;
                write::write_str(write::STD_ERR, "loader: load_library path-hit ");
                write::write_str(write::STD_ERR, &path);
                write::write_str(write::STD_ERR, " -> existing\n");
            }
            self.map_alias(name.to_string(), idx);
            return Ok(idx);
        }

        #[cfg(debug_assertions)]
        {
            use crate::libc::fs::write;
            write::write_str(write::STD_ERR, "loader: load_library miss ");
            write::write_str(write::STD_ERR, name);
            write::write_str(write::STD_ERR, " resolved=");
            write::write_str(write::STD_ERR, &path);
            write::write_str(write::STD_ERR, "\n");
        }

        let object = SharedObject::from_fd(fd);
        Self::close_fd(fd);

        let needed_offsets: SmallVec<[usize; 16]> =
            object.needed_libraries.iter().copied().collect();
        let string_table = object.string_table;

        let idx = self.add_object_with_path(name.to_string(), Some(path), object);
        let mut resolved_dependencies = Vec::with_capacity(needed_offsets.len());
        for needed_offset in needed_offsets {
            let needed_name = string_table.get(needed_offset);
            if needed_name.is_empty() {
                continue;
            }
            let needed_name = needed_name.to_string();
            let dep_idx =
                self.load_library_with_requester(&needed_name, Some(idx), allow_selinux_stub)?;
            if dep_idx < self.objects.len() && dep_idx != idx {
                resolved_dependencies.push(dep_idx);
            }
        }
        self.objects[idx].resolved_dependencies = resolved_dependencies;

        Ok(idx)
    }

    #[inline(always)]
    fn should_stub_selinux_library(name: &str) -> bool {
        name == "libselinux.so.1" || name.ends_with("/libselinux.so.1")
    }

    #[inline(always)]
    fn selinux_stub_enabled() -> bool {
        false
    }

    pub unsafe fn load_library(
        &mut self,
        name: &str,
        _pseudorandom_bytes: *const [u8; 16],
        requester_idx: Option<usize>,
    ) {
        if self.is_loaded(name) {
            return;
        }
        if self
            .load_library_with_requester(name, requester_idx, true)
            .is_err()
        {
            write::write_str(write::STD_ERR, "Error: Could not find library: ");
            write::write_str(write::STD_ERR, name);
            write::write_str(write::STD_ERR, "\n");
            exit::exit(1);
        }
    }

    unsafe fn load_library_runtime_inner(
        &mut self,
        name: &str,
        requester_idx: Option<usize>,
    ) -> Result<usize, &'static str> {
        if Self::should_skip_runtime_nss_backend(name) {
            if Self::trace_runtime_nss() || Self::trace_runtime_all() {
                unsafe {
                    write::write_str(write::STD_ERR, "runtime_nss:skip file=");
                    write::write_str(write::STD_ERR, name);
                    write::write_str(write::STD_ERR, "\n");
                }
            }
            return Err("runtime nss backend disabled");
        }
        self.load_library_with_requester(name, requester_idx, false)
    }

    pub unsafe fn dlopen_runtime(&mut self, file: &str, _mode: i32) -> Result<usize, &'static str> {
        if file.is_empty() {
            return Ok(0);
        }

        if Self::trace_runtime_nss() && Self::is_runtime_nss_name(file) {
            unsafe {
                write::write_str(write::STD_ERR, "runtime_nss:dlopen:start file=");
                write::write_str(write::STD_ERR, file);
                write::write_str(write::STD_ERR, "\n");
            }
        }

        let start_idx = self.objects.len();
        let root_idx = self.load_library_runtime_inner(file, None)?;
        if root_idx == usize::MAX {
            return Err("unsupported runtime object");
        }
        if start_idx >= self.objects.len() {
            return Ok(root_idx);
        }

        if Self::trace_runtime_nss() {
            unsafe {
                write::write_str(write::STD_ERR, "runtime_nss:dlopen:loaded file=");
                write::write_str(write::STD_ERR, file);
                write::write_str(write::STD_ERR, " start_idx=");
                write_trace_dec(start_idx);
                write::write_str(write::STD_ERR, " root_idx=");
                write_trace_dec(root_idx);
                write::write_str(write::STD_ERR, " new_objects=");
                write_trace_dec(self.objects.len().saturating_sub(start_idx));
                write::write_str(write::STD_ERR, "\n");
            }
            for idx in start_idx..self.objects.len() {
                self.trace_runtime_nss_object_state("loaded", idx);
            }
        }

        self.rebuild_lookup_scopes();

        let new_objects_have_tls = self.objects[start_idx..]
            .iter()
            .any(|object| object.tls.is_some());
        if new_objects_have_tls {
            if Self::trace_runtime_nss() {
                unsafe {
                    write::write_str(write::STD_ERR, "runtime_nss:tls:register:start root_idx=");
                    write_trace_dec(root_idx);
                    write::write_str(write::STD_ERR, "\n");
                }
            }
            tls::register_runtime_tls_modules(&mut self.objects[start_idx..])?;
            if Self::trace_runtime_nss() {
                unsafe {
                    write::write_str(write::STD_ERR, "runtime_nss:tls:register:done root_idx=");
                    write_trace_dec(root_idx);
                    write::write_str(write::STD_ERR, "\n");
                }
                for idx in start_idx..self.objects.len() {
                    self.trace_runtime_nss_object_state("post-register-tls", idx);
                }
            }
        }

        let mut ifuncs = Vec::new();
        let mut copies = Vec::new();
        let lookup_cache_capacity = self.objects[start_idx..]
            .iter()
            .map(|object| {
                let slices = object.relocation_slices();
                slices.rela_slice.len() + (slices.relr_slice.len() / 2)
            })
            .sum::<usize>()
            .max(1024);
        let mut lookup_cache = relocation::SymbolLookupCache::with_capacity(lookup_cache_capacity);
        let relocation_indices: Vec<usize> = (start_idx..self.objects.len()).collect();
        for obj_idx in relocation_indices {
            let object_snapshot = self.objects[obj_idx].clone();
            self.trace_runtime_nss_object_state("relocate:start", obj_idx);
            relocation::relocate_with_linker(
                &object_snapshot,
                obj_idx,
                self,
                &mut ifuncs,
                &mut copies,
                &mut lookup_cache,
            );
            self.trace_runtime_nss_object_state("relocate:done", obj_idx);
            core::mem::forget(object_snapshot);
        }
        relocation::apply_copy_relocations(&copies);
        relocation::apply_irelative_relocations(&ifuncs);
        if new_objects_have_tls {
            if Self::trace_runtime_nss() {
                unsafe {
                    write::write_str(write::STD_ERR, "runtime_nss:tls:finalize:start root_idx=");
                    write_trace_dec(root_idx);
                    write::write_str(write::STD_ERR, "\n");
                }
            }
            tls::finalize_runtime_tls_images(&self.objects[start_idx..])?;
            if Self::trace_runtime_nss() {
                unsafe {
                    write::write_str(write::STD_ERR, "runtime_nss:tls:finalize:done root_idx=");
                    write_trace_dec(root_idx);
                    write::write_str(write::STD_ERR, "\n");
                }
            }
        }

        // Run init in dependency order rooted at the object requested by
        // dlopen, mirroring glibc's behavior more closely for plugin trees.
        // Falling back to start_idx keeps behavior sane if root_idx is older.
        let init_root = root_idx.max(start_idx);
        let (arg_count, arg_pointer, env_pointer, auxv_pointer) = self.runtime_init_args();
        let skip_selinux_init = skip_selinux_ctors();
        for idx in self.dependency_init_order(init_root) {
            if skip_selinux_init
                && self.objects[idx]
                    .soname_str()
                    .is_some_and(|soname| soname == "libselinux.so.1")
            {
                continue;
            }
            self.objects[idx].call_init_functions(
                arg_count,
                arg_pointer,
                env_pointer,
                auxv_pointer,
            );
        }

        Ok(root_idx)
    }

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

    pub unsafe fn lookup_symbol_entry_ptr_in_object(
        &self,
        object_index: usize,
        symbol_name: &str,
    ) -> Option<*const Symbol> {
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

            return Some(symtab_ptr.add(sym_idx));
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

    pub unsafe fn lookup_symbol_for_object_excluding_rtld_slow(
        &self,
        requester_object: usize,
        symbol_name: &str,
        exclude_object: Option<usize>,
    ) -> Option<(usize, Symbol)> {
        if let Some(resolved) = self.lookup_rtld_stub_symbol(symbol_name) {
            return Some(resolved);
        }

        // glibc probes NSS backends for module-specific `_nss_*` entry points.
        // Those lookups are backend-local; walking dependency scopes can both
        // return the wrong symbol and force scans through libc for symbols that
        // are expected to be absent on the module.
        if Self::is_nss_module_symbol(symbol_name)
            && requester_object < self.objects.len()
            && exclude_object != Some(requester_object)
        {
            return self.objects[requester_object]
                .lookup_exported_symbol_slow(symbol_name)
                .map(|symbol| (requester_object, symbol));
        }

        let mut candidate_indices = if requester_object < self.lookup_scopes.len() {
            self.lookup_scopes[requester_object].clone()
        } else {
            (0..self.objects.len()).collect()
        };
        if candidate_indices.is_empty() {
            candidate_indices = (0..self.objects.len()).collect();
        }

        if Self::trace_rtld_lookup() {
            eprintln!(
                "rtld_scope: requester={} symbol={} exclude={:?} candidates={:?}",
                requester_object,
                symbol_name,
                exclude_object,
                candidate_indices
            );
        }

        for idx in candidate_indices {
            if exclude_object == Some(idx) || idx >= self.objects.len() {
                continue;
            }
            if Self::trace_rtld_lookup() {
                let soname = self.objects[idx].soname_str().unwrap_or("<none>");
                eprintln!("rtld_scope: try idx={} soname={}", idx, soname);
            }
            if let Some(symbol) = self.objects[idx].lookup_exported_symbol_slow(symbol_name) {
                return Some((idx, symbol));
            }
        }

        None
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

    fn loaded_legacy_glibc_family(&self) -> bool {
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

pub unsafe fn active_linker() -> Option<&'static DynamicLinker> {
    let linker_ptr = core::ptr::read_volatile(core::ptr::addr_of!(ACTIVE_LINKER));
    linker_ptr.as_ref()
}

#[inline(always)]
fn running_under_valgrind() -> bool {
    arch::running_under_valgrind()
}

#[inline(always)]
fn disable_rseq_metadata() -> bool {
    running_under_valgrind() || std::env::var("RUSTLD_DISABLE_RSEQ").is_ok()
}

#[inline(always)]
fn skip_selinux_ctors() -> bool {
    running_under_valgrind() || cfg!(target_arch = "aarch64")
}

pub unsafe fn active_linker_mut() -> Option<&'static mut DynamicLinker> {
    let linker_ptr = core::ptr::read_volatile(core::ptr::addr_of!(ACTIVE_LINKER));
    linker_ptr.as_mut()
}
