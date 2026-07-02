//! glibc libc copy-threshold text patching (x86_64 only).
//!
//! rtld normally initializes these `__x86_*` cache-size tunables during CPU
//! setup; rustld replays that by locating and patching them in mapped libc.

use std::fs;
use std::mem::size_of;
#[cfg(target_family = "unix")]
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use super::find_libc_object_index;
use crate::{elf::header::ElfHeader, linking::DynamicLinker};

#[cfg(target_arch = "x86_64")]
pub(super) unsafe fn patch_libc_copy_thresholds(linker: &DynamicLinker) {
    // These glibc internals are normally initialized by rtld CPU/cache setup.
    // Under our loader they can remain zero, which breaks IFUNC string/memory
    // implementations for non-trivial programs.
    //
    // Offsets are for x86_64 glibc data symbols:
    //   __x86_rep_stosb_threshold
    //   __x86_rep_movsb_threshold
    //   __x86_shared_cache_size
    //   __x86_shared_cache_size_half
    //   __x86_rep_movsb_stop_threshold
    //   __x86_memset_non_temporal_threshold
    //   __x86_shared_non_temporal_threshold
    const LEGACY_REP_STOSB_THRESHOLD: usize = 0x1e9210;
    const LEGACY_REP_MOVSB_THRESHOLD: usize = 0x1e9218;
    const LEGACY_SHARED_CACHE_SIZE: usize = 0x1e9220;
    const LEGACY_SHARED_CACHE_SIZE_HALF: usize = 0x1e9228;
    const LEGACY_REP_MOVSB_STOP_THRESHOLD: usize = 0x1f02c8;
    const LEGACY_MEMSET_NON_TEMPORAL_THRESHOLD: usize = 0x1f02d0;
    const LEGACY_SHARED_NON_TEMPORAL_THRESHOLD: usize = 0x1f02d8;

    let libc_idx = find_libc_object_index(linker);

    let Some(idx) = libc_idx else {
        return;
    };

    let Some(libc_path) = linker.object_path(idx) else {
        return;
    };
    let base = linker.get_base(idx);

    // Prefer real symbol-derived offsets for the active libc file.
    // This is portable across distro-specific glibc builds.
    if let Some(symbol_offsets) = load_libc_copy_threshold_offsets_from_symtab(libc_path) {
        if libc_thresholds_offsets_fit_object_map(linker, idx, base, &symbol_offsets) {
            #[cfg(debug_assertions)]
            {
                use crate::libc::fs::write;
                write::write_str(write::STD_ERR, "loader: libc thresholds via symtab ");
                write::write_str(write::STD_ERR, libc_path);
                write::write_str(write::STD_ERR, "\n");
            }
            apply_libc_copy_threshold_patch(base, &symbol_offsets);
            return;
        }
        #[cfg(debug_assertions)]
        {
            use crate::libc::fs::write;
            write::write_str(
                write::STD_ERR,
                "loader: symtab-derived libc thresholds out of map; ignoring\n",
            );
        }
    }

    // Next try the split debug file (.build-id) if installed. This keeps the
    // offsets resilient across libc updates on stripped distributions.
    if let Some(debug_offsets) = load_libc_copy_threshold_offsets_from_debug_file(libc_path) {
        if libc_thresholds_offsets_fit_object_map(linker, idx, base, &debug_offsets) {
            #[cfg(debug_assertions)]
            {
                use crate::libc::fs::write;
                write::write_str(write::STD_ERR, "loader: libc thresholds via debug symbols ");
                write::write_str(write::STD_ERR, libc_path);
                write::write_str(write::STD_ERR, "\n");
            }
            apply_libc_copy_threshold_patch(base, &debug_offsets);
            return;
        }
        #[cfg(debug_assertions)]
        {
            use crate::libc::fs::write;
            write::write_str(
                write::STD_ERR,
                "loader: debug-derived libc thresholds out of map; ignoring\n",
            );
        }
    }

    // Last automatic fallback: known build-id specific layouts.
    if let Some(buildid_offsets) = load_libc_copy_threshold_offsets_from_known_build_id(libc_path) {
        if libc_thresholds_offsets_fit_object_map(linker, idx, base, &buildid_offsets) {
            #[cfg(debug_assertions)]
            {
                use crate::libc::fs::write;
                write::write_str(write::STD_ERR, "loader: libc thresholds via known build-id ");
                write::write_str(write::STD_ERR, libc_path);
                write::write_str(write::STD_ERR, "\n");
            }
            apply_libc_copy_threshold_patch(base, &buildid_offsets);
            return;
        }
        #[cfg(debug_assertions)]
        {
            use crate::libc::fs::write;
            write::write_str(
                write::STD_ERR,
                "loader: build-id libc thresholds out of map; ignoring\n",
            );
        }
    }

    let fixed_fallback_forced = allow_fixed_libc_thresholds_fallback();

    // Fixed offsets are intentionally opt-in only.
    if fixed_fallback_forced {
        let legacy_offsets = LibcCopyThresholdOffsets {
            rep_stosb: LEGACY_REP_STOSB_THRESHOLD,
            rep_movsb: LEGACY_REP_MOVSB_THRESHOLD,
            shared_cache_size: LEGACY_SHARED_CACHE_SIZE,
            shared_cache_half: LEGACY_SHARED_CACHE_SIZE_HALF,
            rep_movsb_stop: LEGACY_REP_MOVSB_STOP_THRESHOLD,
            memset_non_temporal: Some(LEGACY_MEMSET_NON_TEMPORAL_THRESHOLD),
            shared_non_temporal: LEGACY_SHARED_NON_TEMPORAL_THRESHOLD,
        };

        if !libc_thresholds_offsets_fit_object_map(linker, idx, base, &legacy_offsets) {
            #[cfg(debug_assertions)]
            {
                use crate::libc::fs::write;
                write::write_str(
                    write::STD_ERR,
                    "loader: libc thresholds fixed offsets out of map; skipping\n",
                );
            }
            return;
        }

        #[cfg(debug_assertions)]
        {
            use crate::libc::fs::write;
            write::write_str(write::STD_ERR, "loader: libc thresholds via forced fixed offsets ");
            write::write_str(write::STD_ERR, libc_path);
            write::write_str(write::STD_ERR, "\n");
        }
        apply_libc_copy_threshold_patch(base, &legacy_offsets);
        return;
    }

    #[cfg(debug_assertions)]
    {
        use crate::libc::fs::write;
        write::write_str(
            write::STD_ERR,
            "loader: libc thresholds unavailable (no symtab/debug/known build-id)\n",
        );
    }
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
fn allow_fixed_libc_thresholds_fallback() -> bool {
    false
}

#[cfg(target_arch = "x86_64")]
#[derive(Clone, Copy)]
struct LibcCopyThresholdOffsets {
    rep_stosb: usize,
    rep_movsb: usize,
    shared_cache_size: usize,
    shared_cache_half: usize,
    rep_movsb_stop: usize,
    // Some newer glibc builds no longer expose this internal symbol in symtab.
    memset_non_temporal: Option<usize>,
    shared_non_temporal: usize,
}

#[cfg(target_arch = "x86_64")]
#[repr(C)]
#[derive(Clone, Copy)]
struct Elf64NoteHeader {
    n_namesz: u32,
    n_descsz: u32,
    n_type: u32,
}

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
struct Elf64Symbol {
    st_name: u32,
    st_info: u8,
    st_other: u8,
    st_shndx: u16,
    st_value: u64,
    st_size: u64,
}

#[cfg(target_arch = "x86_64")]
fn libc_thresholds_offsets_complete(
    rep_stosb: Option<usize>,
    rep_movsb: Option<usize>,
    shared_cache_size: Option<usize>,
    shared_cache_half: Option<usize>,
    rep_movsb_stop: Option<usize>,
    _memset_non_temporal: Option<usize>,
    shared_non_temporal: Option<usize>,
) -> bool {
    rep_stosb.is_some()
        && rep_movsb.is_some()
        && shared_cache_size.is_some()
        && shared_cache_half.is_some()
        && rep_movsb_stop.is_some()
        && shared_non_temporal.is_some()
}

#[cfg(all(target_arch = "x86_64", target_family = "unix"))]
fn libc_thresholds_cache_path(path: &str) -> Option<String> {
    let metadata = fs::metadata(path).ok()?;
    let dev = metadata.dev();
    let ino = metadata.ino();
    let size = metadata.len();
    let mtime = metadata.mtime();
    let mtime_nsec = metadata.mtime_nsec();
    Some(format!(
        "/tmp/rustld-libc-thresholds-{dev:x}-{ino:x}-{size:x}-{mtime:x}-{mtime_nsec:x}.cache"
    ))
}

#[cfg(target_arch = "x86_64")]
fn parse_libc_thresholds_cache_line(line: &str) -> Option<LibcCopyThresholdOffsets> {
    let mut parts = line.split_whitespace();
    let mut next_hex = || usize::from_str_radix(parts.next()?, 16).ok();

    let rep_stosb = next_hex()?;
    let rep_movsb = next_hex()?;
    let shared_cache_size = next_hex()?;
    let shared_cache_half = next_hex()?;
    let rep_movsb_stop = next_hex()?;
    let memset_raw = next_hex()?;
    let shared_non_temporal = next_hex()?;

    let offsets = LibcCopyThresholdOffsets {
        rep_stosb,
        rep_movsb,
        shared_cache_size,
        shared_cache_half,
        rep_movsb_stop,
        memset_non_temporal: if memset_raw == 0 { None } else { Some(memset_raw) },
        shared_non_temporal,
    };
    Some(offsets)
}

#[cfg(target_arch = "x86_64")]
fn load_libc_thresholds_offsets_from_cache(path: &str) -> Option<LibcCopyThresholdOffsets> {
    #[cfg(target_family = "unix")]
    {
        let cache_path = libc_thresholds_cache_path(path)?;
        let cache = fs::read_to_string(cache_path).ok()?;
        return parse_libc_thresholds_cache_line(cache.trim());
    }
    #[allow(unreachable_code)]
    None
}

#[cfg(target_arch = "x86_64")]
fn store_libc_thresholds_offsets_cache(path: &str, offsets: &LibcCopyThresholdOffsets) {
    #[cfg(target_family = "unix")]
    {
        if let Some(cache_path) = libc_thresholds_cache_path(path) {
            let memset_non_temporal = offsets.memset_non_temporal.unwrap_or(0);
            let payload = format!(
                "{:x} {:x} {:x} {:x} {:x} {:x} {:x}\n",
                offsets.rep_stosb,
                offsets.rep_movsb,
                offsets.shared_cache_size,
                offsets.shared_cache_half,
                offsets.rep_movsb_stop,
                memset_non_temporal,
                offsets.shared_non_temporal
            );
            let _ = fs::write(cache_path, payload);
        }
    }
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
fn align_up_4(value: usize) -> usize {
    (value + 3) & !3
}

#[cfg(target_arch = "x86_64")]
fn parse_build_id_from_note_block(note_bytes: &[u8]) -> Option<Vec<u8>> {
    const NT_GNU_BUILD_ID: u32 = 3;
    let mut cursor = 0usize;

    while cursor + size_of::<Elf64NoteHeader>() <= note_bytes.len() {
        let hdr = unsafe {
            core::ptr::read_unaligned(note_bytes.as_ptr().add(cursor).cast::<Elf64NoteHeader>())
        };
        cursor += size_of::<Elf64NoteHeader>();

        let namesz = hdr.n_namesz as usize;
        let descsz = hdr.n_descsz as usize;

        let name_end = cursor.checked_add(namesz)?;
        if name_end > note_bytes.len() {
            break;
        }
        let name = &note_bytes[cursor..name_end];
        cursor = align_up_4(name_end);
        if cursor > note_bytes.len() {
            break;
        }

        let desc_end = cursor.checked_add(descsz)?;
        if desc_end > note_bytes.len() {
            break;
        }
        let desc = &note_bytes[cursor..desc_end];
        cursor = align_up_4(desc_end);
        if cursor > note_bytes.len() {
            break;
        }

        let is_gnu_name = name == b"GNU\0" || name == b"GNU";
        if hdr.n_type == NT_GNU_BUILD_ID && is_gnu_name && !desc.is_empty() {
            return Some(desc.to_vec());
        }
    }

    None
}

#[cfg(target_arch = "x86_64")]
fn load_elf_build_id(path: &str) -> Option<Vec<u8>> {
    const SHT_NOTE: u32 = 7;

    let bytes = fs::read(path).ok()?;
    if bytes.len() < size_of::<ElfHeader>() {
        return None;
    }

    let header: ElfHeader = unsafe { core::ptr::read_unaligned(bytes.as_ptr().cast::<ElfHeader>()) };
    if header.e_ident[0..4] != [0x7f, b'E', b'L', b'F'] {
        return None;
    }
    if header.e_ident[4] != 2 || header.e_ident[5] != 1 {
        return None;
    }
    if header.e_shoff == 0 || header.e_shnum == 0 {
        return None;
    }

    let shoff = header.e_shoff;
    let shentsize = header.e_shentsize as usize;
    let shnum = header.e_shnum as usize;
    if shentsize < size_of::<Elf64SectionHeader>() {
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
        if shdr.sh_type != SHT_NOTE {
            continue;
        }

        let start = shdr.sh_offset as usize;
        let len = shdr.sh_size as usize;
        let end = start.checked_add(len)?;
        if end > bytes.len() {
            continue;
        }
        if let Some(build_id) = parse_build_id_from_note_block(&bytes[start..end]) {
            return Some(build_id);
        }
    }

    None
}

#[cfg(target_arch = "x86_64")]
fn debug_symbol_path_for_build_id(build_id: &[u8]) -> Option<String> {
    if build_id.len() < 2 {
        return None;
    }

    let mut first = String::with_capacity(2);
    use core::fmt::Write as _;
    let _ = write!(&mut first, "{:02x}", build_id[0]);

    let mut rest = String::with_capacity((build_id.len() - 1) * 2);
    for byte in build_id.iter().skip(1) {
        let _ = write!(&mut rest, "{:02x}", byte);
    }

    Some(format!("/usr/lib/debug/.build-id/{first}/{rest}.debug"))
}

#[cfg(target_arch = "x86_64")]
unsafe fn load_libc_copy_threshold_offsets_from_debug_file(
    libc_path: &str,
) -> Option<LibcCopyThresholdOffsets> {
    let build_id = load_elf_build_id(libc_path)?;
    let debug_path = debug_symbol_path_for_build_id(&build_id)?;
    if !Path::new(&debug_path).exists() {
        return None;
    }

    load_libc_copy_threshold_offsets_from_symtab(&debug_path)
}

#[cfg(target_arch = "x86_64")]
fn known_libc_threshold_offsets_for_build_id(build_id: &[u8]) -> Option<LibcCopyThresholdOffsets> {
    // Fedora/RHEL-like glibc layout used by the legacy fixed offsets.
    const BUILD_ID_LEGACY: [u8; 20] = [
        0xff, 0x02, 0x67, 0x46, 0x5b, 0xc3, 0xd7, 0x6e, 0x21, 0x00, 0x3b, 0x3b, 0xc5, 0x59,
        0x8f, 0xd5, 0xee, 0x63, 0xe2, 0x61,
    ];
    // Ubuntu/Debian glibc 2.39 stripped libc layout.
    const BUILD_ID_UBUNTU_239: [u8; 20] = [
        0x8e, 0x9f, 0xd8, 0x27, 0x44, 0x6c, 0x24, 0x06, 0x75, 0x41, 0xac, 0x53, 0x90, 0xe6,
        0xf5, 0x27, 0xfb, 0x59, 0x47, 0xbb,
    ];

    if build_id == BUILD_ID_LEGACY {
        return Some(LibcCopyThresholdOffsets {
            rep_stosb: 0x1e9210,
            rep_movsb: 0x1e9218,
            shared_cache_size: 0x1e9220,
            shared_cache_half: 0x1e9228,
            rep_movsb_stop: 0x1f02c8,
            memset_non_temporal: Some(0x1f02d0),
            shared_non_temporal: 0x1f02d8,
        });
    }

    if build_id == BUILD_ID_UBUNTU_239 {
        return Some(LibcCopyThresholdOffsets {
            rep_stosb: 0x203210,
            rep_movsb: 0x203218,
            shared_cache_size: 0x203220,
            shared_cache_half: 0x203228,
            rep_movsb_stop: 0x20a228,
            memset_non_temporal: None,
            shared_non_temporal: 0x20a230,
        });
    }

    None
}

#[cfg(target_arch = "x86_64")]
fn load_libc_copy_threshold_offsets_from_known_build_id(
    libc_path: &str,
) -> Option<LibcCopyThresholdOffsets> {
    let build_id = load_elf_build_id(libc_path)?;
    known_libc_threshold_offsets_for_build_id(&build_id)
}

#[cfg(target_arch = "x86_64")]
fn libc_thresholds_offsets_max(offsets: &LibcCopyThresholdOffsets) -> usize {
    let mut max_offset = offsets
        .rep_stosb
        .max(offsets.rep_movsb)
        .max(offsets.shared_cache_size)
        .max(offsets.shared_cache_half)
        .max(offsets.rep_movsb_stop)
        .max(offsets.shared_non_temporal);
    if let Some(memset_non_temporal) = offsets.memset_non_temporal {
        max_offset = max_offset.max(memset_non_temporal);
    }
    max_offset
}

#[cfg(target_arch = "x86_64")]
fn libc_thresholds_offsets_fit_object_map(
    linker: &DynamicLinker,
    idx: usize,
    base: usize,
    offsets: &LibcCopyThresholdOffsets,
) -> bool {
    let Some((map_start, map_end)) = linker.object_map_range(idx) else {
        return true;
    };
    let max_addr = base.wrapping_add(libc_thresholds_offsets_max(offsets).saturating_add(size_of::<usize>()));
    max_addr >= map_start && max_addr <= map_end
}

#[cfg(target_arch = "x86_64")]
unsafe fn load_libc_copy_threshold_offsets_from_symtab(
    path: &str,
) -> Option<LibcCopyThresholdOffsets> {
    const SHT_SYMTAB: u32 = 2;

    if let Some(cached) = load_libc_thresholds_offsets_from_cache(path) {
        return Some(cached);
    }

    let bytes = fs::read(path).ok()?;
    if bytes.len() < size_of::<ElfHeader>() {
        return None;
    }

    let header: ElfHeader = core::ptr::read_unaligned(bytes.as_ptr().cast::<ElfHeader>());
    if header.e_ident[0..4] != [0x7f, b'E', b'L', b'F'] {
        return None;
    }
    if header.e_ident[4] != 2 || header.e_ident[5] != 1 {
        return None;
    }
    if header.e_shoff == 0 || header.e_shnum == 0 {
        return None;
    }

    let shoff = header.e_shoff;
    let shentsize = header.e_shentsize as usize;
    let shnum = header.e_shnum as usize;
    if shentsize < size_of::<Elf64SectionHeader>() {
        return None;
    }
    if shoff.saturating_add(shnum.saturating_mul(shentsize)) > bytes.len() {
        return None;
    }

    let mut rep_stosb = None;
    let mut rep_movsb = None;
    let mut shared_cache_size = None;
    let mut shared_cache_half = None;
    let mut rep_movsb_stop = None;
    let mut memset_non_temporal = None;
    let mut shared_non_temporal = None;

    let read_shdr = |index: usize| -> Option<Elf64SectionHeader> {
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
        if shdr.sh_type != SHT_SYMTAB || (shdr.sh_entsize as usize) < size_of::<Elf64Symbol>() {
            continue;
        }

        let sym_off = shdr.sh_offset as usize;
        let sym_size = shdr.sh_size as usize;
        if sym_off.saturating_add(sym_size) > bytes.len() {
            continue;
        }

        let strtab_idx = shdr.sh_link as usize;
        if strtab_idx >= shnum {
            continue;
        }
        let str_shdr = read_shdr(strtab_idx)?;
        let str_off = str_shdr.sh_offset as usize;
        let str_size = str_shdr.sh_size as usize;
        if str_off.saturating_add(str_size) > bytes.len() {
            continue;
        }
        let strtab = &bytes[str_off..str_off + str_size];

        let count = sym_size / (shdr.sh_entsize as usize);
        for i in 0..count {
            let off = sym_off + i * (shdr.sh_entsize as usize);
            if off.saturating_add(size_of::<Elf64Symbol>()) > bytes.len() {
                break;
            }
            let sym = core::ptr::read_unaligned(bytes.as_ptr().add(off).cast::<Elf64Symbol>());
            let name_off = sym.st_name as usize;
            if name_off >= strtab.len() {
                continue;
            }
            let name_bytes = &strtab[name_off..];
            let Some(term) = name_bytes.iter().position(|&b| b == 0) else {
                continue;
            };
            let name = &name_bytes[..term];

            if name == b"__x86_rep_stosb_threshold" {
                rep_stosb = Some(sym.st_value as usize);
            } else if name == b"__x86_rep_movsb_threshold" {
                rep_movsb = Some(sym.st_value as usize);
            } else if name == b"__x86_shared_cache_size" {
                shared_cache_size = Some(sym.st_value as usize);
            } else if name == b"__x86_shared_cache_size_half" {
                shared_cache_half = Some(sym.st_value as usize);
            } else if name == b"__x86_rep_movsb_stop_threshold" {
                rep_movsb_stop = Some(sym.st_value as usize);
            } else if name == b"__x86_memset_non_temporal_threshold" {
                memset_non_temporal = Some(sym.st_value as usize);
            } else if name == b"__x86_shared_non_temporal_threshold" {
                shared_non_temporal = Some(sym.st_value as usize);
            }

            if libc_thresholds_offsets_complete(
                rep_stosb,
                rep_movsb,
                shared_cache_size,
                shared_cache_half,
                rep_movsb_stop,
                memset_non_temporal,
                shared_non_temporal,
            ) {
                break;
            }
        }

        if libc_thresholds_offsets_complete(
            rep_stosb,
            rep_movsb,
            shared_cache_size,
            shared_cache_half,
            rep_movsb_stop,
            memset_non_temporal,
            shared_non_temporal,
        ) {
            break;
        }
    }

    let offsets = LibcCopyThresholdOffsets {
        rep_stosb: rep_stosb?,
        rep_movsb: rep_movsb?,
        shared_cache_size: shared_cache_size?,
        shared_cache_half: shared_cache_half?,
        rep_movsb_stop: rep_movsb_stop?,
        memset_non_temporal,
        shared_non_temporal: shared_non_temporal?,
    };

    store_libc_thresholds_offsets_cache(path, &offsets);
    Some(offsets)
}

#[cfg(target_arch = "x86_64")]
unsafe fn apply_libc_copy_threshold_patch(base: usize, offsets: &LibcCopyThresholdOffsets) {
    let rep_stosb_ptr = (base.wrapping_add(offsets.rep_stosb)) as *mut usize;
    let rep_movsb_ptr = (base.wrapping_add(offsets.rep_movsb)) as *mut usize;
    let shared_cache_size_ptr = (base.wrapping_add(offsets.shared_cache_size)) as *mut usize;
    let shared_cache_half_ptr = (base.wrapping_add(offsets.shared_cache_half)) as *mut usize;
    let rep_movsb_stop_ptr = (base.wrapping_add(offsets.rep_movsb_stop)) as *mut usize;
    let memset_non_temporal_ptr = offsets
        .memset_non_temporal
        .map(|off| (base.wrapping_add(off)) as *mut usize);
    let shared_non_temporal_ptr = (base.wrapping_add(offsets.shared_non_temporal)) as *mut usize;

    apply_libc_copy_threshold_patch_raw(
        rep_stosb_ptr,
        rep_movsb_ptr,
        shared_cache_size_ptr,
        shared_cache_half_ptr,
        rep_movsb_stop_ptr,
        memset_non_temporal_ptr,
        shared_non_temporal_ptr,
    );
}

#[cfg(target_arch = "x86_64")]
unsafe fn apply_libc_copy_threshold_patch_raw(
    rep_stosb_ptr: *mut usize,
    rep_movsb_ptr: *mut usize,
    shared_cache_size_ptr: *mut usize,
    shared_cache_half_ptr: *mut usize,
    rep_movsb_stop_ptr: *mut usize,
    memset_non_temporal_ptr: Option<*mut usize>,
    shared_non_temporal_ptr: *mut usize,
) {
    let mut shared_cache_size = core::ptr::read_volatile(shared_cache_size_ptr);
    if shared_cache_size < 4096 || shared_cache_size > (1usize << 34) {
        // Conservative fallback if cache probing did not run.
        shared_cache_size = 1 * 1024 * 1024;
    }
    let shared_cache_half = shared_cache_size / 2;
    const REP_THRESHOLD: usize = 2048;

    // Keep memcpy/memset on conservative paths when rtld CPU/cache init has
    // not run (common under custom loaders) to avoid invalid non-temporal
    // probing on boundary mappings.
    core::ptr::write_volatile(rep_stosb_ptr, REP_THRESHOLD);
    core::ptr::write_volatile(rep_movsb_ptr, REP_THRESHOLD);
    core::ptr::write_volatile(rep_movsb_stop_ptr, usize::MAX);
    if let Some(memset_non_temporal_ptr) = memset_non_temporal_ptr {
        core::ptr::write_volatile(memset_non_temporal_ptr, usize::MAX);
    }
    core::ptr::write_volatile(shared_non_temporal_ptr, usize::MAX);
    core::ptr::write_volatile(shared_cache_size_ptr, shared_cache_size);
    core::ptr::write_volatile(shared_cache_half_ptr, shared_cache_half);
}

