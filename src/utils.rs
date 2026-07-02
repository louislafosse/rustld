use core::cmp::{max, min};

use memchr::memchr;

use crate::{
    arch,
    elf::program_header::{ProgramHeader, PT_LOAD},
    page_size,
};

pub fn round_up_to_boundary(address: usize, boundary: usize) -> usize {
    boundary * address.div_ceil(boundary)
}

/// Page-aligned [min, max) virtual address span covering the PT_LOAD segments.
pub fn calculate_virtual_address_bounds(program_header_table: &[ProgramHeader]) -> (usize, usize) {
    let mut min_addr = usize::MAX;
    let mut max_addr = 0;

    for header in program_header_table {
        if header.p_type != PT_LOAD {
            continue;
        }
        let start = header.p_vaddr;
        let end = start.wrapping_add(header.p_memsz);
        min_addr = min(min_addr, start);
        max_addr = max(max_addr, end);
    }

    (
        page_size::get_page_start(min_addr),
        page_size::get_page_end(max_addr),
    )
}

/// Match a symbol table name against a request, treating a `name@version`
/// candidate as equal to the unversioned `name`.
#[inline(always)]
pub fn symbol_name_matches_bytes(candidate: &[u8], requested: &[u8]) -> bool {
    if candidate.len() == requested.len() {
        return candidate == requested;
    }
    candidate.len() > requested.len()
        && candidate[requested.len()] == b'@'
        && &candidate[..requested.len()] == requested
}

/// Return the portion of a symbol name before any `@version` suffix.
#[inline(always)]
pub fn strip_version_suffix(name: &str) -> &str {
    match memchr(b'@', name.as_bytes()) {
        Some(idx) => &name[..idx],
        None => name,
    }
}

#[inline(always)]
pub fn running_under_valgrind() -> bool {
    arch::running_under_valgrind()
}

#[inline(always)]
pub fn skip_selinux_ctors() -> bool {
    running_under_valgrind() || cfg!(target_arch = "aarch64")
}

/// Fill `buf[..len]` with kernel randomness, returning false on any failure.
pub unsafe fn fill_random_bytes(buf: *mut u8, len: usize) -> bool {
    let mut filled = 0usize;
    while filled < len {
        let ret = arch::getrandom(buf.add(filled), len - filled);
        if ret <= 0 {
            return false;
        }
        filled += ret as usize;
    }
    true
}
