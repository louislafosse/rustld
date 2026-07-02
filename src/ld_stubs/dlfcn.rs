use super::*;

type DlsymEntry = unsafe extern "C" fn(*mut c_void, *const u8) -> *mut c_void;
type DlvsymEntry = unsafe extern "C" fn(*mut c_void, *const u8, *const u8) -> *mut c_void;
type DlopenEntry = unsafe extern "C" fn(*const u8, i32) -> *mut c_void;
type DlcloseEntry = unsafe extern "C" fn(*mut c_void) -> i32;
type DlerrorEntry = unsafe extern "C" fn() -> *const c_char;

#[unsafe(no_mangle)]
pub static mut __rustld_dlsym_entry: DlsymEntry = __rustld_dlsym_entry_impl;

#[unsafe(no_mangle)]
pub static mut __rustld_dlvsym_entry: DlvsymEntry = __rustld_dlvsym_entry_impl;

#[unsafe(no_mangle)]
pub static mut __rustld_dlopen_entry: DlopenEntry = __rustld_dlopen_entry_impl;

#[unsafe(no_mangle)]
pub static mut __rustld_dlclose_entry: DlcloseEntry = __rustld_dlclose_entry_impl;

#[unsafe(no_mangle)]
pub static mut __rustld_dlerror_entry: DlerrorEntry = __rustld_dlerror_entry_impl;

/// Emit a public `#[no_mangle]` dlfcn entry point that dispatches through its
/// swappable `__rustld_*_entry` function pointer (read volatile so the guest
/// can rebind it). Preserves the exact C signature.
macro_rules! dl_dispatch {
    (pub fn $name:ident($($arg:ident: $ty:ty),* $(,)?) -> $ret:ty => $entry:ident) => {
        #[unsafe(no_mangle)]
        #[inline(never)]
        pub extern "C" fn $name($($arg: $ty),*) -> $ret {
            let entry = unsafe { core::ptr::read_volatile(core::ptr::addr_of!($entry)) };
            unsafe { entry($($arg),*) }
        }
    };
}

#[unsafe(no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn __rustld_dlsym_entry_impl(
    handle: *mut c_void,
    name: *const u8,
) -> *mut c_void {
    let resolved = dlsym_impl(handle, name);
    #[cfg(debug_assertions)]
    {
        log_dl_symbol("dlsym", name, resolved as usize);
    }
    resolved
}

dl_dispatch!(pub fn dlsym(handle: *mut c_void, name: *const u8) -> *mut c_void => __rustld_dlsym_entry);

#[unsafe(no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn __rustld_dlvsym_entry_impl(
    handle: *mut c_void,
    name_ptr: *const u8,
    version_ptr: *const u8,
) -> *mut c_void {
    let resolved = if version_ptr.is_null() {
        dlsym_impl(handle, name_ptr)
    } else {
        let name = c_string(name_ptr, 512);
        let version = c_string(version_ptr, 128);
        if let (Some(name), Some(ver)) = (name, version) {
            let resolved = resolve_symbol_with_version(handle, name, ver)
                .or_else(|| resolve_symbol_for_handle(handle, name))
                .unwrap_or(core::ptr::null_mut());
            log_suspicious_runtime_symbol("dlvsym", name, resolved as usize);
            resolved
        } else {
            dlsym_impl(handle, name_ptr)
        }
    };
    #[cfg(debug_assertions)]
    {
        log_dl_symbol("dlvsym", name_ptr, resolved as usize);
    }
    resolved
}

dl_dispatch!(pub fn dlvsym(handle: *mut c_void, name: *const u8, version: *const u8) -> *mut c_void => __rustld_dlvsym_entry);

#[unsafe(no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn __rustld_dlopen_entry_impl(file: *const u8, mode: i32) -> *mut c_void {
    #[cfg(debug_assertions)]
    {
        log_dl_symbol("dlopen", file, 0);
    }
    dlopen_impl(file, mode)
}

dl_dispatch!(pub fn dlopen(file: *const u8, mode: i32) -> *mut c_void => __rustld_dlopen_entry);

#[unsafe(no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn __rustld_dlclose_entry_impl(_handle: *mut c_void) -> i32 {
    clear_dlerror();
    0
}

dl_dispatch!(pub fn dlclose(handle: *mut c_void) -> i32 => __rustld_dlclose_entry);

#[unsafe(no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn __rustld_dlerror_entry_impl() -> *const c_char {
    unsafe {
        if DLERROR_PENDING {
            DLERROR_PENDING = false;
            core::ptr::addr_of!(DLERROR_BUF).cast::<c_char>()
        } else {
            core::ptr::null()
        }
    }
}

dl_dispatch!(pub fn dlerror() -> *const c_char => __rustld_dlerror_entry);

#[repr(C)]
struct DlPhdrInfo {
    dlpi_addr: usize,
    dlpi_name: *const c_char,
    dlpi_phdr: *const ProgramHeader,
    dlpi_phnum: u16,
    dlpi_adds: u64,
    dlpi_subs: u64,
    dlpi_tls_modid: usize,
    dlpi_tls_data: *mut c_void,
}

type DlIteratePhdrCallback = extern "C" fn(*mut c_void, usize, *mut c_void) -> i32;

#[unsafe(no_mangle)]
pub extern "C" fn dl_iterate_phdr(
    callback: Option<DlIteratePhdrCallback>,
    data: *mut c_void,
) -> i32 {
    const EMPTY_NAME: *const c_char = b"\0".as_ptr().cast::<c_char>();

    let Some(callback) = callback else {
        return 0;
    };

    let _guard = lock_rtld_ops();
    let linker = unsafe { linking::active_linker() };
    let Some(linker) = linker else {
        return 0;
    };

    // Use stable names so callbacks may retain dlpi_name pointers after return.
    let dlpi_adds = linker.objects.len() as u64;

    for idx in 0..linker.objects.len() {
        let object = &linker.objects[idx];
        let ehdr = object.map_start as *const ElfHeader;
        if ehdr.is_null() {
            continue;
        }

        let ident = unsafe { (*ehdr).e_ident };
        if ident[..4] != [0x7f, b'E', b'L', b'F'] {
            continue;
        }

        let phdr =
            object.map_start.wrapping_add(unsafe { (*ehdr).e_phoff }) as *const ProgramHeader;
        let phnum = unsafe { (*ehdr).e_phnum };
        if phdr.is_null() || phnum == 0 {
            continue;
        }

        let name_ptr = if idx == 0 {
            EMPTY_NAME
        } else {
            let ptr = linker.object_link_map_name_ptr(idx);
            if ptr.is_null() {
                EMPTY_NAME
            } else {
                ptr
            }
        };

        let tls_modid = object.tls.map(|tls| tls.module_id).unwrap_or(0);
        let mut info = DlPhdrInfo {
            dlpi_addr: object.base,
            dlpi_name: name_ptr,
            dlpi_phdr: phdr,
            dlpi_phnum: phnum,
            dlpi_adds,
            dlpi_subs: 0,
            dlpi_tls_modid: tls_modid,
            dlpi_tls_data: core::ptr::null_mut(),
        };

        let result = callback(
            core::ptr::addr_of_mut!(info).cast(),
            size_of::<DlPhdrInfo>(),
            data,
        );
        if result != 0 {
            return result;
        }
    }

    0
}

#[repr(C)]
pub(crate) struct DlInfo {
    dli_fname: *const c_char,
    dli_fbase: *mut c_void,
    dli_sname: *const c_char,
    dli_saddr: *mut c_void,
}

const RTLD_DL_SYMENT: i32 = 1;
const RTLD_DL_LINKMAP: i32 = 2;

unsafe fn resolve_dladdr(addr: usize, info: *mut DlInfo) -> Option<(usize, *const Symbol)> {
    if info.is_null() {
        return None;
    }

    let linker = linking::active_linker()?;
    let index = linker.object_for_address(addr)?;
    let object = linker.objects.get(index)?;

    let mut symbol_name_ptr = core::ptr::null::<c_char>();
    let mut symbol_addr = core::ptr::null_mut();
    let mut symbol_ptr = core::ptr::null();
    // `None` until a candidate matches, so a symbol at address 0 is not
    // indistinguishable from "no match yet".
    let mut best_match: Option<usize> = None;

    let symbol_table_ptr = object.symbol_table.as_ptr();
    if !symbol_table_ptr.is_null() && object.symbol_count != 0 {
        for sym_idx in 0..object.symbol_count {
            let sym_ptr = symbol_table_ptr.add(sym_idx);
            let sym = *sym_ptr;
            if sym.st_name == 0 || sym.st_shndx == 0 {
                continue;
            }

            let sym_base = if sym.st_shndx == SHN_ABS {
                0
            } else {
                object.base
            };
            let sym_start = sym_base.wrapping_add(sym.st_value);
            let matches = if sym.st_size == 0 {
                addr == sym_start
            } else {
                let sym_end = sym_start.wrapping_add(sym.st_size);
                addr >= sym_start && addr < sym_end
            };
            if !matches || best_match.is_some_and(|best| sym_start < best) {
                continue;
            }

            let sym_name = object.string_table.get_bytes(sym.st_name as usize);
            if sym_name.is_empty() {
                continue;
            }

            best_match = Some(sym_start);
            symbol_name_ptr = sym_name.as_ptr().cast::<c_char>();
            symbol_addr = sym_start as *mut c_void;
            symbol_ptr = sym_ptr;
        }
    }

    let mut file_name = linker.object_link_map_name_ptr(index);
    if file_name.is_null() {
        file_name = b"\0".as_ptr().cast::<c_char>();
    }

    (*info).dli_fname = file_name;
    (*info).dli_fbase = object.base as *mut c_void;
    (*info).dli_sname = symbol_name_ptr;
    (*info).dli_saddr = symbol_addr;

    Some((index, symbol_ptr))
}

#[no_mangle]
pub extern "C" fn dladdr(addr: *const c_void, info: *mut DlInfo) -> i32 {
    if addr.is_null() || info.is_null() {
        return 0;
    }

    let _guard = lock_rtld_ops();
    unsafe {
        core::ptr::write_bytes(info.cast::<u8>(), 0, size_of::<DlInfo>());
        resolve_dladdr(addr as usize, info).is_some() as i32
    }
}

#[no_mangle]
pub extern "C" fn dladdr1(
    addr: *const c_void,
    info: *mut DlInfo,
    extra_info: *mut *mut c_void,
    flags: i32,
) -> i32 {
    if addr.is_null() || info.is_null() {
        return 0;
    }

    let _guard = lock_rtld_ops();
    unsafe {
        core::ptr::write_bytes(info.cast::<u8>(), 0, size_of::<DlInfo>());
        let Some((index, sym_ptr)) = resolve_dladdr(addr as usize, info) else {
            if !extra_info.is_null() {
                *extra_info = core::ptr::null_mut();
            }
            return 0;
        };

        if !extra_info.is_null() {
            *extra_info = match flags {
                RTLD_DL_LINKMAP => linking::active_linker()
                    .map(|linker| linker.object_link_map_ptr(index))
                    .unwrap_or(core::ptr::null_mut()),
                RTLD_DL_SYMENT => sym_ptr.cast_mut().cast::<c_void>(),
                _ => core::ptr::null_mut(),
            };
        }

        1
    }
}

pub(crate) fn clear_dlerror() {
    unsafe {
        DLERROR_PENDING = false;
    }
}

fn set_dlerror(msg: &str) {
    unsafe {
        let bytes = msg.as_bytes();
        let n = bytes.len().min(DLERROR_BUF_SIZE.saturating_sub(1));
        if n != 0 {
            core::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                core::ptr::addr_of_mut!(DLERROR_BUF).cast::<u8>(),
                n,
            );
        }
        core::ptr::write(core::ptr::addr_of_mut!(DLERROR_BUF).cast::<u8>().add(n), 0);
        DLERROR_PENDING = true;
    }
}

#[inline(never)]
pub(crate) fn c_string<'a>(ptr: *const u8, max_len: usize) -> Option<&'a str> {
    if ptr.is_null() || max_len == 0 {
        return None;
    }

    let mut idx = 0usize;
    while idx < max_len {
        let ch = unsafe { core::ptr::read_volatile(ptr.add(idx)) };
        if ch == 0 {
            break;
        }
        idx += 1;
    }

    // Reject empty strings and unterminated buffers.
    if idx == 0 || idx >= max_len {
        return None;
    }

    let bytes = unsafe { core::slice::from_raw_parts(ptr, idx) };
    core::str::from_utf8(bytes).ok()
}

#[inline(never)]
unsafe fn resolve_symbol_with_version(
    handle: *mut c_void,
    name: &str,
    version: &str,
) -> Option<*mut c_void> {
    let mut combined = [0u8; 768];
    let required = name.len().saturating_add(1).saturating_add(version.len());
    if required == 0 || required > combined.len() {
        return None;
    }

    let mut cursor = 0usize;
    combined[cursor..cursor + name.len()].copy_from_slice(name.as_bytes());
    cursor += name.len();
    combined[cursor] = b'@';
    cursor += 1;
    combined[cursor..cursor + version.len()].copy_from_slice(version.as_bytes());
    cursor += version.len();

    let Ok(combined_name) = core::str::from_utf8(&combined[..cursor]) else {
        return None;
    };
    resolve_symbol_for_handle(handle, combined_name)
}

const HANDLE_GLOBAL_SCOPE: usize = 1;
const HANDLE_OBJECT_BIAS: usize = 2;

enum DlHandle {
    GlobalScope,
    NextScope,
    Object(usize),
}

fn encode_global_handle() -> *mut c_void {
    HANDLE_GLOBAL_SCOPE as *mut c_void
}

fn encode_object_handle(idx: usize) -> *mut c_void {
    if let Some(linker) = unsafe { linking::active_linker() } {
        let map = linker.object_link_map_ptr(idx);
        if !map.is_null() {
            return map;
        }
    }
    // Backward-compatible fallback if no link_map is available.
    idx.wrapping_add(HANDLE_OBJECT_BIAS) as *mut c_void
}

fn decode_handle(handle: *mut c_void) -> Option<DlHandle> {
    let raw = handle as usize;
    if raw == 0 {
        // RTLD_DEFAULT (NULL): search global scope.
        return None;
    }
    if raw == usize::MAX {
        // RTLD_NEXT ((void*)-1): search from the next object in scope.
        return Some(DlHandle::NextScope);
    }
    if raw == HANDLE_GLOBAL_SCOPE {
        return Some(DlHandle::GlobalScope);
    }

    // Preferred encoding: real link_map pointer (glibc-compatible).
    if let Some(linker) = unsafe { linking::active_linker() } {
        if let Some(idx) = linker.object_index_for_link_map_ptr(handle.cast_const()) {
            return Some(DlHandle::Object(idx));
        }

        // Legacy synthetic integer handles from older builds.
        if let Some(idx) = raw.checked_sub(HANDLE_OBJECT_BIAS) {
            if idx < linker.objects.len() {
                return Some(DlHandle::Object(idx));
            }
        }
    }

    None
}

#[inline(never)]
unsafe fn resolve_symbol_for_handle(handle: *mut c_void, name: &str) -> Option<*mut c_void> {
    let resolve_global = |exclude: Option<usize>| {
        let linker = linking::active_linker()?;
        let resolve_name = |candidate: &str| {
            linker
                .lookup_symbol_excluding(candidate, exclude)
                .map(|(obj_idx, symbol)| {
                    let base = if symbol.st_shndx == SHN_ABS {
                        0
                    } else {
                        linker.get_base(obj_idx)
                    };
                    base.wrapping_add(symbol.st_value) as *mut c_void
                })
        };
        resolve_name(name).or_else(|| {
            name.split_once('@')
                .and_then(|(base_name, _)| resolve_name(base_name))
        })
    };

    match decode_handle(handle) {
        Some(DlHandle::GlobalScope) => {
            linking::lookup_active_symbol(name).map(|addr| addr as *mut c_void)
        }
        Some(DlHandle::NextScope) => {
            // We do not know the exact caller object here. Skipping the
            // main executable approximates RTLD_NEXT well enough for common
            // interposer paths used by large apps (e.g. Firefox launcher).
            resolve_global(Some(0))
                .or_else(|| linking::lookup_active_symbol(name).map(|addr| addr as *mut c_void))
        }
        Some(DlHandle::Object(idx)) => {
            let resolve_in_object = |candidate: &str| {
                let linker = linking::active_linker()?;
                linker
                    .lookup_symbol_in_object_scope(idx, candidate)
                    .map(|addr| addr as *mut c_void)
            };
            if let Some(addr) = resolve_in_object(name).or_else(|| {
                name.split_once('@')
                    .and_then(|(base_name, _)| resolve_in_object(base_name))
            }) {
                return Some(addr);
            }
            None
        }
        None => linking::lookup_active_symbol(name).map(|addr| addr as *mut c_void),
    }
}

#[inline(never)]
fn dlsym_impl(handle: *mut c_void, name_ptr: *const u8) -> *mut c_void {
    let _guard = lock_rtld_ops();
    clear_dlerror();
    let Some(name) = c_string(name_ptr, 512) else {
        set_dlerror("rustld: dlsym invalid symbol name");
        return core::ptr::null_mut();
    };

    unsafe {
        if let Some(addr) = resolve_symbol_for_handle(handle, &name) {
            log_suspicious_runtime_symbol("dlsym", &name, addr as usize);
            return addr;
        }
    }

    set_dlerror("rustld: dlsym symbol not found");
    core::ptr::null_mut()
}

fn log_suspicious_runtime_symbol(api: &str, name: &str, resolved: usize) {
    #[cfg(not(debug_assertions))]
    {
        let _ = (api, name, resolved);
        return;
    }

    #[cfg(debug_assertions)]
    unsafe {
        use crate::libc::fs::write;

        if let Some(linker) = linking::active_linker() {
            for (idx, object) in linker.objects.iter().enumerate() {
                let base = object.base;
                if resolved >= base && resolved.wrapping_sub(base) < 0x100 {
                    write::write_str(write::STD_ERR, "rustld: suspicious ");
                    write::write_str(write::STD_ERR, api);
                    write::write_str(write::STD_ERR, " ");
                    write::write_str(write::STD_ERR, name);
                    write::write_str(write::STD_ERR, " -> ");
                    write_hex(resolved);
                    write::write_str(write::STD_ERR, " object=");

                    let mut idx_buf = [0u8; 32];
                    let mut value = idx;
                    let mut len = 0usize;
                    if value == 0 {
                        idx_buf[0] = b'0';
                        len = 1;
                    } else {
                        while value > 0 {
                            idx_buf[len] = b'0' + (value % 10) as u8;
                            value /= 10;
                            len += 1;
                        }
                    }
                    for i in 0..len / 2 {
                        idx_buf.swap(i, len - 1 - i);
                    }
                    let idx_text = core::str::from_utf8_unchecked(&idx_buf[..len]);
                    write::write_str(write::STD_ERR, idx_text);

                    write::write_str(write::STD_ERR, " base=");
                    write_hex(base);
                    write::write_str(write::STD_ERR, "\n");
                    break;
                }
            }
        }
    }
}

#[inline(never)]
fn dlopen_impl(file_ptr: *const u8, _mode: i32) -> *mut c_void {
    let _guard = lock_rtld_ops();
    clear_dlerror();
    seed_current_glibc_thread_locale();

    if file_ptr.is_null() {
        // glibc returns a handle for the main program on dlopen(NULL, ...).
        if let Some(linker) = unsafe { linking::active_linker() } {
            let main_map = linker.object_link_map_ptr(0);
            if !main_map.is_null() {
                return main_map;
            }
        }
        return encode_global_handle();
    }

    let Some(file) = c_string(file_ptr, 4096) else {
        set_dlerror("rustld: dlopen invalid file name");
        return core::ptr::null_mut();
    };

    let linker = unsafe { linking::active_linker_mut() };
    let Some(linker) = linker else {
        set_dlerror("rustld: dlopen no active linker");
        return core::ptr::null_mut();
    };

    #[cfg(debug_assertions)]
    {
        use crate::libc::fs::write;
        unsafe {
            write::write_str(write::STD_ERR, "ld_stub: dlopen request ");
            write::write_str(write::STD_ERR, &file);
            write::write_str(write::STD_ERR, "\n");
        }
        if let Some(idx) = linker.loaded_index(&file) {
            unsafe {
                write::write_str(write::STD_ERR, "ld_stub: dlopen already loaded idx=");
            }
            let mut buf = [0u8; 32];
            let mut n = idx;
            let mut len = 0usize;
            if n == 0 {
                buf[0] = b'0';
                len = 1;
            } else {
                while n > 0 {
                    buf[len] = b'0' + (n % 10) as u8;
                    n /= 10;
                    len += 1;
                }
                buf[..len].reverse();
            }
            unsafe {
                write::write_str(
                    write::STD_ERR,
                    core::str::from_utf8(&buf[..len]).unwrap_or("?"),
                );
                write::write_str(write::STD_ERR, "\n");
            }
        } else {
            unsafe {
                write::write_str(write::STD_ERR, "ld_stub: dlopen not in map yet\n");
            }
        }
    }

    let result = unsafe { linker.dlopen_runtime(&file, _mode) };
    match result {
        Ok(idx) => encode_object_handle(idx),
        Err(msg) => {
            set_dlerror(msg);
            core::ptr::null_mut()
        }
    }
}

#[cfg(debug_assertions)]
fn log_dl_symbol(prefix: &str, symbol: *const u8, resolved: usize) {
    use core::str;
    unsafe {
        write::write_str(write::STD_ERR, "ld_stub: ");
        write::write_str(write::STD_ERR, prefix);
        write::write_str(write::STD_ERR, " ");
    }
    if symbol.is_null() {
        unsafe { write::write_str(write::STD_ERR, "<null>\n") };
        return;
    }

    let mut len = 0usize;
    while len < 128 {
        let byte = unsafe { *symbol.add(len) };
        if byte == 0 {
            break;
        }
        len += 1;
    }
    if len == 0 {
        unsafe { write::write_str(write::STD_ERR, "<empty>\n") };
        return;
    }

    let bytes = unsafe { core::slice::from_raw_parts(symbol, len) };
    if let Ok(text) = str::from_utf8(bytes) {
        unsafe {
            write::write_str(write::STD_ERR, text);
            write::write_str(write::STD_ERR, " -> ");
            write_hex(resolved);
            write::write_str(write::STD_ERR, "\n");
        }
    } else {
        unsafe { write::write_str(write::STD_ERR, "<non-utf8>\n") };
    }
}

#[cfg(debug_assertions)]
unsafe fn write_hex(mut value: usize) {
    let mut buf = [0u8; 18];
    buf[0] = b'0';
    buf[1] = b'x';
    let hex = b"0123456789abcdef";
    for i in (0..16).rev() {
        buf[2 + i] = hex[value & 0xF];
        value >>= 4;
    }
    write::write_str(write::STD_ERR, core::str::from_utf8_unchecked(&buf));
}
