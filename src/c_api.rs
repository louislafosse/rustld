use crate::{
    runtime_loader::ElfLoader,
    start::auxiliary_vector::{AuxiliaryVectorItem, AuxiliaryVectorUnion},
};
use core::ffi::c_char;
use std::ffi::CStr;

pub const RUSTLD_OK: i32 = 0;
pub const RUSTLD_EINVAL: i32 = 1;
pub const RUSTLD_EPANIC: i32 = 2;
pub const RUSTLD_EIO: i32 = 3;

#[repr(C)]
pub struct RustLdJumpInfo {
    pub entry: usize,
    pub stack: usize,
}

#[repr(C)]
pub struct RustLdAuxvItem {
    pub a_type: usize,
    pub a_val: usize,
}

unsafe fn parse_argv(argc: usize, argv: *const *const c_char) -> Option<Vec<String>> {
    if argc == 0 || argv.is_null() {
        return None;
    }

    let mut out = Vec::with_capacity(argc);
    for idx in 0..argc {
        let arg_ptr = *argv.add(idx);
        if arg_ptr.is_null() {
            return None;
        }
        // C argv is bytes; accept non-UTF8 by lossily converting for Rust API.
        let arg = CStr::from_ptr(arg_ptr).to_string_lossy().into_owned();
        out.push(arg);
    }
    Some(out)
}

unsafe fn parse_auxv(
    auxv: *const RustLdAuxvItem,
    auxv_len: usize,
) -> Option<Vec<AuxiliaryVectorItem>> {
    if auxv.is_null() || auxv_len == 0 {
        return None;
    }

    let mut out = Vec::with_capacity(auxv_len);
    for idx in 0..auxv_len {
        let item = auxv.add(idx).read();
        out.push(AuxiliaryVectorItem {
            a_type: item.a_type,
            a_un: AuxiliaryVectorUnion { a_val: item.a_val },
        });
    }
    Some(out)
}

/// Returns the host `environ` pointer used by default when `envp == NULL`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rustld_host_environment_pointer() -> *mut *mut c_char {
    crate::host_environment_pointer() as *mut *mut c_char
}

/// C ABI wrapper over `ElfLoader::prepare_from_bytes`.
///
/// Does not jump; returns `RustLdJumpInfo` entry/stack for a later handoff.
/// - `envp == NULL`: reuse parent environment.
/// - `auxv == NULL` / `auxv_len == 0`: reuse parent auxv.
/// - `indirect_syscalls != 0`: route all syscalls through an anonymous RX
///   trampoline page so the syscall opcode never appears in the loader image
///   (x86_64: `0x0F 0x05`, aarch64: `0xD4000001`). Pass 0 for direct syscalls.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rustld_elfloader_prepare_from_bytes(
    elf_bytes: *const u8,
    elf_len: usize,
    argc: usize,
    argv: *const *const c_char,
    envp: *const *const c_char,
    auxv: *const RustLdAuxvItem,
    auxv_len: usize,
    verbose: i32,
    indirect_syscalls: i32,
    out_jump: *mut RustLdJumpInfo,
) -> i32 {
    if elf_bytes.is_null() || elf_len == 0 || out_jump.is_null() {
        return RUSTLD_EINVAL;
    }

    let result = std::panic::catch_unwind(|| unsafe {
        let args = parse_argv(argc, argv).ok_or(RUSTLD_EINVAL)?;
        let bytes = core::slice::from_raw_parts(elf_bytes, elf_len);
        let auxv_vec = parse_auxv(auxv, auxv_len);
        let auxv_override = auxv_vec.as_deref();
        let env_override = if envp.is_null() {
            None
        } else {
            Some(envp as *const *const u8)
        };

        let loader = ElfLoader {
            indirect_syscalls: indirect_syscalls != 0,
        };
        let jump =
            loader.prepare_from_bytes(bytes, args, env_override, auxv_override, verbose != 0);

        (*out_jump).entry = jump.entry;
        (*out_jump).stack = jump.stack;
        Ok::<(), i32>(())
    });

    match result {
        Ok(Ok(())) => RUSTLD_OK,
        Ok(Err(code)) => code,
        Err(_) => RUSTLD_EPANIC,
    }
}

/// C ABI wrapper over `ElfLoader::execute_from_bytes`.
///
/// Returns only on error; on success transfers control to target entrypoint.
/// - `indirect_syscalls != 0`: trampoline mode — syscall opcode hidden from
///   image (x86_64: `0x0F 0x05`, aarch64: `0xD4000001`). Pass 0 for direct.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rustld_elfloader_execute_from_bytes(
    elf_bytes: *const u8,
    elf_len: usize,
    argc: usize,
    argv: *const *const c_char,
    envp: *const *const c_char,
    auxv: *const RustLdAuxvItem,
    auxv_len: usize,
    verbose: i32,
    indirect_syscalls: i32,
) -> i32 {
    if elf_bytes.is_null() || elf_len == 0 {
        return RUSTLD_EINVAL;
    }

    let args = match parse_argv(argc, argv) {
        Some(value) => value,
        None => return RUSTLD_EINVAL,
    };
    let bytes = core::slice::from_raw_parts(elf_bytes, elf_len);
    let auxv_vec = parse_auxv(auxv, auxv_len);
    let auxv_override = auxv_vec.as_deref();
    let env_override = if envp.is_null() {
        None
    } else {
        Some(envp as *const *const u8)
    };
    let loader = ElfLoader {
        indirect_syscalls: indirect_syscalls != 0,
    };
    let result = std::panic::catch_unwind(|| unsafe {
        loader.execute_from_bytes(bytes, args, env_override, auxv_override, verbose != 0);
    });

    match result {
        Ok(()) => RUSTLD_EIO,
        Err(_) => RUSTLD_EPANIC,
    }
}

/// C ABI wrapper over `ElfLoader::execute_from_bytes_with_entry`.
///
/// Pass either `entry_symbol` (non-null) or `entry_address_is_set != 0`, not both.
/// Returns only on error; on success transfers control to selected entrypoint.
/// - `indirect_syscalls != 0`: trampoline mode — syscall opcode hidden from
///   image (x86_64: `0x0F 0x05`, aarch64: `0xD4000001`). Pass 0 for direct.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rustld_elfloader_execute_from_bytes_with_entry(
    elf_bytes: *const u8,
    elf_len: usize,
    argc: usize,
    argv: *const *const c_char,
    entry_symbol: *const c_char,
    entry_address: usize,
    entry_address_is_set: i32,
    envp: *const *const c_char,
    auxv: *const RustLdAuxvItem,
    auxv_len: usize,
    verbose: i32,
    indirect_syscalls: i32,
) -> i32 {
    if elf_bytes.is_null() || elf_len == 0 {
        return RUSTLD_EINVAL;
    }

    let args = match parse_argv(argc, argv) {
        Some(value) => value,
        None => return RUSTLD_EINVAL,
    };
    let bytes = core::slice::from_raw_parts(elf_bytes, elf_len);
    let auxv_vec = parse_auxv(auxv, auxv_len);
    let auxv_override = auxv_vec.as_deref();
    let env_override = if envp.is_null() {
        None
    } else {
        Some(envp as *const *const u8)
    };
    let symbol_override = if entry_symbol.is_null() {
        None
    } else {
        match CStr::from_ptr(entry_symbol).to_str() {
            Ok(value) if !value.is_empty() => Some(value),
            _ => return RUSTLD_EINVAL,
        }
    };
    let address_override = if entry_address_is_set != 0 {
        Some(entry_address)
    } else {
        None
    };

    if symbol_override.is_some() && address_override.is_some() {
        return RUSTLD_EINVAL;
    }

    let result = std::panic::catch_unwind(|| unsafe {
        let loader = ElfLoader {
            indirect_syscalls: indirect_syscalls != 0,
        };
        loader.execute_from_bytes_with_entry(
            bytes,
            args,
            symbol_override,
            address_override,
            env_override,
            auxv_override,
            verbose != 0,
        );
    });

    match result {
        Ok(()) => RUSTLD_EIO,
        Err(_) => RUSTLD_EPANIC,
    }
}
