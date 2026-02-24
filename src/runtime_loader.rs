#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
use crate::ld_stubs::_dl_fini;
use crate::{
    arch, page_size,
    start::{
        self,
        auxiliary_vector::{
            AuxiliaryVectorItem, AT_HWCAP, AT_HWCAP2, AT_MINSIGSTKSZ, AT_PAGE_SIZE, AT_RANDOM,
        },
        JumpInfo,
    },
};
use core::ptr::null;
use std::ffi::CString;

pub use crate::start::auxiliary_vector;
pub use crate::start::auxiliary_vector::AuxiliaryVectorItem as AuxvItem;
use crate::AuxiliaryVectorIter;

/// Returns the current process environment pointer (`environ`).
///
/// The high-level `ElfLoader` API inherits target environment from this
/// parent process pointer.
///
/// # Safety
///
/// The returned raw pointer follows libc conventions and must be treated as
/// borrowed process-global state.
pub unsafe fn host_environment_pointer() -> *mut *mut u8 {
    crate::libc::environ::host_environment_pointer()
}

struct RuntimeMetadata {
    page_size: usize,
    hwcap: usize,
    hwcap2: usize,
    minsigstacksize: usize,
    pseudorandom_bytes: *const [u8; 16],
}

/// High-level runtime loader entrypoints.
///
/// `ElfLoader` prepares an ELF image, reconstructs the target startup context
/// (stack/auxv/env), and transfers control to the loaded entry point.
pub struct ElfLoader;

impl ElfLoader {
    /// Prepares a target ELF image and returns jump metadata.
    ///
    /// This does not jump to the target entry. It performs loading work and
    /// returns `JumpInfo { entry, stack }` for a later handoff.
    ///
    /// `target_argv` must contain the target argv list (`argv[0]` = target
    /// path/binary name). The loader converts it into a C argv pointer array
    /// internally.
    ///
    /// `env_pointer` and `auxv_template` are optional overrides:
    ///
    /// - `None` uses parent process environment/auxv (default behavior).
    /// - `Some(...)` uses the provided value.
    ///
    /// To adjust environment in the default mode, set variables in the parent
    /// process before calling this API (e.g. `std::env::set_var`).
    ///
    /// # Safety
    ///
    /// This performs raw pointer based loader setup internally.
    #[inline(always)]
    pub unsafe fn prepare_from_bytes(
        elf_bytes: &[u8],
        target_argv: Vec<String>,
        env_pointer: Option<*const *const u8>,
        auxv_template: Option<&[AuxiliaryVectorItem]>,
        verbose: bool,
    ) -> JumpInfo {
        if target_argv.is_empty() {
            eprintln!("Error: target argv cannot be empty");
            std::process::exit(1);
        }

        let argv_storage: Vec<CString> = target_argv
            .iter()
            .map(|arg| match CString::new(arg.as_bytes()) {
                Ok(value) => value,
                Err(_) => {
                    eprintln!("Error: target argument contains embedded NUL byte");
                    std::process::exit(1);
                }
            })
            .collect();
        // The rebuilt target stack stores raw pointers to argv strings.
        // Keep argv backing storage alive for process lifetime.
        let argv_storage = Box::leak(argv_storage.into_boxed_slice());
        let target_argc = argv_storage.len();
        let mut argv_ptrs: Vec<*const u8> = argv_storage
            .iter()
            .map(|value| value.as_ptr() as *const u8)
            .collect();
        argv_ptrs.push(core::ptr::null());
        let target_argv = argv_ptrs.as_ptr();

        let parent_env_pointer: *const *const u8 = host_environment_pointer() as *const *const u8;
        if parent_env_pointer.is_null() && (env_pointer.is_none() || auxv_template.is_none()) {
            eprintln!("Error: host environment pointer is null");
            std::process::exit(1);
        }

        let env_pointer = env_pointer.unwrap_or(parent_env_pointer);
        if env_pointer.is_null() {
            eprintln!("Error: effective environment pointer is null");
            std::process::exit(1);
        }

        let derived_auxv;
        let auxv_template = if let Some(auxv) = auxv_template {
            auxv
        } else {
            derived_auxv = AuxiliaryVectorIter::from_env_pointer(parent_env_pointer)
                .collect::<Vec<AuxiliaryVectorItem>>();
            &derived_auxv
        };

        let metadata = derive_runtime_metadata(auxv_template);
        page_size::set_page_size(metadata.page_size);

        start::execute_elf_from_bytes(
            elf_bytes,
            target_argc,
            target_argv,
            env_pointer,
            metadata.pseudorandom_bytes,
            metadata.minsigstacksize,
            metadata.hwcap,
            metadata.hwcap2,
            auxv_template,
            verbose,
        )
    }

    /// Executes a target ELF and jumps to its entry point.
    ///
    /// `env_pointer` and `auxv_template` are optional overrides:
    ///
    /// - `None` uses parent process environment/auxv (default behavior).
    /// - `Some(...)` uses the provided value.
    ///
    /// To adjust environment in default mode, set variables in the parent
    /// process before calling this API (e.g. `std::env::set_var`).
    ///
    /// This calls `prepare_from_bytes` and immediately jumps to the loaded
    /// target entry.
    ///
    /// ## Safety
    ///
    /// This transfers execution to foreign code and never returns.
    ///
    #[inline(always)]
    pub unsafe fn execute_from_bytes(
        elf_bytes: &[u8],
        target_argv: Vec<String>,
        env_pointer: Option<*const *const u8>,
        auxv_template: Option<&[AuxiliaryVectorItem]>,
        verbose: bool,
    ) -> ! {
        let start_time = if verbose {
            Some(std::time::Instant::now())
        } else {
            None
        };

        let jump =
            Self::prepare_from_bytes(elf_bytes, target_argv, env_pointer, auxv_template, verbose);

        if verbose {
            let elapsed =
                start_time.map_or_else(|| std::time::Duration::from_secs(0), |t| t.elapsed());
            eprintln!(
                "rustld: loading completed in: {:.3}ms",
                elapsed.as_secs_f64() * 1000.0
            );
        }

        jump_to_loaded_entry(jump);
    }
}

#[inline(always)]
unsafe fn jump_to_loaded_entry(jump: JumpInfo) -> ! {
    #[cfg(debug_assertions)]
    {
        println!(
            "Jumping to target entry at {:#x} with stack {:#x}",
            jump.entry, jump.stack
        );
    }
    arch::jump_to_entry(jump.entry, jump.stack, _dl_fini as usize)
}

unsafe fn derive_runtime_metadata(auxv_template: &[AuxiliaryVectorItem]) -> RuntimeMetadata {
    let mut page_size_value = 0usize;
    let mut hwcap = 0usize;
    let mut hwcap2 = 0usize;
    let mut minsigstacksize = 0usize;
    let mut parent_random = null::<u8>();

    for value in auxv_template {
        match value.a_type {
            AT_PAGE_SIZE => page_size_value = value.a_un.a_val,
            AT_HWCAP => hwcap = value.a_un.a_val,
            AT_HWCAP2 => hwcap2 = value.a_un.a_val,
            AT_MINSIGSTKSZ => minsigstacksize = value.a_un.a_val,
            AT_RANDOM => parent_random = value.a_un.a_ptr as *const u8,
            _ => {}
        }
    }

    if page_size_value == 0 || !page_size_value.is_power_of_two() {
        page_size_value = 4096;
    }

    let pseudorandom_bytes = if parent_random.is_null() {
        let leaked_random = Box::leak(Box::new([0u8; 16]));
        let _ = fill_random_bytes(leaked_random.as_mut_ptr(), leaked_random.len());
        leaked_random as *const [u8; 16]
    } else {
        parent_random as *const [u8; 16]
    };

    RuntimeMetadata {
        page_size: page_size_value,
        hwcap,
        hwcap2,
        minsigstacksize,
        pseudorandom_bytes,
    }
}

unsafe fn fill_random_bytes(buf: *mut u8, len: usize) -> bool {
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
