use auxiliary_vector::{
    AuxiliaryVectorItem, AuxiliaryVectorUnion, AT_BASE, AT_BASE_PLATFORM, AT_ENTRY, AT_EXECFN,
    AT_HWCAP, AT_HWCAP2, AT_MINSIGSTKSZ, AT_NULL, AT_PAGE_SIZE, AT_PHDR, AT_PHENT, AT_PHNUM,
    AT_PLATFORM, AT_RANDOM,
};
use smallvec::SmallVec;

use crate::{
    arch,
    elf::{
        header::{ElfHeader, ET_DYN, ET_EXEC},
        program_header::{ProgramHeader, PT_DYNAMIC, PT_INTERP, PT_LOAD, PT_PHDR},
        relocate::Relocatable,
    },
    linking::{self, DynamicLinker},
    page_size,
    shared_object::SharedObject,
    syscall::{
        exit,
        mmap::{
            mmap, MAP_ANONYMOUS, MAP_FIXED, MAP_PRIVATE, MAP_STACK, PROT_EXEC, PROT_READ,
            PROT_WRITE,
        },
        relocation,
    },
    tls,
    utils::{
        calculate_virtual_address_bounds, fill_random_bytes, running_under_valgrind,
        skip_selinux_ctors,
    },
};
use std::{
    ffi::c_char,
    ffi::{c_void, CStr, CString},
    mem::size_of,
    ptr::{null, null_mut},
    slice,
};

pub mod auxiliary_vector;
#[cfg(target_arch = "x86_64")]
mod libc_thresholds;
mod musl;

use musl::{is_musl_target, seed_musl_stage2b_runtime_state};

#[repr(C)]
pub struct JumpInfo {
    pub entry: usize,
    pub stack: usize,
}

const AUXV_MAX: usize = 64;
const SHN_ABS: u16 = 0xfff1;

#[inline(always)]
pub unsafe fn execute_elf_from_bytes(
    elf_bytes: &[u8],
    target_argc: usize,
    target_argv: *const *const u8,
    env_pointer: *const *const u8,
    pseudorandom_bytes: *const [u8; 16],
    minsigstacksize: usize,
    hwcap: usize,
    hwcap2: usize,
    auxv_template: &[AuxiliaryVectorItem],
    entry_symbol: Option<&str>,
    entry_address: Option<usize>,
    verbose: bool,
) -> JumpInfo {
    launch_target_from_bytes(
        elf_bytes,
        target_argc,
        target_argv,
        env_pointer,
        pseudorandom_bytes,
        minsigstacksize,
        hwcap,
        hwcap2,
        auxv_template,
        entry_symbol,
        entry_address,
        verbose,
    )
}

#[inline(always)]
unsafe fn launch_target_from_bytes(
    elf_bytes: &[u8],
    target_argc: usize,
    target_argv: *const *const u8,
    env_pointer: *const *const u8,
    pseudorandom_bytes: *const [u8; 16],
    minsigstacksize: usize,
    hwcap: usize,
    hwcap2: usize,
    auxv_template: &[AuxiliaryVectorItem],
    entry_symbol: Option<&str>,
    entry_address: Option<usize>,
    verbose: bool,
) -> JumpInfo {
    let target_path = *target_argv;
    let target_path_string = if target_path.is_null() {
        None
    } else {
        Some(
            unsafe { CStr::from_ptr(target_path.cast::<c_char>()) }
                .to_string_lossy()
                .into_owned(),
        )
    };

    let image = load_target_image_from_bytes(elf_bytes);
    let mut selected_entry = image.entry;
    let (effective_hwcap, effective_hwcap2) = sanitize_hwcap_for_target(&image, hwcap, hwcap2);

    if verbose {
        announce_target_elf_kind(&image);
    }
    let mut auxv_items = auxv_template.to_vec();
    normalize_auxv_items(&mut auxv_items);

    // Update auxv for the target executable.
    set_auxv_ptr(&mut auxv_items, AT_PHDR, image.phdr as *mut ());
    set_auxv_val(&mut auxv_items, AT_PHNUM, image.phnum);
    set_auxv_val(&mut auxv_items, AT_PHENT, image.phent);
    set_auxv_ptr(&mut auxv_items, AT_ENTRY, image.entry as *mut ());
    set_auxv_ptr(&mut auxv_items, AT_EXECFN, target_path as *mut ());
    if minsigstacksize != 0 {
        set_auxv_val(&mut auxv_items, AT_MINSIGSTKSZ, minsigstacksize);
    }
    set_auxv_val(&mut auxv_items, AT_HWCAP, effective_hwcap);
    set_auxv_val(&mut auxv_items, AT_HWCAP2, effective_hwcap2);
    set_auxv_val(&mut auxv_items, AT_PAGE_SIZE, page_size::get_page_size());
    set_auxv_val(&mut auxv_items, AT_BASE, 0);

    let target_args = slice::from_raw_parts(target_argv, target_argc);
    let env_storage = collect_env(env_pointer);
    let mut env_list: Vec<*const u8> = env_storage
        .iter()
        .map(|value| value.as_ptr() as *const u8)
        .collect();
    let _leaked_env_storage = Box::leak(env_storage.into_boxed_slice());
    maybe_disable_glibc_rseq_under_valgrind(&mut env_list);
    let auxv_string_storage = stabilize_auxv_string_pointers(&mut auxv_items);
    let _leaked_auxv_string_storage = Box::leak(auxv_string_storage.into_boxed_slice());

    let new_stack = build_stack(target_args, &env_list, &auxv_items);
    let current_stack_end = current_stack_pointer();
    let new_argv = new_stack.add(1) as *const *const u8;
    let new_envp = new_argv.add(target_argc + 1);
    let new_auxv =
        new_stack.add(1 + (target_argc + 1) + (env_list.len() + 1)) as *mut AuxiliaryVectorItem;

    #[cfg(debug_assertions)]
    {
        use crate::libc::fs::write;
        write::write_str(write::STD_ERR, "loader: stack argc=");
        write_hex(write::STD_ERR, target_argc);
        write::write_str(write::STD_ERR, " argv0=");
        write_hex(write::STD_ERR, *new_argv as usize);
        write::write_str(write::STD_ERR, " argv1=");
        if target_argc > 1 {
            write_hex(write::STD_ERR, *new_argv.add(1) as usize);
        } else {
            write_hex(write::STD_ERR, 0);
        }
        write::write_str(write::STD_ERR, " env0=");
        write_hex(write::STD_ERR, *new_envp as usize);
        write::write_str(write::STD_ERR, "\n");

        if !(*new_argv).is_null() {
            let bytes = CStr::from_ptr((*new_argv).cast::<c_char>()).to_bytes();
            if let Ok(text) = core::str::from_utf8(bytes) {
                write::write_str(write::STD_ERR, "loader: argv0 text=");
                write::write_str(write::STD_ERR, text);
                write::write_str(write::STD_ERR, "\n");
            }
        }
        if !(*new_envp).is_null() {
            let bytes = CStr::from_ptr((*new_envp).cast::<c_char>()).to_bytes();
            if let Ok(text) = core::str::from_utf8(bytes) {
                write::write_str(write::STD_ERR, "loader: env0 text=");
                write::write_str(write::STD_ERR, text);
                write::write_str(write::STD_ERR, "\n");
            }
        }
    }
    let executable = SharedObject::from_loaded(image.base, &image.program_headers);

    if image.has_dynamic {
        let musl_target = is_musl_target(&image);
        // Create dynamic linker
        let mut linker = Box::new(DynamicLinker::new());

        if !musl_target {
            // Initialize rtld stubs before any symbol lookups.
            // musl-linked programs do not consume glibc rtld internals.
            linker.init_rtld_stubs(
                executable.base,
                image.exec_dynamic,
                new_argv,
                current_stack_end,
                minsigstacksize,
                new_stack.add(1 + (target_argc + 1) + (env_list.len() + 1))
                    as *const AuxiliaryVectorItem,
                auxv_items.len(),
                effective_hwcap,
                effective_hwcap2,
            );
        }
        let new_auxv = new_auxv as *const AuxiliaryVectorItem;
        #[cfg(target_arch = "x86_64")]
        let runtime_random = if musl_target {
            pseudorandom_bytes
        } else {
            auxv_lookup_value(new_auxv, AT_RANDOM).unwrap_or(pseudorandom_bytes as usize)
                as *const [u8; 16]
        };

        // Snapshot dependency offsets up-front to avoid String allocations
        // before moving `executable` into the linker.
        let needed_offsets: SmallVec<[usize; 16]> =
            executable.needed_libraries.iter().copied().collect();
        let executable_string_table = executable.string_table;

        let executable_idx =
            linker.add_object_with_path("[executable]".to_string(), target_path_string, executable);

        // Load all required shared libraries recursively
        let interp_name = image
            .interpreter_path
            .as_deref()
            .map(interpreter_name)
            .unwrap_or("");
        let mut resolved_dependencies = Vec::with_capacity(needed_offsets.len());
        for needed_offset in needed_offsets {
            let lib_name = executable_string_table.get(needed_offset);
            if lib_name.is_empty() {
                continue;
            }
            let lib_name = lib_name.to_string();
            // For glibc targets, keep PT_INTERP out of dependency loading.
            // For musl targets, PT_INTERP is also the libc DSO and must be loaded.
            if !musl_target && !interp_name.is_empty() && lib_name == interp_name {
                continue;
            }
            if let Some(dep_idx) =
                linker.load_library_with_requester(&lib_name, Some(executable_idx), true).ok()
            {
                if dep_idx < linker.objects.len() && dep_idx != executable_idx {
                    resolved_dependencies.push(dep_idx);
                }
            }
        }
        linker.objects[executable_idx].resolved_dependencies = resolved_dependencies;

        let interpreter_base = loaded_interpreter_base(&linker, &image);
        if interpreter_base != 0 {
            set_auxv_val(&mut auxv_items, AT_BASE, interpreter_base);
            set_auxv_val_in_place(
                new_auxv as *mut AuxiliaryVectorItem,
                AT_BASE,
                interpreter_base,
            );
        }

        #[cfg(debug_assertions)]
        trace_loaded_objects(&linker);
        linking::set_active_linker((&mut *linker) as *mut DynamicLinker);

        // Prepare TLS layout before relocations (needed for TLS relocations).
        linker.prepare_tls_layout();
        // Build scope order once so relocation lookup does not repeatedly
        // traverse dependency trees for every symbol.
        linker.rebuild_lookup_scopes();

        let mut ifuncs = Vec::new();
        let mut copies = Vec::new();
        let lookup_cache_capacity = linker
            .objects
            .iter()
            .map(|object| {
                let slices = object.relocation_slices();
                slices.rela_slice.len() + (slices.relr_slice.len() / 2)
            })
            .sum::<usize>()
            .max(4096);
        let mut lookup_cache = relocation::SymbolLookupCache::with_capacity(lookup_cache_capacity);
        // Perform relocations for all loaded objects with cross-library symbol resolution
        for obj_idx in 0..linker.objects.len() {
            #[cfg(debug_assertions)]
            {
                use crate::libc::fs::write;
                write::write_str(write::STD_ERR, "Relocating object\n");
            }
            relocation::relocate_with_linker(
                &linker.objects[obj_idx],
                obj_idx,
                &linker,
                &mut ifuncs,
                &mut copies,
                &mut lookup_cache,
            );
        }
        relocation::apply_copy_relocations(&copies);
        // Install TLS after relocations so TLS init images include relocated data.
        if musl_target {
            crate::tls::install_tls_musl(&linker.objects, pseudorandom_bytes);
            #[cfg(target_arch = "x86_64")]
            {
                let startup_symbol_writes = collect_startup_symbol_writes(
                    &linker,
                    new_envp,
                    if target_argc > 0 {
                        *new_argv
                    } else {
                        core::ptr::null()
                    },
                    runtime_random,
                );
                set_symbol_pointer_batch_all(&linker, &startup_symbol_writes);
                seed_musl_stage2b_runtime_state(
                    &linker,
                    new_auxv as *const AuxiliaryVectorItem,
                    image.interpreter_path.as_deref(),
                    core::ptr::null(),
                );
            }
            #[cfg(target_arch = "aarch64")]
            {
                seed_musl_stage2b_runtime_state(
                    &linker,
                    new_auxv as *const AuxiliaryVectorItem,
                    image.interpreter_path.as_deref(),
                    core::ptr::null(),
                );
            }
        } else {
            linker.install_tls(pseudorandom_bytes);
            let startup_symbol_writes = collect_startup_symbol_writes(
                &linker,
                new_envp,
                if target_argc > 0 {
                    *new_argv
                } else {
                    core::ptr::null()
                },
                pseudorandom_bytes,
            );
            set_symbol_pointer_batch_all(&linker, &startup_symbol_writes);
        }
        relocation::apply_irelative_relocations(&ifuncs);
        selected_entry = resolve_requested_entry_for_dynamic(
            entry_symbol,
            entry_address,
            &linker,
            executable_idx,
            image.base,
            selected_entry,
        );
        if !musl_target {
            // Constructors and libc early init expect stack-end metadata to match
            // the argv/env/auxv image we hand to the target process.
            linker.update_rtld_stack_end(new_stack as *const u8);
            #[cfg(target_arch = "x86_64")]
            libc_thresholds::patch_libc_copy_thresholds(&linker);
            call_libc_early_init(&linker);
            #[cfg(target_arch = "x86_64")]
            seed_glibc_thread_locale(&linker);
        }

        // Call init arrays for shared libraries (dependencies first).
        // We always run dependency ctors here because rustld performs the
        // relocation/bootstrap path directly for both glibc and musl targets.
        if linker.objects.len() > 1 {
            let skip_selinux_init = !musl_target && skip_selinux_ctors();
            for idx in linker.dependency_init_order(1) {
                if skip_selinux_init
                    && linker.objects[idx]
                        .soname_str()
                        .is_some_and(|soname| soname == "libselinux.so.1")
                {
                    continue;
                }
                if !musl_target {
                    let ld_linux_by_soname = linker.objects[idx]
                        .soname_str()
                        .is_some_and(|soname| soname.starts_with("ld-linux"));
                    let ld_linux_by_path = linker.object_path(idx).is_some_and(|path| {
                        path.rsplit('/')
                            .next()
                            .is_some_and(|name| name.starts_with("ld-linux"))
                    });
                    if ld_linux_by_soname || ld_linux_by_path {
                        continue;
                    }
                }
                #[cfg(debug_assertions)]
                {
                    use crate::libc::fs::write;
                    let name = linker
                        .library_map
                        .iter()
                        .find(|(_, object_idx)| *object_idx == idx)
                        .map(|(name, _)| name.as_str())
                        .unwrap_or("<unknown>");
                    write::write_str(write::STD_ERR, "loader: init begin ");
                    write::write_str(write::STD_ERR, name);
                    write::write_str(write::STD_ERR, "\n");
                }
                linker.objects[idx]
                    .call_init_functions(target_argc, new_argv, new_envp, new_auxv);
                #[cfg(debug_assertions)]
                {
                    use crate::libc::fs::write;
                    let name = linker
                        .library_map
                        .iter()
                        .find(|(_, object_idx)| *object_idx == idx)
                        .map(|(name, _)| name.as_str())
                        .unwrap_or("<unknown>");
                    write::write_str(write::STD_ERR, "loader: init done ");
                    write::write_str(write::STD_ERR, name);
                    write::write_str(write::STD_ERR, "\n");
                }
                #[cfg(debug_assertions)]
                trace_rpc_vars_slot("after dep init");
            }
        }
        if !musl_target {
            set_symbol_pointer_all(&linker, &["_dl_starting_up"], 0);
        }
        // The main executable init hooks are invoked by __libc_start_main.
        // Running them here causes double initialization.

        #[cfg(debug_assertions)]
        {
            use crate::libc::fs::write;
            if let Some((idx, sym)) = linker.lookup_symbol("_rtld_global_ro") {
                let base = if sym.st_shndx == 0xfff1 {
                    0
                } else {
                    linker.get_base(idx)
                };
                let ro = base.wrapping_add(sym.st_value);
                write::write_str(write::STD_ERR, "loader: rtld_ro pagesize=");
                write_hex(
                    write::STD_ERR,
                    core::ptr::read_volatile((ro + 0x18) as *const usize),
                );
                write::write_str(write::STD_ERR, " tls_size=");
                write_hex(
                    write::STD_ERR,
                    core::ptr::read_volatile((ro + 0x2a0) as *const usize),
                );
                write::write_str(write::STD_ERR, " tls_align=");
                write_hex(
                    write::STD_ERR,
                    core::ptr::read_volatile((ro + 0x2a8) as *const usize),
                );
                write::write_str(write::STD_ERR, "\n");
            }
            if let Some((idx, sym)) = linker.lookup_symbol("_dl_argv") {
                let base = if sym.st_shndx == 0xfff1 {
                    0
                } else {
                    linker.get_base(idx)
                };
                let dl_argv_addr = base.wrapping_add(sym.st_value);
                let dl_argv = core::ptr::read_volatile(dl_argv_addr as *const *const *const u8);
                write::write_str(write::STD_ERR, "loader: _dl_argv var=");
                write_hex(write::STD_ERR, dl_argv_addr);
                write::write_str(write::STD_ERR, " value=");
                write_hex(write::STD_ERR, dl_argv as usize);
                write::write_str(write::STD_ERR, "\n");
                if !dl_argv.is_null() {
                    let a0 = core::ptr::read_volatile(dl_argv as *const *const u8);
                    let a1 = core::ptr::read_volatile(dl_argv.add(1) as *const *const u8);
                    write::write_str(write::STD_ERR, "loader: _dl_argv[0]=");
                    write_hex(write::STD_ERR, a0 as usize);
                    write::write_str(write::STD_ERR, " _dl_argv[1]=");
                    write_hex(write::STD_ERR, a1 as usize);
                    write::write_str(write::STD_ERR, "\n");
                    if !a0.is_null() {
                        let bytes = CStr::from_ptr(a0.cast::<c_char>()).to_bytes();
                        if let Ok(text) = core::str::from_utf8(bytes) {
                            write::write_str(write::STD_ERR, "loader: _dl_argv[0] text=");
                            write::write_str(write::STD_ERR, text);
                            write::write_str(write::STD_ERR, "\n");
                        }
                    }
                }
            }
            write::write_str(write::STD_ERR, "loader: handoff to entry\n");
        }
        let leaked = Box::leak(linker);
        linking::set_active_linker(leaked as *mut DynamicLinker);
    } else {
        // Static binary: only install TLS if present.
        let mut objects = vec![executable];
        tls::prepare_tls_layout(&mut objects);
        tls::install_tls(&objects, pseudorandom_bytes);
        selected_entry = resolve_requested_entry_for_static(
            entry_symbol,
            entry_address,
            &objects[0],
            image.base,
            selected_entry,
        );
        core::mem::forget(objects);
    }

    set_auxv_ptr(&mut auxv_items, AT_ENTRY, selected_entry as *mut ());
    set_auxv_val_in_place(new_auxv, AT_ENTRY, selected_entry);

    JumpInfo {
        entry: selected_entry,
        stack: new_stack as usize,
    }
}

#[inline(always)]
unsafe fn current_stack_pointer() -> *const u8 {
    arch::current_stack_pointer()
}

unsafe fn program_invocation_short_name(argv0: *const u8) -> *const u8 {
    let short = if argv0.is_null() {
        argv0
    } else {
        let mut p = argv0;
        let mut last = argv0;
        while *p != 0 {
            if *p == b'/' {
                last = p.add(1);
            }
            p = p.add(1);
        }
        last
    };
    short
}

unsafe fn collect_startup_symbol_writes(
    linker: &DynamicLinker,
    envp: *const *const u8,
    argv0: *const u8,
    pseudorandom_bytes: *const [u8; 16],
) -> SmallVec<[(&'static str, usize); 16]> {
    let mut writes = SmallVec::<[(&'static str, usize); 16]>::new();

    writes.push(("_dl_starting_up", 1));
    let env_ptr = envp as usize;
    writes.push(("__environ", env_ptr));
    writes.push(("_environ", env_ptr));
    writes.push(("environ", env_ptr));

    writes.push(("program_invocation_name", argv0 as usize));
    writes.push(("__progname_full", argv0 as usize));
    let short = unsafe { program_invocation_short_name(argv0) };
    writes.push(("program_invocation_short_name", short as usize));
    writes.push(("__progname", short as usize));

    if let Some(hook) = unsafe { linker.rtld_dlfcn_hook() } {
        writes.push(("_dl_open_hook", hook));
        writes.push(("_dl_open_hook2", hook));
    }

    if let Some(obj_addr) = unsafe { symbol_address_any(linker, "_IO_2_1_stdin_") } {
        writes.push(("stdin", obj_addr));
    }
    if let Some(obj_addr) = unsafe { symbol_address_any(linker, "_IO_2_1_stdout_") } {
        writes.push(("stdout", obj_addr));
    }
    if let Some(obj_addr) = unsafe { symbol_address_any(linker, "_IO_2_1_stderr_") } {
        writes.push(("stderr", obj_addr));
    }

    if !pseudorandom_bytes.is_null() {
        let random = unsafe { &*pseudorandom_bytes };
        let mut stack_guard =
            usize::from_ne_bytes(random[..size_of::<usize>()].try_into().unwrap());
        // Match glibc behavior: keep the low byte zero so simple string
        // overflows are more likely to hit a NUL terminator.
        stack_guard &= !0xffusize;
        let pointer_guard = usize::from_ne_bytes(
            random[size_of::<usize>()..(2 * size_of::<usize>())]
                .try_into()
                .unwrap(),
        );
        writes.push(("__stack_chk_guard", stack_guard));
        writes.push(("__pointer_chk_guard_local", pointer_guard));
        writes.push(("__pointer_chk_guard", pointer_guard));
        writes.push(("_dl_random", pseudorandom_bytes as usize));
    }

    writes
}

#[inline(always)]
fn resolve_entry_address_for_object(
    object_base: usize,
    object_map_start: usize,
    object_map_end: usize,
    requested: usize,
) -> usize {
    if requested >= object_map_start && requested < object_map_end {
        requested
    } else {
        object_base.wrapping_add(requested)
    }
}

unsafe fn resolve_requested_entry_for_dynamic(
    entry_symbol: Option<&str>,
    entry_address: Option<usize>,
    linker: &DynamicLinker,
    executable_idx: usize,
    executable_base: usize,
    default_entry: usize,
) -> usize {
    match (entry_symbol, entry_address) {
        (None, None) => default_entry,
        (Some(symbol_name), None) => {
            if let Some(address) = linker.lookup_symbol_in_object_scope(executable_idx, symbol_name)
            {
                return address;
            }
            if let Some((object_idx, symbol)) = linker.lookup_symbol(symbol_name) {
                let base = if symbol.st_shndx == SHN_ABS {
                    0
                } else {
                    linker.get_base(object_idx)
                };
                return base.wrapping_add(symbol.st_value);
            }
            eprintln!("Error: entry symbol not found: {symbol_name}");
            exit::exit(1);
        }
        (None, Some(requested_address)) => {
            let (map_start, map_end) = linker
                .object_map_range(executable_idx)
                .unwrap_or((executable_base, executable_base));
            resolve_entry_address_for_object(executable_base, map_start, map_end, requested_address)
        }
        (Some(_), Some(_)) => {
            eprintln!("Error: entry_symbol and entry_address are mutually exclusive");
            exit::exit(1);
        }
    }
}

unsafe fn resolve_requested_entry_for_static(
    entry_symbol: Option<&str>,
    entry_address: Option<usize>,
    executable: &SharedObject,
    executable_base: usize,
    default_entry: usize,
) -> usize {
    match (entry_symbol, entry_address) {
        (None, None) => default_entry,
        (Some(symbol_name), None) => {
            if let Some(symbol) = executable.lookup_exported_symbol(symbol_name) {
                let base = if symbol.st_shndx == SHN_ABS {
                    0
                } else {
                    executable.base
                };
                return base.wrapping_add(symbol.st_value);
            }
            eprintln!("Error: entry symbol not found in image: {symbol_name}");
            exit::exit(1);
        }
        (None, Some(requested_address)) => resolve_entry_address_for_object(
            executable_base,
            executable.map_start,
            executable.map_end,
            requested_address,
        ),
        (Some(_), Some(_)) => {
            eprintln!("Error: entry_symbol and entry_address are mutually exclusive");
            exit::exit(1);
        }
    }
}

unsafe fn symbol_address_any(linker: &DynamicLinker, name: &str) -> Option<usize> {
    const SHN_ABS: u16 = 0xfff1;
    linker.lookup_symbol(name).map(|(lib_idx, sym)| {
        let base = if sym.st_shndx == SHN_ABS {
            0
        } else {
            linker.get_base(lib_idx)
        };
        base.wrapping_add(sym.st_value)
    })
}

unsafe fn set_symbol_pointer_all(linker: &DynamicLinker, names: &[&str], value: usize) {
    const SHN_ABS: u16 = 0xfff1;

    let candidate_indices = startup_symbol_target_indices(linker);
    for &idx in candidate_indices.iter() {
        let object = &linker.objects[idx];
        for &name in names {
            let Some(sym) = object.lookup_exported_symbol(name) else {
                continue;
            };
            let base = if sym.st_shndx == SHN_ABS {
                0
            } else {
                object.base
            };
            let ptr = base.wrapping_add(sym.st_value) as *mut usize;
            core::ptr::write_volatile(ptr, value);
        }
    }
}

unsafe fn set_symbol_pointer_batch_all(linker: &DynamicLinker, writes: &[(&str, usize)]) {
    const SHN_ABS: u16 = 0xfff1;

    let candidate_indices = startup_symbol_target_indices(linker);
    for &(name, value) in writes {
        let mut wrote_any = false;

        for &idx in candidate_indices.iter() {
            let object = &linker.objects[idx];
            let Some(sym) = object.lookup_exported_symbol(name) else {
                continue;
            };
            wrote_any = true;
            let base = if sym.st_shndx == SHN_ABS {
                0
            } else {
                object.base
            };
            let ptr = base.wrapping_add(sym.st_value) as *mut usize;
            core::ptr::write_volatile(ptr, value);
        }

        if wrote_any {
            continue;
        }

        // Rare compatibility fallback: preserve previous behavior if a target
        // symbol is not present in the common startup-bearing DSOs.
        for object in linker.objects.iter() {
            let Some(sym) = object.lookup_exported_symbol(name) else {
                continue;
            };
            let base = if sym.st_shndx == SHN_ABS {
                0
            } else {
                object.base
            };
            let ptr = base.wrapping_add(sym.st_value) as *mut usize;
            core::ptr::write_volatile(ptr, value);
        }
    }
}

unsafe fn startup_symbol_target_indices(linker: &DynamicLinker) -> SmallVec<[usize; 6]> {
    let mut indices: SmallVec<[usize; 6]> = SmallVec::new();
    if !linker.objects.is_empty() {
        indices.push(0);
    }

    for (idx, object) in linker.objects.iter().enumerate().skip(1) {
        let Some(soname) = object.soname_str() else {
            continue;
        };
        let is_startup_dso = soname == "libc.so.6"
            || soname.starts_with("ld-linux")
            || soname.starts_with("ld-musl")
            || soname.starts_with("libc.musl");
        if is_startup_dso && !indices.contains(&idx) {
            indices.push(idx);
        }
    }
    indices
}

unsafe fn call_libc_early_init(linker: &DynamicLinker) {
    #[cfg(target_arch = "x86_64")]
    {
        let force_early_init = allow_libc_early_init_on_unsupported_layout();
        // Our synthetic rtld_global/_ro layout is currently tuned for
        // /lib64-style glibc deployments. On Debian/Ubuntu multiarch layouts,
        // forcing __libc_early_init can crash (SIGFPE in CI).
        if !x86_64_glibc_layout_supported(linker) && !force_early_init {
            // Older Debian/Ubuntu glibc builds expose __ctype_init but expect
            // rtld-internal TLS/locale state to already exist. Calling it
            // directly from rustld can crash before the target reaches entry.
            // On unsupported layouts, skip the manual libc init path entirely
            // and let libc complete its own setup through normal startup.
            return;
        }
    }

    const SHN_ABS: u16 = 0xfff1;
    if let Some((lib_idx, sym)) = linker.lookup_symbol("__libc_early_init") {
        let base = if sym.st_shndx == SHN_ABS {
            0
        } else {
            linker.get_base(lib_idx)
        };
        let func_addr = base.wrapping_add(sym.st_value);
        #[cfg(debug_assertions)]
        {
            use crate::libc::fs::write;
            write::write_str(write::STD_ERR, "loader: __libc_early_init ");
            write_hex(write::STD_ERR, func_addr);
            write::write_str(write::STD_ERR, "\n");
        }
        let init_fn: extern "C" fn(i32) = core::mem::transmute(func_addr);
        init_fn(1);
    } else {
        #[cfg(debug_assertions)]
        {
            use crate::libc::fs::write;
            write::write_str(write::STD_ERR, "loader: __libc_early_init missing\n");
        }
    }
}

#[cfg(target_arch = "x86_64")]
unsafe fn seed_glibc_thread_locale(linker: &DynamicLinker) {
    type UselocaleFn = extern "C" fn(*mut c_void) -> *mut c_void;

    let symbol = linker
        .lookup_symbol("__uselocale")
        .or_else(|| linker.lookup_symbol("uselocale"));
    let Some((lib_idx, sym)) = symbol else {
        return;
    };

    const SHN_ABS: u16 = 0xfff1;
    let base = if sym.st_shndx == SHN_ABS {
        0
    } else {
        linker.get_base(lib_idx)
    };
    let func_addr = base.wrapping_add(sym.st_value);
    if func_addr == 0 {
        return;
    }

    // `uselocale((locale_t)-1)` tells glibc to install the process-global
    // locale object into this thread's TLS slots. Older glibc builds keep the
    // current-locale pointer and derived ctype pointers in libc static TLS;
    // rustld-created child threads inherit those runtime-populated words from
    // the main thread during `_dl_allocate_tls*`.
    let uselocale_fn: UselocaleFn = core::mem::transmute(func_addr);
    let _ = uselocale_fn(usize::MAX as *mut c_void);
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
fn allow_libc_early_init_on_unsupported_layout() -> bool {
    false
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn x86_64_glibc_layout_supported(linker: &DynamicLinker) -> bool {
    let Some(idx) = find_libc_object_index(linker) else {
        return false;
    };
    let Some(libc_path) = linker.object_path(idx) else {
        return false;
    };
    libc_path.ends_with("/lib64/libc.so.6") || libc_path.ends_with("/usr/lib64/libc.so.6")
}

#[inline(always)]
pub(super) unsafe fn find_libc_object_index(linker: &DynamicLinker) -> Option<usize> {
    linker
        .objects
        .iter()
        .enumerate()
        .find_map(|(idx, object)| {
            object
                .soname_str()
                .is_some_and(|soname| soname == "libc.so.6")
                .then_some(idx)
        })
        .or_else(|| {
            linker.library_map.iter().find_map(|(name, idx)| {
                if *idx == usize::MAX {
                    return None;
                }
                if name == "libc.so.6" || name.ends_with("/libc.so.6") {
                    Some(*idx)
                } else {
                    None
                }
            })
        })
}


struct LoadedImage {
    base: usize,
    entry: usize,
    phdr: *const ProgramHeader,
    phnum: usize,
    phent: usize,
    exec_dynamic: *const u8,
    program_headers: Vec<ProgramHeader>,
    has_dynamic: bool,
    interpreter_path: Option<String>,
}

#[inline(always)]
fn set_auxv_val(items: &mut Vec<AuxiliaryVectorItem>, key: usize, val: usize) {
    if let Some(item) = items.iter_mut().find(|item| item.a_type == key) {
        item.a_un = AuxiliaryVectorUnion { a_val: val };
    } else {
        items.push(AuxiliaryVectorItem {
            a_type: key,
            a_un: AuxiliaryVectorUnion { a_val: val },
        });
    }
}

#[inline(always)]
fn set_auxv_ptr(items: &mut Vec<AuxiliaryVectorItem>, key: usize, ptr: *mut ()) {
    if let Some(item) = items.iter_mut().find(|item| item.a_type == key) {
        item.a_un = AuxiliaryVectorUnion { a_ptr: ptr };
    } else {
        items.push(AuxiliaryVectorItem {
            a_type: key,
            a_un: AuxiliaryVectorUnion { a_ptr: ptr },
        });
    }
}

fn normalize_auxv_items(items: &mut Vec<AuxiliaryVectorItem>) {
    items.retain(|item| item.a_type != AT_NULL);
}

pub(super) unsafe fn auxv_lookup_value(auxv_pointer: *const AuxiliaryVectorItem, key: usize) -> Option<usize> {
    if auxv_pointer.is_null() {
        return None;
    }
    let mut cursor = auxv_pointer;
    loop {
        let item = core::ptr::read(cursor);
        if item.a_type == AT_NULL {
            return None;
        }
        if item.a_type == key {
            return Some(item.a_un.a_val);
        }
        cursor = cursor.add(1);
    }
}

unsafe fn set_auxv_val_in_place(auxv_pointer: *mut AuxiliaryVectorItem, key: usize, val: usize) {
    if auxv_pointer.is_null() {
        return;
    }
    let mut cursor = auxv_pointer;
    loop {
        let item = &mut *cursor;
        if item.a_type == AT_NULL {
            return;
        }
        if item.a_type == key {
            item.a_un = AuxiliaryVectorUnion { a_val: val };
            return;
        }
        cursor = cursor.add(1);
    }
}

#[inline(always)]
fn sanitize_hwcap_for_target(image: &LoadedImage, hwcap: usize, hwcap2: usize) -> (usize, usize) {
    #[cfg(target_arch = "x86_64")]
    {
        let is_x86_glibc_dynamic = image.has_dynamic
            && image
                .interpreter_path
                .as_deref()
                .is_some_and(|path| interpreter_name(path).starts_with("ld-linux"));
        if is_x86_glibc_dynamic && !preserve_x86_glibc_hwcap() {
            return (0, 0);
        }
    }

    (hwcap, hwcap2)
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
fn preserve_x86_glibc_hwcap() -> bool {
    false
}

pub(super) fn interpreter_name(interpreter_path: &str) -> &str {
    interpreter_path
        .rsplit('/')
        .next()
        .unwrap_or(interpreter_path)
}

unsafe fn loaded_interpreter_base(linker: &DynamicLinker, image: &LoadedImage) -> usize {
    let Some(interpreter_path) = image.interpreter_path.as_deref() else {
        return 0;
    };

    if let Some(idx) = linker.loaded_index(interpreter_path) {
        if idx != usize::MAX && idx < linker.objects.len() {
            return linker.get_base(idx);
        }
    }

    let interpreter_name = interpreter_name(interpreter_path);
    if let Some(idx) = linker.loaded_index(interpreter_name) {
        if idx != usize::MAX && idx < linker.objects.len() {
            return linker.get_base(idx);
        }
    }

    0
}
unsafe fn collect_env(env_pointer: *const *const u8) -> Vec<CString> {
    let mut count = 0usize;
    let mut cursor = env_pointer;
    while !(*cursor).is_null() {
        count += 1;
        cursor = cursor.add(1);
    }

    let mut env = Vec::with_capacity(count);
    cursor = env_pointer;
    while !(*cursor).is_null() {
        let bytes = CStr::from_ptr((*cursor).cast::<c_char>()).to_bytes();
        if let Ok(value) = CString::new(bytes) {
            env.push(value);
        }
        cursor = cursor.add(1);
    }
    env
}

fn stabilize_auxv_string_pointers(auxv_items: &mut [AuxiliaryVectorItem]) -> Vec<CString> {
    let mut storage = Vec::new();
    for item in auxv_items.iter_mut() {
        let is_string_pointer = matches!(item.a_type, AT_PLATFORM | AT_BASE_PLATFORM | AT_EXECFN);
        if !is_string_pointer {
            continue;
        }
        let raw_ptr = unsafe { item.a_un.a_ptr } as *const c_char;
        if raw_ptr.is_null() {
            continue;
        }
        let bytes = unsafe { CStr::from_ptr(raw_ptr).to_bytes() };
        if let Ok(value) = CString::new(bytes) {
            let ptr = value.as_ptr() as *mut ();
            storage.push(value);
            item.a_un = AuxiliaryVectorUnion { a_ptr: ptr };
        }
    }
    storage
}

fn parse_interp_path_from_bytes(
    program_headers: &[ProgramHeader],
    elf_bytes: &[u8],
) -> Option<String> {
    let interp = program_headers.iter().find(|ph| ph.p_type == PT_INTERP)?;
    if interp.p_filesz == 0 {
        return None;
    }
    let file_start = interp.p_offset;
    let file_end = file_start.checked_add(interp.p_filesz)?;
    if file_end > elf_bytes.len() {
        return None;
    }
    let bytes = &elf_bytes[file_start..file_end];
    let nul = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    if nul == 0 {
        return None;
    }
    let path = core::str::from_utf8(&bytes[..nul]).ok()?;
    Some(path.to_string())
}

fn maybe_disable_glibc_rseq_under_valgrind(env: &mut Vec<*const u8>) {
    if !running_under_valgrind() {
        return;
    }

    static mut GLIBC_TUNABLES_RSEQ_OFF: [u8; 36] = *b"GLIBC_TUNABLES=glibc.pthread.rseq=0\0";
    const GLIBC_TUNABLES_KEY: &[u8] = b"GLIBC_TUNABLES=";
    let tunables_ptr = core::ptr::addr_of_mut!(GLIBC_TUNABLES_RSEQ_OFF).cast::<u8>() as *const u8;

    for slot in env.iter_mut() {
        if slot.is_null() {
            continue;
        }
        let bytes = unsafe { CStr::from_ptr((*slot).cast::<c_char>()).to_bytes() };
        if bytes.starts_with(GLIBC_TUNABLES_KEY) {
            *slot = tunables_ptr;
            return;
        }
    }

    env.push(tunables_ptr);
}

#[cfg(debug_assertions)]
unsafe fn trace_loaded_objects(linker: &DynamicLinker) {
    use crate::libc::fs::write;
    write::write_str(write::STD_ERR, "rustld: loaded objects\n");
    for (idx, object) in linker.objects.iter().enumerate() {
        write::write_str(write::STD_ERR, "  [");
        write_hex(write::STD_ERR, idx);
        write::write_str(write::STD_ERR, "] base=");
        write_hex(write::STD_ERR, object.base);
        write::write_str(write::STD_ERR, " ");
        let mut printed = false;
        if let Some(path) = linker.object_path(idx) {
            write::write_str(write::STD_ERR, path);
            printed = true;
        }
        if !printed {
            if idx == 0 {
                write::write_str(write::STD_ERR, "[executable]");
            } else {
                write::write_str(write::STD_ERR, "<unknown>");
            }
        }
        write::write_str(write::STD_ERR, "\n");
    }
}

#[cfg(debug_assertions)]
unsafe fn trace_rpc_vars_slot(stage: &str) {
    use crate::libc::fs::write;
    let tp = crate::syscall::thread_pointer::get_thread_pointer() as usize;
    if tp == 0 {
        write::write_str(write::STD_ERR, "loader: rpc slot ");
        write::write_str(write::STD_ERR, stage);
        write::write_str(write::STD_ERR, " tp=null\n");
        return;
    }
    let slot_ptr = (tp as *const u8).offset(-0x28) as *const usize;
    let slot = core::ptr::read_volatile(slot_ptr);
    write::write_str(write::STD_ERR, "loader: rpc slot ");
    write::write_str(write::STD_ERR, stage);
    write::write_str(write::STD_ERR, " tp=");
    write_hex(write::STD_ERR, tp);
    write::write_str(write::STD_ERR, " value=");
    write_hex(write::STD_ERR, slot);
    write::write_str(write::STD_ERR, "\n");
}

#[inline(always)]
unsafe fn build_stack(
    args: &[*const u8],
    env: &[*const u8],
    auxv: &[AuxiliaryVectorItem],
) -> *mut usize {
    const STACK_SIZE: usize = 8 * 1024 * 1024;
    let stack_base = mmap(
        null_mut(),
        STACK_SIZE,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK,
        -1,
        0,
    ) as usize;
    if running_under_valgrind() {
        core::ptr::write_bytes(stack_base as *mut u8, 0, STACK_SIZE);
    }

    let mut sp = (stack_base + STACK_SIZE) & !0xFusize;

    // Provide a fresh AT_RANDOM payload in the new stack image.
    let mut parent_at_random: *const u8 = null();
    for item in auxv {
        if item.a_type == AT_RANDOM {
            parent_at_random = item.a_un.a_ptr as *const u8;
            break;
        }
    }

    sp -= 16;
    let new_at_random = sp as *mut u8;
    core::ptr::write_bytes(new_at_random, 0, 16);
    if !fill_random_bytes(new_at_random, 16) && !parent_at_random.is_null() {
        core::ptr::copy_nonoverlapping(parent_at_random, new_at_random, 16);
    }

    let auxv_words = (auxv.len() + 1) * 2; // +1 for AT_NULL
    let total_words = 1 + (args.len() + 1) + (env.len() + 1) + auxv_words;
    if total_words % 2 != 0 {
        sp -= size_of::<usize>();
        *(sp as *mut usize) = 0;
    }

    let mut push = |value: usize| {
        sp -= size_of::<usize>();
        unsafe {
            *(sp as *mut usize) = value;
        }
    };

    // Auxv (terminated by AT_NULL)
    push(0);
    push(AT_NULL);
    for item in auxv.iter().rev() {
        let val = if item.a_type == AT_RANDOM {
            new_at_random as usize
        } else {
            item.a_un.a_val
        };
        push(val);
        push(item.a_type);
    }

    // Envp (NULL terminated)
    push(0);
    for &envp in env.iter().rev() {
        push(envp as usize);
    }

    // Argv (NULL terminated)
    push(0);
    for &arg in args.iter().rev() {
        push(arg as usize);
    }

    // Argc
    push(args.len());

    sp as *mut usize
}

unsafe fn announce_target_elf_kind(image: &LoadedImage) {
    use crate::libc::fs::write;
    if image.has_dynamic {
        write::write_str(write::STD_ERR, "rustld: target ELF=dynamic");
        if let Some(ref interp_path) = image.interpreter_path {
            write::write_str(write::STD_ERR, " (");
            write::write_str(write::STD_ERR, interpreter_name(interp_path));
            write::write_str(write::STD_ERR, ")");
        }
        write::write_str(write::STD_ERR, "\n");
    } else {
        write::write_str(write::STD_ERR, "rustld: target ELF=static\n");
    }
}

#[inline(always)]
unsafe fn load_target_image_from_bytes(elf_bytes: &[u8]) -> LoadedImage {
    if elf_bytes.len() < size_of::<ElfHeader>() {
        use crate::libc::fs::write;
        write::write_str(
            write::STD_ERR,
            "Error: target bytes too small for ELF header\n",
        );
        exit::exit(1);
    }

    let header = core::ptr::read_unaligned(elf_bytes.as_ptr() as *const ElfHeader);

    if header.e_ident[0..4] != [0x7f, b'E', b'L', b'F'] {
        use crate::libc::fs::write;
        write::write_str(
            write::STD_ERR,
            "Error: target is not an ELF binary (script/shebang not supported)\n",
        );
        exit::exit(1);
    }

    if header.e_phentsize as usize != size_of::<ProgramHeader>() {
        use crate::libc::fs::write;
        write::write_str(write::STD_ERR, "Error: unsupported program header size\n");
        exit::exit(1);
    }

    let phoff = header.e_phoff as usize;
    let phnum = header.e_phnum as usize;
    let ph_bytes_len = phnum.saturating_mul(size_of::<ProgramHeader>());
    let ph_end = phoff.saturating_add(ph_bytes_len);
    if ph_end > elf_bytes.len() {
        use crate::libc::fs::write;
        write::write_str(write::STD_ERR, "Error: truncated program header table\n");
        exit::exit(1);
    }

    let mut program_headers = Vec::with_capacity(phnum);
    let mut cursor = phoff;
    while cursor < ph_end {
        let ph = core::ptr::read_unaligned(elf_bytes.as_ptr().add(cursor) as *const ProgramHeader);
        program_headers.push(ph);
        cursor += size_of::<ProgramHeader>();
    }

    let interpreter_path = parse_interp_path_from_bytes(&program_headers, elf_bytes);
    let (min_addr, max_addr) = calculate_virtual_address_bounds(&program_headers);
    let mmap_base = match header.e_type {
        ET_DYN => mmap(
            null_mut(),
            max_addr - min_addr,
            PROT_READ | PROT_WRITE | PROT_EXEC,
            MAP_PRIVATE | MAP_ANONYMOUS,
            -1,
            0,
        ) as usize,
        ET_EXEC => mmap(
            min_addr as *mut u8,
            max_addr - min_addr,
            PROT_READ | PROT_WRITE | PROT_EXEC,
            MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
            -1,
            0,
        ) as usize,
        _ => {
            use crate::libc::fs::write;
            write::write_str(write::STD_ERR, "Error: unsupported ELF type\n");
            exit::exit(1);
        }
    };

    let base = if header.e_type == ET_DYN {
        mmap_base.wrapping_sub(min_addr)
    } else {
        0
    };

    for header in &program_headers {
        if header.p_type != PT_LOAD {
            continue;
        }

        let dest = (base.wrapping_add(header.p_vaddr)) as *mut u8;
        let file_size = header.p_filesz;
        if file_size > 0 {
            let file_start = header.p_offset;
            let file_end = file_start.saturating_add(file_size);
            if file_end > elf_bytes.len() {
                use crate::libc::fs::write;
                write::write_str(write::STD_ERR, "Error: truncated PT_LOAD segment\n");
                exit::exit(1);
            }
            core::ptr::copy_nonoverlapping(elf_bytes.as_ptr().add(file_start), dest, file_size);
        }
        if header.p_memsz > header.p_filesz {
            let bss_start = dest.add(header.p_filesz);
            let bss_size = header.p_memsz - header.p_filesz;
            core::ptr::write_bytes(bss_start, 0, bss_size);
        }
    }

    let mut exec_dynamic = null();
    for header in &program_headers {
        if header.p_type == PT_DYNAMIC {
            exec_dynamic = (base.wrapping_add(header.p_vaddr)) as *const u8;
            break;
        }
    }

    // Prefer PT_PHDR when present, otherwise derive the in-memory PHDR address
    // from the PT_LOAD segment that contains e_phoff.
    let mut phdr_ptr: *const ProgramHeader = null();
    for ph in &program_headers {
        if ph.p_type == PT_PHDR {
            phdr_ptr = (base.wrapping_add(ph.p_vaddr)) as *const ProgramHeader;
            break;
        }
    }
    if phdr_ptr.is_null() {
        for ph in &program_headers {
            if ph.p_type != PT_LOAD {
                continue;
            }
            let seg_start = ph.p_offset;
            let seg_end = ph.p_offset.wrapping_add(ph.p_filesz);
            if header.e_phoff >= seg_start && header.e_phoff < seg_end {
                let delta = header.e_phoff.wrapping_sub(ph.p_offset);
                phdr_ptr =
                    (base.wrapping_add(ph.p_vaddr).wrapping_add(delta)) as *const ProgramHeader;
                break;
            }
        }
    }
    if phdr_ptr.is_null() {
        use crate::libc::fs::write;
        write::write_str(
            write::STD_ERR,
            "Error: could not resolve in-memory program header table\n",
        );
        exit::exit(1);
    }

    let entry = base.wrapping_add(header.e_entry);

    LoadedImage {
        base,
        entry,
        phdr: phdr_ptr,
        phnum: header.e_phnum as usize,
        phent: header.e_phentsize as usize,
        exec_dynamic,
        program_headers,
        has_dynamic: !exec_dynamic.is_null(),
        interpreter_path,
    }
}

unsafe fn write_hex(fd: i32, mut value: usize) {
    use crate::libc::fs::write;
    let mut buf = [0u8; 18];
    buf[0] = b'0';
    buf[1] = b'x';
    let hex = b"0123456789abcdef";
    for i in (0..16).rev() {
        buf[2 + i] = hex[value & 0xF];
        value >>= 4;
    }
    write::write_str(fd, core::str::from_utf8_unchecked(&buf));
}

