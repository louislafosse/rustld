use auxiliary_vector::{
    AuxiliaryVectorItem, AuxiliaryVectorUnion, AT_BASE, AT_BASE_PLATFORM, AT_ENTRY, AT_EXECFN,
    AT_HWCAP, AT_HWCAP2, AT_MINSIGSTKSZ, AT_NULL, AT_PAGE_SIZE, AT_PHDR, AT_PHENT, AT_PHNUM,
    AT_PLATFORM, AT_RANDOM,
};
use smallvec::SmallVec;

#[cfg(feature = "custom_start")]
use crate::ld_stubs::_dl_fini;
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
};
use core::cmp::{max, min};
use std::{
    ffi::c_char,
    ffi::{CStr, CString},
    mem::{size_of, MaybeUninit},
    ptr::{null, null_mut},
    slice,
};

pub mod auxiliary_vector;
pub mod environment_variables;

#[repr(C)]
pub struct JumpInfo {
    pub entry: usize,
    pub stack: usize,
}

const AUXV_MAX: usize = 64;
const SHN_ABS: u16 = 0xfff1;

unsafe fn dependency_init_order(linker: &DynamicLinker, start_idx: usize) -> SmallVec<[usize; 32]> {
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

        let object = &linker.objects[idx];
        for &needed_offset in &object.needed_libraries {
            let needed_name = unsafe { object.string_table.get(needed_offset) };
            if needed_name.is_empty() {
                continue;
            }
            if let Some(dep_idx) = linker.loaded_index(needed_name) {
                if dep_idx < linker.objects.len() && dep_idx != idx {
                    visit(dep_idx, start_idx, linker, state, order);
                }
            }
        }

        state[idx] = 2;
        order.push(idx);
    }

    let mut state = vec![0u8; linker.objects.len()];
    let mut order = SmallVec::<[usize; 32]>::new();
    order.reserve(linker.objects.len().saturating_sub(start_idx));
    for idx in start_idx..linker.objects.len() {
        visit(idx, start_idx, linker, &mut state, &mut order);
    }
    order
}

enum TargetImageSource<'a> {
    Path,
    Bytes(&'a [u8]),
}

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
    launch_target_with_source(
        target_argc,
        target_argv,
        env_pointer,
        TargetImageSource::Bytes(elf_bytes),
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
unsafe fn launch_target_with_source(
    target_argc: usize,
    target_argv: *const *const u8,
    env_pointer: *const *const u8,
    source: TargetImageSource<'_>,
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
    let target_path_string = cstr_ptr_to_string(target_path);

    let image = match source {
        TargetImageSource::Path => load_target_image(target_path),
        TargetImageSource::Bytes(bytes) => load_target_image_from_bytes(bytes),
    };
    let mut selected_entry = image.entry;

    if verbose {
        announce_target_elf_kind(&image);
    }
    try_chainload_musl_interpreter(
        &image,
        target_argc,
        target_argv,
        env_pointer,
        target_path_string.as_deref(),
    );
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
    set_auxv_val(&mut auxv_items, AT_HWCAP, hwcap);
    set_auxv_val(&mut auxv_items, AT_HWCAP2, hwcap2);
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
    maybe_force_c_locale(&mut env_list);
    let auxv_string_storage = stabilize_auxv_string_pointers(&mut auxv_items);
    let _leaked_auxv_string_storage = Box::leak(auxv_string_storage.into_boxed_slice());

    let new_stack = build_stack(target_args, &env_list, &auxv_items);
    let current_stack_end = current_stack_pointer();
    let new_argv = new_stack.add(1) as *const *const u8;
    let new_envp = new_argv.add(target_argc + 1);

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
                hwcap,
                hwcap2,
            );
        }
        let new_auxv = new_stack.add(1 + (target_argc + 1) + (env_list.len() + 1))
            as *const AuxiliaryVectorItem;
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

        #[cfg(target_arch = "aarch64")]
        if !musl_target {
            if let Some(interpreter_path) = image.interpreter_path.as_deref() {
                let interp_name = interpreter_name(interpreter_path);
                if !interp_name.is_empty() {
                    linker.load_library(interp_name, pseudorandom_bytes, Some(executable_idx));
                }
            }
        }

        // Load all required shared libraries recursively
        for needed_offset in needed_offsets {
            let lib_name = executable_string_table.get(needed_offset);
            if lib_name.is_empty() {
                continue;
            }
            linker.load_library(lib_name, pseudorandom_bytes, Some(executable_idx));
        }

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
        if !musl_target {
            linking::set_active_linker((&mut *linker) as *mut DynamicLinker);
        }

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
        if !musl_target {
            // Install TLS after relocations so TLS init images include relocated data.
            linker.install_tls(pseudorandom_bytes);
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
            }
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
            call_libc_early_init(&linker);
            #[cfg(target_arch = "x86_64")]
            patch_libc_copy_thresholds(&linker);
        }

        // Call init arrays for shared libraries (dependencies first).
        // musl's libc startup path runs its own initialization sequence.
        if !musl_target && linker.objects.len() > 1 {
            let skip_selinux_init = skip_selinux_ctors();
            for idx in dependency_init_order(&linker, 1) {
                if skip_selinux_init
                    && linker.objects[idx]
                        .soname_str()
                        .is_some_and(|soname| soname == "libselinux.so.1")
                {
                    continue;
                }
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
                linker.objects[idx].call_init_functions(target_argc, new_argv, new_envp, new_auxv);
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
        #[cfg(target_arch = "x86_64")]
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
        if !musl_target {
            linker.update_rtld_stack_end(new_stack as *const u8);
            let leaked = Box::leak(linker);
            linking::set_active_linker(leaked as *mut DynamicLinker);
        }
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
    let new_auxv =
        new_stack.add(1 + (target_argc + 1) + (env_list.len() + 1)) as *mut AuxiliaryVectorItem;
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

    for object in linker.objects.iter() {
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

    for object in linker.objects.iter() {
        for &(name, value) in writes {
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

unsafe fn call_libc_early_init(linker: &DynamicLinker) {
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
unsafe fn patch_libc_copy_thresholds(linker: &DynamicLinker) {
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
    const LIBC_REP_STOSB_THRESHOLD: usize = 0x1e9210;
    const LIBC_REP_MOVSB_THRESHOLD: usize = 0x1e9218;
    const LIBC_SHARED_CACHE_SIZE: usize = 0x1e9220;
    const LIBC_SHARED_CACHE_SIZE_HALF: usize = 0x1e9228;
    const LIBC_REP_MOVSB_STOP_THRESHOLD: usize = 0x1f02c8;
    const LIBC_MEMSET_NON_TEMPORAL_THRESHOLD: usize = 0x1f02d0;
    const LIBC_SHARED_NON_TEMPORAL_THRESHOLD: usize = 0x1f02d8;

    let libc_idx = linker
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
        });

    let Some(idx) = libc_idx else {
        return;
    };

    let base = linker.get_base(idx);
    let rep_stosb_ptr = (base.wrapping_add(LIBC_REP_STOSB_THRESHOLD)) as *mut usize;
    let rep_movsb_ptr = (base.wrapping_add(LIBC_REP_MOVSB_THRESHOLD)) as *mut usize;
    let rep_movsb_stop_ptr = (base.wrapping_add(LIBC_REP_MOVSB_STOP_THRESHOLD)) as *mut usize;
    let memset_non_temporal_ptr =
        (base.wrapping_add(LIBC_MEMSET_NON_TEMPORAL_THRESHOLD)) as *mut usize;
    let shared_non_temporal_ptr =
        (base.wrapping_add(LIBC_SHARED_NON_TEMPORAL_THRESHOLD)) as *mut usize;

    let shared_cache_size_ptr = (base.wrapping_add(LIBC_SHARED_CACHE_SIZE)) as *mut usize;
    let shared_cache_half_ptr = (base.wrapping_add(LIBC_SHARED_CACHE_SIZE_HALF)) as *mut usize;

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
    core::ptr::write_volatile(memset_non_temporal_ptr, usize::MAX);
    core::ptr::write_volatile(shared_non_temporal_ptr, usize::MAX);
    core::ptr::write_volatile(shared_cache_size_ptr, shared_cache_size);
    core::ptr::write_volatile(shared_cache_half_ptr, shared_cache_half);
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

unsafe fn auxv_lookup_value(auxv_pointer: *const AuxiliaryVectorItem, key: usize) -> Option<usize> {
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

fn interpreter_name(interpreter_path: &str) -> &str {
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

fn is_musl_target(image: &LoadedImage) -> bool {
    image
        .interpreter_path
        .as_deref()
        .is_some_and(|path| interpreter_name(path).contains("ld-musl"))
}

fn should_chainload_interpreter(image: &LoadedImage) -> bool {
    if is_musl_target(image) {
        return true;
    }

    #[cfg(target_arch = "aarch64")]
    {
        if let Some(path) = image.interpreter_path.as_deref() {
            let interp = interpreter_name(path);
            // AArch64 glibc compatibility mode: delegate startup to the
            // target interpreter until in-process rtld parity is complete.
            if interp.starts_with("ld-linux-aarch64") {
                return true;
            }
        }
    }

    false
}

fn derive_target_root_prefix(target_path: &str) -> Option<&str> {
    for marker in ["/usr/bin/", "/bin/", "/usr/sbin/", "/sbin/"] {
        if let Some(pos) = target_path.find(marker) {
            return Some(&target_path[..pos]);
        }
    }
    None
}

#[inline(always)]
unsafe fn try_chainload_musl_interpreter(
    image: &LoadedImage,
    target_argc: usize,
    target_argv: *const *const u8,
    env_pointer: *const *const u8,
    target_path_hint: Option<&str>,
) {
    if !should_chainload_interpreter(image) {
        return;
    }
    let Some(interpreter_path) = image.interpreter_path.as_deref() else {
        return;
    };
    let mut path_candidates: Vec<String> = vec![interpreter_path.to_string()];
    if interpreter_path.starts_with('/') {
        if let Some(target_path) = target_path_hint {
            if let Some(prefix) = derive_target_root_prefix(target_path) {
                let candidate = format!("{prefix}{interpreter_path}");
                if candidate != interpreter_path {
                    path_candidates.push(candidate);
                }
            }
        }
        if let Ok(prefix) = std::env::var("QEMU_LD_PREFIX") {
            let prefix = prefix.trim_end_matches('/');
            if !prefix.is_empty() {
                let candidate = format!("{prefix}{interpreter_path}");
                if candidate != interpreter_path && !path_candidates.iter().any(|c| c == &candidate)
                {
                    path_candidates.push(candidate);
                }
            }
        }
        if let Ok(ld_library_path) = std::env::var("LD_LIBRARY_PATH") {
            for entry in ld_library_path.split(':') {
                let entry = entry.trim_end_matches('/');
                if entry.is_empty() {
                    continue;
                }
                let prefix = if let Some(value) = entry.strip_suffix("/usr/lib64") {
                    value
                } else if let Some(value) = entry.strip_suffix("/usr/lib") {
                    value
                } else if let Some(value) = entry.strip_suffix("/lib64") {
                    value
                } else if let Some(value) = entry.strip_suffix("/lib") {
                    value
                } else {
                    continue;
                };
                if prefix.is_empty() {
                    continue;
                }
                let candidate = format!("{prefix}{interpreter_path}");
                if candidate != interpreter_path && !path_candidates.iter().any(|c| c == &candidate)
                {
                    path_candidates.push(candidate);
                }
            }
        }
    }

    for candidate in path_candidates {
        let Ok(interpreter_cstr) = CString::new(candidate) else {
            continue;
        };

        let mut argv = Vec::with_capacity(target_argc + 2);
        argv.push(interpreter_cstr.as_ptr() as *const u8);
        for arg_idx in 0..target_argc {
            argv.push(*target_argv.add(arg_idx));
        }
        argv.push(core::ptr::null());

        let result = execve_raw(
            interpreter_cstr.as_ptr() as *const u8,
            argv.as_ptr(),
            env_pointer,
        );
        if result == 0 {
            return;
        }
    }

    use crate::libc::fs::write;
    write::write_str(
        write::STD_ERR,
        "rustld: interpreter chainload failed, falling back\n",
    );
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

unsafe fn parse_interp_path_from_fd(fd: i32, program_headers: &[ProgramHeader]) -> Option<String> {
    let interp = program_headers.iter().find(|ph| ph.p_type == PT_INTERP)?;
    if interp.p_filesz == 0 {
        return None;
    }
    let mut bytes = vec![0u8; interp.p_filesz];
    pread_exact(fd, &mut bytes, interp.p_offset);
    let nul = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    if nul == 0 {
        return None;
    }
    let path = core::str::from_utf8(&bytes[..nul]).ok()?;
    Some(path.to_string())
}

fn maybe_force_c_locale(env: &mut Vec<*const u8>) {
    // Avoid locale initialization hangs by defaulting to C locale when
    // LC_ALL is unset and LANG is non-C.
    static mut LC_ALL_C: [u8; 9] = *b"LC_ALL=C\0";
    const LC_ALL_KEY: &[u8] = b"LC_ALL=";
    const LANG_KEY: &[u8] = b"LANG=";

    if env_find_key(env, LC_ALL_KEY).is_some() {
        return;
    }

    if let Some(lang) = env_find_key(env, LANG_KEY) {
        if lang == b"C" || lang == b"POSIX" {
            return;
        }
    }

    env.push(core::ptr::addr_of_mut!(LC_ALL_C).cast::<u8>() as *const u8);
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

fn env_find_key<'a>(env: &'a [*const u8], key: &[u8]) -> Option<&'a [u8]> {
    for &ptr in env.iter() {
        if ptr.is_null() {
            continue;
        }
        let bytes = unsafe { CStr::from_ptr(ptr.cast::<c_char>()).to_bytes() };
        if bytes.starts_with(key) {
            return Some(&bytes[key.len()..]);
        }
    }
    None
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

fn cstr_ptr_to_string(ptr: *const u8) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    let text = unsafe { CStr::from_ptr(ptr.cast::<c_char>()) }
        .to_string_lossy()
        .into_owned();
    Some(text)
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

#[inline(always)]
unsafe fn load_target_image(path: *const u8) -> LoadedImage {
    let fd = openat_readonly(path);
    if fd < 0 {
        use crate::libc::fs::write;
        write::write_str(write::STD_ERR, "Error: could not open target binary\n");
        exit::exit(1);
    }

    // Read ELF Header
    let mut uninit_header: MaybeUninit<ElfHeader> = MaybeUninit::uninit();
    let header_bytes = slice::from_raw_parts_mut(
        uninit_header.as_mut_ptr() as *mut u8,
        size_of::<ElfHeader>(),
    );
    pread_exact(fd, header_bytes, 0);
    let header = uninit_header.assume_init();

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

    // Read Program Headers
    let mut program_headers: Vec<ProgramHeader> = Vec::with_capacity(header.e_phnum as usize);
    let ph_bytes = slice::from_raw_parts_mut(
        program_headers.as_mut_ptr() as *mut u8,
        header.e_phnum as usize * size_of::<ProgramHeader>(),
    );
    pread_exact(fd, ph_bytes, header.e_phoff);
    program_headers.set_len(header.e_phnum as usize);

    let interpreter_path = parse_interp_path_from_fd(fd, &program_headers);
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
        if header.p_filesz > 0 {
            let segment = slice::from_raw_parts_mut(dest, header.p_filesz);
            pread_exact(fd, segment, header.p_offset);
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
    close_fd(fd);

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

unsafe fn calculate_virtual_address_bounds(
    program_header_table: &[ProgramHeader],
) -> (usize, usize) {
    let mut min_addr = usize::MAX;
    let mut max_addr = 0;

    for header in program_header_table {
        if header.p_type != PT_LOAD {
            continue;
        }

        let start = header.p_vaddr as usize;
        let end = start + header.p_memsz as usize;

        min_addr = min(min_addr, start);
        max_addr = max(max_addr, end);
    }

    (
        page_size::get_page_start(min_addr),
        page_size::get_page_end(max_addr),
    )
}

unsafe fn openat_readonly(path: *const u8) -> i32 {
    arch::openat_readonly(path.cast::<c_char>())
}

unsafe fn execve_raw(path: *const u8, argv: *const *const u8, envp: *const *const u8) -> isize {
    arch::execve(
        path.cast::<c_char>(),
        argv.cast::<*const c_char>(),
        envp.cast::<*const c_char>(),
    )
}

unsafe fn close_fd(fd: i32) {
    arch::close_fd(fd);
}

unsafe fn pread_exact(fd: i32, buf: &mut [u8], offset: usize) {
    let result = arch::pread(fd, buf.as_mut_ptr(), buf.len(), offset);

    if result != buf.len() as isize {
        use crate::libc::fs::write;
        write::write_str(write::STD_ERR, "Error: could not read from file\n");
        exit::exit(1);
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

#[inline(always)]
fn running_under_valgrind() -> bool {
    arch::running_under_valgrind()
}

#[inline(always)]
fn skip_selinux_ctors() -> bool {
    running_under_valgrind() || cfg!(target_arch = "aarch64")
}
