use crate::{
    elf::relocate::Relocatable,
    io_macros::syscall_assert,
    linking::DynamicLinker,
    page_size::get_page_size,
    relocation_common::*,
};

use super::mmap::{mprotect, PROT_READ, PROT_WRITE};

pub use crate::relocation_common::SymbolLookupCache;

#[inline(always)]
fn prefer_stub_first(symbol_name: &str) -> bool {
    let name = symbol_without_version(symbol_name);
    name.starts_with("_dl_")
        || name.starts_with("__tunable_")
        || matches!(
            name,
            "__nptl_change_stack_perm"
                | "__tls_get_addr"
                | "dlsym"
                | "dlvsym"
                | "dlopen"
                | "dlclose"
                | "dlerror"
                | "dladdr"
                | "dladdr1"
                | "dl_iterate_phdr"
                | "is_selinux_enabled"
                | "freecon"
                | "getcon"
                | "getfilecon"
                | "lgetfilecon"
                | "fgetfilecon"
                | "getfilecon_raw"
        )
}


pub unsafe fn relocate_with_linker(
    object: &impl Relocatable,
    object_index: usize,
    linker: &DynamicLinker,
    ifuncs: &mut Vec<IrelativeReloc>,
    copies: &mut Vec<CopyReloc>,
    lookup_cache: &mut SymbolLookupCache,
) {
    let relocation_slices = object.relocation_slices();

    if !relocation_slices.rela_slice.is_empty() || !relocation_slices.relr_slice.is_empty() {
        let page_size = get_page_size();
        let mut min_addr = usize::MAX;
        let mut max_addr = 0usize;

        for rela in relocation_slices.rela_slice {
            let addr = rela.r_offset.wrapping_add(object.base());
            if addr < min_addr {
                min_addr = addr;
            }
            if addr > max_addr {
                max_addr = addr;
            }
        }

        if let Some((relr_min, relr_max)) =
            relr_address_range(object.base(), relocation_slices.relr_slice)
        {
            if relr_min < min_addr {
                min_addr = relr_min;
            }
            if relr_max > max_addr {
                max_addr = relr_max;
            }
        }

        if min_addr != usize::MAX {
            let start_page = (min_addr / page_size) * page_size;
            let end_page = ((max_addr + 15 + page_size - 1) / page_size) * page_size;
            let length = end_page - start_page;
            let _ = mprotect(start_page as *mut u8, length, PROT_READ | PROT_WRITE);
        }
    }

    const R_AARCH64_NONE: u32 = 0;
    const R_AARCH64_ABS64: u32 = 257;
    const R_AARCH64_ABS32: u32 = 258;
    const R_AARCH64_ABS16: u32 = 259;
    const R_AARCH64_COPY: u32 = 1024;
    const R_AARCH64_GLOB_DAT: u32 = 1025;
    const R_AARCH64_JUMP_SLOT: u32 = 1026;
    const R_AARCH64_RELATIVE: u32 = 1027;
    const R_AARCH64_TLS_DTPMOD64: u32 = 1028;
    const R_AARCH64_TLS_DTPREL64: u32 = 1029;
    const R_AARCH64_TLS_TPREL64: u32 = 1030;
    const R_AARCH64_TLSDESC: u32 = 1031;
    const R_AARCH64_IRELATIVE: u32 = 1032;

    for rela in relocation_slices.rela_slice {
        let relocate_address = rela.r_offset.wrapping_add(object.base());

        match rela.r_type() {
            R_AARCH64_NONE => {}
            R_AARCH64_ABS64 | R_AARCH64_GLOB_DAT | R_AARCH64_JUMP_SLOT => {
                let symbol = object.symbol(rela.r_sym() as usize);
                let symbol_name = linker.objects[object_index]
                    .string_table
                    .get(symbol.st_name as usize);
                if should_keep_weak_init_fini_undef(symbol, symbol_name) {
                    if rela.r_type() == R_AARCH64_ABS64 {
                        core::ptr::write(relocate_address as *mut usize, rela.r_addend as usize);
                    } else {
                        core::ptr::write(relocate_address as *mut usize, 0);
                    }
                    continue;
                }
                let prefer_stub = prefer_stub_first(symbol_name);
                let (mut symbol_addr, symbol_type) = if prefer_stub {
                    if let Some(stub_addr) = get_stub_symbol_any(symbol_name) {
                        #[cfg(debug_assertions)]
                        {
                            if symbol_name.starts_with("_dl_")
                                || symbol_name.starts_with("__tunable_")
                                || symbol_name == "__tls_get_addr"
                            {
                                use crate::libc::fs::write;
                                write::write_str(write::STD_ERR, "symbind ");
                                write::write_str(write::STD_ERR, symbol_name);
                                write::write_str(write::STD_ERR, " -> <stub-pre>\n");
                            }
                        }
                        (stub_addr, 0)
                    } else if let Some((lib_idx, resolved_symbol)) =
                        lookup_symbol_any(linker, object_index, symbol_name, None, lookup_cache)
                    {
                        let base = if resolved_symbol.st_shndx == SHN_ABS {
                            0
                        } else {
                            linker.get_base(lib_idx)
                        };
                        (
                            resolved_symbol.st_value.wrapping_add(base),
                            resolved_symbol.st_info & 0x0f,
                        )
                    } else if symbol.st_shndx == SHN_UNDEF {
                        if symbol_binding(symbol) != STB_WEAK {
                            unresolved_nonweak_symbol(
                                linker,
                                object_index,
                                symbol_name,
                                "R_AARCH64_ABS64/GLOB_DAT/JUMP_SLOT",
                            );
                        }
                        (0usize, symbol.st_info & 0x0f)
                    } else {
                        let base = if symbol.st_shndx == SHN_ABS {
                            0
                        } else {
                            object.base()
                        };
                        (symbol.st_value.wrapping_add(base), symbol.st_info & 0x0f)
                    }
                } else if let Some((lib_idx, resolved_symbol)) =
                    lookup_symbol_any(linker, object_index, symbol_name, None, lookup_cache)
                {
                    #[cfg(debug_assertions)]
                    {
                        if symbol_name.starts_with("_dl_")
                            || symbol_name.starts_with("__tunable_")
                            || symbol_name == "__tls_get_addr"
                        {
                            use crate::libc::fs::write;
                            write::write_str(write::STD_ERR, "symbind ");
                            write::write_str(write::STD_ERR, symbol_name);
                            write::write_str(write::STD_ERR, " -> obj=");
                            if let Some(path) = linker.object_path(lib_idx) {
                                write::write_str(write::STD_ERR, path);
                            } else {
                                write::write_str(write::STD_ERR, "<unknown>");
                            }
                            write::write_str(write::STD_ERR, "\n");
                        }
                    }
                    let base = if resolved_symbol.st_shndx == SHN_ABS {
                        0
                    } else {
                        linker.get_base(lib_idx)
                    };
                    (
                        resolved_symbol.st_value.wrapping_add(base),
                        resolved_symbol.st_info & 0x0f,
                    )
                } else if let Some(stub_addr) = get_stub_symbol_any(symbol_name) {
                    #[cfg(debug_assertions)]
                    {
                        if symbol_name.starts_with("_dl_")
                            || symbol_name.starts_with("__tunable_")
                            || symbol_name == "__tls_get_addr"
                        {
                            use crate::libc::fs::write;
                            write::write_str(write::STD_ERR, "symbind ");
                            write::write_str(write::STD_ERR, symbol_name);
                            write::write_str(write::STD_ERR, " -> <stub>\n");
                        }
                    }
                    (stub_addr, 0)
                } else if symbol.st_shndx == SHN_UNDEF {
                    if symbol_binding(symbol) != STB_WEAK {
                        unresolved_nonweak_symbol(
                            linker,
                            object_index,
                            symbol_name,
                            "R_AARCH64_ABS64/GLOB_DAT/JUMP_SLOT",
                        );
                    }
                    (0usize, symbol.st_info & 0x0f)
                } else {
                    let base = if symbol.st_shndx == SHN_ABS {
                        0
                    } else {
                        object.base()
                    };
                    (symbol.st_value.wrapping_add(base), symbol.st_info & 0x0f)
                };

                if rela.r_type() == R_AARCH64_ABS64 {
                    symbol_addr = symbol_addr.wrapping_add_signed(rela.r_addend);
                }

                if symbol_type == STT_GNU_IFUNC {
                    ifuncs.push(IrelativeReloc {
                        relocate_address,
                        function_pointer: symbol_addr,
                    });
                } else {
                    core::ptr::write(relocate_address as *mut usize, symbol_addr);
                }
            }
            R_AARCH64_ABS32 => {
                let symbol = object.symbol(rela.r_sym() as usize);
                let symbol_name = linker.objects[object_index]
                    .string_table
                    .get(symbol.st_name as usize);
                let resolved =
                    lookup_symbol_any(linker, object_index, symbol_name, None, lookup_cache);
                let symbol_addr = if let Some((lib_idx, resolved_symbol)) = resolved {
                    let base = if resolved_symbol.st_shndx == SHN_ABS {
                        0
                    } else {
                        linker.get_base(lib_idx)
                    };
                    resolved_symbol.st_value.wrapping_add(base)
                } else if symbol.st_shndx == SHN_UNDEF {
                    0
                } else {
                    object.base().wrapping_add(symbol.st_value)
                };
                core::ptr::write(
                    relocate_address as *mut u32,
                    symbol_addr.wrapping_add_signed(rela.r_addend) as u32,
                );
            }
            R_AARCH64_ABS16 => {
                let symbol = object.symbol(rela.r_sym() as usize);
                let symbol_name = linker.objects[object_index]
                    .string_table
                    .get(symbol.st_name as usize);
                let resolved =
                    lookup_symbol_any(linker, object_index, symbol_name, None, lookup_cache);
                let symbol_addr = if let Some((lib_idx, resolved_symbol)) = resolved {
                    let base = if resolved_symbol.st_shndx == SHN_ABS {
                        0
                    } else {
                        linker.get_base(lib_idx)
                    };
                    resolved_symbol.st_value.wrapping_add(base)
                } else if symbol.st_shndx == SHN_UNDEF {
                    0
                } else {
                    object.base().wrapping_add(symbol.st_value)
                };
                core::ptr::write(
                    relocate_address as *mut u16,
                    symbol_addr.wrapping_add_signed(rela.r_addend) as u16,
                );
            }
            R_AARCH64_RELATIVE => {
                let relocate_value = object.base().wrapping_add_signed(rela.r_addend);
                core::ptr::write(relocate_address as *mut usize, relocate_value);
            }
            R_AARCH64_COPY => {
                let symbol = object.symbol(rela.r_sym() as usize);
                let symbol_name = linker.objects[object_index]
                    .string_table
                    .get(symbol.st_name as usize);

                if let Some((lib_idx, resolved_symbol)) = lookup_symbol_any(
                    linker,
                    object_index,
                    symbol_name,
                    Some(object_index),
                    lookup_cache,
                ) {
                    let base = if resolved_symbol.st_shndx == SHN_ABS {
                        0
                    } else {
                        linker.get_base(lib_idx)
                    };
                    let source_address = resolved_symbol.st_value.wrapping_add(base);
                    let size = if symbol.st_size != 0 {
                        symbol.st_size as usize
                    } else {
                        resolved_symbol.st_size as usize
                    };
                    copies.push(CopyReloc {
                        destination_address: relocate_address,
                        source_address,
                        size,
                    });
                }
            }
            R_AARCH64_IRELATIVE => {
                let function_pointer = object.base().wrapping_add_signed(rela.r_addend);
                ifuncs.push(IrelativeReloc {
                    relocate_address,
                    function_pointer,
                });
            }
            R_AARCH64_TLS_DTPMOD64 => {
                let symbol = object.symbol(rela.r_sym() as usize);
                let symbol_name = linker.objects[object_index]
                    .string_table
                    .get(symbol.st_name as usize);
                let (def_idx, _def_sym) =
                    resolve_tls_symbol(object_index, symbol, symbol_name, linker, lookup_cache);
                let module_id = linker.objects[def_idx]
                    .tls
                    .as_ref()
                    .map(|tls| tls.module_id)
                    .unwrap_or(0);
                core::ptr::write(relocate_address as *mut usize, module_id);
            }
            R_AARCH64_TLS_DTPREL64 => {
                let symbol = object.symbol(rela.r_sym() as usize);
                let symbol_name = linker.objects[object_index]
                    .string_table
                    .get(symbol.st_name as usize);
                let (_def_idx, def_sym) =
                    resolve_tls_symbol(object_index, symbol, symbol_name, linker, lookup_cache);
                let relocate_value = def_sym.st_value.wrapping_add_signed(rela.r_addend);
                core::ptr::write(relocate_address as *mut usize, relocate_value);
            }
            R_AARCH64_TLS_TPREL64 => {
                let symbol = object.symbol(rela.r_sym() as usize);
                let symbol_name = linker.objects[object_index]
                    .string_table
                    .get(symbol.st_name as usize);
                let (def_idx, def_sym) =
                    resolve_tls_symbol(object_index, symbol, symbol_name, linker, lookup_cache);
                let tls_offset = linker.objects[def_idx]
                    .tls
                    .as_ref()
                    .map(|tls| tls.offset)
                    .unwrap_or(0);
                let relocate_value = tls_offset
                    .wrapping_add(def_sym.st_value as isize)
                    .wrapping_add(rela.r_addend);
                core::ptr::write(relocate_address as *mut usize, relocate_value as usize);
                #[cfg(debug_assertions)]
                {
                    if let Some(path) = linker.object_path(object_index) {
                        if path.contains("libc.so.6")
                            && matches!(
                                rela.r_addend as usize,
                                0x0 | 0x8 | 0x10 | 0x18 | 0x20 | 0x30 | 0x38 | 0x50 | 0x58
                            )
                        {
                            use crate::libc::fs::write;
                            write::write_str(write::STD_ERR, "tls-tprel libc addend=");
                            write_hex(write::STD_ERR, rela.r_addend as usize);
                            write::write_str(write::STD_ERR, " value=");
                            write_hex(write::STD_ERR, relocate_value as usize);
                            write::write_str(write::STD_ERR, " def=");
                            if let Some(def_path) = linker.object_path(def_idx) {
                                write::write_str(write::STD_ERR, def_path);
                            } else {
                                write::write_str(write::STD_ERR, "<unknown>");
                            }
                            write::write_str(write::STD_ERR, " tls_off=");
                            write_hex(write::STD_ERR, tls_offset as usize);
                            write::write_str(write::STD_ERR, "\n");
                        }
                    }
                }
            }
            R_AARCH64_TLSDESC => {
                let symbol = object.symbol(rela.r_sym() as usize);
                let symbol_name = linker.objects[object_index]
                    .string_table
                    .get(symbol.st_name as usize);
                let (def_idx, def_sym) =
                    resolve_tls_symbol(object_index, symbol, symbol_name, linker, lookup_cache);
                let tls_meta = linker.objects[def_idx].tls.as_ref();
                let (module_id, tls_offset, has_static_offset) = tls_meta
                    .map(|tls| {
                        (
                            tls.module_id,
                            tls.offset,
                            // Static TLS modules are assigned a concrete TP-relative
                            // offset during prepare_tls_layout(). Keep TLSDESC in the
                            // static fast path whenever that offset is known.
                            tls.offset != 0,
                        )
                    })
                    .unwrap_or((0, 0, false));
                let dtpoff = def_sym.st_value.wrapping_add_signed(rela.r_addend);
                let desc = relocate_address as *mut usize;
                if has_static_offset {
                    let tprel = tls_offset
                        .wrapping_add(def_sym.st_value as isize)
                        .wrapping_add(rela.r_addend);
                    core::ptr::write(desc, crate::arch::tlsdesc_return_addr());
                    core::ptr::write(desc.add(1), tprel as usize);
                } else if module_id != 0 {
                    let ti = std::boxed::Box::new(crate::ld_stubs::TlsIndex {
                        ti_module: module_id,
                        ti_offset: dtpoff,
                    });
                    core::ptr::write(desc, crate::arch::tlsdesc_resolver_addr());
                    core::ptr::write(desc.add(1), std::boxed::Box::into_raw(ti) as usize);
                } else {
                    let tprel = tls_offset
                        .wrapping_add(def_sym.st_value as isize)
                        .wrapping_add(rela.r_addend);
                    core::ptr::write(desc, crate::arch::tlsdesc_return_addr());
                    core::ptr::write(desc.add(1), tprel as usize);
                }
            }
            reloc_type => {
                use crate::libc::fs::write;
                write::write_str(write::STD_ERR, "Unsupported AArch64 relocation type: ");
                write_hex(write::STD_ERR, reloc_type as usize);
                write::write_str(write::STD_ERR, " object=");
                if let Some(path) = linker.object_path(object_index) {
                    write::write_str(write::STD_ERR, path);
                } else {
                    write::write_str(write::STD_ERR, "<unknown>");
                }
                write::write_str(write::STD_ERR, " r_offset=");
                write_hex(write::STD_ERR, rela.r_offset);
                write::write_str(write::STD_ERR, " r_info=");
                write_hex(write::STD_ERR, rela.r_info);
                write::write_str(write::STD_ERR, "\n");
                syscall_assert!(false, "unsupported relocation");
            }
        }
    }

    apply_relr_relocations(object.base(), relocation_slices.relr_slice);
}

pub unsafe fn apply_irelative_relocations(ifuncs: &[IrelativeReloc]) {
    for ifunc in ifuncs {
        let function: extern "C" fn() -> usize = core::mem::transmute(ifunc.function_pointer);
        let relocate_value = function();
        core::ptr::write(ifunc.relocate_address as *mut usize, relocate_value);
    }
}

pub unsafe fn apply_copy_relocations(copies: &[CopyReloc]) {
    for copy in copies {
        if copy.size == 0 {
            continue;
        }
        core::ptr::copy_nonoverlapping(
            copy.source_address as *const u8,
            copy.destination_address as *mut u8,
            copy.size,
        );
    }
}

pub unsafe fn relocate(object: &impl Relocatable) {
    let relocation_slices = object.relocation_slices();

    if !relocation_slices.rela_slice.is_empty() || !relocation_slices.relr_slice.is_empty() {
        let page_size = get_page_size();
        let mut min_addr = usize::MAX;
        let mut max_addr = 0usize;

        for rela in relocation_slices.rela_slice {
            let addr = rela.r_offset.wrapping_add(object.base());
            if addr < min_addr {
                min_addr = addr;
            }
            if addr > max_addr {
                max_addr = addr;
            }
        }

        if let Some((relr_min, relr_max)) =
            relr_address_range(object.base(), relocation_slices.relr_slice)
        {
            if relr_min < min_addr {
                min_addr = relr_min;
            }
            if relr_max > max_addr {
                max_addr = relr_max;
            }
        }

        if min_addr != usize::MAX {
            let start_page = (min_addr / page_size) * page_size;
            let end_page = ((max_addr + 15 + page_size - 1) / page_size) * page_size;
            let length = end_page - start_page;
            let _ = mprotect(start_page as *mut u8, length, PROT_READ | PROT_WRITE);
        }
    }

    const R_AARCH64_ABS64: u32 = 257;
    const R_AARCH64_RELATIVE: u32 = 1027;
    const R_AARCH64_IRELATIVE: u32 = 1032;

    for rela in relocation_slices.rela_slice {
        let relocate_address = rela.r_offset.wrapping_add(object.base());

        match rela.r_type() {
            R_AARCH64_ABS64 => {
                let relocate_value = object
                    .symbol(rela.r_sym() as usize)
                    .st_value
                    .wrapping_add(object.base())
                    .wrapping_add_signed(rela.r_addend);
                core::ptr::write(relocate_address as *mut usize, relocate_value);
            }
            R_AARCH64_RELATIVE => {
                let relocate_value = object.base().wrapping_add_signed(rela.r_addend);
                core::ptr::write(relocate_address as *mut usize, relocate_value);
            }
            R_AARCH64_IRELATIVE => {
                let function_pointer = object.base().wrapping_add_signed(rela.r_addend);
                let function: extern "C" fn() -> usize = core::mem::transmute(function_pointer);
                let relocate_value = function();
                core::ptr::write(relocate_address as *mut usize, relocate_value);
            }
            _ => {}
        }
    }

    apply_relr_relocations(object.base(), relocation_slices.relr_slice);
}
