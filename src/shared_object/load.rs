use super::*;

impl SharedObject {
    #[inline(always)]
    pub unsafe fn from_loaded(base_addr: usize, program_header_table: &[ProgramHeader]) -> Self {
        let (min_addr, max_addr) = calculate_virtual_address_bounds(program_header_table);
        let map_start = base_addr.wrapping_add(min_addr);
        let map_end = base_addr.wrapping_add(max_addr);
        let load_segments = collect_load_segment_ranges(base_addr, program_header_table);

        let (mut dynamic_header, mut tls_program_header, mut eh_frame_header) = (None, None, None);
        for header in program_header_table {
            match header.p_type {
                PT_DYNAMIC => dynamic_header = Some(header),
                PT_TLS => tls_program_header = Some(header),
                PT_GNU_EH_FRAME => eh_frame_header = Some(header),
                _ => (),
            }
        }

        let tls = tls_program_header.map(|header| TlsInfo::from_program_header(base_addr, header));
        let eh_frame = eh_frame_header
            .map(|header| (base_addr.wrapping_add(header.p_vaddr)) as *const u8)
            .unwrap_or(null());

        match dynamic_header {
            Some(dynamic) => Self::build(
                base_addr,
                dynamic,
                tls,
                map_start,
                map_end,
                load_segments,
                eh_frame,
            ),
            None => Self::build_static(base_addr, tls, map_start, map_end, load_segments, eh_frame),
        }
    }

    pub unsafe fn from_fd(fd: i32) -> Self {
        #[cfg(debug_assertions)]
        {
            write::write_str(write::STD_OUT, "from_fd: Reading ELF header...\n");
        }

        // Read ELF Header using pread syscall
        let mut uninit_header: MaybeUninit<ElfHeader> = MaybeUninit::uninit();
        let as_bytes = slice::from_raw_parts_mut(
            uninit_header.as_mut_ptr() as *mut u8,
            size_of::<ElfHeader>(),
        );

        let mut result = arch::pread(fd, as_bytes.as_mut_ptr(), as_bytes.len(), 0);

        if result != size_of::<ElfHeader>() as isize {
            write::write_str(
                write::STD_ERR,
                "Error: could not read ElfHeader from file\n",
            );
            exit::exit(1);
        }

        let header = uninit_header.assume_init();

        // Reject anything that is not a 64-bit ELF for the host architecture
        // before trusting header fields (phnum, offsets) drawn from the file.
        #[cfg(target_arch = "x86_64")]
        const EXPECTED_MACHINE: u16 = 62; // EM_X86_64
        #[cfg(target_arch = "aarch64")]
        const EXPECTED_MACHINE: u16 = 183; // EM_AARCH64
        if header.e_ident[0..4] != [0x7F, b'E', b'L', b'F']
            || header.e_ident[4] != 2
            || header.e_machine != EXPECTED_MACHINE
        {
            write::write_str(write::STD_ERR, "Error: not a supported ELF object\n");
            exit::exit(1);
        }

        #[cfg(debug_assertions)]
        {
            write::write_str(write::STD_OUT, "from_fd: Read ELF header\n");
        }

        // Read Program Headers
        let mut program_header_table: Vec<ProgramHeader> =
            Vec::with_capacity(header.e_phnum as usize);
        let as_bytes = slice::from_raw_parts_mut(
            program_header_table.as_mut_ptr() as *mut u8,
            header.e_phnum as usize * size_of::<ProgramHeader>(),
        );

        result = arch::pread(
            fd,
            as_bytes.as_mut_ptr(),
            as_bytes.len(),
            header.e_phoff as usize,
        );

        if result != (header.e_phnum as usize * size_of::<ProgramHeader>()) as isize {
            write::write_str(
                write::STD_ERR,
                "Error: could not read &[ProgramHeader] from file\n",
            );
            exit::exit(1);
        }

        program_header_table.set_len(header.e_phnum as usize);
        #[cfg(debug_assertions)]
        {
            write::write_str(write::STD_OUT, "from_fd: Read program headers\n");
        }

        let (min_addr, max_addr) = calculate_virtual_address_bounds(&program_header_table);
        #[cfg(debug_assertions)]
        {
            write::write_str(
                write::STD_OUT,
                "from_fd: Calculated virtual address bounds\n",
            );
        }

        let reservation = mmap::mmap(
            null_mut(),
            max_addr - min_addr,
            mmap::PROT_NONE,
            mmap::MAP_PRIVATE | mmap::MAP_ANONYMOUS,
            -1,
            0,
        );
        if reservation.is_null() || (reservation as isize) < 0 {
            write::write_str(
                write::STD_ERR,
                "Error: could not reserve memory for PT_LOAD segments\n",
            );
            exit::exit(1);
        }

        // `base_addr + p_vaddr` yields the in-memory address for each ELF virtual address.
        let base_addr = (reservation as usize).wrapping_sub(min_addr);

        #[cfg(debug_assertions)]
        {
            write::write_str(write::STD_OUT, "from_fd: Allocated memory for library\n");
        }

        let map_start = base_addr.wrapping_add(min_addr);
        let map_end = base_addr.wrapping_add(max_addr);
        let load_segments = collect_load_segment_ranges(base_addr, &program_header_table);
        let (mut dynamic_header, mut tls_program_header, mut eh_frame_header) = (None, None, None);
        for header in &program_header_table {
            match header.p_type {
                PT_DYNAMIC => dynamic_header = Some(header),
                PT_TLS => tls_program_header = Some(header),
                PT_GNU_EH_FRAME => eh_frame_header = Some(header),
                PT_LOAD => {
                    let segment_map_start = page_size::get_page_start(header.p_vaddr);
                    let segment_file_offset = page_size::get_page_start(header.p_offset);
                    let segment_file_map_end =
                        page_size::get_page_end(header.p_vaddr.wrapping_add(header.p_filesz));
                    let segment_mem_map_end =
                        page_size::get_page_end(header.p_vaddr.wrapping_add(header.p_memsz));
                    let protection = segment_protection_from_flags(header.p_flags);

                    if header.p_filesz > 0 {
                        let file_map_len = segment_file_map_end.saturating_sub(segment_map_start);
                        let file_map_addr = (base_addr + segment_map_start) as *mut u8;
                        let mapped = mmap::mmap(
                            file_map_addr,
                            file_map_len,
                            protection,
                            mmap::MAP_PRIVATE | mmap::MAP_FIXED,
                            fd as isize,
                            segment_file_offset,
                        );
                        if mapped != file_map_addr {
                            write::write_str(
                                write::STD_ERR,
                                "Error: could not mmap PT_LOAD file segment\n",
                            );
                            exit::exit(1);
                        }
                    }

                    if header.p_filesz == 0 && header.p_memsz > 0 {
                        let bss_map_len = segment_mem_map_end.saturating_sub(segment_map_start);
                        let bss_map_addr = (base_addr + segment_map_start) as *mut u8;
                        let mapped = mmap::mmap(
                            bss_map_addr,
                            bss_map_len,
                            protection,
                            mmap::MAP_PRIVATE | mmap::MAP_ANONYMOUS | mmap::MAP_FIXED,
                            -1,
                            0,
                        );
                        if mapped != bss_map_addr {
                            write::write_str(
                                write::STD_ERR,
                                "Error: could not mmap PT_LOAD bss segment\n",
                            );
                            exit::exit(1);
                        }
                        // Anonymous mappings are already zero-filled by kernel.
                        #[cfg(debug_assertions)]
                        core::ptr::write_bytes(bss_map_addr, 0, bss_map_len);
                    } else if header.p_memsz > header.p_filesz {
                        let zero_start = base_addr + header.p_vaddr + header.p_filesz;
                        let zero_end = base_addr + header.p_vaddr + header.p_memsz;
                        let zero_page_start = page_size::get_page_end(zero_start);

                        if zero_start < zero_page_start {
                            let partial_zero_end = min(zero_page_start, zero_end);
                            let page_start = page_size::get_page_start(zero_start);
                            let page_len = zero_page_start.saturating_sub(page_start);
                            let prefix_len = zero_start.saturating_sub(page_start);

                            // Avoid writing directly into the file-backed partial tail page.
                            // Some host/kernel combinations are unhappy about zeroing the
                            // beyond-EOF bytes of that mapping in place, so rebuild the page
                            // as anonymous memory, restore the initialized prefix, and then
                            // zero the BSS tail.
                            let mut prefix = Vec::with_capacity(prefix_len);
                            prefix.set_len(prefix_len);
                            core::ptr::copy_nonoverlapping(
                                page_start as *const u8,
                                prefix.as_mut_ptr(),
                                prefix_len,
                            );

                            let page_addr = page_start as *mut u8;
                            let mapped = mmap::mmap(
                                page_addr,
                                page_len,
                                protection,
                                mmap::MAP_PRIVATE | mmap::MAP_ANONYMOUS | mmap::MAP_FIXED,
                                -1,
                                0,
                            );
                            if mapped != page_addr {
                                write::write_str(
                                    write::STD_ERR,
                                    "Error: could not remap PT_LOAD partial bss page\n",
                                );
                                exit::exit(1);
                            }

                            if prefix_len > 0 {
                                core::ptr::copy_nonoverlapping(
                                    prefix.as_ptr(),
                                    page_addr,
                                    prefix_len,
                                );
                            }
                            core::ptr::write_bytes(
                                zero_start as *mut u8,
                                0,
                                partial_zero_end.saturating_sub(zero_start),
                            );
                        }

                        if zero_end > zero_page_start {
                            let anon_map_len =
                                page_size::get_page_end(zero_end).saturating_sub(zero_page_start);
                            let anon_map_addr = zero_page_start as *mut u8;
                            let mapped = mmap::mmap(
                                anon_map_addr,
                                anon_map_len,
                                protection,
                                mmap::MAP_PRIVATE | mmap::MAP_ANONYMOUS | mmap::MAP_FIXED,
                                -1,
                                0,
                            );
                            if mapped != anon_map_addr {
                                write::write_str(
                                    write::STD_ERR,
                                    "Error: could not mmap PT_LOAD bss tail\n",
                                );
                                exit::exit(1);
                            }
                            // Anonymous mappings are already zero-filled by kernel.
                            #[cfg(debug_assertions)]
                            core::ptr::write_bytes(anon_map_addr, 0, anon_map_len);
                        }
                    }
                }
                _ => (),
            }
        }

        #[cfg(debug_assertions)]
        {
            write::write_str(write::STD_OUT, "from_fd: Loaded all segments\n");
        }

        let tls = tls_program_header.map(|header| TlsInfo::from_program_header(base_addr, header));
        let eh_frame = eh_frame_header
            .map(|header| (base_addr.wrapping_add(header.p_vaddr)) as *const u8)
            .unwrap_or(null());

        let dynamic_header = match dynamic_header {
            Some(header) => header,
            None => {
                write::write_str(write::STD_ERR, "Error: ELF object has no PT_DYNAMIC\n");
                exit::exit(1);
            }
        };

        Self::build(
            base_addr,
            dynamic_header,
            tls,
            map_start,
            map_end,
            load_segments,
            eh_frame,
        )
    }
}
