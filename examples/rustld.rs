use std::{ffi::OsStr, os::fd::AsRawFd, os::unix::ffi::OsStrExt};

use rustld::ElfLoader;

fn main() {
    unsafe {
        let argv_storage = collect_process_arguments();

        if argv_storage.len() < 2 {
            eprintln!(
                "Usage: rustld [--entry-symbol <name> | --entry-addr <addr>] <program> [args...]"
            );
            std::process::exit(1);
        }

        let mut args = argv_storage.into_iter();
        let _self_name = args.next();

        let mut entry_symbol: Option<String> = None;
        let mut entry_address: Option<usize> = None;
        let mut target_argv: Vec<String> = Vec::new();

        while let Some(arg) = args.next() {
            if arg == "--entry-symbol" {
                let Some(symbol) = args.next() else {
                    eprintln!("Error: --entry-symbol expects a value");
                    std::process::exit(1);
                };
                entry_symbol = Some(symbol);
                continue;
            }
            if arg == "--entry-addr" {
                let Some(raw_addr) = args.next() else {
                    eprintln!("Error: --entry-addr expects a value");
                    std::process::exit(1);
                };
                let parsed = parse_address(&raw_addr);
                entry_address = Some(parsed);
                continue;
            }

            target_argv.push(arg);
            target_argv.extend(args);
            break;
        }

        if target_argv.is_empty() {
            eprintln!("Error: missing target program path");
            std::process::exit(1);
        }
        if entry_symbol.is_some() && entry_address.is_some() {
            eprintln!("Error: --entry-symbol and --entry-addr are mutually exclusive");
            std::process::exit(1);
        }

        let target_bytes = map_file_readonly(OsStr::from_bytes(target_argv[0].as_bytes()));

        #[cfg(debug_assertions)]
        eprintln!("Executing target binary: {}", target_argv[0]);
        if entry_symbol.is_some() || entry_address.is_some() {
            ElfLoader::new_with_obf(true).execute_from_bytes_with_entry(
                target_bytes,
                target_argv,
                entry_symbol.as_deref(),
                entry_address,
                None,
                None,
                false,
            );
        } else {
            ElfLoader::new_with_obf(true).execute_from_bytes(target_bytes, target_argv, None, None, false);
        }
    }
}

fn parse_address(raw: &str) -> usize {
    let (digits, radix) = if let Some(hex) = raw.strip_prefix("0x") {
        (hex, 16)
    } else if let Some(hex) = raw.strip_prefix("0X") {
        (hex, 16)
    } else {
        (raw, 10)
    };

    match usize::from_str_radix(digits, radix) {
        Ok(value) => value,
        Err(_) => {
            eprintln!("Error: invalid entry address: {raw}");
            std::process::exit(1);
        }
    }
}

fn collect_process_arguments() -> Vec<String> {
    std::env::args_os()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect()
}

unsafe fn map_file_readonly(path: &OsStr) -> &'static [u8] {
    use rustld::syscall::mmap::{self, MAP_PRIVATE, PROT_READ};

    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(error) => {
            eprintln!("Error: could not open target binary: {error}");
            std::process::exit(1);
        }
    };

    let length = match file.metadata() {
        Ok(metadata) => metadata.len() as usize,
        Err(error) => {
            eprintln!("Error: could not stat target binary: {error}");
            std::process::exit(1);
        }
    };

    if length == 0 {
        eprintln!("Error: target binary is empty");
        std::process::exit(1);
    }

    let mapped = mmap::mmap(
        core::ptr::null_mut(),
        length,
        PROT_READ,
        MAP_PRIVATE,
        file.as_raw_fd() as isize,
        0,
    );
    let mapped_addr = mapped as isize;
    if mapped_addr < 0 {
        eprintln!("Error: could not map target binary");
        std::process::exit(1);
    }

    core::mem::drop(file);
    core::slice::from_raw_parts(mapped as *const u8, length)
}
