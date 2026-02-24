use std::{ffi::OsStr, os::fd::AsRawFd, os::unix::ffi::OsStrExt};

use rustld::ElfLoader;

fn main() {
    unsafe {
        let argv_storage = collect_process_arguments();

        if argv_storage.len() < 2 {
            eprintln!("Usage: rustld <program> [args...]");
            std::process::exit(1);
        }

        let target_bytes = map_file_readonly(OsStr::from_bytes(argv_storage[1].as_bytes()));
        let target_argv: Vec<String> = argv_storage.into_iter().skip(1).collect();

        #[cfg(debug_assertions)]
        eprintln!("Executing target binary: {}", target_argv[0]);
        ElfLoader::execute_from_bytes(target_bytes, target_argv, None, None, false);
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
