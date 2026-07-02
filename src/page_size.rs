use std::sync::atomic::{AtomicUsize, Ordering};

// 0 means "not yet set"; readers fall back to a 4 KiB default so a lookup
// before `set_page_size` can never read uninitialized memory.
static PAGE_SIZE: AtomicUsize = AtomicUsize::new(0);

pub fn set_page_size(page_size: usize) {
    PAGE_SIZE.store(page_size, Ordering::Relaxed);
}

pub fn get_page_size() -> usize {
    match PAGE_SIZE.load(Ordering::Relaxed) {
        0 => 4096,
        size => size,
    }
}

pub fn get_page_start(address: usize) -> usize {
    address & !(get_page_size() - 1)
}

pub fn get_page_end(address: usize) -> usize {
    get_page_start(address + get_page_size() - 1)
}
