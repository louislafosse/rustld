use crate::arch;

pub(crate) unsafe fn bcmp(left_pointer: *const u8, right_pointer: *const u8, length: usize) -> i32 {
    memcmp(left_pointer, right_pointer, length)
}

pub(crate) unsafe fn memmove(
    destination: *mut u8,
    source: *const u8,
    number_of_bytes: usize,
) -> *mut u8 {
    arch::memmove(destination, source, number_of_bytes)
}

pub(crate) unsafe fn memcpy(
    destination: *mut u8,
    source: *const u8,
    number_of_bytes_to_copy: usize,
) -> *mut u8 {
    arch::memcpy(destination, source, number_of_bytes_to_copy)
}

pub(crate) unsafe fn memset(
    destination: *mut u8,
    single_byte_thats_32_bits_for_some_fucking_reason: u32, // I hate this stupid fucking API... Like why?
    number_of_bytes_to_set: usize,
) -> *mut u8 {
    arch::memset(
        destination,
        single_byte_thats_32_bits_for_some_fucking_reason as u8,
        number_of_bytes_to_set,
    )
}

pub(crate) unsafe fn memcmp(
    left_pointer: *const u8,
    right_pointer: *const u8,
    length_of_comparison: usize,
) -> i32 {
    arch::memcmp(left_pointer, right_pointer, length_of_comparison)
}
