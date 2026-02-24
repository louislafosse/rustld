use core::{slice, str};
use memchr::memchr;

/// A collection of null-terminated strings stored in contiguous memory.
///
/// The initial pointer can be found via the `DT_STRTAB` entry in the dynamic array. The first and last index are guaranteed to be null.
/// To get the string at index `i`, start at the `i`th byte and read until a null byte is encountered.
///
/// The following shows a string table with 38 bytes and example string locations:
/// ```text
/// |    |  0  |  1  |  2  |  3  |  4  |  5  |  6  |  7  |  8  |  9  |
/// |:--:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
/// | 0x | \0  |  H  |  e  |  l  |  l  |  o  | \0  |  W  |  o  |  r  |
/// | 1x |  l  |  d  |  !  | \0  |  T  |  h  |  a  |  n  |  k  |  s  |
/// | 2x | \0  |  f  |  o  |  r  | \0  |  A  |  l  |  l  | \0  |  t  |
/// | 3x |  h  |  e  | \0  |  F  |  i  |  s  |  h  | \0  |     |     |
/// ```
///
/// Example string lookups:
/// ```text
/// | Index | String |
/// |:-----:|--------|
/// |   0   |  None  |
/// |   1   |  Hello |
/// |   3   |  llo   |
/// |   32  |  None  |
/// |   33  |  Fish  |
/// ```

#[repr(C)]
#[derive(Clone, Copy)]
pub struct StringTable {
    ptr: *const u8,
    size: usize,
}

impl StringTable {
    #[inline(always)]
    pub const fn new(ptr: *const u8, size: usize) -> Self {
        Self { ptr, size }
    }

    /// Returns "" if ptr is null, index is OOB, or the first byte is NUL.
    /// SAFETY: `ptr..ptr+size` must be readable. Strings must be valid UTF-8 if you want meaningful `&str`.
    #[inline(always)]
    pub unsafe fn get(&self, index: usize) -> &'static str {
        // Fast reject: null ptr or OOB
        if self.ptr.is_null() || (index >= self.size) {
            return "";
        }

        let start = self.ptr.add(index);
        let len_max = self.size - index;

        // Search for NUL using memchr (vectorized / optimized)
        let bytes = slice::from_raw_parts(start, len_max);
        let len = match memchr(0, bytes) {
            Some(p) => p,
            None => len_max,
        };

        // Zero-copy UTF-8 view (unchecked)
        str::from_utf8_unchecked(slice::from_raw_parts(start, len))
    }

    // Use later to optimize string table accesses by avoiding UTF-8 checks when possible.
    #[inline(always)]
    pub unsafe fn get_bytes(&self, index: usize) -> &'static [u8] {
        if self.ptr.is_null() || (index >= self.size) {
            return &[];
        }

        let start = self.ptr.add(index);
        let len_max = self.size - index;
        let bytes = slice::from_raw_parts(start, len_max);
        let len = match memchr(0, bytes) {
            Some(p) => p,
            None => len_max,
        };
        slice::from_raw_parts(start, len)
    }

    #[inline(always)]
    pub const fn into_inner(self) -> *const u8 {
        self.ptr
    }
}
