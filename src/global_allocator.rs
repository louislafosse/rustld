use core::{
    alloc::{GlobalAlloc, Layout},
    cell::UnsafeCell,
    cmp::max,
    hint::spin_loop,
    ptr::null_mut,
    sync::atomic::{AtomicUsize, Ordering},
};
use std::ptr::copy_nonoverlapping;

#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

use crate::{
    io_macros::syscall_debug_assert,
    start::auxiliary_vector::{AuxiliaryVectorIter, AT_PAGE_SIZE},
    syscall::mmap::{mmap, munmap, MAP_ANONYMOUS, MAP_PRIVATE, PROT_READ, PROT_WRITE},
};

#[cfg(not(feature = "mmap_allocator"))]
#[global_allocator]
static SYSTEM_ALLOCATOR: std::alloc::System = std::alloc::System;

#[cfg(feature = "mmap_allocator")]
#[link_section = ".init_array"]
pub(crate) static INIT_ALLOCATOR: extern "C" fn(usize, *const *const u8, *const *const u8) =
    init_allocator;

#[cfg(feature = "mmap_allocator")]
extern "C" fn init_allocator(
    _arg_count: usize,
    _arg_pointer: *const *const u8,
    env_pointer: *const *const u8,
) {
    unsafe {
        let mut auxiliary_vector = AuxiliaryVectorIter::from_env_pointer(env_pointer);

        let page_size = auxiliary_vector
            .find(|item| item.a_type == AT_PAGE_SIZE)
            .unwrap()
            .a_un
            .a_val;

        #[allow(static_mut_refs)]
        ALLOCATOR.initialize(page_size);
    }
}

#[cfg(feature = "mmap_allocator")]
#[global_allocator]
pub(crate) static mut ALLOCATOR: Allocator = Allocator::new();

const MAX_SUPPORTED_ALIGN: usize = 4096;
const PAGE_CACHE_CAPACITY: usize = 256;
const SMALL_CLASS_COUNT: usize = 14;
const SMALL_CLASS_SIZES: [usize; SMALL_CLASS_COUNT] = [
    16, 32, 48, 64, 96, 128, 192, 256, 384, 512, 768, 1024, 1536, 2048,
];
const CACHE_LINE_SIZE: usize = 64;
const MAX_BACKOFF_SPINS: u32 = 64;

pub(crate) struct Allocator {
    // I can't use OnceCell/OnceLock because they aren't sync
    page_size: AtomicUsize,

    page_cache: PageCache,
    small_classes: [SmallClass; SMALL_CLASS_COUNT],
}

impl Allocator {
    pub const fn new() -> Self {
        Allocator {
            page_size: AtomicUsize::new(0),

            page_cache: PageCache::new(),
            small_classes: Self::new_small_classes(),
        }
    }

    const fn new_small_classes() -> [SmallClass; SMALL_CLASS_COUNT] {
        [
            SmallClass::new(),
            SmallClass::new(),
            SmallClass::new(),
            SmallClass::new(),
            SmallClass::new(),
            SmallClass::new(),
            SmallClass::new(),
            SmallClass::new(),
            SmallClass::new(),
            SmallClass::new(),
            SmallClass::new(),
            SmallClass::new(),
            SmallClass::new(),
            SmallClass::new(),
        ]
    }

    pub fn initialize(&mut self, page_size: usize) {
        syscall_debug_assert!(self.page_size.load(Ordering::Relaxed) == 0);

        self.page_size.store(page_size, Ordering::Release);
    }

    fn align_layout_to_page_size(&self, layout: Layout) -> Option<Layout> {
        let page_size = self.page_size.load(Ordering::Acquire);

        let aligned_layout = layout.align_to(max(layout.align(), page_size)).ok()?;
        Some(aligned_layout)
    }

    #[inline(always)]
    fn page_size_or_default(&self) -> usize {
        let page_size = self.page_size.load(Ordering::Acquire);
        if page_size == 0 || !page_size.is_power_of_two() {
            4096
        } else {
            page_size
        }
    }

    #[inline(always)]
    fn mapping_size(&self, layout: Layout) -> usize {
        layout.pad_to_align().size().max(1)
    }

    #[inline(always)]
    fn small_class_index(&self, layout: Layout) -> Option<usize> {
        let size = self.mapping_size(layout);
        let alignment = layout.align().max(core::mem::size_of::<usize>());
        if alignment > MAX_SUPPORTED_ALIGN {
            return None;
        }
        let mut idx = 0usize;
        while idx < SMALL_CLASS_COUNT {
            let class_size = unsafe { *SMALL_CLASS_SIZES.get_unchecked(idx) };
            if class_size >= size && class_size % alignment == 0 {
                return Some(idx);
            }
            idx += 1;
        }
        None
    }

    #[inline(always)]
    fn page_bucket_eligible(&self, layout: Layout, page_size: usize) -> bool {
        layout.align() <= page_size && self.mapping_size(layout) <= page_size
    }

    fn small_class_chunk_size(&self, page_size: usize, class_size: usize) -> usize {
        let pages = if class_size <= 64 {
            8
        } else if class_size <= 256 {
            4
        } else if class_size <= 1024 {
            2
        } else {
            1
        };
        page_size * pages
    }

    unsafe fn alloc_small_class(&self, class_index: usize, page_size: usize) -> *mut u8 {
        if let Some(pointer) = self.small_classes[class_index].pop() {
            return pointer;
        }

        let class_size = SMALL_CLASS_SIZES[class_index];
        let chunk_size = self.small_class_chunk_size(page_size, class_size);
        let chunk = mmap(
            null_mut(),
            chunk_size,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS,
            -1,
            0,
        );
        if (chunk as isize) < 0 {
            return null_mut();
        }

        let mut offset = class_size;
        while offset + class_size <= chunk_size {
            self.small_classes[class_index].push(chunk.add(offset));
            offset += class_size;
        }

        chunk
    }
}

unsafe impl GlobalAlloc for Allocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if layout.align() > MAX_SUPPORTED_ALIGN {
            return null_mut();
        }

        let page_size = self.page_size_or_default();
        if let Some(class_index) = self.small_class_index(layout) {
            return self.alloc_small_class(class_index, page_size);
        }

        if self.page_bucket_eligible(layout, page_size) {
            if let Some(pointer) = self.page_cache.pop() {
                unsafe { fast_zero_memory(pointer, page_size) };
                return pointer;
            }

            let pointer = mmap(
                null_mut(),
                page_size,
                PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS,
                -1,
                0,
            );
            if (pointer as isize) < 0 {
                return null_mut();
            }
            // mmap with MAP_ANONYMOUS returns zero-filled pages
            return pointer;
        }

        let Some(size) = self
            .align_layout_to_page_size(layout)
            .map(|value| value.pad_to_align().size())
        else {
            return null_mut();
        };

        let pointer = mmap(
            null_mut(),
            size,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS,
            -1, // file descriptor (-1 for anonymous mapping)
            0,  // offset
        );
        if (pointer as isize) < 0 {
            null_mut()
        } else {
            pointer
        }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        if pointer.is_null() {
            return;
        }

        let page_size = self.page_size_or_default();
        if let Some(class_index) = self.small_class_index(layout) {
            self.small_classes[class_index].push(pointer);
            return;
        }

        if self.page_bucket_eligible(layout, page_size) {
            if self.page_cache.push(pointer) {
                return;
            }
            munmap(pointer, page_size);
            return;
        }

        let Some(size) = self
            .align_layout_to_page_size(layout)
            .map(|value| value.pad_to_align().size())
        else {
            return;
        };

        munmap(pointer, size);
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if ptr.is_null() {
            return self.alloc(Layout::from_size_align_unchecked(new_size, layout.align()));
        }

        if new_size == 0 {
            self.dealloc(ptr, layout);
            return null_mut();
        }

        if layout.align() > MAX_SUPPORTED_ALIGN {
            return null_mut();
        }

        let page_size = self.page_size_or_default();
        let old_small_class = self.small_class_index(layout);
        let Some(old_aligned_size) = self
            .align_layout_to_page_size(layout)
            .map(|value| value.pad_to_align().size())
        else {
            return null_mut();
        };
        let new_layout = Layout::from_size_align_unchecked(new_size, layout.align());
        let new_small_class = self.small_class_index(new_layout);
        let Some(new_aligned_size) = self
            .align_layout_to_page_size(new_layout)
            .map(|value| value.pad_to_align().size())
        else {
            return null_mut();
        };

        if old_small_class == new_small_class && old_small_class.is_some() {
            return ptr;
        }

        if old_small_class.is_none()
            && new_small_class.is_none()
            && self.page_bucket_eligible(layout, page_size)
            && self.page_bucket_eligible(new_layout, page_size)
        {
            return ptr;
        }

        if old_aligned_size == new_aligned_size && old_small_class.is_none() {
            return ptr;
        }

        let new_ptr = self.alloc(new_layout);
        if new_ptr.is_null() {
            return null_mut();
        }

        copy_nonoverlapping(
            ptr,
            new_ptr,
            core::cmp::min(layout.pad_to_align().size(), new_size),
        );
        self.dealloc(ptr, layout);

        new_ptr
    }
}

/// SIMD-optimized memory zeroing
#[cfg(target_arch = "x86_64")]
#[inline]
unsafe fn fast_zero_memory(ptr: *mut u8, size: usize) {
    if is_x86_feature_detected!("avx2") && size >= 256 {
        fast_zero_memory_avx2(ptr, size);
    } else if is_x86_feature_detected!("sse2") && size >= 64 {
        fast_zero_memory_sse2(ptr, size);
    } else {
        core::ptr::write_bytes(ptr, 0, size);
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
#[inline]
unsafe fn fast_zero_memory_avx2(mut ptr: *mut u8, mut size: usize) {
    let zero = _mm256_setzero_si256();

    // Align to 32-byte boundary
    let align_offset = (ptr as usize) & 31;
    if align_offset != 0 {
        let to_align = 32 - align_offset;
        let align_size = core::cmp::min(to_align, size);
        core::ptr::write_bytes(ptr, 0, align_size);
        ptr = ptr.add(align_size);
        size -= align_size;
    }

    // Process 256 bytes (8x32) at a time
    while size >= 256 {
        _mm256_store_si256(ptr as *mut __m256i, zero);
        _mm256_store_si256(ptr.add(32) as *mut __m256i, zero);
        _mm256_store_si256(ptr.add(64) as *mut __m256i, zero);
        _mm256_store_si256(ptr.add(96) as *mut __m256i, zero);
        _mm256_store_si256(ptr.add(128) as *mut __m256i, zero);
        _mm256_store_si256(ptr.add(160) as *mut __m256i, zero);
        _mm256_store_si256(ptr.add(192) as *mut __m256i, zero);
        _mm256_store_si256(ptr.add(224) as *mut __m256i, zero);
        ptr = ptr.add(256);
        size -= 256;
    }

    // Process remaining 32-byte chunks
    while size >= 32 {
        _mm256_store_si256(ptr as *mut __m256i, zero);
        ptr = ptr.add(32);
        size -= 32;
    }

    // Handle remainder
    if size > 0 {
        core::ptr::write_bytes(ptr, 0, size);
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse2")]
#[inline]
unsafe fn fast_zero_memory_sse2(mut ptr: *mut u8, mut size: usize) {
    let zero = _mm_setzero_si128();

    // Align to 16-byte boundary
    let align_offset = (ptr as usize) & 15;
    if align_offset != 0 {
        let to_align = 16 - align_offset;
        let align_size = core::cmp::min(to_align, size);
        core::ptr::write_bytes(ptr, 0, align_size);
        ptr = ptr.add(align_size);
        size -= align_size;
    }

    // Process 128 bytes (8x16) at a time
    while size >= 128 {
        _mm_store_si128(ptr as *mut __m128i, zero);
        _mm_store_si128(ptr.add(16) as *mut __m128i, zero);
        _mm_store_si128(ptr.add(32) as *mut __m128i, zero);
        _mm_store_si128(ptr.add(48) as *mut __m128i, zero);
        _mm_store_si128(ptr.add(64) as *mut __m128i, zero);
        _mm_store_si128(ptr.add(80) as *mut __m128i, zero);
        _mm_store_si128(ptr.add(96) as *mut __m128i, zero);
        _mm_store_si128(ptr.add(112) as *mut __m128i, zero);
        ptr = ptr.add(128);
        size -= 128;
    }

    // Process remaining 16-byte chunks
    while size >= 16 {
        _mm_store_si128(ptr as *mut __m128i, zero);
        ptr = ptr.add(16);
        size -= 16;
    }

    // Handle remainder
    if size > 0 {
        core::ptr::write_bytes(ptr, 0, size);
    }
}

#[cfg(not(target_arch = "x86_64"))]
#[inline]
unsafe fn fast_zero_memory(ptr: *mut u8, size: usize) {
    core::ptr::write_bytes(ptr, 0, size);
}

#[repr(align(64))]
struct PageCache {
    lock: AtomicUsize,
    count: UnsafeCell<usize>,
    slots: UnsafeCell<[usize; PAGE_CACHE_CAPACITY]>,
}

unsafe impl Sync for PageCache {}

impl PageCache {
    pub const fn new() -> Self {
        Self {
            lock: AtomicUsize::new(0),
            count: UnsafeCell::new(0),
            slots: UnsafeCell::new([0; PAGE_CACHE_CAPACITY]),
        }
    }

    #[inline(always)]
    fn lock(&self) {
        let mut backoff = 1u32;
        while self
            .lock
            .compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            // Exponential backoff to reduce CPU waste
            for _ in 0..backoff {
                spin_loop();
            }
            backoff = (backoff << 1).min(MAX_BACKOFF_SPINS);
        }
    }

    #[inline(always)]
    fn unlock(&self) {
        self.lock.store(0, Ordering::Release);
    }

    #[inline]
    fn push(&self, pointer: *mut u8) -> bool {
        self.lock();
        let count = unsafe { *self.count.get() };
        if count >= PAGE_CACHE_CAPACITY {
            self.unlock();
            return false;
        }
        unsafe {
            (*self.slots.get())[count] = pointer as usize;
            *self.count.get() = count + 1;
        }
        self.unlock();
        true
    }

    #[inline]
    fn pop(&self) -> Option<*mut u8> {
        self.lock();
        let count = unsafe { *self.count.get() };
        if count == 0 {
            self.unlock();
            return None;
        }
        let idx = count - 1;
        let pointer = unsafe { (*self.slots.get())[idx] as *mut u8 };
        unsafe {
            (*self.slots.get())[idx] = 0;
            *self.count.get() = idx;
        }
        self.unlock();
        Some(pointer)
    }
}

#[repr(align(64))]
struct SmallClass {
    lock: AtomicUsize,
    head: UnsafeCell<usize>,
}

unsafe impl Sync for SmallClass {}

impl SmallClass {
    pub const fn new() -> Self {
        Self {
            lock: AtomicUsize::new(0),
            head: UnsafeCell::new(0),
        }
    }

    #[inline(always)]
    fn lock(&self) {
        let mut backoff = 1u32;
        while self
            .lock
            .compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            // Exponential backoff to reduce CPU waste
            for _ in 0..backoff {
                spin_loop();
            }
            backoff = (backoff << 1).min(MAX_BACKOFF_SPINS);
        }
    }

    #[inline(always)]
    fn unlock(&self) {
        self.lock.store(0, Ordering::Release);
    }

    #[inline]
    fn push(&self, pointer: *mut u8) {
        self.lock();
        unsafe {
            let head = *self.head.get();
            *(pointer as *mut usize) = head;
            *self.head.get() = pointer as usize;
        }
        self.unlock();
    }

    #[inline]
    fn pop(&self) -> Option<*mut u8> {
        self.lock();
        let head = unsafe { *self.head.get() };
        if head == 0 {
            self.unlock();
            return None;
        }
        unsafe {
            *self.head.get() = *(head as *const usize);
        }
        self.unlock();
        Some(head as *mut u8)
    }
}
