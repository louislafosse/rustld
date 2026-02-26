pub mod exit;
pub mod mmap;
pub mod relocation;
pub mod thread_pointer;
pub mod trampoline;

pub use trampoline::set_use_indirect;
