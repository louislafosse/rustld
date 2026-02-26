#![feature(impl_trait_in_assoc_type)]
#![feature(c_variadic)]
#![feature(type_changing_struct_update)]
#![feature(thread_id_value)]
#![feature(thread_local)]
#![allow(dead_code)]

pub(crate) mod arch;
#[cfg_attr(target_arch = "x86_64", path = "arch/x86_64/syscall/mod.rs")]
#[cfg_attr(target_arch = "aarch64", path = "arch/aarch64/syscall/mod.rs")]
pub mod syscall;

pub mod runtime_loader;

mod c_api;
mod elf;
mod global_allocator;
mod io_macros;
mod ld_stubs;
mod libc;
mod linking;
mod page_size;
mod shared_object;
mod start;
mod tls;
mod utils;

pub use runtime_loader::{host_environment_pointer, ElfLoader};
pub use start::auxiliary_vector::{AuxiliaryVectorItem, AuxiliaryVectorIter};
