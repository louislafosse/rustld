use crate::arch;

// Keep pthread key management in glibc. Our local stubs were incomplete for
// destructor/teardown semantics and can break Rust TLS on foreign threads.

pub(crate) unsafe fn gettid() -> i32 {
    arch::gettid()
}
