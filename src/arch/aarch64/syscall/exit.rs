use std::arch::asm;

const CODE_ADDEND: usize = 22200;

pub const EXIT_UNKNOWN_RELOCATION: usize = CODE_ADDEND + 1;

#[inline(always)]
pub fn exit(code: usize) -> ! {
    const EXIT: usize = 93;

    unsafe {
        asm!(
            "svc 0",
            in("x8") EXIT,
            in("x0") code,
            options(noreturn)
        )
    }
}
