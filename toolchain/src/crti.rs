//! crti
#![no_std]
#![allow(internal_features)]
#![feature(linkage)]
#![feature(core_intrinsics)]

// https://wiki.osdev.org/Creating_a_C_Library#crtbegin.o.2C_crtend.o.2C_crti.o.2C_and_crtn.o
#[cfg(target_arch = "x86_64")]
core::arch::global_asm!(
    r#"
    .section .init
    .global _init
    _init:
        push rbp
        mov rbp, rsp
        // Created a new stack frame and updated the stack pointer
        // Body will be filled in by gcc and ended by crtn.o

    .section .fini
    .global _fini
    _fini:
        push rbp
        mov rbp, rsp
        // Created a new stack frame and updated the stack pointer
        // Body will be filled in by gcc and ended by crtn.o
"#
);

// https://git.musl-libc.org/cgit/musl/tree/crt/aarch64/crti.s
#[cfg(target_arch = "aarch64")]
core::arch::global_asm!(
    r#"
    .section .init
    .global _init
    .type _init,%function
    _init:
        stp x29,x30,[sp,-16]!
        mov x29,sp
        // stp: "stores two doublewords from the first and second argument to memory addressed by addr"
        // Body will be filled in by gcc and ended by crtn.o

    .section .fini
    .global _fini
    .type _fini,%function
    _fini:
        stp x29,x30,[sp,-16]!
        mov x29,sp
        // stp: "stores two doublewords from the first and second argument to memory addressed by addr"
        // Body will be filled in by gcc and ended by crtn.o
"#
);

#[panic_handler]
#[linkage = "weak"]
#[no_mangle]
pub unsafe fn rust_begin_unwind(_pi: &::core::panic::PanicInfo) -> ! {
    core::intrinsics::abort()
}
