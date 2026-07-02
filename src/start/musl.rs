//! musl-specific runtime seeding: detect musl targets and replay the
//! bootstrap state (stage-2b queue slots, threading fastpath) that musl's
//! own `__dls2`/`__dls2b` would normally set up.

use super::auxiliary_vector::{AuxiliaryVectorItem, AT_HWCAP};
use super::{auxv_lookup_value, interpreter_name, LoadedImage};
use crate::linking::DynamicLinker;

const SHN_ABS: u16 = 0xfff1;

pub(super) fn is_musl_target(image: &LoadedImage) -> bool {
    image
        .interpreter_path
        .as_deref()
        .is_some_and(|path| interpreter_name(path).contains("ld-musl"))
}

#[cfg(target_arch = "x86_64")]
unsafe fn enable_musl_threading_fastpath(linker: &DynamicLinker) {
    // In musl's dynamic startup path, __dls2b initializes internal thread
    // readiness flags before user code can call pthread_create. While the full
    // stage-2b replacement is in progress, patch these runtime flags by
    // pattern-matching pthread_create's early checks.
    let Some((obj_idx, sym)) = linker.lookup_symbol("pthread_create") else {
        return;
    };
    let base = if sym.st_shndx == SHN_ABS {
        0
    } else {
        linker.get_base(obj_idx)
    };
    let func = base.wrapping_add(sym.st_value);
    if func == 0 {
        return;
    }

    let bytes = core::slice::from_raw_parts(func as *const u8, 256);
    let mut patched = 0usize;
    let mut i = 0usize;
    while i + 7 <= bytes.len() {
        // cmp byte ptr [rip+disp32], 0
        if bytes[i] == 0x80 && bytes[i + 1] == 0x3d && bytes[i + 6] == 0x00 {
            let disp = i32::from_le_bytes([bytes[i + 2], bytes[i + 3], bytes[i + 4], bytes[i + 5]]);
            let target = (func.wrapping_add(i).wrapping_add(7) as isize).wrapping_add(disp as isize)
                as *mut u8;
            if !target.is_null() {
                core::ptr::write_volatile(target, 1u8);
                patched = patched.saturating_add(1);
                if patched >= 2 {
                    break;
                }
            }
            i += 7;
            continue;
        }
        i += 1;
    }
}

#[cfg(not(target_arch = "x86_64"))]
unsafe fn enable_musl_threading_fastpath(_linker: &DynamicLinker) {}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
#[derive(Default, Clone, Copy)]
struct MuslStage2bSlots {
    auxv_ptr_slot: Option<usize>,
    tls_size_slot: Option<usize>,
    tls_size_default: Option<usize>,
    tls_align_template_slot: Option<usize>,
    tls_align_slot: Option<usize>,
    hwcap_slot: Option<usize>,
    self_slot: Option<usize>,
    stage2b_init_arg: Option<usize>,
    stage2b_fn1: Option<usize>,
    stage2b_fn2: Option<usize>,
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
fn rip_target(insn_addr: usize, insn_len: usize, disp: i32) -> usize {
    (insn_addr.wrapping_add(insn_len) as isize).wrapping_add(disp as isize) as usize
}

#[cfg(target_arch = "x86_64")]
unsafe fn derive_musl_stage2b_slots(dls2b_addr: usize) -> MuslStage2bSlots {
    // Decode RIP-relative references from __dls2b so we do not rely entirely
    // on build-specific absolute offsets in musl's .data layout.
    let code = core::slice::from_raw_parts(dls2b_addr as *const u8, 0x180);
    let mut slots = MuslStage2bSlots::default();
    let mut last_mov_rax_from_rip: Option<usize> = None;
    let mut last_lea_rdi_rip: Option<usize> = None;

    let mut i = 0usize;
    while i + 10 < code.len() {
        // mov rax, [rip+disp32]
        if code[i] == 0x48 && code[i + 1] == 0x8b && code[i + 2] == 0x05 {
            let disp = i32::from_le_bytes([code[i + 3], code[i + 4], code[i + 5], code[i + 6]]);
            last_mov_rax_from_rip = Some(rip_target(dls2b_addr + i, 7, disp));
            i += 7;
            continue;
        }

        // lea rdi, [rip+disp32]
        if code[i] == 0x48 && code[i + 1] == 0x8d && code[i + 2] == 0x3d {
            let disp = i32::from_le_bytes([code[i + 3], code[i + 4], code[i + 5], code[i + 6]]);
            last_lea_rdi_rip = Some(rip_target(dls2b_addr + i, 7, disp));
        }

        // call rel32; mov rdi, rax; call rel32
        if code[i] == 0xe8
            && i + 13 < code.len()
            && code[i + 5] == 0x48
            && code[i + 6] == 0x89
            && code[i + 7] == 0xc7
            && code[i + 8] == 0xe8
        {
            let disp1 = i32::from_le_bytes([code[i + 1], code[i + 2], code[i + 3], code[i + 4]]);
            let disp2 = i32::from_le_bytes([code[i + 9], code[i + 10], code[i + 11], code[i + 12]]);
            slots.stage2b_fn1 = Some(rip_target(dls2b_addr + i, 5, disp1));
            slots.stage2b_fn2 = Some(rip_target(dls2b_addr + i + 8, 5, disp2));
            slots.stage2b_init_arg = last_lea_rdi_rip;
            i += 13;
            continue;
        }

        // mov [rip+disp32], rbx
        if code[i] == 0x48 && code[i + 1] == 0x89 && code[i + 2] == 0x1d {
            let disp = i32::from_le_bytes([code[i + 3], code[i + 4], code[i + 5], code[i + 6]]);
            slots.auxv_ptr_slot = Some(rip_target(dls2b_addr + i, 7, disp));
            i += 7;
            continue;
        }

        // mov qword ptr [rip+disp32], imm32
        if code[i] == 0x48 && code[i + 1] == 0xc7 && code[i + 2] == 0x05 {
            let disp = i32::from_le_bytes([code[i + 3], code[i + 4], code[i + 5], code[i + 6]]);
            let imm = u32::from_le_bytes([code[i + 7], code[i + 8], code[i + 9], code[i + 10]]);
            slots.tls_size_slot = Some(rip_target(dls2b_addr + i, 11, disp));
            slots.tls_size_default = Some(imm as usize);
            i += 11;
            continue;
        }

        // mov [rip+disp32], rax
        if code[i] == 0x48 && code[i + 1] == 0x89 && code[i + 2] == 0x05 {
            let disp = i32::from_le_bytes([code[i + 3], code[i + 4], code[i + 5], code[i + 6]]);
            let target = rip_target(dls2b_addr + i, 7, disp);
            // hwcap store path in __dls2b: mov rax,[rdx+8]; mov [rip+disp],rax
            if i >= 4
                && code[i - 4] == 0x48
                && code[i - 3] == 0x8b
                && code[i - 2] == 0x42
                && code[i - 1] == 0x08
            {
                slots.hwcap_slot = Some(target);
            } else if slots.tls_align_slot.is_none() {
                slots.tls_align_slot = Some(target);
                if slots.tls_align_template_slot.is_none() {
                    slots.tls_align_template_slot = last_mov_rax_from_rip;
                }
            }
            i += 7;
            continue;
        }

        // lea rdi, [rip+disp32]; xor edx, edx (self dso slot path in __dls2b)
        if code[i] == 0x48
            && code[i + 1] == 0x8d
            && code[i + 2] == 0x3d
            && code[i + 7] == 0x31
            && code[i + 8] == 0xd2
        {
            let disp = i32::from_le_bytes([code[i + 3], code[i + 4], code[i + 5], code[i + 6]]);
            slots.self_slot = Some(rip_target(dls2b_addr + i, 7, disp));
            i += 9;
            continue;
        }

        i += 1;
    }

    slots
}

#[cfg(target_arch = "aarch64")]
#[inline(always)]
fn sign_extend_i64(value: i64, bits: u32) -> i64 {
    let shift = 64u32.saturating_sub(bits);
    (value << shift) >> shift
}

#[cfg(target_arch = "aarch64")]
#[inline(always)]
fn read_u32_le(code: &[u8], offset: usize) -> Option<u32> {
    if offset + 4 > code.len() {
        return None;
    }
    Some(u32::from_le_bytes([
        code[offset],
        code[offset + 1],
        code[offset + 2],
        code[offset + 3],
    ]))
}

#[cfg(target_arch = "aarch64")]
#[inline(always)]
fn decode_adrp(insn: u32, pc: usize) -> Option<(usize, usize)> {
    if (insn & 0x9f00_0000) != 0x9000_0000 {
        return None;
    }
    let rd = (insn & 0x1f) as usize;
    let immlo = ((insn >> 29) & 0x3) as i64;
    let immhi = ((insn >> 5) & 0x7ffff) as i64;
    let imm21 = (immhi << 2) | immlo;
    let page_delta = sign_extend_i64(imm21, 21) << 12;
    let pc_page = (pc & !0xfff) as i64;
    Some((rd, pc_page.wrapping_add(page_delta) as usize))
}

#[cfg(target_arch = "aarch64")]
#[inline(always)]
fn decode_add_imm_x(insn: u32) -> Option<(usize, usize, usize)> {
    if (insn & 0xff00_0000) != 0x9100_0000 {
        return None;
    }
    let rd = (insn & 0x1f) as usize;
    let rn = ((insn >> 5) & 0x1f) as usize;
    let imm12 = ((insn >> 10) & 0xfff) as usize;
    let shift = ((insn >> 22) & 0x1) as usize;
    let imm = if shift == 0 { imm12 } else { imm12 << 12 };
    Some((rd, rn, imm))
}

#[cfg(target_arch = "aarch64")]
#[inline(always)]
fn decode_movz_x(insn: u32) -> Option<(usize, usize)> {
    if (insn & 0xff80_0000) != 0xd280_0000 {
        return None;
    }
    let rd = (insn & 0x1f) as usize;
    let imm16 = ((insn >> 5) & 0xffff) as usize;
    let hw = ((insn >> 21) & 0x3) as usize;
    Some((rd, imm16 << (hw * 16)))
}

#[cfg(target_arch = "aarch64")]
#[inline(always)]
fn decode_ldr_uimm_x(insn: u32) -> Option<(usize, usize, usize)> {
    if (insn & 0xffc0_0000) != 0xf940_0000 {
        return None;
    }
    let rt = (insn & 0x1f) as usize;
    let rn = ((insn >> 5) & 0x1f) as usize;
    let imm = (((insn >> 10) & 0xfff) as usize) << 3;
    Some((rt, rn, imm))
}

#[cfg(target_arch = "aarch64")]
#[inline(always)]
fn decode_str_uimm_x(insn: u32) -> Option<(usize, usize, usize)> {
    if (insn & 0xffc0_0000) != 0xf900_0000 {
        return None;
    }
    let rt = (insn & 0x1f) as usize;
    let rn = ((insn >> 5) & 0x1f) as usize;
    let imm = (((insn >> 10) & 0xfff) as usize) << 3;
    Some((rt, rn, imm))
}

#[cfg(target_arch = "aarch64")]
#[inline(always)]
fn decode_stp_uimm_x(insn: u32) -> Option<(usize, usize, usize, usize)> {
    if (insn & 0xffc0_0000) != 0xa900_0000 {
        return None;
    }
    let rt = (insn & 0x1f) as usize;
    let rn = ((insn >> 5) & 0x1f) as usize;
    let rt2 = ((insn >> 10) & 0x1f) as usize;
    let imm7 = ((insn >> 15) & 0x7f) as usize;
    Some((rt, rt2, rn, imm7 << 3))
}

#[cfg(target_arch = "aarch64")]
#[inline(always)]
fn decode_bl_target(insn: u32, pc: usize) -> Option<usize> {
    if (insn & 0xfc00_0000) != 0x9400_0000 {
        return None;
    }
    let imm26 = (insn & 0x03ff_ffff) as i64;
    let rel = sign_extend_i64(imm26, 26) << 2;
    Some((pc as i64).wrapping_add(rel) as usize)
}

#[cfg(target_arch = "aarch64")]
unsafe fn derive_musl_stage2b_slots(dls2b_addr: usize) -> MuslStage2bSlots {
    // Decode PC-relative slot references from __dls2b to avoid hardcoded
    // musl build offsets.
    let code = core::slice::from_raw_parts(dls2b_addr as *const u8, 0x240);
    let mut slots = MuslStage2bSlots::default();
    let mut reg_const: [Option<usize>; 32] = [None; 32];
    let mut reg_loaded_from_slot: [Option<usize>; 32] = [None; 32];
    let mut reg_loaded_from_src: [Option<(usize, usize)>; 32] = [None; 32];

    let mut i = 0usize;
    while i + 4 <= code.len() {
        let pc = dls2b_addr + i;
        let Some(insn) = read_u32_le(code, i) else {
            break;
        };

        if let Some((rd, page)) = decode_adrp(insn, pc) {
            reg_const[rd] = Some(page);
            reg_loaded_from_slot[rd] = None;
            reg_loaded_from_src[rd] = None;
            i += 4;
            continue;
        }

        if let Some((rd, rn, imm)) = decode_add_imm_x(insn) {
            if let Some(base) = reg_const[rn] {
                reg_const[rd] = Some(base.wrapping_add(imm));
                reg_loaded_from_slot[rd] = None;
                reg_loaded_from_src[rd] = None;

                if rd == 0 && rn == 0 {
                    if let (Some(insn1), Some(insn2)) =
                        (read_u32_le(code, i + 4), read_u32_le(code, i + 8))
                    {
                        if let (Some(fn1), Some(fn2)) = (
                            decode_bl_target(insn1, pc + 4),
                            decode_bl_target(insn2, pc + 8),
                        ) {
                            slots.stage2b_init_arg = reg_const[0];
                            slots.stage2b_fn1 = Some(fn1);
                            slots.stage2b_fn2 = Some(fn2);
                        }
                    }
                }
            } else {
                reg_const[rd] = None;
                reg_loaded_from_slot[rd] = None;
                reg_loaded_from_src[rd] = None;
            }
            i += 4;
            continue;
        }

        if let Some((rd, value)) = decode_movz_x(insn) {
            reg_const[rd] = Some(value);
            reg_loaded_from_slot[rd] = None;
            reg_loaded_from_src[rd] = None;
            i += 4;
            continue;
        }

        if let Some((rt, rn, offset)) = decode_ldr_uimm_x(insn) {
            if let Some(base) = reg_const[rn] {
                let slot = base.wrapping_add(offset);
                reg_const[rt] = None;
                reg_loaded_from_slot[rt] = Some(slot);
                reg_loaded_from_src[rt] = Some((rn, offset));
                // In __dls2b epilogue this is the ldso self-base slot.
                if rt == 2 && offset >= 0x800 {
                    slots.self_slot = Some(slot);
                }
            } else {
                reg_const[rt] = None;
                reg_loaded_from_slot[rt] = None;
                reg_loaded_from_src[rt] = None;
            }
            i += 4;
            continue;
        }

        if let Some((rt, rn, offset)) = decode_str_uimm_x(insn) {
            if let Some(base) = reg_const[rn] {
                let slot = base.wrapping_add(offset);
                if rt == 19 && offset == 8 {
                    slots.auxv_ptr_slot = Some(slot);
                }
                if let Some((src_rn, src_off)) = reg_loaded_from_src[rt] {
                    // hwcap path in __dls2b: ldr x1, [x2, #8]; str x1, [global]
                    if src_rn == 2 && src_off == 8 {
                        slots.hwcap_slot = Some(slot);
                    }
                }
            }
            i += 4;
            continue;
        }

        if let Some((rt, rt2, rn, offset)) = decode_stp_uimm_x(insn) {
            if let Some(base) = reg_const[rn] {
                let slot1 = base.wrapping_add(offset);
                let slot2 = slot1.wrapping_add(size_of::<usize>());
                if rt == 1 {
                    slots.tls_size_slot = Some(slot1);
                    slots.tls_size_default = reg_const[1];
                }
                if rt2 == 2 {
                    slots.tls_align_slot = Some(slot2);
                    slots.tls_align_template_slot = reg_loaded_from_slot[2];
                }
            }
            i += 4;
            continue;
        }

        i += 4;
    }

    slots
}

#[cfg(target_arch = "x86_64")]
unsafe fn seed_musl_internal_queue_slot(linker: &DynamicLinker) {
    let Some((lib_idx, start_sym)) = linker.lookup_symbol("__libc_start_main") else {
        return;
    };
    let base = if start_sym.st_shndx == SHN_ABS {
        0
    } else {
        linker.get_base(lib_idx)
    };
    let start_addr = base.wrapping_add(start_sym.st_value);
    if start_addr == 0 {
        return;
    }

    // __libc_start_main: find `lea rax,[rip+disp32]` used before `jmp *%rax`.
    let start_code = core::slice::from_raw_parts(start_addr as *const u8, 0x80);
    let mut stage_fn = None;
    let mut i = 0usize;
    while i + 7 <= start_code.len() {
        if start_code[i] == 0x48 && start_code[i + 1] == 0x8d && start_code[i + 2] == 0x05 {
            let disp = i32::from_le_bytes([
                start_code[i + 3],
                start_code[i + 4],
                start_code[i + 5],
                start_code[i + 6],
            ]);
            stage_fn = Some(rip_target(start_addr + i, 7, disp));
            break;
        }
        i += 1;
    }
    let Some(stage_addr) = stage_fn else {
        return;
    };

    // Stage function begins with a call to an internal startup helper.
    let stage_code = core::slice::from_raw_parts(stage_addr as *const u8, 0x40);
    let mut helper = None;
    i = 0;
    while i + 5 <= stage_code.len() {
        if stage_code[i] == 0xe8 {
            let disp = i32::from_le_bytes([
                stage_code[i + 1],
                stage_code[i + 2],
                stage_code[i + 3],
                stage_code[i + 4],
            ]);
            helper = Some(rip_target(stage_addr + i, 5, disp));
            break;
        }
        i += 1;
    }
    let Some(helper_addr) = helper else {
        return;
    };

    // Helper prologue pattern:
    //   mov rdi, [rip+slot]
    //   ...
    //   lea rax, [rip+default]
    let helper_code = core::slice::from_raw_parts(helper_addr as *const u8, 0x60);
    let mut slot_addr = None;
    let mut default_ptr = None;
    i = 0;
    while i + 7 <= helper_code.len() {
        if slot_addr.is_none()
            && helper_code[i] == 0x48
            && helper_code[i + 1] == 0x8b
            && helper_code[i + 2] == 0x3d
        {
            let disp = i32::from_le_bytes([
                helper_code[i + 3],
                helper_code[i + 4],
                helper_code[i + 5],
                helper_code[i + 6],
            ]);
            slot_addr = Some(rip_target(helper_addr + i, 7, disp));
        }
        if default_ptr.is_none()
            && helper_code[i] == 0x48
            && helper_code[i + 1] == 0x8d
            && helper_code[i + 2] == 0x05
        {
            let disp = i32::from_le_bytes([
                helper_code[i + 3],
                helper_code[i + 4],
                helper_code[i + 5],
                helper_code[i + 6],
            ]);
            default_ptr = Some(rip_target(helper_addr + i, 7, disp));
        }
        if slot_addr.is_some() && default_ptr.is_some() {
            break;
        }
        i += 1;
    }

    if let (Some(slot), Some(default_value)) = (slot_addr, default_ptr) {
        let slot_ptr = slot as *mut usize;
        if core::ptr::read_volatile(slot_ptr) == 0 {
            core::ptr::write_volatile(slot_ptr, default_value);
        }
    }
}

#[cfg(target_arch = "aarch64")]
unsafe fn seed_musl_internal_queue_slot(linker: &DynamicLinker) {
    let Some((lib_idx, start_sym)) = linker.lookup_symbol("__libc_start_main") else {
        return;
    };
    let base = if start_sym.st_shndx == SHN_ABS {
        0
    } else {
        linker.get_base(lib_idx)
    };
    let start_addr = base.wrapping_add(start_sym.st_value);
    if start_addr == 0 {
        return;
    }

    // __libc_start_main sets x3 to a stage helper then branches through x16.
    let start_code = core::slice::from_raw_parts(start_addr as *const u8, 0x80);
    let mut reg_const: [Option<usize>; 32] = [None; 32];
    let mut stage_addr = None;
    let mut i = 0usize;
    while i + 4 <= start_code.len() {
        let Some(insn) = read_u32_le(start_code, i) else {
            break;
        };
        let pc = start_addr + i;

        if let Some((rd, page)) = decode_adrp(insn, pc) {
            reg_const[rd] = Some(page);
            i += 4;
            continue;
        }
        if let Some((rd, rn, imm)) = decode_add_imm_x(insn) {
            reg_const[rd] = reg_const[rn].map(|base| base.wrapping_add(imm));
            if rd == 3 && rn == 3 {
                stage_addr = reg_const[3];
            }
            i += 4;
            continue;
        }
        i += 4;
    }
    let Some(stage_addr) = stage_addr else {
        return;
    };

    // Stage function starts with a BL into the queue/loader setup helper.
    let stage_code = core::slice::from_raw_parts(stage_addr as *const u8, 0x40);
    let mut helper_addr = None;
    i = 0;
    while i + 4 <= stage_code.len() {
        let Some(insn) = read_u32_le(stage_code, i) else {
            break;
        };
        if let Some(target) = decode_bl_target(insn, stage_addr + i) {
            helper_addr = Some(target);
            break;
        }
        i += 4;
    }
    let Some(helper_addr) = helper_addr else {
        return;
    };

    // In helper:
    //   adrp x19, ...
    //   ldr  x0, [x19, #slot_off]
    //   ...
    //   adrp x1, ...
    //   add  x1, x1, #default_off
    let helper_code = core::slice::from_raw_parts(helper_addr as *const u8, 0x80);
    let mut helper_regs: [Option<usize>; 32] = [None; 32];
    let mut slot_addr = None;
    let mut default_ptr = None;
    i = 0;
    while i + 4 <= helper_code.len() {
        let Some(insn) = read_u32_le(helper_code, i) else {
            break;
        };
        let pc = helper_addr + i;

        if let Some((rd, page)) = decode_adrp(insn, pc) {
            helper_regs[rd] = Some(page);
            i += 4;
            continue;
        }
        if let Some((rd, rn, imm)) = decode_add_imm_x(insn) {
            helper_regs[rd] = helper_regs[rn].map(|base| base.wrapping_add(imm));
            if rd == 1 && rn == 1 && default_ptr.is_none() {
                default_ptr = helper_regs[1];
            }
            i += 4;
            continue;
        }
        if let Some((rt, rn, off)) = decode_ldr_uimm_x(insn) {
            if rt == 0 && rn == 19 {
                if let Some(base_addr) = helper_regs[rn] {
                    slot_addr = Some(base_addr.wrapping_add(off));
                }
            }
            i += 4;
            continue;
        }
        i += 4;
    }

    if let (Some(slot), Some(default_value)) = (slot_addr, default_ptr) {
        let slot_ptr = slot as *mut usize;
        if core::ptr::read_volatile(slot_ptr) == 0 {
            core::ptr::write_volatile(slot_ptr, default_value);
        }
    }
}

#[cfg(target_arch = "x86_64")]
pub(super) unsafe fn seed_musl_stage2b_runtime_state(
    linker: &DynamicLinker,
    auxv: *const AuxiliaryVectorItem,
    interpreter_path: Option<&str>,
    _stack_ptr: *const usize,
) {
    // musl's native startup (__dls2b) seeds a small set of ldso/libc state
    // before user code runs. We currently do not execute __dls2b, so initialize
    // the critical words directly from our prepared auxv image.
    let Some((lib_idx, dls2b_symbol)) = linker.lookup_symbol("__dls2b") else {
        return;
    };
    let base = linker.get_base(lib_idx);
    if base == 0 {
        return;
    }
    let dls2b_addr = if dls2b_symbol.st_shndx == SHN_ABS {
        dls2b_symbol.st_value
    } else {
        base.wrapping_add(dls2b_symbol.st_value)
    };
    if dls2b_addr == 0 {
        return;
    }
    let derived = derive_musl_stage2b_slots(dls2b_addr);

    if let Some(auxv_slot) = derived.auxv_ptr_slot {
        core::ptr::write_volatile(auxv_slot as *mut usize, auxv as usize);
    }
    #[cfg(target_arch = "x86_64")]
    {
        if let Some(tls_size_slot) = derived.tls_size_slot {
            let tls_size_ptr = tls_size_slot as *mut usize;
            if core::ptr::read_volatile(tls_size_ptr) == 0 {
                if let Some(default_size) = derived.tls_size_default {
                    core::ptr::write_volatile(tls_size_ptr, default_size);
                }
            }
        }

        if let (Some(tls_align_slot), Some(template_slot)) =
            (derived.tls_align_slot, derived.tls_align_template_slot)
        {
            let tls_align = core::ptr::read_volatile(template_slot as *const usize);
            if tls_align != 0 {
                core::ptr::write_volatile(tls_align_slot as *mut usize, tls_align);
            }
        }
    }

    if let Some(hwcap_slot) = derived.hwcap_slot {
        let hwcap = auxv_lookup_value(auxv, AT_HWCAP).unwrap_or(0);
        core::ptr::write_volatile(hwcap_slot as *mut usize, hwcap);
    }

    let mut stage2_runtime_seeded = false;
    #[cfg(target_arch = "x86_64")]
    {
        if let (Some(init_arg), Some(init_fn1), Some(init_fn2)) = (
            derived.stage2b_init_arg,
            derived.stage2b_fn1,
            derived.stage2b_fn2,
        ) {
            let state_ptr = {
                let init: unsafe extern "C" fn(*mut u8) -> *mut u8 = core::mem::transmute(init_fn1);
                init(init_arg as *mut u8)
            };
            if !state_ptr.is_null() {
                let finalize: unsafe extern "C" fn(*mut u8) -> i32 = core::mem::transmute(init_fn2);
                let _ = finalize(state_ptr);
                stage2_runtime_seeded = true;
            }
        }
    }
    if !stage2_runtime_seeded {
        enable_musl_threading_fastpath(linker);
    }

    #[cfg(target_arch = "x86_64")]
    {
        if let Some(self_slot) = derived.self_slot {
            core::ptr::write_volatile(self_slot as *mut usize, base);
            let path_slot = (self_slot + size_of::<usize>()) as *mut usize;
            if core::ptr::read_volatile(path_slot) == 0 {
                if let Some(path) = interpreter_path {
                    if !path.as_bytes().contains(&0) {
                        let mut bytes = path.as_bytes().to_vec();
                        bytes.push(0);
                        let leaked = Box::leak(bytes.into_boxed_slice());
                        core::ptr::write_volatile(path_slot, leaked.as_ptr() as usize);
                    }
                }
            }
        }
    }

    #[cfg(target_arch = "x86_64")]
    seed_musl_internal_queue_slot(linker);
}

#[cfg(target_arch = "aarch64")]
pub(super) unsafe fn seed_musl_stage2b_runtime_state(
    linker: &DynamicLinker,
    auxv: *const AuxiliaryVectorItem,
    interpreter_path: Option<&str>,
    _stack_ptr: *const usize,
) {
    let Some((lib_idx, dls2b_symbol)) = linker.lookup_symbol("__dls2b") else {
        seed_musl_internal_queue_slot(linker);
        return;
    };
    let base = linker.get_base(lib_idx);
    if base == 0 {
        seed_musl_internal_queue_slot(linker);
        return;
    }

    let dls2b_addr = if dls2b_symbol.st_shndx == SHN_ABS {
        dls2b_symbol.st_value
    } else {
        base.wrapping_add(dls2b_symbol.st_value)
    };
    if dls2b_addr == 0 {
        seed_musl_internal_queue_slot(linker);
        return;
    }
    let derived = derive_musl_stage2b_slots(dls2b_addr);

    if let Some(auxv_slot) = derived.auxv_ptr_slot {
        core::ptr::write_volatile(auxv_slot as *mut usize, auxv as usize);
    }

    if let Some(tls_size_slot) = derived.tls_size_slot {
        let tls_size_ptr = tls_size_slot as *mut usize;
        if core::ptr::read_volatile(tls_size_ptr) == 0 {
            if let Some(default_size) = derived.tls_size_default {
                core::ptr::write_volatile(tls_size_ptr, default_size);
            }
        }
    }

    if let (Some(tls_align_slot), Some(template_slot)) =
        (derived.tls_align_slot, derived.tls_align_template_slot)
    {
        let tls_align = core::ptr::read_volatile(template_slot as *const usize);
        if tls_align != 0 {
            core::ptr::write_volatile(tls_align_slot as *mut usize, tls_align);
        }
    }

    if let Some(hwcap_slot) = derived.hwcap_slot {
        let hwcap = auxv_lookup_value(auxv, AT_HWCAP).unwrap_or(0);
        core::ptr::write_volatile(hwcap_slot as *mut usize, hwcap);
    }

    if let (Some(init_arg), Some(init_fn1), Some(init_fn2)) = (
        derived.stage2b_init_arg,
        derived.stage2b_fn1,
        derived.stage2b_fn2,
    ) {
        let state_ptr = {
            let init: unsafe extern "C" fn(*mut u8) -> *mut u8 = core::mem::transmute(init_fn1);
            init(init_arg as *mut u8)
        };
        if !state_ptr.is_null() {
            let finalize: unsafe extern "C" fn(*mut u8) -> i32 = core::mem::transmute(init_fn2);
            let _ = finalize(state_ptr);
        }
    }

    if let Some(self_slot) = derived.self_slot {
        core::ptr::write_volatile(self_slot as *mut usize, base);
        let path_slot = (self_slot + size_of::<usize>()) as *mut usize;
        if core::ptr::read_volatile(path_slot) == 0 {
            if let Some(path) = interpreter_path {
                if !path.as_bytes().contains(&0) {
                    let mut bytes = path.as_bytes().to_vec();
                    bytes.push(0);
                    let leaked = Box::leak(bytes.into_boxed_slice());
                    core::ptr::write_volatile(path_slot, leaked.as_ptr() as usize);
                }
            }
        }
    }

    // musl/aarch64 relies on an internal queue slot initialized during
    // stage-2 startup; keep this explicit fallback even after stage-2b
    // decode seeding above.
    seed_musl_internal_queue_slot(linker);
}

