#ifndef RUSTLD_H
#define RUSTLD_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
    RUSTLD_OK = 0,
    RUSTLD_EINVAL = 1,
    RUSTLD_EPANIC = 2,
    RUSTLD_EIO = 3
};

typedef struct RustLdJumpInfo {
    uintptr_t entry;
    uintptr_t stack;
} RustLdJumpInfo;

typedef struct RustLdAuxvItem {
    uintptr_t a_type;
    uintptr_t a_val;
} RustLdAuxvItem;

/*
 * Returns host process environ pointer, usable as envp override.
 */
char **rustld_host_environment_pointer(void);

/*
 * Wrapper around ElfLoader::prepare_from_bytes.
 *
 * Does not jump; fills out_jump with entry/stack for a later handoff.
 * - envp == NULL: reuse parent environment.
 * - auxv == NULL or auxv_len == 0: reuse parent auxv.
 * - indirect_syscalls != 0: route all syscalls through an anonymous RX
 *   trampoline page so the syscall opcode never appears in the loader image
 *   (x86_64: 0x0F 0x05, aarch64: 0xD4000001). Recommended for anti-RE.
 *   Pass 0 for conventional direct syscalls.
 */
int32_t rustld_elfloader_prepare_from_bytes(
    const uint8_t *elf_bytes,
    size_t elf_len,
    size_t argc,
    const char *const *argv,
    const char *const *envp,
    const RustLdAuxvItem *auxv,
    size_t auxv_len,
    int32_t verbose,
    int32_t indirect_syscalls,
    RustLdJumpInfo *out_jump
);

/*
 * Wrapper around ElfLoader::execute_from_bytes.
 *
 * Returns only on error; on success transfers control to target entrypoint.
 * - indirect_syscalls != 0: trampoline mode — syscall opcode hidden from image
 *   (x86_64: 0x0F 0x05, aarch64: 0xD4000001). Pass 0 for direct syscalls.
 */
int32_t rustld_elfloader_execute_from_bytes(
    const uint8_t *elf_bytes,
    size_t elf_len,
    size_t argc,
    const char *const *argv,
    const char *const *envp,
    const RustLdAuxvItem *auxv,
    size_t auxv_len,
    int32_t verbose,
    int32_t indirect_syscalls
);

/*
 * Wrapper around ElfLoader::execute_from_bytes_with_entry.
 *
 * Pass either entry_symbol (non-NULL) or entry_address_is_set != 0, not both.
 * Returns only on error; on success transfers control to selected entrypoint.
 * - indirect_syscalls != 0: trampoline mode — syscall opcode hidden from image
 *   (x86_64: 0x0F 0x05, aarch64: 0xD4000001). Pass 0 for direct syscalls.
 */
int32_t rustld_elfloader_execute_from_bytes_with_entry(
    const uint8_t *elf_bytes,
    size_t elf_len,
    size_t argc,
    const char *const *argv,
    const char *entry_symbol,
    uintptr_t entry_address,
    int32_t entry_address_is_set,
    const char *const *envp,
    const RustLdAuxvItem *auxv,
    size_t auxv_len,
    int32_t verbose,
    int32_t indirect_syscalls
);

#ifdef __cplusplus
}
#endif

#endif /* RUSTLD_H */
