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
 * - envp == NULL: reuse parent environment.
 * - auxv == NULL or auxv_len == 0: reuse parent auxv.
 * - out_jump receives entry/stack jump metadata.
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
    RustLdJumpInfo *out_jump
);

/*
 * Wrapper around ElfLoader::execute_from_bytes.
 *
 * Returns only on error. On success, transfers control to target entrypoint.
 */
int32_t rustld_elfloader_execute_from_bytes(
    const uint8_t *elf_bytes,
    size_t elf_len,
    size_t argc,
    const char *const *argv,
    const char *const *envp,
    const RustLdAuxvItem *auxv,
    size_t auxv_len,
    int32_t verbose
);

/*
 * Wrapper around ElfLoader::execute_from_bytes_with_entry.
 *
 * - entry_symbol != NULL: resolve and jump to that symbol.
 * - entry_address_is_set != 0: use entry_address.
 * - Do not provide both at once.
 *
 * Returns only on error. On success, transfers control to selected entrypoint.
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
    int32_t verbose
);

#ifdef __cplusplus
}
#endif

#endif /* RUSTLD_H */
