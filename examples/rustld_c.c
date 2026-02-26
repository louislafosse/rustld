#include "rustld.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

static const uint8_t *map_file_readonly(const char *path, size_t *out_len) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        fprintf(stderr, "Error: could not open target binary '%s': %s\n", path, strerror(errno));
        return NULL;
    }

    struct stat st;
    if (fstat(fd, &st) != 0) {
        fprintf(stderr, "Error: could not stat target binary '%s': %s\n", path, strerror(errno));
        close(fd);
        return NULL;
    }

    if (st.st_size <= 0) {
        fprintf(stderr, "Error: target binary is empty\n");
        close(fd);
        return NULL;
    }

    size_t len = (size_t)st.st_size;
    void *mapped = mmap(NULL, len, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);

    if (mapped == MAP_FAILED) {
        fprintf(stderr, "Error: could not map target binary '%s': %s\n", path, strerror(errno));
        return NULL;
    }

    *out_len = len;
    return (const uint8_t *)mapped;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: rustld_c <program> [args...]\n");
        return 1;
    }

    size_t target_len = 0;
    const uint8_t *target_bytes = map_file_readonly(argv[1], &target_len);
    if (target_bytes == NULL) {
        return 1;
    }

    /*
     * Forward target argv exactly like rustld example:
     * argv[0] becomes target program path.
     */
    const char *const *target_argv = (const char *const *)(argv + 1);
    size_t target_argc = (size_t)(argc - 1);

    /*
     * envp = NULL and auxv = NULL => reuse parent environment and auxv.
     * indirect_syscalls = 1 => route syscalls through anonymous RX trampoline
     * (syscall opcode hidden from the loader image).
     * On success this does not return.
     */
    int32_t rc = rustld_elfloader_execute_from_bytes(
        target_bytes,
        target_len,
        target_argc,
        target_argv,
        NULL,
        NULL,
        0,
        0,
        1   /* indirect_syscalls: trampoline mode */
    );

    fprintf(stderr, "rustld_c: execute_from_bytes failed (code=%d)\n", (int)rc);
    return (rc == 0) ? 0 : 1;
}
