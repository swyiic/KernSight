/* SPDX-License-Identifier: Apache-2.0
 * Root helper: PTRACE_ATTACH, remote mmap, call __loader_dlopen, detach.
 * Brief attach window; no Frida. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#if defined(__aarch64__)
#include <asm/ptrace.h>
#include <linux/elf.h>
#endif

static int mem_write(pid_t pid, unsigned long addr, const void *buf, size_t n) {
    const unsigned char *p = buf;
    size_t off = 0;
    while (off < n) {
        unsigned long word = 0;
        size_t chunk = n - off;
        if (chunk > sizeof(long)) {
            chunk = sizeof(long);
        }
        memcpy(&word, p + off, chunk);
        if (ptrace(PTRACE_POKEDATA, pid, (void *)(addr + off), (void *)word) < 0) {
            return -1;
        }
        off += sizeof(long);
    }
    return 0;
}

static unsigned long parse_hex(const char *s, const char **end) {
    unsigned long v = 0;
    while (*s) {
        unsigned char h = (unsigned char)*s;
        int d = -1;
        if (h >= '0' && h <= '9') {
            d = h - '0';
        } else if (h >= 'a' && h <= 'f') {
            d = h - 'a' + 10;
        } else if (h >= 'A' && h <= 'F') {
            d = h - 'A' + 10;
        } else {
            break;
        }
        v = (v << 4) | (unsigned)d;
        s++;
    }
    if (end) {
        *end = s;
    }
    return v;
}

static unsigned long find_linker_sym(pid_t pid, const char *sym) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    FILE *fp = fopen(path, "r");
    if (!fp) {
        return 0;
    }
    char line[512];
    unsigned long base = 0;
    char linker[256] = {0};
    while (fgets(line, sizeof(line), fp)) {
        if (!strstr(line, "linker64") || !strstr(line, "r-xp")) {
            continue;
        }
        const char *rest;
        base = parse_hex(line, &rest);
        char *p = strstr(line, "/");
        if (p) {
            p[strcspn(p, "\n")] = 0;
            strncpy(linker, p, sizeof(linker) - 1);
        }
        break;
    }
    fclose(fp);
    if (!base || !linker[0]) {
        return 0;
    }
    FILE *lf = fopen(linker, "rb");
    if (!lf) {
        return 0;
    }
    fseek(lf, 0, SEEK_END);
    long sz = ftell(lf);
    fseek(lf, 0, SEEK_SET);
    if (sz < 64 || sz > 8 * 1024 * 1024) {
        fclose(lf);
        return 0;
    }
    unsigned char *elf = malloc((size_t)sz);
    if (!elf || fread(elf, 1, (size_t)sz, lf) != (size_t)sz) {
        free(elf);
        fclose(lf);
        return 0;
    }
    fclose(lf);
    if (elf[0] != 0x7f || elf[4] != 2) {
        free(elf);
        return 0;
    }
    unsigned long phoff, dyn_off = 0, dyn_sz = 0;
    memcpy(&phoff, elf + 32, 8);
    unsigned short phentsize, phnum;
    memcpy(&phentsize, elf + 54, 2);
    memcpy(&phnum, elf + 56, 2);
    for (unsigned i = 0; i < phnum; i++) {
        unsigned char *ph = elf + phoff + (unsigned long)i * phentsize;
        unsigned int type;
        memcpy(&type, ph, 4);
        if (type == 2) {
            memcpy(&dyn_off, ph + 8, 8);
            memcpy(&dyn_sz, ph + 32, 8);
            break;
        }
    }
    unsigned long strtab = 0, symtab = 0, syment = 24;
    for (unsigned long off = 0; off + 16 <= dyn_sz; off += 16) {
        unsigned long tag, val;
        memcpy(&tag, elf + dyn_off + off, 8);
        memcpy(&val, elf + dyn_off + off + 8, 8);
        if (tag == 0) {
            break;
        }
        if (tag == 5) {
            strtab = val;
        } else if (tag == 6) {
            symtab = val;
        } else if (tag == 11) {
            syment = val;
        }
    }
    unsigned long result = 0;
    if (strtab && symtab && syment) {
        for (unsigned s = 1; s < 8192; s++) {
            unsigned char *e = elf + symtab + s * syment;
            unsigned int name;
            unsigned long value;
            memcpy(&name, e, 4);
            memcpy(&value, e + 8, 8);
            if (!name) {
                continue;
            }
            const char *nm = (const char *)(elf + strtab + name);
            if (strcmp(nm, sym) == 0 && value) {
                result = base + value;
                break;
            }
        }
    }
    free(elf);
    return result;
}

static int remote_call(pid_t pid, unsigned long fn, unsigned long a0, unsigned long a1,
                       unsigned long a2, unsigned long *out) {
#if !defined(__aarch64__)
    (void)pid;
    (void)fn;
    (void)a0;
    (void)a1;
    (void)a2;
    (void)out;
    return -1;
#else
    struct iovec iov;
    struct user_pt_regs regs, saved;
    memset(&regs, 0, sizeof(regs));
    iov.iov_base = &regs;
    iov.iov_len = sizeof(regs);
    if (ptrace(PTRACE_GETREGSET, pid, (void *)NT_PRSTATUS, &iov) < 0) {
        return -1;
    }
    saved = regs;
    regs.regs[0] = a0;
    regs.regs[1] = a1;
    regs.regs[2] = a2;
    regs.regs[30] = 0;
    regs.pc = fn;
    iov.iov_base = &regs;
    iov.iov_len = sizeof(regs);
    if (ptrace(PTRACE_SETREGSET, pid, (void *)NT_PRSTATUS, &iov) < 0) {
        return -1;
    }
    if (ptrace(PTRACE_CONT, pid, 0, 0) < 0) {
        return -1;
    }
    int status = 0;
    if (waitpid(pid, &status, 0) < 0) {
        return -1;
    }
    iov.iov_base = &regs;
    iov.iov_len = sizeof(regs);
    if (ptrace(PTRACE_GETREGSET, pid, (void *)NT_PRSTATUS, &iov) < 0) {
        return -1;
    }
    if (out) {
        *out = regs.regs[0];
    }
    iov.iov_base = &saved;
    iov.iov_len = sizeof(saved);
    ptrace(PTRACE_SETREGSET, pid, (void *)NT_PRSTATUS, &iov);
    return 0;
#endif
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "usage: ksight-inject <pid> <lib.so>\n");
        return 2;
    }
    pid_t pid = (pid_t)atoi(argv[1]);
    const char *lib = argv[2];
    if (pid <= 0 || !lib[0]) {
        return 2;
    }
    unsigned long dlopen_addr = find_linker_sym(pid, "__loader_dlopen");
    if (!dlopen_addr) {
        dlopen_addr = find_linker_sym(pid, "android_dlopen_ext");
    }
    if (!dlopen_addr) {
        fprintf(stderr, "ksight-inject: dlopen symbol not found\n");
        return 1;
    }
    if (ptrace(PTRACE_ATTACH, pid, 0, 0) < 0) {
        perror("PTRACE_ATTACH");
        return 1;
    }
    int status = 0;
    if (waitpid(pid, &status, 0) < 0) {
        ptrace(PTRACE_DETACH, pid, 0, 0);
        return 1;
    }
    unsigned long mmap_addr = find_linker_sym(pid, "mmap");
    if (!mmap_addr) {
        /* libc mmap */
        char path[64];
        snprintf(path, sizeof(path), "/proc/%d/maps", pid);
        FILE *fp = fopen(path, "r");
        char line[512];
        unsigned long libc = 0;
        if (fp) {
            while (fgets(line, sizeof(line), fp)) {
                if (strstr(line, "libc.so") && strstr(line, "r-xp")) {
                    const char *rest;
                    libc = parse_hex(line, &rest);
                    break;
                }
            }
            fclose(fp);
        }
        (void)libc;
    }
#if defined(__aarch64__)
    struct iovec iov;
    struct user_pt_regs regs, saved;
    memset(&regs, 0, sizeof(regs));
    iov.iov_base = &regs;
    iov.iov_len = sizeof(regs);
    if (ptrace(PTRACE_GETREGSET, pid, (void *)NT_PRSTATUS, &iov) < 0) {
        ptrace(PTRACE_DETACH, pid, 0, 0);
        return 1;
    }
    saved = regs;
    unsigned long sp = (regs.sp - 256) & ~0xfUL;
    if (mem_write(pid, sp, lib, strlen(lib) + 1) != 0) {
        fprintf(stderr, "ksight-inject: write path failed\n");
        ptrace(PTRACE_DETACH, pid, 0, 0);
        return 1;
    }
    unsigned long brk_word = ptrace(PTRACE_PEEKDATA, pid, (void *)saved.pc, 0);
    unsigned long brk_ins = 0xd4200000; /* brk #0 */
    if (ptrace(PTRACE_POKEDATA, pid, (void *)saved.pc, (void *)brk_ins) < 0) {
        ptrace(PTRACE_DETACH, pid, 0, 0);
        return 1;
    }
    regs.regs[0] = sp;
    regs.regs[1] = 2; /* RTLD_NOW */
    regs.regs[2] = 0;
    regs.regs[30] = saved.pc;
    regs.pc = dlopen_addr;
    iov.iov_base = &regs;
    iov.iov_len = sizeof(regs);
    if (ptrace(PTRACE_SETREGSET, pid, (void *)NT_PRSTATUS, &iov) < 0) {
        ptrace(PTRACE_POKEDATA, pid, (void *)saved.pc, (void *)brk_word);
        ptrace(PTRACE_DETACH, pid, 0, 0);
        return 1;
    }
    ptrace(PTRACE_CONT, pid, 0, 0);
    if (waitpid(pid, &status, 0) < 0) {
        ptrace(PTRACE_POKEDATA, pid, (void *)saved.pc, (void *)brk_word);
        ptrace(PTRACE_DETACH, pid, 0, 0);
        return 1;
    }
    iov.iov_base = &regs;
    iov.iov_len = sizeof(regs);
    ptrace(PTRACE_GETREGSET, pid, (void *)NT_PRSTATUS, &iov);
    unsigned long handle = regs.regs[0];
    ptrace(PTRACE_POKEDATA, pid, (void *)saved.pc, (void *)brk_word);
    iov.iov_base = &saved;
    iov.iov_len = sizeof(saved);
    ptrace(PTRACE_SETREGSET, pid, (void *)NT_PRSTATUS, &iov);
    ptrace(PTRACE_DETACH, pid, 0, 0);
    fprintf(stderr, "ksight-inject pid=%d handle=%lx\n", pid, handle);
    return handle ? 0 : 1;
#else
    ptrace(PTRACE_DETACH, pid, 0, 0);
    fprintf(stderr, "ksight-inject: aarch64 only\n");
    return 1;
#endif
}
