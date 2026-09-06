/* SPDX-License-Identifier: Apache-2.0
 * Late-loaded. Inline-hooks Conscrypt and Cronet SSL_write/SSL_read only.
 * Separate orig per library so Cronet SSL* is never passed to Conscrypt. */
typedef unsigned long u64;
typedef unsigned int u32;
typedef unsigned short u16;
typedef unsigned char u8;
typedef long i64;
typedef int i32;

#if defined(__aarch64__)
#define SYS_OPENAT 56
#define SYS_CLOSE 57
#define SYS_READ 63
#define SYS_WRITE 64
#define SYS_PREAD64 67
#define SYS_SOCKET 198
#define SYS_CONNECT 203
#define SYS_MMAP 222
#define SYS_MPROTECT 226
#elif defined(__arm__)
#define SYS_OPENAT 322
#define SYS_CLOSE 6
#define SYS_READ 3
#define SYS_WRITE 4
#define SYS_PREAD64 180
#define SYS_SOCKET 281
#define SYS_CONNECT 283
#define SYS_MMAP 192
#define SYS_MPROTECT 125
#endif
#define AT_FDCWD -100
#define O_RDONLY 0
#define O_WRONLY 1
#define O_CREAT 64
#define O_APPEND 1024
#define PROT_READ 1
#define PROT_WRITE 2
#define PROT_EXEC 4
#define MAP_PRIVATE 0x02
#define MAP_ANONYMOUS 0x20
#define AF_INET 2
#define SOCK_DGRAM 2
#define MAGIC 0x31544c4b
#define MAX_COPY 2048
#define UDP_PORT 18444

static long svc6(long n, long a0, long a1, long a2, long a3, long a4, long a5) {
#if defined(__aarch64__)
    register long x8 __asm__("x8") = n;
    register long x0 __asm__("x0") = a0;
    register long x1 __asm__("x1") = a1;
    register long x2 __asm__("x2") = a2;
    register long x3 __asm__("x3") = a3;
    register long x4 __asm__("x4") = a4;
    register long x5 __asm__("x5") = a5;
    __asm__ volatile("svc #0"
                     : "+r"(x0)
                     : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5)
                     : "memory");
    return x0;
#elif defined(__arm__)
    register long r7 __asm__("r7") = n;
    register long r0 __asm__("r0") = a0;
    register long r1 __asm__("r1") = a1;
    register long r2 __asm__("r2") = a2;
    register long r3 __asm__("r3") = a3;
    register long r4 __asm__("r4") = a4;
    register long r5 __asm__("r5") = a5;
    __asm__ volatile("svc #0"
                     : "+r"(r0)
                     : "r"(r7), "r"(r1), "r"(r2), "r"(r3), "r"(r4), "r"(r5)
                     : "memory");
    return r0;
#else
    (void)n;
    (void)a0;
    (void)a1;
    (void)a2;
    (void)a3;
    (void)a4;
    (void)a5;
    return -1;
#endif
}

static long kopen(const char *path) {
    return svc6(SYS_OPENAT, AT_FDCWD, (long)path, O_RDONLY, 0, 0, 0);
}

static long kopen_append(const char *path) {
    return svc6(SYS_OPENAT, AT_FDCWD, (long)path, O_WRONLY | O_CREAT | O_APPEND, 0600, 0, 0);
}

static long kread(long fd, void *buf, unsigned long n) {
    return svc6(SYS_READ, fd, (long)buf, (long)n, 0, 0, 0);
}

static long kpread(long fd, void *buf, unsigned long n, unsigned long off) {
    return svc6(SYS_PREAD64, fd, (long)buf, (long)n, (long)off, 0, 0);
}

static void kclose(long fd) { svc6(SYS_CLOSE, fd, 0, 0, 0, 0, 0); }

static void *kmmap(unsigned long n, int prot) {
#if defined(__arm__)
    /* mmap2: offset in 4096-byte units, 0 for anonymous. */
    long p = svc6(SYS_MMAP, 0, (long)n, prot, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
#else
    long p = svc6(SYS_MMAP, 0, (long)n, prot, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
#endif
    if (p < 0) {
        return 0;
    }
    return (void *)p;
}

static int kmprotect(void *p, unsigned long n, int prot) {
    return (int)svc6(SYS_MPROTECT, (long)p, (long)n, prot, 0, 0, 0);
}

static void iclear(void *p, unsigned long n) {
#if defined(__aarch64__)
    unsigned long a = (unsigned long)p & ~63UL;
    unsigned long e = (unsigned long)p + n + 63;
    unsigned long x;
    for (x = a; x < e; x += 64) {
        __asm__ volatile("dc cvau, %0" ::"r"(x) : "memory");
    }
    __asm__ volatile("dsb ish" ::: "memory");
    for (x = a; x < e; x += 64) {
        __asm__ volatile("ic ivau, %0" ::"r"(x) : "memory");
    }
    __asm__ volatile("dsb ish; isb" ::: "memory");
#else
    (void)p;
    (void)n;
    __asm__ volatile("isb" ::: "memory");
#endif
}

static u64 ru64(const u8 *p) {
    u64 v = 0;
    int i;
    for (i = 7; i >= 0; i--) {
        v = (v << 8) | p[i];
    }
    return v;
}

static u32 ru32(const u8 *p) {
    return (u32)p[0] | ((u32)p[1] << 8) | ((u32)p[2] << 16) | ((u32)p[3] << 24);
}

static u16 ru16(const u8 *p) { return (u16)p[0] | ((u16)p[1] << 8); }

static int streq(const char *a, const char *b) {
    while (*a && *b) {
        if (*a != *b) {
            return 0;
        }
        a++;
        b++;
    }
    return *a == *b;
}

static int starts(const char *s, const char *n) {
    while (*n) {
        if (*s != *n) {
            return 0;
        }
        s++;
        n++;
    }
    return 1;
}

static int contains(const char *s, const char *n) {
    unsigned i, j;
    for (i = 0; s[i]; i++) {
        for (j = 0; n[j] && s[i + j] == n[j]; j++) {
        }
        if (!n[j]) {
            return 1;
        }
    }
    return 0;
}

static void cpy(char *d, const char *s, unsigned max) {
    unsigned i = 0;
    while (s[i] && i + 1 < max) {
        d[i] = s[i];
        i++;
    }
    d[i] = 0;
}

static unsigned slen(const char *s) {
    unsigned n = 0;
    while (s[n]) {
        n++;
    }
    return n;
}

static long g_out = -1;

static void ensure_out(void) {
    char cmd[96];
    char path[160];
    unsigned i, n = 0;
    long fd;
    u8 pkt[16];
    if (g_out >= 0) {
        return;
    }
    cmd[0] = 0;
    fd = kopen("/proc/self/cmdline");
    if (fd >= 0) {
        long r = kread(fd, cmd, sizeof(cmd) - 1);
        kclose(fd);
        if (r > 0) {
            cmd[r] = 0;
            for (i = 0; i < (unsigned)r; i++) {
                if (cmd[i] == 0 || cmd[i] == ':') {
                    cmd[i] = 0;
                    break;
                }
            }
            n = 1;
        }
    }
    if (n && cmd[0] && cmd[0] != '-') {
        cpy(path, "/data/user/0/", sizeof(path));
        i = slen(path);
        cpy(path + i, cmd, sizeof(path) - i);
        i = slen(path);
        cpy(path + i, "/cache/.fl", sizeof(path) - i);
        g_out = kopen_append(path);
        if (g_out >= 0) {
            return;
        }
    }
    g_out = svc6(SYS_SOCKET, AF_INET, SOCK_DGRAM, 0, 0, 0, 0);
    if (g_out < 0) {
        return;
    }
    for (i = 0; i < sizeof(pkt); i++) {
        pkt[i] = 0;
    }
    pkt[0] = AF_INET;
    pkt[2] = (u8)(UDP_PORT >> 8);
    pkt[3] = (u8)UDP_PORT;
    pkt[4] = 127;
    pkt[7] = 1;
    svc6(SYS_CONNECT, g_out, (long)pkt, 16, 0, 0, 0);
}

static void emit(u8 dir, const void *buf, i64 num) {
    u32 n;
    u8 pkt[12 + MAX_COPY];
    unsigned i;
    const u8 *in;
    if (num <= 0 || !buf) {
        return;
    }
    n = (u32)num;
    if (n > MAX_COPY) {
        n = MAX_COPY;
    }
    ensure_out();
    if (g_out < 0) {
        return;
    }
    pkt[0] = (u8)MAGIC;
    pkt[1] = (u8)(MAGIC >> 8);
    pkt[2] = (u8)(MAGIC >> 16);
    pkt[3] = (u8)(MAGIC >> 24);
    pkt[4] = dir;
    pkt[5] = 0;
    pkt[6] = 0;
    pkt[7] = 0;
    pkt[8] = (u8)n;
    pkt[9] = (u8)(n >> 8);
    pkt[10] = (u8)(n >> 16);
    pkt[11] = (u8)(n >> 24);
    in = (const u8 *)buf;
    for (i = 0; i < n; i++) {
        pkt[12 + i] = in[i];
    }
    svc6(SYS_WRITE, g_out, (long)pkt, 12 + n, 0, 0, 0);
}

typedef i32 (*ssl_rw_fn)(void *, const void *, i32);
typedef i32 (*ssl_rw_ex_fn)(void *, const void *, u64, u64 *);

static ssl_rw_fn orig_w_cs;
static ssl_rw_fn orig_r_cs;
static ssl_rw_fn orig_w_cr;
static ssl_rw_fn orig_r_cr;
static ssl_rw_ex_fn orig_wx_cs;
static ssl_rw_ex_fn orig_rx_cs;
static ssl_rw_ex_fn orig_wx_cr;
static ssl_rw_ex_fn orig_rx_cr;

static i32 hw_cs(void *s, const void *b, i32 n) {
    emit(0, b, n);
    return orig_w_cs(s, b, n);
}
static i32 hr_cs(void *s, void *b, i32 n) {
    i32 r = orig_r_cs(s, b, n);
    if (r > 0) {
        emit(1, b, r);
    }
    return r;
}
static i32 hw_cr(void *s, const void *b, i32 n) {
    emit(0, b, n);
    return orig_w_cr(s, b, n);
}
static i32 hr_cr(void *s, void *b, i32 n) {
    i32 r = orig_r_cr(s, b, n);
    if (r > 0) {
        emit(1, b, r);
    }
    return r;
}
static i32 hwx_cs(void *s, const void *b, u64 n, u64 *w) {
    i32 ok = orig_wx_cs(s, b, n, w);
    if (ok == 1 && w && *w) {
        emit(0, b, (i64)*w);
    } else if (n) {
        emit(0, b, (i64)n);
    }
    return ok;
}
static i32 hrx_cs(void *s, void *b, u64 n, u64 *r) {
    i32 ok = orig_rx_cs(s, b, n, r);
    if (ok == 1 && r && *r) {
        emit(1, b, (i64)*r);
    }
    return ok;
}
static i32 hwx_cr(void *s, const void *b, u64 n, u64 *w) {
    i32 ok = orig_wx_cr(s, b, n, w);
    if (ok == 1 && w && *w) {
        emit(0, b, (i64)*w);
    } else if (n) {
        emit(0, b, (i64)n);
    }
    return ok;
}
static i32 hrx_cr(void *s, void *b, u64 n, u64 *r) {
    i32 ok = orig_rx_cr(s, b, n, r);
    if (ok == 1 && r && *r) {
        emit(1, b, (i64)*r);
    }
    return ok;
}

static u64 v2o(const u8 *ph, u16 phnum, u16 phentsize, u64 v) {
    u16 i;
    for (i = 0; i < phnum; i++) {
        const u8 *p = ph + (u64)i * phentsize;
        if (ru32(p) != 1) {
            continue;
        }
        u64 va = ru64(p + 16);
        u64 sz = ru64(p + 32);
        if (v >= va && v < va + sz) {
            return ru64(p + 8) + (v - va);
        }
    }
    return 0;
}

static int pread_ok(long fd, u64 off, void *buf, unsigned n) {
    return kpread(fd, buf, n, off) == (long)n;
}

static void *export_from_fd32(long fd, u64 bias, const char *want) {
    u8 ehdr[52];
    u8 ph[32 * 16];
    u8 dyn[8];
    u16 phnum, phentsize, i;
    u32 phoff, dyn_off = 0, dyn_sz = 0, strtab = 0, symtab = 0, syment = 16, off;
    if (!pread_ok(fd, 0, ehdr, 52) || ehdr[0] != 0x7f || ehdr[4] != 1) {
        return 0;
    }
    phoff = ru32(ehdr + 28);
    phentsize = ru16(ehdr + 42);
    phnum = ru16(ehdr + 44);
    if (phnum > 16 || phentsize > 32) {
        return 0;
    }
    if (!pread_ok(fd, phoff, ph, (unsigned)phnum * phentsize)) {
        return 0;
    }
    for (i = 0; i < phnum; i++) {
        u8 *p = ph + (u32)i * phentsize;
        if (ru32(p) == 2) {
            u32 vaddr = ru32(p + 8);
            u16 j;
            dyn_sz = ru32(p + 16);
            dyn_off = 0;
            for (j = 0; j < phnum; j++) {
                u8 *l = ph + (u32)j * phentsize;
                if (ru32(l) == 1) {
                    u32 lv = ru32(l + 8);
                    u32 ls = ru32(l + 16);
                    if (vaddr >= lv && vaddr < lv + ls) {
                        dyn_off = ru32(l + 4) + (vaddr - lv);
                        break;
                    }
                }
            }
        }
    }
    if (!dyn_off) {
        return 0;
    }
    for (off = 0; off + 8 <= dyn_sz; off += 8) {
        u32 tag, val;
        if (!pread_ok(fd, dyn_off + off, dyn, 8)) {
            break;
        }
        tag = ru32(dyn);
        val = ru32(dyn + 4);
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
    if (!strtab || !symtab || !syment) {
        return 0;
    }
    {
        u32 str_off = 0, sym_off = 0, s;
        u16 j;
        for (j = 0; j < phnum; j++) {
            u8 *l = ph + (u32)j * phentsize;
            if (ru32(l) != 1) {
                continue;
            }
            {
                u32 lv = ru32(l + 8);
                u32 ls = ru32(l + 16);
                u32 fo = ru32(l + 4);
                if (strtab >= lv && strtab < lv + ls) {
                    str_off = fo + (strtab - lv);
                }
                if (symtab >= lv && symtab < lv + ls) {
                    sym_off = fo + (symtab - lv);
                }
            }
        }
        if (!str_off || !sym_off) {
            return 0;
        }
        for (s = 1; s < 8192; s++) {
            u8 ent[16];
            char nbuf[48];
            u32 name, value;
            if (!pread_ok(fd, sym_off + s * syment, ent, 16)) {
                break;
            }
            name = ru32(ent);
            value = ru32(ent + 4);
            if (!name || !value) {
                continue;
            }
            if (!pread_ok(fd, str_off + name, nbuf, 47)) {
                continue;
            }
            nbuf[47] = 0;
            if (streq(nbuf, want)) {
                return (void *)(unsigned long)(bias + value);
            }
        }
    }
    return 0;
}

static void *export_from_fd(long fd, u64 bias, const char *want) {
    u8 ehdr[64];
    u8 ph[56 * 16];
    u8 dyn[16];
    u16 phnum, phentsize, i;
    u64 phoff, dyn_off = 0, dyn_sz = 0, strtab = 0, symtab = 0, syment = 24, off;
    if (!pread_ok(fd, 0, ehdr, 16)) {
        return 0;
    }
    if (ehdr[4] == 1) {
        return export_from_fd32(fd, bias, want);
    }
    if (!pread_ok(fd, 0, ehdr, 64) || ehdr[0] != 0x7f || ehdr[4] != 2) {
        return 0;
    }
    phoff = ru64(ehdr + 32);
    phentsize = ru16(ehdr + 54);
    phnum = ru16(ehdr + 56);
    if (phnum > 16 || phentsize > 56) {
        return 0;
    }
    if (!pread_ok(fd, phoff, ph, (unsigned)phnum * phentsize)) {
        return 0;
    }
    for (i = 0; i < phnum; i++) {
        u8 *p = ph + (u64)i * phentsize;
        if (ru32(p) == 2) {
            dyn_off = v2o(ph, phnum, phentsize, ru64(p + 16));
            dyn_sz = ru64(p + 32);
        }
    }
    if (!dyn_off) {
        return 0;
    }
    for (off = 0; off + 16 <= dyn_sz; off += 16) {
        u64 tag, val;
        if (!pread_ok(fd, dyn_off + off, dyn, 16)) {
            break;
        }
        tag = ru64(dyn);
        val = ru64(dyn + 8);
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
    if (!strtab || !symtab || !syment) {
        return 0;
    }
    {
        u64 str_off = v2o(ph, phnum, phentsize, strtab);
        u64 sym_off = v2o(ph, phnum, phentsize, symtab);
        u64 s;
        if (!str_off || !sym_off) {
            return 0;
        }
        for (s = 1; s < 8192; s++) {
            u8 ent[24];
            char nbuf[32];
            u32 name;
            u64 value;
            if (!pread_ok(fd, sym_off + s * syment, ent, 24)) {
                break;
            }
            name = ru32(ent);
            value = ru64(ent + 8);
            if (!name || !value) {
                continue;
            }
            if (!pread_ok(fd, str_off + name, nbuf, 31)) {
                continue;
            }
            nbuf[31] = 0;
            if (streq(nbuf, want)) {
                return (void *)(bias + value);
            }
        }
    }
    return 0;
}

static int lib_kind(const char *path) {
    if (!contains(path, "libssl.so")) {
        return 0;
    }
    if (contains(path, "conscrypt")) {
        return 1;
    }
    if (contains(path, "cronet")) {
        return 2;
    }
    return 0;
}

static void *find_in_kind(int kind, const char *name) {
    long fd = kopen("/proc/self/maps");
    char *buf;
    long n, got = 0;
    char *p;
    if (fd < 0) {
        return 0;
    }
    buf = (char *)kmmap(256 * 1024, PROT_READ | PROT_WRITE);
    if (!buf) {
        kclose(fd);
        return 0;
    }
    while (got < 256 * 1024 - 1) {
        n = kread(fd, buf + got, (unsigned long)(256 * 1024 - 1 - got));
        if (n <= 0) {
            break;
        }
        got += n;
    }
    kclose(fd);
    buf[got] = 0;
    p = buf;
    while (*p) {
        char *line = p;
        char *path;
        const char *rest;
        u64 start = 0;
        int hex, saw = 0;
        char *offp;
        while (*p && *p != '\n') {
            p++;
        }
        if (*p == '\n') {
            *p++ = 0;
        }
        rest = line;
        while (*rest) {
            hex = -1;
            if (*rest >= '0' && *rest <= '9') {
                hex = *rest - '0';
            } else if (*rest >= 'a' && *rest <= 'f') {
                hex = *rest - 'a' + 10;
            } else if (*rest >= 'A' && *rest <= 'F') {
                hex = *rest - 'A' + 10;
            } else {
                break;
            }
            start = (start << 4) | (u64)hex;
            rest++;
        }
        offp = line;
        while (*offp) {
            if (starts(offp, " 00000000 ")) {
                saw = 1;
                break;
            }
            offp++;
        }
        if (!saw) {
            continue;
        }
        path = line;
        while (*path && *path != '/') {
            path++;
        }
        if (*path != '/' || lib_kind(path) != kind) {
            continue;
        }
        {
            long so = kopen(path);
            void *sym;
            if (so < 0) {
                continue;
            }
            sym = export_from_fd(so, start, name);
            kclose(so);
            if (sym) {
                return sym;
            }
        }
    }
    return 0;
}

static void install_jump(void *from, void *to) {
    u8 *p;
    unsigned long page;
    int i;
    if (!from || !to) {
        return;
    }
#if defined(__aarch64__)
    p = (u8 *)from;
    page = (unsigned long)p & ~0xfffUL;
    if (p[0] == 0x50 && p[1] == 0x00 && p[2] == 0x00 && p[3] == 0x58) {
        return;
    }
    kmprotect((void *)page, 0x2000, PROT_READ | PROT_WRITE | PROT_EXEC);
    p[0] = 0x50;
    p[1] = 0x00;
    p[2] = 0x00;
    p[3] = 0x58;
    p[4] = 0x00;
    p[5] = 0x02;
    p[6] = 0x1f;
    p[7] = 0xd6;
    {
        u64 addr = (u64)to;
        for (i = 0; i < 8; i++) {
            p[8 + i] = (u8)(addr >> (8 * i));
        }
    }
    kmprotect((void *)page, 0x2000, PROT_READ | PROT_EXEC);
    iclear(from, 16);
#elif defined(__arm__)
    {
        u32 addr = (u32)(unsigned long)to;
        int thumb = addr & 1;
        addr &= ~1u;
        p = (u8 *)((unsigned long)from & ~1UL);
        page = (unsigned long)p & ~0xfffUL;
        kmprotect((void *)page, 0x2000, PROT_READ | PROT_WRITE | PROT_EXEC);
        if (thumb) {
            p[0] = 0xdf;
            p[1] = 0xf8;
            p[2] = 0x04;
            p[3] = 0xc0;
            p[4] = 0x60;
            p[5] = 0x47;
            p[6] = 0x00;
            p[7] = 0xbf;
            for (i = 0; i < 4; i++) {
                p[8 + i] = (u8)(addr >> (8 * i));
            }
            iclear(p, 12);
        } else {
            p[0] = 0x04;
            p[1] = 0xf0;
            p[2] = 0x1f;
            p[3] = 0xe5;
            for (i = 0; i < 4; i++) {
                p[4 + i] = (u8)(addr >> (8 * i));
            }
            iclear(p, 8);
        }
        kmprotect((void *)page, 0x2000, PROT_READ | PROT_EXEC);
    }
#endif
}

static ssl_rw_fn make_rw_tramp(void *orig) {
    u8 *tramp;
    u8 *src;
    int i;
    if (!orig) {
        return 0;
    }
    tramp = (u8 *)kmmap(64, PROT_READ | PROT_WRITE);
    if (!tramp) {
        return 0;
    }
#if defined(__aarch64__)
    {
        u64 back = (u64)orig + 16;
        src = (u8 *)orig;
        for (i = 0; i < 16; i++) {
            tramp[i] = src[i];
        }
        tramp[16] = 0x50;
        tramp[17] = 0x00;
        tramp[18] = 0x00;
        tramp[19] = 0x58;
        tramp[20] = 0x00;
        tramp[21] = 0x02;
        tramp[22] = 0x1f;
        tramp[23] = 0xd6;
        for (i = 0; i < 8; i++) {
            tramp[24 + i] = (u8)(back >> (8 * i));
        }
        kmprotect(tramp, 64, PROT_READ | PROT_EXEC);
        iclear(tramp, 32);
        return (ssl_rw_fn)tramp;
    }
#elif defined(__arm__)
    {
        u32 orig_u = (u32)(unsigned long)orig;
        int thumb = orig_u & 1;
        u32 aligned = orig_u & ~1u;
        u32 back = aligned + 8;
        src = (u8 *)(unsigned long)aligned;
        for (i = 0; i < 8; i++) {
            tramp[i] = src[i];
        }
        if (thumb) {
            tramp[8] = 0xdf;
            tramp[9] = 0xf8;
            tramp[10] = 0x04;
            tramp[11] = 0xc0;
            tramp[12] = 0x60;
            tramp[13] = 0x47;
            tramp[14] = 0x00;
            tramp[15] = 0xbf;
            back |= 1;
            for (i = 0; i < 4; i++) {
                tramp[16 + i] = (u8)(back >> (8 * i));
            }
            kmprotect(tramp, 64, PROT_READ | PROT_EXEC);
            iclear(tramp, 20);
            return (ssl_rw_fn)((unsigned long)tramp | 1);
        }
        tramp[8] = 0x04;
        tramp[9] = 0xf0;
        tramp[10] = 0x1f;
        tramp[11] = 0xe5;
        for (i = 0; i < 4; i++) {
            tramp[12 + i] = (u8)(back >> (8 * i));
        }
        kmprotect(tramp, 64, PROT_READ | PROT_EXEC);
        iclear(tramp, 16);
        return (ssl_rw_fn)tramp;
    }
#else
    return 0;
#endif
}

static ssl_rw_ex_fn make_ex_tramp(void *orig) {
    return (ssl_rw_ex_fn)make_rw_tramp(orig);
}

static void hook_lib(int kind) {
    void *w = find_in_kind(kind, "SSL_write");
    void *r = find_in_kind(kind, "SSL_read");
    void *wx = find_in_kind(kind, "SSL_write_ex");
    void *rx = find_in_kind(kind, "SSL_read_ex");
    if (kind == 1) {
        if (w) {
            orig_w_cs = make_rw_tramp(w);
            install_jump(w, (void *)hw_cs);
        }
        if (r) {
            orig_r_cs = make_rw_tramp(r);
            install_jump(r, (void *)hr_cs);
        }
        if (wx) {
            orig_wx_cs = make_ex_tramp(wx);
            install_jump(wx, (void *)hwx_cs);
        }
        if (rx) {
            orig_rx_cs = make_ex_tramp(rx);
            install_jump(rx, (void *)hrx_cs);
        }
    } else {
        if (w) {
            orig_w_cr = make_rw_tramp(w);
            install_jump(w, (void *)hw_cr);
        }
        if (r) {
            orig_r_cr = make_rw_tramp(r);
            install_jump(r, (void *)hr_cr);
        }
        if (wx) {
            orig_wx_cr = make_ex_tramp(wx);
            install_jump(wx, (void *)hwx_cr);
        }
        if (rx) {
            orig_rx_cr = make_ex_tramp(rx);
            install_jump(rx, (void *)hrx_cr);
        }
    }
}

typedef void (*setv_fn)(void *, int, void *);
typedef void (*setcert_fn)(void *, void *, void *);

static setv_fn orig_ctx_cv;
static setv_fn orig_ssl_cv;
static setv_fn orig_ctx_v;
static setv_fn orig_ssl_v;
static setcert_fn orig_ctx_cert;

static int always_ok(void *ssl, unsigned char *alert) {
    (void)ssl;
    if (alert) {
        *alert = 0;
    }
    return 0;
}

static int cert_ok(void *ctx, void *arg) {
    (void)ctx;
    (void)arg;
    return 1;
}

static void h_ctx_cv(void *ctx, int mode, void *cb) {
    (void)mode;
    (void)cb;
    if (orig_ctx_cv) {
        orig_ctx_cv(ctx, 1, (void *)always_ok);
    }
}

static void h_ssl_cv(void *ssl, int mode, void *cb) {
    (void)mode;
    (void)cb;
    if (orig_ssl_cv) {
        orig_ssl_cv(ssl, 1, (void *)always_ok);
    }
}

static void h_ctx_v(void *ctx, int mode, void *cb) {
    (void)mode;
    (void)cb;
    if (orig_ctx_v) {
        orig_ctx_v(ctx, 0, 0);
    }
}

static void h_ssl_v(void *ssl, int mode, void *cb) {
    (void)mode;
    (void)cb;
    if (orig_ssl_v) {
        orig_ssl_v(ssl, 0, 0);
    }
}

static void h_ctx_cert(void *ctx, void *cb, void *arg) {
    (void)cb;
    (void)arg;
    if (orig_ctx_cert) {
        orig_ctx_cert(ctx, (void *)cert_ok, 0);
    }
}

static setv_fn make_setv_tramp(void *orig) {
    return (setv_fn)make_rw_tramp(orig);
}

static void hook_verify(int kind) {
    void *cv = find_in_kind(kind, "SSL_CTX_set_custom_verify");
    void *sv = find_in_kind(kind, "SSL_set_custom_verify");
    void *v = find_in_kind(kind, "SSL_CTX_set_verify");
    void *s = find_in_kind(kind, "SSL_set_verify");
    void *c = find_in_kind(kind, "SSL_CTX_set_cert_verify_callback");
    if (cv) {
        orig_ctx_cv = make_setv_tramp(cv);
        install_jump(cv, (void *)h_ctx_cv);
    }
    if (sv) {
        orig_ssl_cv = make_setv_tramp(sv);
        install_jump(sv, (void *)h_ssl_cv);
    }
    if (v) {
        orig_ctx_v = make_setv_tramp(v);
        install_jump(v, (void *)h_ctx_v);
    }
    if (s) {
        orig_ssl_v = make_setv_tramp(s);
        install_jump(s, (void *)h_ssl_v);
    }
    if (c) {
        orig_ctx_cert = (setcert_fn)make_rw_tramp(c);
        install_jump(c, (void *)h_ctx_cert);
    }
}

void ksight_tls_init(void) {
#if defined(__arm__)
    /* 32-bit: Pixel GKI cannot uprobe AArch32. Copy SSL_write/read instead.
     * Do not kill verify — app keeps the real server cert (no MITM). */
    hook_lib(1);
    hook_lib(2);
    emit(0, "KSIGHT_TLS32", 12);
#else
    hook_verify(1);
    hook_verify(2);
#endif
}

__attribute__((section(".init_array"), used)) static void (*ksight_init_ptr)(void) = ksight_tls_init;
