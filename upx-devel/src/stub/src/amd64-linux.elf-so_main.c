/* amd64-linux.elf-so_main.c -- stub loader for compressed shared library

   This file is part of the UPX executable compressor.

   Copyright (C) Markus Franz Xaver Johannes Oberhumer
   Copyright (C) Laszlo Molnar
   Copyright (C) John F. Reiser
   All Rights Reserved.

   UPX and the UCL library are free software; you can redistribute them
   and/or modify them under the terms of the GNU General Public License as
   published by the Free Software Foundation; either version 2 of
   the License, or (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; see the file COPYING.
   If not, write to the Free Software Foundation, Inc.,
   59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.

   Markus F.X.J. Oberhumer              Laszlo Molnar
   <markus@oberhumer.com>               <ezerotven+github@gmail.com>

   John F. Reiser
   <jreiser@users.sourceforge.net>
 */


#include "include/linux.h"
#include "../../parallax_vm4.h"

// Pprotect is mprotect, but page-aligned on the lo end (Linux requirement)
extern unsigned Pprotect(void *, size_t, unsigned);
extern void *Pmap(void *, size_t, unsigned, unsigned, int, size_t);
extern int Punmap(void *, size_t);
extern int Psync(void const *, size_t, unsigned);
extern size_t Pwrite(unsigned, void const *, size_t);
#define MS_SYNC 4
#define MFD_EXEC 0x10

extern void f_int3(int arg);

#ifndef DEBUG  //{
#define DEBUG 0
#endif  //}

#if !DEBUG //{
#define DPRINTF(fmt, args...) /*empty*/
#else  //}{
// DPRINTF is defined as an expression using "({ ... })"
// so that DPRINTF can be invoked inside an expression,
// and then followed by a comma to ignore the return value.
// The only complication is that percent and backslash
// must be doubled in the format string, because the format
// string is processed twice: once at compile-time by 'asm'
// to produce the assembled value, and once at runtime to use it.
#if defined(__powerpc__)  //{
#define DPRINTF(fmt, args...) ({ \
    char const *r_fmt; \
    asm("bl 0f; .string \"" fmt "\"; .balign 4; 0: mflr %0" \
/*out*/ : "=r"(r_fmt) \
/* in*/ : \
/*und*/ : "lr"); \
    dprintf(r_fmt, args); \
})
#elif defined(__x86_64) //}{
#define DPRINTF(fmt, args...) ({ \
    char const *r_fmt; \
    asm("call 0f; .asciz \"" fmt "\"; 0: pop %0" \
/*out*/ : "=r"(r_fmt) ); \
    dprintf(r_fmt, args); \
})
#elif defined(__aarch64__) //}{
#define DPRINTF(fmt, args...) ({ \
    char const *r_fmt; \
    asm("bl 0f; .string \"" fmt "\"; .balign 4; 0: mov %0,x30" \
/*out*/ : "=r"(r_fmt) \
/* in*/ : \
/*und*/ : "x30"); \
    dprintf(r_fmt, args); \
})
#elif defined(__riscv) //}{
#define DPRINTF(fmt, args...) ({ \
    char const *r_fmt; \
    asm("jal %0, 0f; .string \"" fmt "\"; .balign 4; 0:" \
/*out*/ : "=r"(r_fmt) \
/* in*/ : \
/*und*/ : ); \
    dprintf(r_fmt, args); \
})

#endif  //}

static int dprintf(char const *fmt, ...); // forward
#endif  /*}*/

#if DEBUG  //{
void dprint8(
    char const *fmt,
    void *a, void *b, void *c, void *d,
    void *e, void *f, void *g, void *h
)
{
    dprintf(fmt, a, b, c, d, e, f, g, h);
}
#endif  //}

/*************************************************************************
// configuration section
**************************************************************************/

// In order to make it much easier to move this code at runtime and execute
// it at an address different from it load address:  there must be no
// static data, and no string constants.

/*************************************************************************
// util
**************************************************************************/

#if 0  //{  save space
#define ERR_LAB error: exit(127);
#define err_exit(a) goto error
#else  //}{  save debugging time
#define ERR_LAB /*empty*/
void my_bkpt(void const *, ...);

static void
err_exit(int a)
{
    (void)a;  // debugging convenience
    DPRINTF("err_exit %%x\\n", a);
    my_bkpt((void const *)(long)a);
    exit(127);
}
#endif  //}

/*************************************************************************
// "file" util
**************************************************************************/

typedef struct {
    size_t size;  // must be first to match size[0] uncompressed size
    char *buf;
} Extent;


static void
parallax_secure_zero(void *address, size_t length)
{
    volatile unsigned char *p = (volatile unsigned char *)address;
    while (length-- != 0)
        *p++ = 0;
}

static void
xread(Extent *x, char *buf, size_t count)
{
    DPRINTF("xread x.size=%%x  x.buf=%%p  buf=%%p  count=%%x\\n",
        x->size, x->buf, buf, count);
    char *p=x->buf, *q=buf;
    size_t j;
    if (x->size < count) {
        err_exit(8);
    }
    for (j = count; 0!=j--; ++p, ++q) {
        *q = *p;
    }
    x->buf  += count;
    x->size -= count;
    DPRINTF("yread x.size=%%x  x.buf=%%p  buf=%%p  count=%%x\\n",
        x->size, x->buf, buf, count);
}

/*************************************************************************
// UPX & NRV stuff
**************************************************************************/

int f_expand( // .globl in $(ARCH)-linux.elf-so_fold.S
    nrv_byte const *binfo, nrv_byte *dst, size_t *dstlen);

static void
unpackExtent(
    Extent *const xi,  // input includes struct b_info
    Extent *const xo,  // output
    unsigned const pvm_program_id
)
{
    while (xo->size) {
        DPRINTF("unpackExtent xi=(%%p %%p)  xo=(%%p %%p)\\n",
            xi->size, xi->buf, xo->size, xo->buf);
        struct b_info h;
        //   Note: if h.sz_unc == h.sz_cpr then the block was not
        //   compressible and is stored in its uncompressed form.

        // Read and check block sizes.
        xread(xi, (char *)&h, sizeof(h));
        DPRINTF("h.sz_unc=%%x  h.sz_cpr=%%x  h.b_method=%%x\\n",
            h.sz_unc, h.sz_cpr, h.b_method);
        if (h.sz_unc == 0) {                     // uncompressed size 0 -> EOF
            if (h.sz_cpr != UPX_MAGIC_LE32)      // h.sz_cpr must be h->magic
                err_exit(2);
            if (xi->size != 0)                 // all bytes must be written
                err_exit(3);
            break;
        }
        if (h.sz_cpr <= 0) {
            err_exit(4);
ERR_LAB
        }
        if (h.sz_cpr > h.sz_unc
        ||  h.sz_unc > xo->size ) {
            err_exit(5);
        }

#if defined(__aarch64__)
        unsigned char *const pvm_block_start = (unsigned char *)xi->buf;
        size_t const pvm_block_size = h.sz_cpr;
        /*
         * PVM4 is opt-in per block via b_unused. The disk copy remains in
         * diversified form; only the block currently being consumed is
         * decoded inside the already-private side buffer.
         */
        if (parallax_vm4_is_tag(h.b_unused)) {
            if (pvm_program_id == 0 || h.sz_cpr == 0) {
                err_exit(9);
            }
            parallax_vm4_decode(
                    (unsigned char *)xi->buf,
                    h.sz_cpr,
                    pvm_program_id,
                    h.sz_unc,
                    h.sz_cpr,
                    h.b_method,
                    h.b_unused);

            /*
             * f_expand() receives the b_info immediately before xi->buf.
             * Clear only the private copy's transport marker so legacy
             * decompressor code never interprets it as compression metadata.
             */
            ((struct b_info *)(void *)(xi->buf - sizeof(h)))->b_unused = 0;
        }
#else
        (void)pvm_program_id;
#endif
        // Now we have:
        //   assert(h.sz_cpr <= h.sz_unc);
        //   assert(h.sz_unc > 0 && h.sz_unc <= blocksize);
        //   assert(h.sz_cpr > 0 && h.sz_cpr <= blocksize);

        if (h.sz_cpr < h.sz_unc) { // Decompress block
            size_t out_len = h.sz_unc;  // EOF for lzma
            int const j = f_expand((unsigned char *)xi->buf - sizeof(h),
                (unsigned char *)xo->buf, &out_len);
            if (j != 0 || out_len != (nrv_uint)h.sz_unc) {
                DPRINTF("  j=%%x  out_len=%%x  &h=%%p\\n", j, out_len, &h);
                err_exit(7);
            }
#if defined(__aarch64__)
            parallax_secure_zero(pvm_block_start, pvm_block_size);
#endif
            xi->buf  += h.sz_cpr;
            xi->size -= h.sz_cpr;
        }
        else { // copy literal block
            DPRINTF("  copy %%p  %%p  %%p\\n", xi->buf, xo->buf, h.sz_cpr);
            xi->size += sizeof(h);  // xread(xi, &h, sizeof(h)) was a peek
            xread(xi, xo->buf, h.sz_cpr);
        }
        xo->buf  += h.sz_unc;
        xo->size -= h.sz_unc;
    }
}

#if defined(__x86_64) //}{
#define addr_string(string) ({ \
    char const *str; \
    asm("call 0f; .asciz \"" string "\"; 0: pop %0" \
/*out*/ : "=r"(str) ); \
    str; \
})
#elif defined(__aarch64__) //}{
#define addr_string(string) ({ \
    char const *str; \
    asm("bl 0f; .string \"" string "\"; .balign 4; 0: mov %0,x30" \
/*out*/ : "=r"(str) \
/* in*/ : \
/*und*/ : "x30"); \
    str; \
})
#elif defined(__riscv) //}{
#define addr_string(string) ({ \
    char const *str; \
    asm("jal %0,0f; .string \"" string "\"; .balign 4; 0:" \
/*out*/ : "=r"(str) \
/* in*/ : \
/*und*/ : ); \
    str; \
})
#else  //}{
       error;
#endif  //}

extern int memfd_create(const char *name, unsigned int flags);

#define ElfW(sym) Elf64_ ## sym

#define nullptr (void *)0

#if defined(__aarch64__)

/*
 * Conservative client-side hook guard for Android ARM64 shared libraries.
 *
 * Compatibility rules:
 *   - no network access or server dependency;
 *   - no port probing;
 *   - root/Magisk alone is not a failure signal;
 *   - only strong hook/tracer evidence is fatal;
 *   - checks use /proc plus already-relocated ELF metadata and do not patch GOT.
 */

#define PARALLAX_PT_DYNAMIC 2
#define PARALLAX_DT_NULL 0
#define PARALLAX_DT_PLTRELSZ 2
#define PARALLAX_DT_STRTAB 5
#define PARALLAX_DT_SYMTAB 6
#define PARALLAX_DT_RELA 7
#define PARALLAX_DT_RELASZ 8
#define PARALLAX_DT_RELAENT 9
#define PARALLAX_DT_PLTREL 20
#define PARALLAX_DT_JMPREL 23
#define PARALLAX_R_AARCH64_GLOB_DAT 1025u
#define PARALLAX_R_AARCH64_JUMP_SLOT 1026u

typedef struct {
    Elf64_Sxword d_tag;
    union {
        Elf64_Xword d_val;
        Elf64_Addr d_ptr;
    } d_un;
} ParallaxDyn64;

typedef struct {
    Elf64_Addr r_offset;
    Elf64_Xword r_info;
    Elf64_Sxword r_addend;
} ParallaxRela64;

typedef struct {
    Elf64_Word st_name;
    unsigned char st_info;
    unsigned char st_other;
    Elf64_Half st_shndx;
    Elf64_Addr st_value;
    Elf64_Xword st_size;
} ParallaxSym64;

static unsigned char parallax_ascii_lower(unsigned char c) {
    if (c >= 'A' && c <= 'Z')
        return (unsigned char)(c + ('a' - 'A'));
    return c;
}

static unsigned char parallax_token_byte(uint64_t lo, uint64_t hi, unsigned index) {
    if (index < 8u)
        return (unsigned char)((lo >> (index * 8u)) & 0xffu);
    index -= 8u;
    return (unsigned char)((hi >> (index * 8u)) & 0xffu);
}

static long parallax_find_token_ci(
        char const *buf,
        size_t len,
        uint64_t lo,
        uint64_t hi,
        unsigned token_len) {
    size_t i;
    if (token_len == 0 || token_len > 16u || len < token_len)
        return -1;
    for (i = 0; i + token_len <= len; ++i) {
        unsigned j;
        for (j = 0; j < token_len; ++j) {
            unsigned char a = parallax_ascii_lower((unsigned char)buf[i + j]);
            unsigned char b = parallax_ascii_lower(parallax_token_byte(lo, hi, j));
            if (a != b)
                break;
        }
        if (j == token_len)
            return (long)i;
    }
    return -1;
}

static int parallax_has_token_ci(
        char const *buf,
        size_t len,
        uint64_t lo,
        uint64_t hi,
        unsigned token_len) {
    return 0 <= parallax_find_token_ci(buf, len, lo, hi, token_len);
}

static void parallax_unpack_path(
        char *out,
        unsigned len,
        uint64_t a,
        uint64_t b,
        uint64_t d) {
    unsigned i;
    for (i = 0; i < len; ++i) {
        uint64_t word = i < 8u ? a : (i < 16u ? b : d);
        unsigned shift = (i & 7u) * 8u;
        out[i] = (char)((word >> shift) & 0xffu);
    }
    out[len] = 0;
}

static int parallax_ld_preload_active(void) {
    char path[19];
    char buf[4096 + 16];
    size_t carry = 0;
    int fd;

    parallax_unpack_path(
            path, 18,
            0x65732f636f72702full,
            0x7269766e652f666cull,
            0x0000000000006e6full);
    fd = openat(0, path, O_RDONLY, 0);
    if (fd < 0)
        return 0; /* compatibility: unreadable /proc is not by itself an attack */

    for (;;) {
        ssize_t got = read(fd, buf + carry, 4096);
        size_t total;
        long at;
        if (got <= 0)
            break;
        total = carry + (size_t)got;
        at = parallax_find_token_ci(
                buf, total,
                0x4f4c4552505f444cull,
                0x00000000003d4441ull,
                11u);
        if (0 <= at && (size_t)at + 11u < total && buf[at + 11] != 0) {
            close(fd);
            return 1;
        }

        carry = total < 16u ? total : 16u;
        {
            size_t i;
            for (i = 0; i < carry; ++i)
                buf[i] = buf[total - carry + i];
        }
    }
    close(fd);
    return 0;
}

static int parallax_tracer_attached(void) {
    char path[18];
    char buf[4096];
    ssize_t got;
    int fd;
    long at;
    size_t i;

    parallax_unpack_path(
            path, 17,
            0x65732f636f72702full,
            0x75746174732f666cull,
            0x0000000000000073ull);
    fd = openat(0, path, O_RDONLY, 0);
    if (fd < 0)
        return 0;
    got = read(fd, buf, sizeof(buf));
    close(fd);
    if (got <= 0)
        return 0;

    at = parallax_find_token_ci(
            buf, (size_t)got,
            0x6950726563617254ull,
            0x0000000000003a64ull,
            10u);
    if (at < 0)
        return 0;
    i = (size_t)at + 10u;
    while (i < (size_t)got && (buf[i] == ' ' || buf[i] == '\t'))
        ++i;
    return i < (size_t)got && buf[i] >= '1' && buf[i] <= '9';
}

static int parallax_parse_hex_range(
        char const *line,
        size_t len,
        Elf64_Addr *lo,
        Elf64_Addr *hi) {
    size_t i = 0;
    Elf64_Addr a = 0, b = 0;
    int seen = 0;

    while (i < len && line[i] != '-') {
        unsigned v;
        char c = line[i++];
        if (c >= '0' && c <= '9')
            v = (unsigned)(c - '0');
        else if (c >= 'a' && c <= 'f')
            v = 10u + (unsigned)(c - 'a');
        else if (c >= 'A' && c <= 'F')
            v = 10u + (unsigned)(c - 'A');
        else
            return 0;
        if (a > (~(Elf64_Addr)0 >> 4))
            return 0;
        a = (a << 4) | v;
        seen = 1;
    }
    if (!seen || i >= len || line[i++] != '-')
        return 0;

    seen = 0;
    while (i < len && line[i] != ' ') {
        unsigned v;
        char c = line[i++];
        if (c >= '0' && c <= '9')
            v = (unsigned)(c - '0');
        else if (c >= 'a' && c <= 'f')
            v = 10u + (unsigned)(c - 'a');
        else if (c >= 'A' && c <= 'F')
            v = 10u + (unsigned)(c - 'A');
        else
            return 0;
        if (b > (~(Elf64_Addr)0 >> 4))
            return 0;
        b = (b << 4) | v;
        seen = 1;
    }
    if (!seen || b <= a)
        return 0;
    *lo = a;
    *hi = b;
    return 1;
}

static int parallax_maps_scan(Elf64_Addr *libc_lo, Elf64_Addr *libc_hi) {
    char path[16];
    char buf[4096 + 512];
    size_t carry = 0;
    int fd;
    int suspicious = 0;

    *libc_lo = 0;
    *libc_hi = 0;
    parallax_unpack_path(
            path, 15,
            0x65732f636f72702full,
            0x00007370616d2f66ull,
            0);
    fd = openat(0, path, O_RDONLY, 0);
    if (fd < 0)
        return 0;

    for (;;) {
        ssize_t got = read(fd, buf + carry, 4096);
        size_t total;
        size_t search = 0;
        if (got <= 0)
            break;
        total = carry + (size_t)got;

        /* Strong framework/module markers; generic words such as "hook" are
           intentionally excluded to avoid breaking legitimate SDKs. */
        if (parallax_has_token_ci(buf, total, 0x0000006164697266ull, 0, 5u) ||
            parallax_has_token_ci(buf, total, 0x7461727473627573ull, 0x65ull, 9u) ||
            parallax_has_token_ci(buf, total, 0x00006465736f7078ull, 0, 6u) ||
            parallax_has_token_ci(buf, total, 0x006465736f70736cull, 0, 7u) ||
            parallax_has_token_ci(buf, total, 0x6465736f70786465ull, 0, 8u) ||
            parallax_has_token_ci(buf, total, 0x6b6f6f68646e6173ull, 0, 8u) ||
            parallax_has_token_ci(buf, total, 0x0000006166686179ull, 0, 5u) ||
            parallax_has_token_ci(buf, total, 0x0000000075726972ull, 0, 4u) ||
            parallax_has_token_ci(buf, total, 0x00006b736967797aull, 0, 6u) ||
            parallax_has_token_ci(buf, total, 0x6f7463656a6e696cull, 0x72ull, 9u)) {
            suspicious = 1;
        }

        /* Collect executable libc mapping. */
        while (search < total) {
            long rel = parallax_find_token_ci(
                    buf + search, total - search,
                    0x6f732e6362696c2full, 0, 8u);
            size_t at, ls, le, dash, perm;
            Elf64_Addr lo, hi;
            if (rel < 0)
                break;
            at = search + (size_t)rel;
            ls = at;
            while (ls > 0 && buf[ls - 1] != '\n')
                --ls;
            le = at;
            while (le < total && buf[le] != '\n')
                ++le;
            dash = ls;
            while (dash < le && buf[dash] != '-')
                ++dash;
            perm = dash;
            while (perm < le && buf[perm] != ' ')
                ++perm;
            while (perm < le && buf[perm] == ' ')
                ++perm;

            if (perm + 3u < le && buf[perm] == 'r' && buf[perm + 2u] == 'x' &&
                parallax_parse_hex_range(buf + ls, le - ls, &lo, &hi)) {
                if (*libc_lo == 0 || lo < *libc_lo)
                    *libc_lo = lo;
                if (hi > *libc_hi)
                    *libc_hi = hi;
            }
            search = at + 8u;
        }

        carry = total < 512u ? total : 512u;
        {
            size_t i;
            for (i = 0; i < carry; ++i)
                buf[i] = buf[total - carry + i];
        }
    }
    close(fd);
    return suspicious;
}

static int parallax_in_range(
        Elf64_Addr addr,
        size_t size,
        Elf64_Addr lo,
        Elf64_Addr hi) {
    if (lo == 0 || hi <= lo || addr < lo)
        return 0;
    if ((Elf64_Addr)size > hi - addr)
        return 0;
    return addr + (Elf64_Addr)size <= hi;
}

static Elf64_Addr parallax_resolve_module_ptr(
        Elf64_Addr value,
        Elf64_Addr base,
        Elf64_Addr lo,
        Elf64_Addr hi,
        size_t size) {
    Elf64_Addr candidate;
    if (parallax_in_range(value, size, lo, hi))
        return value;
    if (value > ~(Elf64_Addr)0 - base)
        return 0;
    candidate = base + value;
    return parallax_in_range(candidate, size, lo, hi) ? candidate : 0;
}

static int parallax_name_is_strlen(char const *name) {
    return name[0] == 's' && name[1] == 't' && name[2] == 'r' &&
           name[3] == 'l' && name[4] == 'e' && name[5] == 'n' &&
           name[6] == 0;
}

static int parallax_branch_escapes_libc(
        Elf64_Addr target,
        Elf64_Addr libc_lo,
        Elf64_Addr libc_hi) {
    unsigned i;
    if (!parallax_in_range(target, 16u, libc_lo, libc_hi) || (target & 3u))
        return 1;

    for (i = 0; i < 4u; ++i) {
        Elf64_Addr pc = target + 4u * i;
        uint32_t insn = *(volatile uint32_t const *)(uintptr_t)pc;
        if ((insn & 0xfc000000u) == 0x14000000u) { /* unconditional B imm26 */
            int64_t imm = (int64_t)(insn & 0x03ffffffu);
            Elf64_Addr destination;
            if (imm & 0x02000000ll)
                imm |= ~0x03ffffffll;
            destination = (Elf64_Addr)((int64_t)pc + (imm << 2));
            if (!parallax_in_range(destination, 4u, libc_lo, libc_hi))
                return 1;
        }
    }
    return 0;
}

static int parallax_check_rela_table(
        ParallaxRela64 const *rela,
        size_t bytes,
        ParallaxSym64 const *symtab,
        char const *strtab,
        Elf64_Addr base,
        Elf64_Addr module_lo,
        Elf64_Addr module_hi,
        Elf64_Addr libc_lo,
        Elf64_Addr libc_hi) {
    size_t count;
    size_t i;

    if (!rela || !symtab || !strtab || bytes == 0 ||
        bytes % sizeof(ParallaxRela64) != 0)
        return 0;
    count = bytes / sizeof(ParallaxRela64);
    if (count > 16384u)
        return 1; /* malformed/unexpected table: fail closed */

    for (i = 0; i < count; ++i) {
        Elf64_Xword info = rela[i].r_info;
        unsigned type = (unsigned)(info & 0xffffffffu);
        Elf64_Xword sym_index = info >> 32;
        Elf64_Addr sym_addr;
        ParallaxSym64 const *sym;
        Elf64_Addr name_addr;
        char const *name;
        Elf64_Addr slot_addr;
        Elf64_Addr target;

        if (type != PARALLAX_R_AARCH64_JUMP_SLOT &&
            type != PARALLAX_R_AARCH64_GLOB_DAT)
            continue;
        if (sym_index > 1048576u)
            return 1;

        sym_addr = (Elf64_Addr)(uintptr_t)symtab;
        if (sym_index > (~(Elf64_Addr)0 - sym_addr) / sizeof(*symtab))
            return 1;
        sym_addr += sym_index * sizeof(*symtab);
        if (!parallax_in_range(sym_addr, sizeof(*symtab), module_lo, module_hi))
            continue;
        sym = (ParallaxSym64 const *)(uintptr_t)sym_addr;

        name_addr = (Elf64_Addr)(uintptr_t)strtab;
        if (sym->st_name > ~(Elf64_Addr)0 - name_addr)
            return 1;
        name_addr += sym->st_name;
        if (!parallax_in_range(name_addr, 7u, module_lo, module_hi))
            continue;
        name = (char const *)(uintptr_t)name_addr;
        if (!parallax_name_is_strlen(name))
            continue;

        slot_addr = parallax_resolve_module_ptr(
                rela[i].r_offset, base, module_lo, module_hi, sizeof(Elf64_Addr));
        if (!slot_addr)
            return 1;
        target = *(volatile Elf64_Addr const *)(uintptr_t)slot_addr;
        if (!parallax_in_range(target, 4u, libc_lo, libc_hi))
            return 1;
        if (parallax_branch_escapes_libc(target, libc_lo, libc_hi))
            return 1;
    }
    return 0;
}

static int parallax_strlen_hooked(
        ElfW(Ehdr) const *ehdr,
        char const *va_load,
        Elf64_Addr libc_lo,
        Elf64_Addr libc_hi) {
    ElfW(Phdr) const *phdr;
    ElfW(Phdr) const *phdrN;
    Elf64_Addr base = 0;
    Elf64_Addr module_lo = ~(Elf64_Addr)0;
    Elf64_Addr module_hi = 0;
    ElfW(Phdr) const *dynamic_phdr = nullptr;
    ParallaxDyn64 const *dyn;
    size_t dyn_count;
    size_t i;
    Elf64_Addr strtab_v = 0, symtab_v = 0, jmprel_v = 0, rela_v = 0;
    size_t pltrelsz = 0, relasz = 0, relaent = sizeof(ParallaxRela64);
    Elf64_Xword pltrel = 0;
    char const *strtab;
    ParallaxSym64 const *symtab;
    ParallaxRela64 const *jmprel = nullptr;
    ParallaxRela64 const *rela = nullptr;

    if (!libc_lo || libc_hi <= libc_lo)
        return 0; /* cannot establish a safe baseline */

    phdr = (ElfW(Phdr) const *)(ehdr + 1);
    phdrN = phdr + ehdr->e_phnum;
    for (i = 0; phdr + i < phdrN; ++i) {
        ElfW(Phdr) const *p = phdr + i;
        if (p->p_type == PT_LOAD && base == 0)
            base = (Elf64_Addr)(uintptr_t)va_load - p->p_vaddr;
    }
    if (base == 0)
        return 0;

    for (i = 0; phdr + i < phdrN; ++i) {
        ElfW(Phdr) const *p = phdr + i;
        if (p->p_type == PT_LOAD) {
            Elf64_Addr lo, hi;
            if (p->p_vaddr > ~(Elf64_Addr)0 - base ||
                p->p_memsz > ~(Elf64_Addr)0 - (base + p->p_vaddr))
                return 1;
            lo = base + p->p_vaddr;
            hi = lo + p->p_memsz;
            if (lo < module_lo)
                module_lo = lo;
            if (hi > module_hi)
                module_hi = hi;
        } else if (p->p_type == PARALLAX_PT_DYNAMIC) {
            dynamic_phdr = p;
        }
    }
    if (!dynamic_phdr || module_hi <= module_lo ||
        dynamic_phdr->p_vaddr > ~(Elf64_Addr)0 - base)
        return 0;

    dyn = (ParallaxDyn64 const *)(uintptr_t)(base + dynamic_phdr->p_vaddr);
    dyn_count = dynamic_phdr->p_memsz / sizeof(*dyn);
    if (dyn_count > 4096u)
        return 1;

    for (i = 0; i < dyn_count; ++i) {
        if (dyn[i].d_tag == PARALLAX_DT_NULL)
            break;
        switch ((long)dyn[i].d_tag) {
        case PARALLAX_DT_STRTAB: strtab_v = dyn[i].d_un.d_ptr; break;
        case PARALLAX_DT_SYMTAB: symtab_v = dyn[i].d_un.d_ptr; break;
        case PARALLAX_DT_JMPREL: jmprel_v = dyn[i].d_un.d_ptr; break;
        case PARALLAX_DT_PLTRELSZ: pltrelsz = (size_t)dyn[i].d_un.d_val; break;
        case PARALLAX_DT_PLTREL: pltrel = dyn[i].d_un.d_val; break;
        case PARALLAX_DT_RELA: rela_v = dyn[i].d_un.d_ptr; break;
        case PARALLAX_DT_RELASZ: relasz = (size_t)dyn[i].d_un.d_val; break;
        case PARALLAX_DT_RELAENT: relaent = (size_t)dyn[i].d_un.d_val; break;
        default: break;
        }
    }

    if (!strtab_v || !symtab_v)
        return 0;
    if (relaent != sizeof(ParallaxRela64))
        return 1;

    {
        Elf64_Addr p = parallax_resolve_module_ptr(
                strtab_v, base, module_lo, module_hi, 7u);
        if (!p)
            return 0;
        strtab = (char const *)(uintptr_t)p;
    }
    {
        Elf64_Addr p = parallax_resolve_module_ptr(
                symtab_v, base, module_lo, module_hi, sizeof(ParallaxSym64));
        if (!p)
            return 0;
        symtab = (ParallaxSym64 const *)(uintptr_t)p;
    }
    if (jmprel_v && pltrelsz) {
        Elf64_Addr p;
        if (pltrel != PARALLAX_DT_RELA)
            return 1;
        p = parallax_resolve_module_ptr(
                jmprel_v, base, module_lo, module_hi, pltrelsz);
        if (!p)
            return 1;
        jmprel = (ParallaxRela64 const *)(uintptr_t)p;
        if (parallax_check_rela_table(
                jmprel, pltrelsz, symtab, strtab,
                base, module_lo, module_hi, libc_lo, libc_hi))
            return 1;
    }
    if (rela_v && relasz) {
        Elf64_Addr p = parallax_resolve_module_ptr(
                rela_v, base, module_lo, module_hi, relasz);
        if (!p)
            return 1;
        rela = (ParallaxRela64 const *)(uintptr_t)p;
        if ((void const *)rela != (void const *)jmprel &&
            parallax_check_rela_table(
                rela, relasz, symtab, strtab,
                base, module_lo, module_hi, libc_lo, libc_hi))
            return 1;
    }
    return 0;
}

static int parallax_runtime_precheck(Elf64_Addr *libc_lo, Elf64_Addr *libc_hi) {
    if (parallax_ld_preload_active())
        return 1;
    if (parallax_tracer_attached())
        return 1;
    if (parallax_maps_scan(libc_lo, libc_hi))
        return 1;
    return 0;
}

#endif /* __aarch64__ */

extern char *upx_mmap_and_fd(  // x86_64 Android emulator of i386 is not faithful
     void *ptr  // desired address
     , unsigned len  // also pre-allocate space in file
     , char *pathname  // 0 ==> call get_upxfn_path, which stores if 1st time
);

#if defined(__x86_64__)  //{
char *
make_hatch(
    ElfW(Phdr) const *const phdr,
    char *next_unc,
    unsigned frag_mask
)
{
    unsigned *hatch = 0;
    unsigned code[3] = {
        0x5e5f050f,  // syscall; pop %arg1{%rdi}; pop %arg2{%rsi}
        0xff3e585a,  // pop %arg3{%rdx}; pop %rax; notrack jmp
        0x909090e0   // *%rax; nop; nop; nop
    };
    DPRINTF("make_hatch %%p %%p %%x\\n", phdr, next_unc, frag_mask);
    if (phdr->p_type==PT_LOAD && phdr->p_flags & PF_X) {
        next_unc += phdr->p_memsz - phdr->p_filesz;  // Skip over local .bss
        frag_mask &= -(long)next_unc;  // bytes left on page
        if (sizeof(code) <= frag_mask) {
            hatch = (unsigned *)next_unc;
            hatch[0] = code[0];
            hatch[1] = code[1];
            hatch[2] = code[2];
        }
        else { // Does not fit at hi end of .text, so must use a new page "permanently"
            unsigned long fdmap = (long)upx_mmap_and_fd((void *)0, sizeof(code), nullptr);
            unsigned mfd = -1+ (0xfff& fdmap);
            write(mfd, &code, sizeof(code));
            hatch = mmap((void *)(fdmap & ~0xffful), sizeof(code),
              PROT_READ|PROT_EXEC, MAP_PRIVATE, mfd, 0);
            close(mfd);
        }
    }
    DPRINTF("hatch=%%p\\n", hatch);
    return (char *)hatch;
}
#elif defined(__powerpc64__)  //}{
static unsigned
ORRX(unsigned ra, unsigned rs, unsigned rb) // or ra,rs,rb
{
    return (31<<26) | ((037&(rs))<<21) | ((037&(ra))<<16) | ((037&(rb))<<11) | (444<<1) | 0;
}

static char *
make_hatch(
    ElfW(Phdr) const *const phdr,
    char *next_unc,
    unsigned frag_mask
)
{
    unsigned code[4] = {
        0x44000002,  // sc
        ORRX(12,31,31),  // movr r12,r31 ==> or r12,r31,r31
        0x38800000,  // li r4,0
        0x4e800020,  // blr
    };
    unsigned *hatch = 0;
    DPRINTF("make_hatch %%p %%p %%x\\n", phdr, next_unc, frag_mask);
    if (phdr->p_type==PT_LOAD && phdr->p_flags & PF_X) {
        next_unc += phdr->p_memsz - phdr->p_filesz;  // Skip over local .bss
        frag_mask &= -(long)next_unc;  // bytes left on page
        if (4*4 <= frag_mask) {
            hatch = (unsigned *)(void *)(~3ul & (long)(3+ next_unc);
            hatch[0]= code[0];
            hatch[1]= code[1];
            hatch[2]= code[2];
            hatch[3]= code[3];
        }
        else { // Does not fit at hi end of .text, so must use a new page "permanently"
            int mfd = memfd_create(addr_string("parallax"), 0);  // the directory entry
            Pwrite(mfd, code, sizeof(code));
            hatch = Pmap(0, sizeof(code), PROT_READ|PROT_EXEC, MAP_PRIVATE, mfd, 0);
            close(mfd);
        }
    }
    DPRINTF("hatch=%%p\\n", hatch);
    return hatch;
}
#elif defined(__riscv)  //}{
extern void *my_memcpy(void *, const void *, long unsigned int);

static void * __attribute__((noinline))
make_hatch(
    ElfW(Phdr) const *const phdr,
    char *next_unc,
    unsigned const frag_mask
)
{
    unsigned long a = (unsigned long)next_unc;
    short *hatch = (short *)((1u & a) + a);
#define SZ_CODE (8*sizeof(short))
    char const *code;  // embedded "\x00" terminates!
    asm("jal %0,0f; \
        .int 0x00000073; \
        .short 0x6502, 0x65a2, 0x6642, 0x60e2, 0x6105; \
        .short 0x8082; \
     0: .balign 4" \
/*out*/ : "=r"(code) \
/* in*/ : \
/*und*/ : );
    DPRINTF("make_hatch %%p %%p %%x\\n", phdr, next_unc, frag_mask);
    if (phdr->p_type==PT_LOAD && phdr->p_flags & PF_X) {
        if (SZ_CODE <= (unsigned)(frag_mask & -(long)hatch)) {
            my_memcpy(hatch, code, SZ_CODE);
        }
        else { // Does not fit at hi end of .text, so must use a new page "permanently"
            int mfd = memfd_create(addr_string("parallax"), MFD_EXEC);  // the directory entry
            write(mfd, &code, SZ_CODE);
            hatch = mmap(0, SZ_CODE, PROT_READ|PROT_EXEC, MAP_SHARED, mfd, 0);
            close(mfd);
        }
    }
    DPRINTF("hatch=%%p\\n", hatch);
    return hatch;
}
#elif defined(__aarch64__)  //}{
static char *
make_hatch(
    ElfW(Phdr) const *const phdr,
    char *next_unc,
    unsigned frag_mask
)
{
    unsigned code[4] = {
        0xd4000001,  // svc #0
        0xa9417be2,  // ldp x2,lr,[sp,#2*8)]
        0xa8c207e0,  // ldp x0,x1,[sp], 4*8
        0xd61f03c0,  // br x30
    };
    unsigned *hatch = 0;
    DPRINTF("make_hatch phdr=%%p  next_unc=%%p  frag_mask= %%x\\n",
        phdr, next_unc, frag_mask);
    if (phdr->p_type==PT_LOAD && phdr->p_flags & PF_X) {
        next_unc += phdr->p_memsz - phdr->p_filesz;  // Skip over local .bss
        frag_mask &= -(long)next_unc;  // bytes left on page
        if (4*4 <= frag_mask) {
            hatch = (unsigned *)(void *)(~3ul & (long)(3+ next_unc));
            hatch[0]= code[0];
            hatch[1]= code[1];
            hatch[2]= code[2];
            hatch[3]= code[3];
            hatch = (unsigned *)&hatch[0];
        }
        else { // Does not fit at hi end of .text, so must use a new page "permanently"
            int mfd = memfd_create(addr_string("parallax"), 0);  // the directory entry
            Pwrite(mfd, code, sizeof(code));
            void *mfd_addr = Pmap(0, sizeof(code), PROT_READ|PROT_EXEC, MAP_PRIVATE, mfd, 0);
            close(mfd);
            hatch = (unsigned *)mfd_addr;
        }
    }
    DPRINTF("hatch=%%p\\n", hatch);
    return (char *)hatch;
}
#endif  //}

// The PF_* and PROT_* bits are {1,2,4}; the conversion table fits in 32 bits.
#define REP8(x) \
    ((x)|((x)<<4)|((x)<<8)|((x)<<12)|((x)<<16)|((x)<<20)|((x)<<24)|((x)<<28))
#define EXP8(y) \
    ((1&(y)) ? 0xf0f0f0f0 : (2&(y)) ? 0xff00ff00 : (4&(y)) ? 0xffff0000 : 0)
#define PF_TO_PROT(pf) \
    ((PROT_READ|PROT_WRITE|PROT_EXEC) & ( \
        ( (REP8(PROT_EXEC ) & EXP8(PF_X)) \
         |(REP8(PROT_READ ) & EXP8(PF_R)) \
         |(REP8(PROT_WRITE) & EXP8(PF_W)) \
        ) >> ((pf & (PF_R|PF_W|PF_X))<<2) ))

#undef PAGE_MASK

#if defined(__riscv)  //{  why is riscv the only one?
extern ElfW(Addr) get_page_mask(void);
#else  //}{
static ElfW(Addr)
get_page_mask(void)  // the mask which KEEPS the page, discards the offset
{
    ElfW(Addr) rv = ~0xffful;  // default to (PAGE_SIZE == 4KiB)
    int fd = openat(0, addr_string("/proc/self/auxv"), O_RDONLY, 0);
    if (0 <= fd) {
        ElfW(auxv_t) data[40];
        ElfW(auxv_t) *end = &data[read(fd, data, sizeof(data)) / sizeof(data[0])];
        close(fd);
        ElfW(auxv_t) *ptr; for (ptr = &data[0]; ptr < end ; ++ptr) {
            if (AT_PAGESZ == ptr->a_type) {
                rv = (0u - ptr->a_un.a_val);
                break;
            }
        }
    }
    DPRINTF("get_page_mask= %%p\\n", rv);
    return rv;
}
#endif  //}

extern void *memcpy(void *dst, void const *src, size_t n);
extern void *memset(void *dst, int val, size_t n);

// maximum page sizes
#if defined(__powerpc64__) || defined(__powerpc__)
#define SAVED_SIZE (1<<16)  /* 64 KB */
#else
#define SAVED_SIZE (1<<14)  /* 16 KB */
#endif

#ifndef __arm__  //{
// Segregate large local array, to avoid code bloat due to large displacements.
static void
underlay(unsigned size, char *ptr, unsigned page_mask)
{
    unsigned frag = ~page_mask & (unsigned)(long)ptr;
    if (frag) {
        unsigned saved[SAVED_SIZE / sizeof(unsigned)];  // want alignment
        ptr -= frag;
        memcpy(saved, ptr, frag);
        mmap(ptr, frag + size, PROT_WRITE|PROT_READ,
            MAP_FIXED|MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
        memcpy(ptr, saved, frag);
    }
    else { // already page-aligned
        mmap(ptr, frag + size, PROT_WRITE|PROT_READ,
            MAP_FIXED|MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    }
}
#else  //}{ // use assembler because large local array on __arm__ is horrible
extern void
underlay(unsigned size, char *ptr, unsigned page_mask);
#endif  //}

// Exchange the bits with values 4 (PF_R, PROT_EXEC) and 1 (PF_X, PROT_READ)
// Use table lookup into a PIC-string that pre-computes the result.
unsigned PF_to_PROT(ElfW(Phdr) const *phdr)
{
    return 7& addr_string("@\x04\x02\x06\x01\x05\x03\x07")
        [phdr->p_flags & (PF_R|PF_W|PF_X)];
}

unsigned
fini_SELinux(
    unsigned size,
    char *ptr,
    ElfW(Phdr) const *phdr,
    unsigned mfd,
    ElfW(Addr) base
)
{
    DPRINTF("fini_SELinux  size=%%p  ptr=%%p  phdr=%%p  mfd=%%p  base=%%p\\n",
            size, ptr, phdr, mfd, base);
    if (phdr->p_flags & PF_X) {
        // Map the contents of mfd as per *phdr.

        Psync(ptr, size, MS_SYNC); // be sure file gets de-compressed bytes
            // Android 14 gets -EINVAL; ignore it

        Punmap(ptr, size);
        Pmap(ptr, size, PF_to_PROT(phdr), MAP_FIXED|MAP_PRIVATE, mfd, 0);
        close(mfd);
    }
    else { // easy
        Pprotect( (char *)(phdr->p_vaddr + base), phdr->p_memsz, PF_to_PROT(phdr));
    }
    return 0;
}

unsigned
prep_SELinux(unsigned size, char *ptr, ElfW(Addr) page_mask) // returns mfd
{
    // Cannot set PROT_EXEC except via mmap() into a region (Linux "vma")
    // that has never had PROT_WRITE.  So use a Linux-only "memory file"
    // to hold the contents.
    unsigned saved[SAVED_SIZE / sizeof(unsigned)];  // want alignment
    char *page = (char *)(page_mask & (ElfW(Addr))ptr);
    unsigned frag = (unsigned)(ptr - page);
    if (frag) {
        memcpy(saved, page, frag);
    }
    char *val = upx_mmap_and_fd(page, frag + size, nullptr);
    unsigned mfd = 0xfff & (unsigned)(ElfW(Addr))val;
    val -= mfd; --mfd;
    if (val != page) {
        my_bkpt((void const *)0x1262, val, page, ptr, frag);
    }
    if (frag)
        write(mfd, saved, frag);  // Save lo fragment of contents on page.
    return mfd;
}

typedef struct {
    long argc;
    char **argv;
    char **envp;
} So_args;

typedef struct {
    unsigned off_reloc;  // distance back to &ElfW(Ehdr)
    unsigned off_user_DT_INIT;
    unsigned off_xct_off;  // where un-compressed bytes end
    unsigned off_info;  //  xct_off: {l_info; p_info; b_info; compressed data)
} So_info;

/*************************************************************************
// upx_so_main - called by our folded entry code
**************************************************************************/

void *
upx_so_main(  // returns &escape_hatch
    So_info *so_info,
    So_args *so_args,
    ElfW(Ehdr) *elf_tmp  // scratch for ElfW(Ehdr) and ElfW(Phdrs)
)
{
    ElfW(Addr) const page_mask = get_page_mask();
#if defined(__aarch64__)
    Elf64_Addr parallax_libc_lo = 0;
    Elf64_Addr parallax_libc_hi = 0;
    if (parallax_runtime_precheck(&parallax_libc_lo, &parallax_libc_hi))
        err_exit(90);
#endif
    char *const va_load = (char *)&so_info->off_reloc - so_info->off_reloc;
    So_info so_infc;  // So_info Copy
    memcpy(&so_infc, so_info, sizeof(so_infc));  // before de-compression overwrites
    unsigned const xct_off = so_infc.off_xct_off;  (void)xct_off;

    char *const cpr_ptr = so_info->off_info + va_load;
    unsigned const cpr_len = (char *)so_info - cpr_ptr;
    typedef void (*Dt_init)(int argc, char *argv[], char *envp[]);
    Dt_init const dt_init = (Dt_init)(void *)(so_info->off_user_DT_INIT + va_load);
    DPRINTF("upx_so_main  va_load=%%p  so_infc=%%p  cpr_ptr=%%p  cpr_len=%%x  xct_off=%%x\\n",
        va_load, &so_infc, cpr_ptr, cpr_len, xct_off);
    // DO NOT USE *so_info AFTER THIS!!  It gets overwritten.

    // Copy compressed data before de-compression overwrites it.
    char *const sideaddr = mmap(nullptr, cpr_len, PROT_WRITE|PROT_READ,
        MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    DPRINTF("&sideaddr=%%p\\n", &sideaddr);
    memcpy(sideaddr, cpr_ptr, cpr_len);

    // Transition to copied data
    struct p_info *pinfo = (struct p_info *)(void *)(sideaddr + sizeof(struct l_info));
    unsigned const pvm_program_id = pinfo->p_progid;
    struct b_info *binfo = (struct b_info *)(void *)(sideaddr +
        sizeof(struct l_info) + sizeof(struct p_info));
    DPRINTF("upx_so_main  va_load=%%p  sideaddr=%%p  b_info=%%p\\n",
        va_load, sideaddr, binfo);

    // All the destination page frames exist or have been reserved,
    // but the access permissions may be wrong and the data may be compressed.
    // Also, rtld maps the convex hull of all PT_LOAD but assumes that the
    // file supports those pages, even though the pages might lie beyond EOF.
    // If so, then Pprotect() is not enough: SIGBUS will occur.  Thus we
    // must mmap anonymous pages, except for first PT_LOAD with ELF headers.
    // So the general strategy (for each PT_LOAD) is:
    //   Save any contents on low end of destination page (the "prefix" pfx).
    //   mmap(,, PROT_WRITE|PROT_READ, MAP_FIXED|MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    //   Restore the prefix on the first destination page.
    //   De-compress from remaining [sideaddr, +sidelen).
    //   Pprotect(,, PF_TO_PROT(.p_flags));

    // Get the uncompressed ElfW(Ehdr) and ElfW(Phdr)
    // The first b_info is aligned, so direct access to fields is OK.
    Extent x1 = {binfo->sz_unc, (char *)elf_tmp};  // destination
    Extent x0 = {binfo->sz_cpr + sizeof(*binfo), (char *)binfo};  // source
    unpackExtent(&x0, &x1, pvm_program_id);  // de-compress _Ehdr and _Phdrs

    ElfW(Phdr) const *phdr = (ElfW(Phdr) *)(1+ elf_tmp);
    ElfW(Phdr) const *const phdrN = &phdr[elf_tmp->e_phnum];

#if defined(__aarch64__)
    if (parallax_strlen_hooked(
            elf_tmp, va_load, parallax_libc_lo, parallax_libc_hi))
        err_exit(91);
#endif

    // Process each read-only PT_LOAD.
    // A read+write PT_LOAD might be relocated by rtld before de-compression,
    // so it cannot be compressed.
    void *hatch = nullptr;
    ElfW(Addr) base = 0;
    int n_load = 0;

    for (; phdr < phdrN; ++phdr)
    if (phdr->p_type == PT_LOAD && !(phdr->p_flags & PF_W)) {
        if  (!base) {
            base = (ElfW(Addr))va_load - phdr->p_vaddr;
            DPRINTF("base=%%p\\n", base);
        }
        unsigned const va_top = phdr->p_filesz + phdr->p_vaddr;
        // Need un-aligned read of b_info to determine compression sizes.
        struct b_info al_bi;  // for aligned data from binfo
        x0.size = sizeof(struct b_info);
        xread(&x0, (char *)&al_bi, x0.size);  // aligned binfo
        x0.buf -= sizeof(al_bi);  // back up (the xread() was a peek)
        x0.size = al_bi.sz_cpr;
        x1.size = al_bi.sz_unc;
        x1.buf = (void *)(va_top + base - al_bi.sz_unc);

        DPRINTF("\\nphdr@%%p  p_offset=%%p  p_vaddr=%%p  p_filesz=%%p  p_memsz=%%p\\n",
            phdr, phdr->p_offset, phdr->p_vaddr, phdr->p_filesz, phdr->p_memsz);
        DPRINTF("x0=%%p  x1=%%p\\n", &x0, &x1);

        if ((phdr->p_filesz + phdr->p_offset) <= xct_off) { // va_top <= xct_off
            if (!n_load) {
                ++n_load;
                continue;  // 1st PT_LOAD is non-compressed loader tables ONLY!
            }
        }

        int mfd = 0;
        if (phdr->p_flags & PF_X) {
            mfd = prep_SELinux(x1.size, x1.buf, page_mask);
        }
        else {
            underlay(x1.size, x1.buf, page_mask);  // also makes PROT_WRITE
        }
        Extent xt = x1;
        unpackExtent(&x0, &x1, pvm_program_id);
        if (!hatch && phdr->p_flags & PF_X) {
            hatch = make_hatch(phdr, x1.buf, ~page_mask);
            fini_SELinux(xt.size, xt.buf, phdr, mfd, base);
        }
        ++n_load;
    }

    DPRINTF("Punmap sideaddr=%%p  cpr_len=%%p\\n", sideaddr, cpr_len);
    parallax_secure_zero(sideaddr, cpr_len);
    Punmap(sideaddr, cpr_len);
    DPRINTF("calling user DT_INIT %%p\\n", dt_init);
    dt_init(so_args->argc, so_args->argv, so_args->envp);

    DPRINTF("returning hatch=%%p\\n", hatch);
    return hatch;
}

#if DEBUG  //{

#if defined(__powerpc64__) //{
#define __NR_write 4

typedef unsigned long size_t;

#if 0  //{
static int
write(int fd, char const *ptr, size_t len)
{
    register  int        sys asm("r0") = __NR_write;
    register  int         a0 asm("r3") = fd;
    register void const  *a1 asm("r4") = ptr;
    register size_t const a2 asm("r5") = len;
    __asm__ __volatile__("sc"
    : "=r"(a0)
    : "r"(sys), "r"(a0), "r"(a1), "r"(a2)
    : "r0", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12", "r13"
    );
    return a0;
}
#else //}{
ssize_t
write(int fd, void const *ptr, size_t len)
{
    register  int        sys asm("r0") = __NR_write;
    register  int         a0 asm("r3") = fd;
    register void const  *a1 asm("r4") = ptr;
    register size_t       a2 asm("r5") = len;
    __asm__ __volatile__("sc"
    : "+r"(sys), "+r"(a0), "+r"(a1), "+r"(a2)
    :
    : "r6", "r7", "r8", "r9", "r10", "r11", "r12", "r13"
    );
    return a0;
}
#endif  //}
#endif  //}

static int
unsimal(unsigned x, char *ptr, int n)
{
    unsigned m = 10;
    while (10 <= (x / m)) m *= 10;
    while (10 <= x) {
        unsigned d = x / m;
        x -= m * d;
        m /= 10;
        ptr[n++] = '0' + d;
    }
    ptr[n++] = '0' + x;
    return n;
}

static int
decimal(int x, char *ptr, int n)
{
    if (x < 0) {
        ptr[n++] = '-';
    }
    return unsimal(-x, ptr, n);
}

static int
heximal(unsigned long x, char *ptr, int n)
{
    unsigned j = -1+ 2*sizeof(unsigned long);
    unsigned long m = 0xful << (4 * j);
    for (; j; --j, m >>= 4) { // omit leading 0 digits
        if (m & x) break;
    }
    for (; m; --j, m >>= 4) {
        unsigned d = 0xf & (x >> (4 * j));
        ptr[n++] = ((10<=d) ? ('a' - 10) : '0') + d;
    }
    return n;
}

#define va_arg      __builtin_va_arg
#define va_end      __builtin_va_end
#define va_list     __builtin_va_list
#define va_start    __builtin_va_start

static int
dprintf(char const *fmt, ...)
{
    int n= 0;
    char const *literal = 0;  // NULL
    char buf[24];  // ~0ull == 18446744073709551615 ==> 20 chars
    va_list va; va_start(va, fmt);
    for (;;) {
        char c = *fmt++;
        if (!c) { // end of fmt
            if (literal) {
                goto finish;
            }
            break;  // goto done
        }
        if ('%'!=c) {
            if (!literal) {
                literal = fmt;  // 1 beyond start of literal
            }
            continue;
        }
        // '%' == c
        if (literal) {
finish:
            n += write(2, -1+ literal, fmt - literal);
            literal = 0;  // NULL
            if (!c) { // fmt already ended
               break;  // goto done
            }
        }
        switch (c= *fmt++) { // deficiency: does not handle _long_
        default: { // un-implemented conversion
            n+= write(2, -1+ fmt, 1);
        } break;
        case 0: { // fmt ends with "%\0" ==> ignore
            goto done;
        } break;
        case 'u': {
            n+= write(2, buf, unsimal((unsigned)(unsigned long)va_arg(va, void *), buf, 0));
        } break;
        case 'd': {
            n+= write(2, buf, decimal((int)(unsigned long)va_arg(va, void *), buf, 0));
        } break;
        case 'p': {
            buf[0] = '0';
            buf[1] = 'x';
            n+= write(2, buf, heximal((unsigned long)va_arg(va, void *), buf, 2));
        } break;
        case 'x': {
            buf[0] = '0';
            buf[1] = 'x';
            n+= write(2, buf, heximal((unsigned)(unsigned long)va_arg(va, void *), buf, 2));
        } break;
        } // 'switch'
    }
done:
    va_end(va);
    return n;
 }
#endif  //}

/* vim:set ts=4 sw=4 et: */
