.intel_syntax noprefix
.global _main
.section __TEXT,__text

_main:
    push    rbp
    mov     rbp, rsp
    
    nop
    nop
    nop
    
    xor     eax, eax
    pop     rbp
    ret
