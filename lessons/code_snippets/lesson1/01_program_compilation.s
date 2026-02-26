.intel_syntax noprefix
.global _main
.section __TEXT,__text

_main:
    push    rbp
    mov     rbp, rsp
    
    mov     eax, 1337
    mov     edx, 31337
    add     eax, edx
    
    xor     eax, eax
    pop     rbp
    ret
