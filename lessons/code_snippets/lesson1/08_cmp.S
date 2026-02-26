.intel_syntax noprefix
.global _main
.section __TEXT,__text

_main:
    push    rbp
    mov     rbp, rsp
    
    mov     eax, 5
    mov     ecx, 3
    cmp     eax, ecx
    
    xor     eax, eax
    pop     rbp
    ret
