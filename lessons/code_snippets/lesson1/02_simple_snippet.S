.intel_syntax noprefix
.global _main
.section __TEXT,__text

_main:
    push    rbp
    mov     rbp, rsp
    
    mov     edi, 5
    mov     esi, 10
    mov     eax, edi
    add     eax, esi
    
    pop     rbp
    ret
