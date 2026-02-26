.intel_syntax noprefix
.global _main
.section __TEXT,__text

_main:
    push    rbp
    mov     rbp, rsp
    
    mov     rax, 0x100
    mov     rbx, rax
    mov     rcx, rbx
    mov     rdx, rcx
    
    xor     eax, eax
    pop     rbp
    ret
