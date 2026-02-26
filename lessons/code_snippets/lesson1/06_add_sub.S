.intel_syntax noprefix
.global _main
.section __TEXT,__text

_main:
    push    rbp
    mov     rbp, rsp
    
    mov     rax, 0x100
    mov     rbx, 0x200
    add     rax, rbx
    
    mov     rcx, 0x50
    sub     rax, rcx
    
    xor     eax, eax
    pop     rbp
    ret
