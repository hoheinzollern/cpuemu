.intel_syntax noprefix
.global _main
.section __TEXT,__text

_main:
    push    rbp
    mov     rbp, rsp
    
    mov     eax, 5
    mov     ecx, 10
    cmp     eax, ecx
    jl      less
    
    mov     edx, 0
    jmp     end
    
less:
    mov     edx, 1
    
end:
    xor     eax, eax
    pop     rbp
    ret
