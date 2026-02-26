.intel_syntax noprefix
.global _main
.section __TEXT,__text

_main:
    push    rbp
    mov     rbp, rsp
    
    mov     rax, 0
    jmp     end
    
    mov     rax, 0xdeadbeef
    
end:
    pop     rbp
    ret
