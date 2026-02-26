.intel_syntax noprefix
.global _main
.global _foo
.section __TEXT,__text

_foo:
    push    rbp
    mov     rbp, rsp
    
    mov     eax, 0x42
    
    pop     rbp
    ret

_main:
    push    rbp
    mov     rbp, rsp
    
    call    _foo
    
    pop     rbp
    ret
