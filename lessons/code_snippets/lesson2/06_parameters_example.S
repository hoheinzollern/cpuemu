.intel_syntax noprefix
.global _main
.global _foo
.section __TEXT,__text

_foo:
    push    rbp
    mov     rbp, rsp
    
    mov     eax, 1
    
    pop     rbp
    ret

_main:
    push    rbp
    mov     rbp, rsp
    
    mov     edi, 1
    mov     esi, 2
    mov     edx, 3
    mov     ecx, 4
    mov     r8d, 5
    
    call    _foo
    
    pop     rbp
    ret
