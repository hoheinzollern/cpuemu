.intel_syntax noprefix
.global _main
.global _foo
.global _bar
.section __TEXT,__text

_foo:
    push    rbp
    mov     rbp, rsp
    mov     eax, 2
    pop     rbp
    ret

_bar:
    push    rbp
    mov     rbp, rsp
    mov     eax, 3
    pop     rbp
    ret

_main:
    push    rbp
    mov     rbp, rsp
    
    mov     eax, 1
    call    _foo
    call    _bar
    
    pop     rbp
    ret
