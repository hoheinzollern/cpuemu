.intel_syntax noprefix
.global _main
.global _foo
.section __TEXT,__text

_foo:
    push    rbp
    mov     rbp, rsp
    sub     rsp, 16
    
    mov     dword ptr [rbp - 4], 1
    mov     dword ptr [rbp - 8], 2
    
    mov     eax, dword ptr [rbp - 4]
    mov     ecx, dword ptr [rbp - 8]
    add     eax, ecx
    
    mov     rsp, rbp
    pop     rbp
    ret

_main:
    push    rbp
    mov     rbp, rsp
    
    call    _foo
    
    pop     rbp
    ret
