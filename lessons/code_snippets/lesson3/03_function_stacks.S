.intel_syntax noprefix
.global _main
.global _level3
.global _level2
.global _level1
.section __TEXT,__text

_level3:
    push    rbp
    mov     rbp, rsp
    sub     rsp, 8
    
    mov     dword ptr [rbp - 4], 3
    
    mov     rsp, rbp
    pop     rbp
    ret

_level2:
    push    rbp
    mov     rbp, rsp
    sub     rsp, 8
    
    mov     dword ptr [rbp - 4], 2
    call    _level3
    
    mov     rsp, rbp
    pop     rbp
    ret

_level1:
    push    rbp
    mov     rbp, rsp
    sub     rsp, 8
    
    mov     dword ptr [rbp - 4], 1
    call    _level2
    
    mov     rsp, rbp
    pop     rbp
    ret

_main:
    push    rbp
    mov     rbp, rsp
    
    call    _level1
    
    pop     rbp
    ret
