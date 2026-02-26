.intel_syntax noprefix
.global _main
.section __TEXT,__text

_main:
    push    rbp
    mov     rbp, rsp
    sub     rsp, 16
    
    mov     qword ptr [rbp - 8], 0x1234
    mov     qword ptr [rbp - 16], 0x5678
    
    mov     rax, qword ptr [rbp - 8]
    mov     rbx, qword ptr [rbp - 16]
    
    mov     rsp, rbp
    pop     rbp
    ret
