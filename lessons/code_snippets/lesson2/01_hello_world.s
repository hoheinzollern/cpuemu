.intel_syntax noprefix
.global _main
.section __TEXT,__text

_main:
    push    rbp
    mov     rbp, rsp
    
    lea     rdi, [rip + msg]
    call    _puts
    
    xor     eax, eax
    pop     rbp
    ret

.section __TEXT,__cstring
msg:
    .asciz  "Hello World!"
