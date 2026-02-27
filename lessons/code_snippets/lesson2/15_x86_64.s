main:
    push    rbp
    mov     rbp, rsp
    mov     r8d, 5
    mov     ecx, 4
    mov     edx, 3
    mov     esi, 2
    mov     edi, 1
    mov     eax, 0
    call    foo
    mov     eax, 0
    pop     rbp
    ret

foo:
    push    rbp
    mov     rbp, rsp
    mov     DWORD PTR [rbp-4], edi
    mov     DWORD PTR [rbp-8], esi
    mov     DWORD PTR [rbp-12], edx
    mov     DWORD PTR [rbp-16], ecx
    mov     DWORD PTR [rbp-20], r8d
    mov     eax, 1
    pop     rbp
    ret
