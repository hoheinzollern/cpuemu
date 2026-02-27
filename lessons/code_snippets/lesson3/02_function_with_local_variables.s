foo:
push   rbp
mov    rbp, rsp
sub    rsp, 0x10
mov    DWORD PTR [rbp-0xc], 0x3e8
mov    DWORD PTR [rbp-0x8], 0x7d0
mov    DWORD PTR [rbp-0x4], 0xbb8
mov    edx, DWORD PTR [rbp-0xc]
mov    eax, DWORD PTR [rbp-0x8]
add    edx, eax
mov    eax, DWORD PTR [rbp-0x4]
add    eax, edx
leave
ret
