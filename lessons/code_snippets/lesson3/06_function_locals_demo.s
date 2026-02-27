main:
  push   rbp
  mov    rbp, rsp
  mov    esi, 0xdead
  mov    edi, 0
  call   foo
  nop
  pop    rbp
  ret

foo:
  push   rbp
  mov    rbp, rsp
  sub    rsp, 48
  mov    DWORD PTR [rbp-36], edi
  mov    DWORD PTR [rbp-40], esi
  mov    DWORD PTR [rbp-32], 1
  mov    DWORD PTR [rbp-28], 2
  mov    DWORD PTR [rbp-24], 3
  mov    DWORD PTR [rbp-20], 4
  mov    DWORD PTR [rbp-4], 0x1337
  mov    eax, DWORD PTR [rbp-36]
  cdqe
  mov    edx, DWORD PTR [rbp-40]
  mov    DWORD PTR [rbp-32+rax*4], edx
  mov    eax, DWORD PTR [rbp-4]
  leave
  ret
