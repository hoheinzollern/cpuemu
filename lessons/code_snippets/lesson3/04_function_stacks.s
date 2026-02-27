main:
  push  rbp
  mov   rbp, rsp
  mov   eax, 0
  call  a
  nop
  pop   rbp
  ret

a:
  push  rbp
  mov   rbp, rsp
  sub   rsp, 16
  mov   DWORD PTR [rbp-4], 0xAAAA
  mov   eax, 0
  call  b
  nop
  leave
  ret

b:
  push  rbp
  mov   rbp, rsp
  mov   DWORD PTR [rbp-4], 0xBBBB
  nop
  pop   rbp
  ret
