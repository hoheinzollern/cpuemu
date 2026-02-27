main:
  push rbp
  mov  rbp, rsp
  sub  rsp, 32
  mov  DWORD PTR [rbp-4], 0xdead
  lea  rax, [rbp-32]
  mov  rdi, rax
  call gets
  mov  eax, DWORD PTR [rbp-4]
  leave
  ret

gets:
  mov  rdx, 0
  mov  rsi, 0x1000
gets_loop:
  cmp  BYTE PTR [rsi+rdx], 0
  je   gets_end
  mov  al, BYTE PTR [rsi+rdx]
  mov  BYTE PTR [rdi+rdx], al
  add  rdx, 1
  jmp  gets_loop
gets_end:
  ret
