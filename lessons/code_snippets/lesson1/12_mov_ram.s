mov rax, 0x1337
mov rdx, 0x2000
mov QWORD PTR [rdx], rax
mov DWORD PTR [rdx+0x8], 0xdead
