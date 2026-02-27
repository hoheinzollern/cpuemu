mov     rax, 0x100
mov     rbx, 0x200
cmp     rax, rbx
mov     rcx, rax
jl      rbx_lesser
mov     rcx, rbx
rbx_lesser:
nop
