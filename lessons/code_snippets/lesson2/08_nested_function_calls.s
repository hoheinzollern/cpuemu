main:
mov   rax, 1
call  foo
hlt

foo:
mov   rax, 2
call  bar
ret

bar:
mov   rax, 3
ret
