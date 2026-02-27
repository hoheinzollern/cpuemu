main:
mov   rax, 1
call  foo
call  bar
hlt

foo:
mov   rax, 2
ret

bar:
mov   rax, 3
ret
